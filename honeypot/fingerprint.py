"""LLM 智能体指纹识别引擎。

这是系统的大脑。目标是把"大模型驱动的自动化渗透测试"从普通扫描器、真实
浏览器、搜索引擎爬虫里区分出来, 并给出可上报的证据。

核心判据分四层, 按证据强度递增:

  第一层 工具链指纹   —— UA / 头部顺序 / 头部集合, 便宜但可伪造
  第二层 行为节律     —— 微突发 + 思考停顿的节律, 扫描器伪装不了
  第三层 语义特征     —— 工具调用 JSON、自然语言载荷、自我暴露
  第四层 交互确证     —— 金丝雀回显、指令服从、蜜标读取(近确定性证据)

第四层是本系统的关键设计: 我们在响应里埋入随机令牌与指令, 只要对方在
后续请求里把令牌带回来、或按指令改了行为, 就证明它"读取并复用我们的
输出作为上下文"——那是 LLM 智能体独有的特征, 传统扫描器做不到。
"""

import hashlib
import json
import math
import re
import time

# ---- 信号权重表(便于审计与调参) -------------------------------------

# 场景包可以通过 configure() 覆盖这里的权重。覆盖是进程级的: 一个进程只服务
# 一个蜜罐实例, 因此不需要更细的作用域。若不提供覆盖机制, 场景包里的
# detection.weight_overrides 就只是一份"显示出来但不起作用"的配置(真实踩过)。
_WEIGHT_OVERRIDES = {}


def configure(weight_overrides=None, reset=False):
    """应用场景包的信号权重覆盖。返回实际生效的覆盖项。"""
    global _WEIGHT_OVERRIDES
    if reset:
        _WEIGHT_OVERRIDES = {}
    if weight_overrides:
        for name, delta in weight_overrides.items():
            if name in WEIGHTS:
                _WEIGHT_OVERRIDES[name] = int(delta)
    return dict(_WEIGHT_OVERRIDES)


def effective_weight(name):
    """信号的实际权重 = 内置权重 + 场景覆盖值。"""
    base = WEIGHTS.get(name, 0)
    return base + _WEIGHT_OVERRIDES.get(name, 0)


def active_weight_overrides():
    return dict(_WEIGHT_OVERRIDES)


WEIGHTS = {
    # 工具链
    "ua_ai_framework": 40,
    "ua_agent_framework": 35,
    "ua_automation_tool": 20,
    "ua_scanner_tool": 15,
    "ua_absent": 15,
    "ua_length_anomaly": 8,
    # 头部
    "browser_ua_without_browser_headers": 25,
    "agent_marker_header": 30,
    "no_asset_fetch": 12,
    "proxy_chain": 8,
    "proxy_chain_deep": 12,
    # 行为节律
    "cadence_agent_rhythm": 30,
    "cadence_machine_uniform": 18,
    "sequential_low_concurrency": 15,
    # 语义
    "toolcall_payload": 40,
    "self_identification": 25,
    "natural_language_payload": 15,
    "playbook_order": 5,
    "pentest_vocabulary": 10,
    "malformed_or_raw_http": 8,
    # 交互确证(最高价值)
    "canary_echo": 45,
    "injection_compliance": 50,
    "beacon_callback": 45,
    "honeytoken_read": 20,
    # 跨会话归因
    "multi_ip_same_toolchain": 15,
    "behavior_campaign": 20,
    "honeypot_path": 8,
    # SSH 诱饵(ssh_decoy.py)
    #
    # SSH 客户端在密钥交换完成前的报文是**未加密**的, 因此可以解析它的
    # KEXINIT 拿到算法偏好列表 —— 那是类似 TLS JA3 的强指纹: 不同客户端库
    # 的算法顺序高度稳定, 且难以随意更改。这使 SSH 侧也能做工具链归因。
    "ssh_client_paramiko": 40,       # Python 自动化(LLM 智能体常用)
    "ssh_client_automation": 30,     # Go/JS/Java 等自动化库
    "ssh_client_openssh": -15,       # 真实运维客户端, 反向信号
    "ssh_client_putty": -10,
    "ssh_client_scanner": 20,        # 扫描器自带的 SSH 探测
    "ssh_algorithm_fingerprint_repeat": 18,   # 同一算法指纹来自多个源 IP
    "ssh_kex_attempt": 10,           # 真的发起了密钥交换(而非只抓 banner)
    "ssh_banner_grab_only": 15,      # 只连不发, 典型扫描行为
    "ssh_kex_absent": 14,            # 交换了 banner 却不发起密钥交换
    "ssh_no_banner": 22,             # 不按协议发 banner, 非真实 SSH 客户端
    "ssh_brute_force_volume": 32,    # 同一来源高频重连(口令爆破特征)
    "ssh_old_or_anomalous_client": 16,

    # 反向信号(压低误报)
    "search_engine_crawler": -35,
    "real_browser_behavior": -40,
    "human_like_cadence": -35,
    "asset_fetching_client": -15,
}

# ---- 指纹表 ------------------------------------------------------------

# AI 厂商/推理框架直接出现在 UA —— 基本可以确定是 LLM 工具链
AI_UA_PATTERNS = [
    (r"openai", "openai"),
    (r"anthropic", "anthropic"),
    (r"claude", "claude"),
    (r"chatgpt", "chatgpt"),
    (r"gpt-?[0-9o]", "gpt"),
    (r"deepseek", "deepseek"),
    (r"qwen|tongyi", "qwen"),
    (r"glm-?[0-9]|chatglm|zhipu", "glm"),
    (r"moonshot|kimi", "kimi"),
    (r"gemini|bard", "gemini"),
    (r"mistral|mixtral", "mistral"),
    (r"llama[_-]?index|llamaindex", "llamaindex"),
    (r"langchain|langgraph", "langchain"),
    (r"llama[-_ ]?cpp|ollama", "local-llm"),
    (r"vllm|sglang", "local-llm"),
    (r"dify|coze|n8n|flowise", "llm-platform"),
]

# 智能体/自动化执行框架: 它们代表"有脑子的浏览器操作者"
AGENT_UA_PATTERNS = [
    (r"browser-?use", "browser-use"),
    (r"computer-?use", "computer-use"),
    (r"autogen|auto-?gen", "autogen"),
    (r"crewai|crew-ai", "crewai"),
    (r"semantic-?kernel", "semantic-kernel"),
    (r"mcp[-_/]|modelcontextprotocol", "mcp-client"),
    (r"autogpt|babyagi|agentgpt", "autogpt"),
    (r"swarm|metagpt|openmanus|manus", "agent-framework"),
    (r"playwright", "playwright"),
    (r"puppeteer", "puppeteer"),
    (r"selenium|webdriver", "selenium"),
    (r"headlesschrome", "headless-chrome"),
]

# 通用自动化客户端 —— 中性偏可疑, 本身不是 LLM 证据
AUTOMATION_UA_PATTERNS = [
    (r"python-requests", "python-requests"),
    (r"httpx", "httpx"),
    (r"aiohttp", "aiohttp"),
    (r"urllib", "urllib"),
    (r"^curl/", "curl"),
    (r"^wget/", "wget"),
    (r"go-http-client", "go-http-client"),
    (r"okhttp", "okhttp"),
    (r"java/", "java"),
    (r"libwww-perl", "libwww-perl"),
    (r"powershell", "powershell"),
    (r"axios|node-fetch|undici", "node-http"),
    (r"httpie", "httpie"),
]

# 传统扫描器 —— 说明是自动化, 但不是 LLM
SCANNER_UA_PATTERNS = [
    (r"nuclei", "nuclei"),
    (r"sqlmap", "sqlmap"),
    (r"nikto", "nikto"),
    (r"nmap", "nmap"),
    (r"masscan", "masscan"),
    (r"zgrab", "zgrab"),
    (r"ffuf", "ffuf"),
    (r"gobuster", "gobuster"),
    (r"dirsearch", "dirsearch"),
    (r"wfuzz", "wfuzz"),
    (r"feroxbuster", "feroxbuster"),
    (r"xray|xpoc", "xray"),
    (r"goby", "goby"),
    (r"awvs|acunetix", "acunetix"),
    (r"nessus|openvas|qualys", "nessus"),
    (r"whatweb|wpscan|joomscan", "cms-scanner"),
    (r"hydra|medusa|patator", "bruteforcer"),
    (r"testssl|sslscan", "tls-scanner"),
    (r"zap|burpsuite|burp", "burp-zap"),
    (r"metasploit|msfconsole", "metasploit"),
]

SEARCH_ENGINE_UA_PATTERNS = [
    (r"googlebot", "googlebot"),
    (r"bingbot|bingpreview", "bingbot"),
    (r"baiduspider", "baiduspider"),
    (r"yandex(bot)?", "yandexbot"),
    (r"sogou web spider", "sogou"),
    (r"360spider", "360spider"),
    (r"duckduckbot", "duckduckbot"),
    (r"applebot", "applebot"),
    (r"ahrefsbot|semrushbot|mj12bot|dotbot", "seo-crawler"),
    (r"petalbot", "petalbot"),
]

BROWSER_UA_RE = re.compile(r"mozilla/5\.0.*(chrome|firefox|safari|edg|trident|gecko)", re.I)

# 只有智能体/自动化工具会加的头部
AGENT_MARKER_HEADERS = [
    ("x-agent", 30), ("x-agent-id", 30), ("x-tool", 30), ("x-tool-name", 30),
    ("x-mcp-server", 35), ("x-mcp-session", 35), ("x-session-id", 12),
    ("x-llm", 35), ("x-model", 30), ("x-ai-provider", 35),
    ("x-automation", 25), ("x-bot", 18), ("x-scraper", 25),
    ("x-request-source", 10), ("x-trace-id", 8),
]

# 常见渗透"侦察清单"顺序: LLM 智能体倾向按逻辑清单推进, 而不是字典序
RECON_PLAYBOOK = [
    "/", "/robots.txt", "/sitemap.xml", "/llms.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/favicon.ico",
    "/login", "/admin", "/admin/login", "/dashboard", "/console",
    "/api", "/api/v1", "/api/v1/users", "/api/docs", "/api/health",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/v2/api-docs",
    "/health", "/healthz", "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/.env", "/.env.bak", "/config.json", "/config.php", "/settings.py",
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.aws/credentials",
    "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/info.php", "/test.php", "/debug", "/server-status",
    "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/administrator/",
    "/upload", "/uploads/", "/static/", "/assets/", "/files/",
    "/user", "/users", "/account", "/profile", "/search",
    "/api/v1/orders", "/api/v1/products", "/api/v1/items",
]
_PLAYBOOK_INDEX = {}
for _i, _p in enumerate(RECON_PLAYBOOK):
    _PLAYBOOK_INDEX.setdefault(_p.rstrip("/").lower() or "/", _i)

# 蜜罐专有路径: 正常业务系统不会有人访问
HONEYPOT_PATHS = [
    "/llms.txt", "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/admin.php", "/shell.php", "/cmd.php", "/webshell.php", "/1.php",
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.svn/entries",
    "/backup.zip", "/www.zip", "/web.tar.gz", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/phpmyadmin/", "/pma/", "/adminer.php",
    "/actuator/env", "/actuator/heapdump", "/actuator/httptrace",
    "/console/", "/h2-console/", "/jmx-console/", "/druid/index.html",
    "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa", "/.bash_history",
    "/server-status", "/nginx_status", "/status",
    "/api/v1/internal/config", "/_debug", "/__debug__", "/debug/vars",
]

# 工具调用 / 智能体编排载荷特征
TOOLCALL_PATTERNS = [
    (r'"tool_calls?"\s*:', "openai_tool_calls"),
    (r'"function_call"\s*:', "openai_function_call"),
    (r'"action_input"|"tool_input"', "react_action"),
    (r'"jsonrpc"\s*:\s*"2\.0"', "jsonrpc"),
    (r'"method"\s*:\s*"(tools/call|tools/list|resources/read|prompts/get)"', "mcp_tools_call"),
    (r'"params"\s*:\s*\{[^}]*"name"\s*:\s*"(fetch|browse|read_url|http_request|web_search|run_command|execute|shell|terminal)"', "agent_tool_invoke"),
    (r'"name"\s*:\s*"(fetch_url|read_file|execute_command|run_shell|http_get|browser_navigate|click|type)"', "agent_tool_name"),
    (r'"model"\s*:\s*"(gpt-|claude-|o1|o3|o4|deepseek|qwen|glm|kimi|gemini|llama)', "llm_api_payload"),
    (r'"messages"\s*:\s*\[\s*\{[^}]*"role"\s*:\s*"(system|user|assistant)"', "llm_chat_payload"),
    (r'"max_tokens"|"temperature"\s*:', "llm_sampling_params"),
    (r'"system_prompt"|"instructions"\s*:\s*"you are', "llm_system_prompt"),
    (r'"thought"|"reasoning"|"scratchpad"|"next_action"', "agent_scratchpad"),
    (r'"observation"\s*:|"final_answer"\s*:', "react_loop_trace"),
]

# 自我暴露 / 授权声明
SELF_ID_PATTERNS = [
    r"as an ai\b", r"i am an ai\b", r"i'm an ai\b", r"language model",
    r"我是一个?(ai|人工智能|大模型|智能体)", r"作为(一个)?(ai|人工智能|大模型)",
    r"autonomous agent", r"自主渗透", r"渗透测试智能体", r"自动化渗透",
    r"\bllm\b.*(agent|test|scan)", r"(agent|模型).*(发起|执行).*(渗透|扫描)",
    r"根据(我的|系统)?(指令|提示词|prompt)", r"我的(系统)?(提示词|指令)",
]

# 渗透术语 + "授权声明": LLM 智能体常被要求在请求里声明已授权
PENTEST_VOCAB_RE = re.compile(
    r"(authorized (penetration|pentest|security) test|penetration test|pentest|"
    r"security assessment|vulnerability scan|bug ?bounty|red ?team|"
    r"授权(测试|渗透)|渗透测试|漏洞(扫描|检测)|安全评估|众测|红队|攻防演练|"
    r"scope\.txt|hackerone|bugcrowd)",
    re.I,
)

# 自然语言载荷: 查询参数里塞进一句话 —— 人肉/工具都不会这么干
_NL_PAYLOAD_RE = re.compile(r"[A-Za-z\u4e00-\u9fff]{2,}(?:[ +%][A-Za-z\u4e00-\u9fff]{2,}){6,}")

LLM_MODEL_MENTIONS = [
    (r"claude[- ]?[0-9.]*", "claude"), (r"gpt-?[0-9o.]*", "gpt"),
    (r"deepseek[- ]?[a-z0-9.]*", "deepseek"), (r"qwen[\-0-9.]*", "qwen"),
    (r"glm[- ]?[0-9.]*", "glm"), (r"kimi", "kimi"), (r"gemini[- ]?[0-9.]*", "gemini"),
    (r"llama[- ]?[0-9.]*", "llama"), (r"mistral|mixtral", "mistral"),
    (r"grok[- ]?[0-9.]*", "grok"), (r"ernie|文心", "ernie"),
]


# ---- 工具函数 ----------------------------------------------------------

def sha1_short(text, length=16):
    return hashlib.sha1((text or "").encode("utf-8", "replace")).hexdigest()[:length]


def _match_table(patterns, text):
    """返回 [(名称, 正则)] 中所有匹配项。"""
    hits = []
    lowered = (text or "").lower()
    for pattern, name in patterns:
        if re.search(pattern, lowered):
            hits.append(name)
    return hits


def _match_regexes(patterns, text):
    """返回实际匹配到的文本片段(而非正则本身), 便于作为上报证据。"""
    hits = []
    for pattern in patterns:
        match = re.search(pattern, text or "", re.I)
        if match:
            hits.append(match.group(0)[:120])
    return hits


def analyze_cadence(intervals):
    """分析请求间隔节律。

    LLM 智能体的签名节律是"微突发 + 思考停顿":
      工具调用是连续几次毫秒级请求(微突发), 之后等模型推理 2~90 秒(停顿)。
    传统扫描器是均匀高速或均匀限速; 真人则是长尾不规则。
    """
    stats = {}
    if len(intervals) < 5:
        return None, stats

    micro = [g for g in intervals if g < 0.35]
    think = [g for g in intervals if 2.0 <= g <= 90.0]
    huge = [g for g in intervals if g > 90.0]
    mean = sum(intervals) / float(len(intervals))
    variance = sum((g - mean) ** 2 for g in intervals) / float(len(intervals))
    stdev = math.sqrt(variance)
    cv = stdev / mean if mean > 0 else 0.0
    ratio = (len(micro) + len(think)) / float(len(intervals))

    stats.update({
        "n": len(intervals), "mean": round(mean, 3), "stdev": round(stdev, 3),
        "cv": round(cv, 3), "micro_bursts": len(micro), "thinking_gaps": len(think),
        "long_gaps": len(huge), "explained_ratio": round(ratio, 3),
    })

    if len(micro) >= 2 and len(think) >= 2 and ratio >= 0.7 and not huge:
        return "agent_rhythm", stats
    if len(intervals) >= 8 and cv < 0.22 and mean < 1.5:
        return "machine_uniform", stats
    # 人类判定: 长且不规则的间隔。
    #
    # 原先要求必须存在 >90 秒的停顿, 结果短样本(十几次请求)永远凑不出这种停顿,
    # 于是真人的会话拿不到 reverse 信号(真实误报来源)。改为: 只要存在 >20 秒的
    # 明显停顿, 或整体间隔很长且高度不规则, 即可判定为人类节奏。
    longest = max(intervals) if intervals else 0.0
    stats["longest_gap"] = round(longest, 3)
    if mean > 2.5 and cv > 0.85 and (len(huge) >= 1 or longest > 20.0):
        return "human_like", stats
    return "mixed", stats


def playbook_monotonicity(paths):
    """衡量请求顺序与"侦察清单"顺序的一致程度。

    LLM 智能体按逻辑清单推进(recon -> auth -> api -> secrets), 因此它在
    清单里的索引序列高度单调递增; 字典序爆破和随机爬取的单调性很低。
    """
    indices = []
    for path in paths:
        key = (path or "/").rstrip("/").lower() or "/"
        if key in _PLAYBOOK_INDEX:
            indices.append(_PLAYBOOK_INDEX[key])
    if len(indices) < 4:
        return 0.0, len(indices)
    ascending = 0
    for prev, cur in zip(indices, indices[1:]):
        if cur >= prev:
            ascending += 1
    return ascending / float(len(indices) - 1), len(indices)


def classify_toolchain(ua, headers, body_text, target):
    """综合判定工具链与模型猜测。返回 (toolchain标签, 模型猜测, 命中细节)。"""
    haystack = " ".join([ua or "", target or ""])
    toolchain_hits = []
    model_guess = ""

    for family, table in (("ai", AI_UA_PATTERNS), ("agent", AGENT_UA_PATTERNS),
                          ("automation", AUTOMATION_UA_PATTERNS),
                          ("scanner", SCANNER_UA_PATTERNS),
                          ("searchengine", SEARCH_ENGINE_UA_PATTERNS)):
        for hit in _match_table(table, ua or ""):
            toolchain_hits.append("%s:%s" % (family, hit))

    # UA 之外: 正文/头部里出现框架名也算(库会在载荷里暴露自己)
    body_lower = (body_text or "")[:8192].lower()
    for family, table in (("ai", AI_UA_PATTERNS), ("agent", AGENT_UA_PATTERNS)):
        for name in _match_table(table, body_lower):
            toolchain_hits.append("body:%s" % name)

    for name, value in headers:
        lowered = (value or "").lower()
        for family, table in (("ai", AI_UA_PATTERNS), ("agent", AGENT_UA_PATTERNS)):
            for hit in _match_table(table, lowered):
                toolchain_hits.append("header:%s:%s" % (name.lower(), hit))

    for pattern, name in LLM_MODEL_MENTIONS:
        if re.search(pattern, haystack, re.I) or re.search(pattern, body_lower, re.I):
            model_guess = name
            break

    deduped = []
    for item in toolchain_hits:
        if item not in deduped:
            deduped.append(item)
    return ",".join(deduped), model_guess, deduped


# ---- 会话画像 ----------------------------------------------------------

class SessionProfile(object):
    """单个会话的行为画像。请求流持续喂给它, 它负责节律/顺序/一致性分析。"""

    def __init__(self, sid, ip, port, first_ts=None):
        self.sid = sid
        self.ip = ip
        self.port = port
        self.first_ts = first_ts or time.time()
        self.last_ts = self.first_ts
        self.timestamps = []
        self.paths = []
        self.methods = []
        self.asset_count = 0
        self.req_count = 0
        self.ua = ""
        self.ua_hash = ""
        self.header_sigs = {}
        self.header_sets = []
        self.body_kinds = set()
        self.tarpit_seconds = 0.0
        self.bytes_in = 0
        self.bytes_out = 0
        self.concurrency_peak = 0
        self.tokens_presented = []      # 我们埋的令牌被对方带回来的记录
        self.compliance_events = []     # 指令服从事件
        self.beacon_events = []         # 信标回调事件
        self.honeytoken_paths = []      # 触碰到蜜标的路径
        self.honeypot_path_hits = []
        self.non_http_probes = 0
        self.ip_seen_count = 0          # 同一 IP 的并发/累计连接数
        # 注意: 缓存字段必须叫 _behavior_hash。若叫 behavior_hash 会与下面的
        # behavior_hash() 方法同名, 实例属性会遮蔽方法, 调用即报
        # "'str' object is not callable"(真实踩过的坑)。
        self._behavior_hash = ""
        self.evaluations = 0

    # ---- 摄入 ----------------------------------------------------------

    def record(self, req, ts, body_text=""):
        self.req_count += 1
        self.last_ts = ts
        self.timestamps.append(ts)
        self.paths.append(req.path or "/")
        self.methods.append(req.method or "")
        if req.is_asset:
            self.asset_count += 1
        if not self.ua and req.ua:
            self.ua = req.ua
            self.ua_hash = sha1_short(req.ua)
        sig = req.header_order_sig
        self.header_sigs[sig] = self.header_sigs.get(sig, 0) + 1
        if len(self.header_sets) < 8:
            self.header_sets.append([name.lower() for name, _ in req.headers])
        body_lower = (body_text or "")[:8192].lower()
        if body_lower:
            for pattern, name in TOOLCALL_PATTERNS:
                if re.search(pattern, body_lower):
                    self.body_kinds.add(name)
        key = (req.path or "/").rstrip("/").lower() or "/"
        if key in HONEYPOT_PATHS and key not in self.honeypot_path_hits:
            self.honeypot_path_hits.append(key)

    def note_token_presented(self, token, where):
        item = {"token": token, "where": where, "ts": time.time()}
        if not any(e["token"] == token for e in self.tokens_presented):
            self.tokens_presented.append(item)

    def note_compliance(self, kind, detail):
        self.compliance_events.append({"kind": kind, "detail": detail, "ts": time.time()})

    def note_beacon(self, detail):
        self.beacon_events.append({"detail": detail, "ts": time.time()})

    def note_honeytoken(self, path):
        if path not in self.honeytoken_paths:
            self.honeytoken_paths.append(path)

    # ---- 分析 ----------------------------------------------------------

    def intervals(self):
        return [b - a for a, b in zip(self.timestamps, self.timestamps[1:]) if b >= a]

    def dominant_header_sig(self):
        if not self.header_sigs:
            return ""
        return max(self.header_sigs.items(), key=lambda pair: pair[1])[0]

    def claims_browser(self):
        return bool(BROWSER_UA_RE.search(self.ua or ""))

    def behavior_hash(self):
        """行为指纹: 不依赖 IP, 用于跨源 IP 关联同一操作者。

        组成: UA 哈希 + 主导头部顺序 + 路径集合 + 载荷类型 + 方法集合。
        换代理、换 VPS 都不会改变这四项。
        """
        if self._behavior_hash:
            return self._behavior_hash
        material = "|".join((
            self.ua_hash or "",
            self.dominant_header_sig(),
            ",".join(sorted(set((p or "/").rstrip("/").lower() or "/" for p in self.paths))[:64]),
            ",".join(sorted(self.body_kinds)),
            ",".join(sorted(set(m for m in self.methods if m))),
        ))
        self._behavior_hash = sha1_short(material, 20)
        return self._behavior_hash

    def summary(self):
        return {
            "sid": self.sid, "ip": self.ip, "req_count": self.req_count,
            "duration": round(self.last_ts - self.first_ts, 2),
            "paths": len(set(self.paths)), "assets": self.asset_count,
            "ua": self.ua[:200], "header_sig": self.dominant_header_sig(),
            "behavior_hash": self.behavior_hash(),
            "tokens_presented": [e["token"] for e in self.tokens_presented],
            "compliance_events": [e["kind"] for e in self.compliance_events],
            "beacons": [e["detail"] for e in self.beacon_events],
            "honeytokens": list(self.honeytoken_paths),
            "honeypot_paths": list(self.honeypot_path_hits),
            "body_kinds": sorted(self.body_kinds),
        }


# ---- 跨会话关联索引 ----------------------------------------------------

class CrossIndex(object):
    """内存关联索引: 头部指纹/行为指纹 -> 出现过的源 IP 集合。

    攻击方用代理池轮换 IP 时, 单看 IP 就漏了; 这里按工具链与行为聚合,
    能把同一操作者的多个来源 IP 串成一个战役。
    """

    def __init__(self):
        self.header_sig_ips = {}
        self.behavior_ips = {}
        self.ua_hash_ips = {}

    def observe(self, profile):
        sig = profile.dominant_header_sig()
        if sig:
            self.header_sig_ips.setdefault(sig, set()).add(profile.ip)
        bh = profile.behavior_hash()
        self.behavior_ips.setdefault(bh, set()).add(profile.ip)
        if profile.ua_hash:
            self.ua_hash_ips.setdefault(profile.ua_hash, set()).add(profile.ip)

    def ips_for_header_sig(self, sig):
        return self.header_sig_ips.get(sig, set())

    def ips_for_behavior(self, bh):
        return self.behavior_ips.get(bh, set())

    def ips_for_ua(self, ua_hash):
        return self.ua_hash_ips.get(ua_hash, set())


# ---- 判定结构 ----------------------------------------------------------

class Verdict(object):
    """一次评估的结论。"""

    def __init__(self):
        self.score = 0
        self.label = "unknown"
        self.confidence = 0.0
        self.signals = []          # [{"name","weight","kind","evidence"}]
        self.toolchain = ""
        self.model_guess = ""
        self.behavior_hash = ""
        self.cadence = None
        self.cadence_stats = {}
        self.playbook_ratio = 0.0
        self.decisive = []         # 近确定性证据(金丝雀/指令服从/信标)

    def add(self, name, weight=None, kind="behavior", evidence=""):
        amount = effective_weight(name) if weight is None else weight
        self.signals.append({
            "name": name, "weight": amount, "kind": kind, "evidence": str(evidence)[:512],
        })
        return amount

    def names(self):
        return [s["name"] for s in self.signals]

    def has(self, name):
        return name in self.names()

    def to_dict(self):
        return {
            "score": self.score, "label": self.label,
            "confidence": round(self.confidence, 3), "signals": self.signals,
            "toolchain": self.toolchain, "model_guess": self.model_guess,
            "behavior_hash": self.behavior_hash, "cadence": self.cadence,
            "cadence_stats": self.cadence_stats,
            "playbook_monotonicity": round(self.playbook_ratio, 3),
            "decisive": self.decisive,
        }


def _looks_like_human_assets(profile):
    return profile.asset_count >= 3


def evaluate(profile, req, index=None, now=None):
    """对一个会话的当前状态给出判定。

    这是一个纯函数式评估: 只看 profile 里累积的证据 + 跨会话索引,
    不做任何 IO, 方便单元测试与回放。
    """
    now = now or time.time()
    verdict = Verdict()
    verdict.behavior_hash = profile.behavior_hash()
    ua = profile.ua or req.ua or ""
    body_text = req.body_text
    target = (req.target or "") + " " + (req.query or "")
    headers_lower = [(name.lower(), (value or "")) for name, value in req.headers]

    # ---------- 第一层: 工具链 ----------
    toolchain, model_guess, tool_hits = classify_toolchain(
        ua, req.headers, body_text, req.target or ""
    )
    verdict.toolchain = toolchain
    verdict.model_guess = model_guess

    ua_lower = ua.lower()
    ai_hits = _match_table(AI_UA_PATTERNS, ua_lower)
    agent_hits = _match_table(AGENT_UA_PATTERNS, ua_lower)
    auto_hits = _match_table(AUTOMATION_UA_PATTERNS, ua_lower)
    scanner_hits = _match_table(SCANNER_UA_PATTERNS, ua_lower)
    se_hits = _match_table(SEARCH_ENGINE_UA_PATTERNS, ua_lower)

    if ai_hits:
        verdict.add("ua_ai_framework", kind="toolchain", evidence=",".join(ai_hits))
    if agent_hits:
        verdict.add("ua_agent_framework", kind="toolchain", evidence=",".join(agent_hits))
    if not ai_hits and not agent_hits and auto_hits:
        verdict.add("ua_automation_tool", kind="toolchain", evidence=",".join(auto_hits))
    if scanner_hits:
        verdict.add("ua_scanner_tool", kind="toolchain", evidence=",".join(scanner_hits))
    if not ua:
        verdict.add("ua_absent", kind="toolchain", evidence="no user-agent header")
    elif len(ua) > 400:
        verdict.add("ua_length_anomaly", kind="toolchain", evidence="ua length %d" % len(ua))
    if se_hits:
        verdict.add("search_engine_crawler", kind="negative", evidence=",".join(se_hits))

    # ---------- 第一层: 头部集合 ----------
    for name, value in headers_lower:
        for marker, weight in AGENT_MARKER_HEADERS:
            if name == marker:
                verdict.add("agent_marker_header", kind="toolchain",
                            evidence="%s: %s" % (name, value[:80]))
                break

    claims_browser = bool(BROWSER_UA_RE.search(ua))
    if claims_browser:
        # 按**会话内观测到的头部集合**判断, 而不是只看当前这一个请求。
        # 真实浏览器的不同请求头部集合不同(favicon/XHR 不发送 navigate 类头部),
        # 只看单请求会把正常浏览器判成"伪装 UA" —— 真实踩过的误报来源。
        # 只要会话中**有过一次**完整的浏览器头部集合, 就认定它确实是浏览器。
        observed_sets = list(profile.header_sets) or [
            [name.lower() for name, _ in req.headers]]
        best_missing = None
        for header_set in observed_sets:
            has_names = set(header_set)
            missing = 0
            if "accept-language" not in has_names:
                missing += 1
            if not any(n.startswith("sec-fetch") for n in has_names):
                missing += 1
            if not any(n.startswith("sec-ch-ua") for n in has_names):
                missing += 1
            if best_missing is None or missing < best_missing:
                best_missing = missing
        if best_missing is not None and best_missing >= 2:
            verdict.add("browser_ua_without_browser_headers", kind="toolchain",
                        evidence="浏览器 UA 但会话内从未出现完整浏览器头部集合(缺 %d 项)"
                                 % best_missing)

    xff = req.header("x-forwarded-for")
    if xff:
        hops = len([part for part in xff.split(",") if part.strip()])
        if hops >= 3:
            verdict.add("proxy_chain_deep", kind="toolchain", evidence="XFF hops=%d" % hops)
        elif hops >= 1:
            verdict.add("proxy_chain", kind="toolchain", evidence="XFF=%s" % xff[:120])
    for proxy_header in ("via", "x-real-ip", "forwarded", "cf-connecting-ip",
                         "x-proxy-user", "proxy-authorization"):
        if req.has_header(proxy_header):
            verdict.add("proxy_chain", kind="toolchain",
                        evidence="存在 %s 头部" % proxy_header)
            break

    # ---------- 第二层: 行为节律 ----------
    cadence, stats = analyze_cadence(profile.intervals())
    verdict.cadence = cadence
    verdict.cadence_stats = stats
    if cadence == "agent_rhythm":
        verdict.add("cadence_agent_rhythm", kind="behavior",
                    evidence="微突发 %d 次 / 思考停顿 %d 次, 解释率 %.2f" % (
                        stats.get("micro_bursts", 0), stats.get("thinking_gaps", 0),
                        stats.get("explained_ratio", 0)))
    elif cadence == "machine_uniform":
        verdict.add("cadence_machine_uniform", kind="behavior",
                    evidence="间隔均值 %.3fs, 变异系数 %.3f" % (
                        stats.get("mean", 0), stats.get("cv", 0)))
    elif cadence == "human_like":
        verdict.add("human_like_cadence", kind="negative",
                    evidence="间隔均值 %.2fs, 变异系数 %.2f, 长停顿 %d 次" % (
                        stats.get("mean", 0), stats.get("cv", 0), stats.get("long_gaps", 0)))

    # 低并发 + 长驻留: 智能体一次只跑一个工具调用
    #
    # 但这个信号本身有歧义 —— 真人浏览也是低并发顺序访问。实测发现它会给
    # 正常浏览器平白加 15 分(真实误报来源), 因此要求**至少还有一项自动化证据**
    # 才计入: 没拉取静态资源、或 UA 是自动化工具。这两者任一条成立时, 低并发
    # 才真正指向"工具驱动"而非"人在看页面"。
    duration = profile.last_ts - profile.first_ts
    automation_evidence = (
        profile.asset_count == 0
        or bool(_match_table(AUTOMATION_UA_PATTERNS, ua_lower))
        or bool(_match_table(AGENT_UA_PATTERNS, ua_lower))
        or bool(_match_table(AI_UA_PATTERNS, ua_lower))
    )
    if (profile.req_count >= 8 and duration >= 20.0
            and profile.concurrency_peak <= 2 and profile.concurrency_peak > 0
            and automation_evidence):
        verdict.add("sequential_low_concurrency", kind="behavior",
                    evidence="并发峰值 %d, 会话时长 %.1fs, 请求 %d, 且存在自动化迹象" % (
                        profile.concurrency_peak, duration, profile.req_count))

    if profile.req_count >= 8 and profile.asset_count == 0 and not profile.claims_browser():
        verdict.add("no_asset_fetch", kind="behavior",
                    evidence="%d 次请求未拉取任何静态资源" % profile.req_count)
    if _looks_like_human_assets(profile) and profile.claims_browser():
        verdict.add("asset_fetching_client", kind="negative",
                    evidence="已拉取 %d 个静态资源" % profile.asset_count)

    # ---------- 第三层: 语义 ----------
    body_kinds = set(profile.body_kinds)
    for pattern, name in TOOLCALL_PATTERNS:
        if re.search(pattern, body_text, re.I):
            body_kinds.add(name)
    if body_kinds:
        verdict.add("toolcall_payload", kind="semantic", evidence=",".join(sorted(body_kinds)))

    self_id = _match_regexes(SELF_ID_PATTERNS, body_text + " " + target)
    if self_id:
        verdict.add("self_identification", kind="semantic",
                    evidence="正文/参数中出现模型自我暴露: %s" % self_id[0][:60])

    if PENTEST_VOCAB_RE.search(target) or PENTEST_VOCAB_RE.search(body_text[:4096]):
        verdict.add("pentest_vocabulary", kind="semantic",
                    evidence="载荷包含渗透/授权术语")

    probe = "%s %s %s" % (req.path or "", req.query or "", body_text[:2048])
    nl_match = _NL_PAYLOAD_RE.search(probe.replace("&", " ").replace("=", " "))
    if nl_match and len(nl_match.group(0)) >= 40:
        verdict.add("natural_language_payload", kind="semantic",
                    evidence="参数中含自然语言串: %s" % nl_match.group(0)[:80])

    # 清单顺序单调性: **低权重辅助信号, 不作为主要依据**。
    #
    # 实测(见 tests/test_detection.py 的样本)单调性为: 智能体 0.64、
    # 传统扫描器 0.55、真实浏览器 0.75 —— 浏览器反而最高, 因为它的路径少,
    # 偶然就会是升序。该特征不足以承担判别责任, 因此权重从 20 降到 5,
    # 并要求至少命中 8 条清单路径才计入(样本太少时比值噪声过大)。
    # 真正承担判别责任的是节律、工具链与交互确证。
    playbook_ratio, playbook_len = playbook_monotonicity(profile.paths)
    verdict.playbook_ratio = playbook_ratio
    if playbook_len >= 8 and playbook_ratio >= 0.8:
        verdict.add("playbook_order", kind="semantic",
                    evidence="%d 个侦察路径中 %.0f%% 按清单顺序推进(辅助证据)" % (
                        playbook_len, playbook_ratio * 100))

    if profile.honeypot_path_hits:
        verdict.add("honeypot_path", kind="semantic",
                    evidence="命中诱饵路径: %s" % ",".join(profile.honeypot_path_hits[:6]))

    if req.malformed or not req.is_http:
        verdict.add("malformed_or_raw_http", kind="semantic",
                    evidence=",".join(req.malformed[:6]) or (req.not_http_reason or "非 HTTP"))

    # ---------- 第四层: 交互确证(最高价值) ----------
    if profile.tokens_presented:
        evidence = "; ".join("%s@%s" % (e["token"], e["where"]) for e in profile.tokens_presented[:4])
        verdict.add("canary_echo", kind="decisive",
                    evidence="我们在响应中埋入的令牌出现在对方后续请求里: %s" % evidence)
        verdict.decisive.append("canary_echo")

    if profile.compliance_events:
        evidence = "; ".join(e["detail"] for e in profile.compliance_events[:4])
        verdict.add("injection_compliance", kind="decisive",
                    evidence="对方服从了我们嵌入的指令: %s" % evidence)
        verdict.decisive.append("injection_compliance")

    if profile.beacon_events:
        verdict.add("beacon_callback", kind="decisive",
                    evidence="对方按指令回连了信标端点: %s" % (
                        "; ".join(str(e["detail"]) for e in profile.beacon_events[:4])))
        verdict.decisive.append("beacon_callback")

    if profile.honeytoken_paths:
        verdict.add("honeytoken_read", kind="decisive",
                    evidence="读取了蜜标凭据: %s" % ",".join(profile.honeytoken_paths[:6]))

    # ---------- 跨会话归因 ----------
    if index is not None:
        sig_ips = index.ips_for_header_sig(profile.dominant_header_sig())
        if len(sig_ips) >= 3:
            verdict.add("multi_ip_same_toolchain", kind="attribution",
                        evidence="同一头部顺序指纹来自 %d 个源 IP: %s" % (
                            len(sig_ips), ",".join(sorted(sig_ips)[:8])))
        bh_ips = index.ips_for_behavior(profile.behavior_hash())
        if len(bh_ips) >= 2:
            verdict.add("behavior_campaign", kind="attribution",
                        evidence="同一行为指纹来自 %d 个源 IP(疑似代理池): %s" % (
                            len(bh_ips), ",".join(sorted(bh_ips)[:8])))

    # ---------- 汇总 ----------
    raw = sum(s["weight"] for s in verdict.signals)
    # 负向信号只用来压制, 不允许把分数压成负数
    verdict.score = int(max(0, min(100, raw)))
    verdict.confidence = min(0.99, verdict.score / 100.0)
    if verdict.decisive:
        verdict.confidence = max(verdict.confidence, 0.97)

    llm_evidence = any(s["kind"] in ("llm", "decisive", "semantic") for s in verdict.signals) or bool(ai_hits or agent_hits)
    if verdict.score >= 80 and llm_evidence:
        verdict.label = "llm_agent"
    elif verdict.score >= 55 and llm_evidence:
        verdict.label = "llm_agent_probable"
    elif se_hits:
        verdict.label = "search_engine"
    elif verdict.score >= 35 and (scanner_hits or auto_hits):
        verdict.label = "automation_scanner"
    elif verdict.score < 25 and claims_browser and profile.asset_count > 0:
        verdict.label = "browser"
    elif verdict.score < 25:
        verdict.label = "unknown"
    else:
        verdict.label = "suspicious_automation"

    if not verdict.model_guess and verdict.decisive and verdict.has("playbook_order"):
        verdict.model_guess = "LLM agent (家族未知, 已确证上下文记忆)"
    elif not verdict.model_guess and agent_hits:
        verdict.model_guess = "agent framework: %s" % agent_hits[0]
    return verdict


def render_report_line(verdict, profile):
    """生成一行告警文本, 便于直接进日志/汇报。"""
    return "[%s] score=%d conf=%.2f ip=%s reqs=%d ua=%r toolchain=%r model=%r evidence=%s" % (
        verdict.label, verdict.score, verdict.confidence, profile.ip, profile.req_count,
        (profile.ua or "")[:80], verdict.toolchain, verdict.model_guess,
        ",".join(verdict.decisive) or "-",
    )
