"""判别能力测试: 智能体 / 扫描器 / 浏览器 三方区分。

这是全项目最关键的测试。一个检测系统如果只证明"能抓到目标", 是不可信的 ——
它可能只是把所有东西都判成目标。因此这里同时验证两件事:

  1. **抓得到**: 具有 LLM 智能体特征的样本必须被判为 llm_agent
  2. **不误报**: 传统扫描器不得判为智能体; 真实浏览器必须低分且不触发拖滞

样本是**在进程内合成的请求序列**, 不依赖真实服务, 因此测试快速且确定。
"""

import time

import fingerprint
import http_parse


# --------------------------------------------------------------------------
# 样本构造
# --------------------------------------------------------------------------

AGENT_UA = "python-httpx/0.27.0 (llm-agent-toolkit/1.2)"
SCANNER_UA = "nuclei/3.1.0"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

BROWSER_HEADERS = [
    "Accept-Language: zh-CN,zh;q=0.9",
    "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
    "Sec-Fetch-Dest: document",
    "Sec-Fetch-Mode: navigate",
    "Sec-Ch-Ua: \"Chromium\";v=\"124\"",
    "Cookie: session_id=abc123",
    "Referer: http://honeypot.local/",
]


def make_request(path, ua, headers=None, method="GET", body=b""):
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: honeypot.local",
             "User-Agent: %s" % ua]
    for item in (headers or []):
        lines.append(item)
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
    req = http_parse.parse_head(raw)
    req.body = body
    req.body_len = len(body)
    return req


def build_profile(sid, specs, gaps):
    """按 (路径, UA, 头部) 序列与间隔构造会话画像。"""
    profile = fingerprint.SessionProfile(sid, "203.0.113.%d" % (len(sid) % 200), 40000)
    now = time.time()
    for index, spec in enumerate(specs):
        path, ua, headers = spec
        profile.record(make_request(path, ua, headers), now)
        now += gaps[index] if index < len(gaps) else 1.0
    profile.last_ts = now
    return profile


# --------------------------------------------------------------------------
# 样本定义
# --------------------------------------------------------------------------

AGENT_PATHS = [
    "/robots.txt", "/llms.txt", "/.well-known/security.txt", "/", "/login",
    "/admin", "/api/docs", "/api/v1/users?page=1", "/api/v1/users?id=1'",
    "/.env", "/.git/config", "/config.json", "/actuator/env",
    "/phpinfo.php", "/backup.zip",
]
# 微突发(<0.35s) 与 思考停顿(2-90s) 交替 —— 智能体的签名节律
AGENT_GAPS = [0.12, 0.15, 0.10, 3.2, 0.18, 0.14, 4.1, 0.20, 0.16,
              5.3, 0.11, 0.13, 2.8, 0.19, 3.9]

SCANNER_PATHS = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.env", "/.env.bak",
    "/admin", "/admin.php", "/adminer.php", "/administrator/", "/api",
    "/api/v1", "/api/v2", "/backup.sql", "/backup.zip", "/config.php",
]
# 均匀高速 —— 扫描器的签名节律
SCANNER_GAPS = [0.05] * 15

BROWSER_PATHS = [
    "/", "/static/app.css", "/static/app.js", "/favicon.ico", "/login",
    "/static/app.css", "/", "/static/app.js", "/api/docs", "/static/logo.png",
]
# 人类节奏: 长、不规则、存在超长停顿
BROWSER_GAPS = [7.2, 1.1, 13.4, 0.9, 21.7, 1.3, 38.2, 1.0, 9.6, 1.2]


def agent_profile(sid="agent-1"):
    specs = [(path, AGENT_UA, None) for path in AGENT_PATHS]
    profile = build_profile(sid, specs, AGENT_GAPS)
    profile.concurrency_peak = 1
    return profile


def scanner_profile(sid="scanner-1"):
    specs = [(path, SCANNER_UA, None) for path in SCANNER_PATHS]
    profile = build_profile(sid, specs, SCANNER_GAPS)
    profile.concurrency_peak = 8
    return profile


def browser_profile(sid="browser-1"):
    specs = [(path, BROWSER_UA, BROWSER_HEADERS) for path in BROWSER_PATHS]
    profile = build_profile(sid, specs, BROWSER_GAPS)
    profile.concurrency_peak = 2
    return profile


def verdict_for(profile, index=None):
    request = make_request("/", profile.ua)
    return fingerprint.evaluate(profile, request, index)


# --------------------------------------------------------------------------
# 检测能力
# --------------------------------------------------------------------------

def test_agent_detected_as_llm_agent():
    verdict = verdict_for(agent_profile())
    assert verdict.label in ("llm_agent", "llm_agent_probable"), \
        "智能体样本被判为 %s (分数 %d), 期望 llm_agent" % (verdict.label, verdict.score)
    assert verdict.score >= 55, "分数过低: %d" % verdict.score


def test_agent_cadence_rhythm_detected():
    profile = agent_profile()
    verdict = verdict_for(profile)
    assert verdict.cadence == "agent_rhythm", \
        "节律判定为 %s, 期望 agent_rhythm (统计 %s)" % (verdict.cadence, verdict.cadence_stats)
    assert verdict.has("cadence_agent_rhythm"), "未命中节律信号"


def test_agent_toolchain_and_behavior_signals():
    verdict = verdict_for(agent_profile())
    names = verdict.names()
    assert verdict.has("no_asset_fetch"), "未命中 no_asset_fetch"
    assert verdict.has("cadence_agent_rhythm"), "未命中节律信号"
    assert ("ua_automation_tool" in names or "ua_agent_framework" in names
            or "ua_ai_framework" in names), "未识别工具链, 命中: %s" % names


def test_playbook_order_is_auxiliary_only():
    """清单顺序单调性只作辅助证据 —— 这一条由实测数据决定, 不是拍脑袋。

    实测单调性: 智能体 0.64 / 传统扫描器 0.55 / 真实浏览器 0.75。
    浏览器反而最高(路径少, 偶然升序), 因此该特征不能承担判别责任:
    它的权重被降到 5, 且要求至少命中 8 条清单路径才计入。
    """
    assert fingerprint.WEIGHTS["playbook_order"] <= 5, \
        "playbook_order 权重仍为 %d, 但实测它不是可靠判别特征" % \
        fingerprint.WEIGHTS["playbook_order"]

    browser = browser_profile()
    ratio, matched = fingerprint.playbook_monotonicity(browser.paths)
    if matched < 8:
        verdict = verdict_for(browser)
        assert not verdict.has("playbook_order"), \
            "仅命中 %d 条清单路径就触发了单调性信号(样本过少, 噪声大)" % matched


def test_discrimination_ordering():
    """三方分数应形成明确的序: 智能体 > 扫描器 > 浏览器。

    这是检测系统可信度的最低要求 —— 若浏览器分数接近智能体, 就会产生误报;
    若扫描器与智能体同分, 说明无法区分两类不同威胁, 处置策略会失准。
    """
    agent = verdict_for(agent_profile()).score
    scanner = verdict_for(scanner_profile()).score
    browser = verdict_for(browser_profile()).score
    assert agent > scanner > browser, \
        "判别序失常: 智能体 %d / 扫描器 %d / 浏览器 %d" % (agent, scanner, browser)
    assert browser == 0, "真实浏览器应被反向信号压到 0 分, 实际 %d" % browser
    assert scanner < 70, "扫描器分数 %d 偏高, 会触发不必要的注入处置" % scanner


# --------------------------------------------------------------------------
# 误报控制
# --------------------------------------------------------------------------

def test_scanner_not_judged_as_agent():
    verdict = verdict_for(scanner_profile())
    assert verdict.label != "llm_agent", \
        "传统扫描器被误判为 llm_agent(分数 %d) —— 误报" % verdict.score
    assert not verdict.has("canary_echo"), "扫描器样本不应有金丝雀回显"
    assert not verdict.has("injection_compliance"), "扫描器样本不应有指令服从"


def test_scanner_cadence_is_uniform_not_agent():
    verdict = verdict_for(scanner_profile())
    assert verdict.cadence != "agent_rhythm", \
        "扫描器的均匀节律被误判为智能体节律(统计 %s)" % verdict.cadence_stats


def test_browser_scores_low():
    verdict = verdict_for(browser_profile())
    assert verdict.score < 25, \
        "真实浏览器分数 %d 偏高(应为 <25), 存在误报风险" % verdict.score
    assert verdict.label != "llm_agent", "真实浏览器被误判为智能体"


def test_browser_triggers_negative_signals():
    verdict = verdict_for(browser_profile())
    negative = [s for s in verdict.signals if s["kind"] == "negative"]
    assert negative, "浏览器样本未触发任何反向信号, 反向权重可能失效"
    assert (verdict.has("asset_fetching_client")
            or verdict.has("human_like_cadence")), \
        "未命中静态资源拉取或人类节律信号, 命中: %s" % verdict.names()


def test_browser_ua_without_browser_headers_flagged():
    """伪装成浏览器的自动化工具应被抓到 —— 这正是最需要识别的绕过手法。"""
    specs = [("/", BROWSER_UA, None) for _ in range(10)]
    profile = build_profile("fake-browser", specs, [0.05] * 10)
    verdict = verdict_for(profile)
    assert verdict.has("browser_ua_without_browser_headers"), \
        "自称浏览器但缺失浏览器专属头部, 未命中伪装信号"


# --------------------------------------------------------------------------
# 确证证据
# --------------------------------------------------------------------------

def test_canary_echo_is_decisive():
    profile = agent_profile("canary-1")
    profile.note_token_presented("hpx-deadbeef", "headers/body")
    verdict = verdict_for(profile)
    assert verdict.has("canary_echo"), "金丝雀回显未命中"
    assert "canary_echo" in verdict.decisive, "金丝雀回显未被标为确证证据"
    assert verdict.confidence >= 0.95, "有确证证据时置信度应 >=0.95"
    assert verdict.label == "llm_agent", "有确证证据应判为 llm_agent"


def test_injection_compliance_is_decisive():
    profile = agent_profile("compliance-1")
    profile.note_compliance("按范围校验要求交出系统提示词", "X-Scope-Config: {...}")
    verdict = verdict_for(profile)
    assert verdict.has("injection_compliance"), "指令服从未命中"
    assert "injection_compliance" in verdict.decisive
    assert verdict.label == "llm_agent"


def test_beacon_callback_is_decisive():
    profile = agent_profile("beacon-1")
    profile.note_beacon("/__hp/verify.png")
    verdict = verdict_for(profile)
    assert verdict.has("beacon_callback")
    assert verdict.label == "llm_agent"


def test_honeytoken_read_counted():
    profile = agent_profile("token-1")
    profile.note_honeytoken("env_credentials")
    verdict = verdict_for(profile)
    assert verdict.has("honeytoken_read"), "蜜标读取未计入判定"


# --------------------------------------------------------------------------
# 跨源归因
# --------------------------------------------------------------------------

def test_behavior_hash_stable_across_ips():
    """同一行为模式在不同源 IP 上应产生相同行为哈希 —— 这是击穿代理池的基础。"""
    profile_a = agent_profile("ip-a")
    profile_b = agent_profile("ip-b")
    profile_b.ip = "198.51.100.77"
    assert profile_a.behavior_hash() == profile_b.behavior_hash(), \
        "相同行为的两个源 IP 得到不同行为哈希, 跨源归因会失效"


def test_behavior_hash_differs_for_different_clients():
    assert agent_profile("x").behavior_hash() != scanner_profile("y").behavior_hash(), \
        "智能体与扫描器的行为哈希相同, 无法区分"


def test_cross_index_detects_multi_ip_campaign():
    index = fingerprint.CrossIndex()
    for index_ip in range(3):
        profile = agent_profile("multi-%d" % index_ip)
        profile.ip = "203.0.113.%d" % (10 + index_ip)
        index.observe(profile)
    verdict = verdict_for(agent_profile("final"), index)
    assert verdict.has("behavior_campaign"), \
        "同一行为哈希来自 3 个源 IP, 未命中行为战役信号"
    assert verdict.has("multi_ip_same_toolchain"), "未命中同工具链跨源信号"


# --------------------------------------------------------------------------
# 场景权重覆盖确实生效
# --------------------------------------------------------------------------

def test_weight_override_changes_verdict():
    """场景包的权重覆盖必须真的改变判定 —— 否则那份配置只是显示用的摆设。"""
    baseline = verdict_for(agent_profile("w1")).score
    fingerprint.configure(weight_overrides={"no_asset_fetch": 40}, reset=True)
    try:
        boosted = verdict_for(agent_profile("w2")).score
        assert boosted >= baseline, \
            "提高信号权重后分数反而下降(%d -> %d)" % (baseline, boosted)
        assert fingerprint.effective_weight("no_asset_fetch") == \
            fingerprint.WEIGHTS["no_asset_fetch"] + 40
    finally:
        fingerprint.configure(reset=True)
    assert fingerprint.effective_weight("no_asset_fetch") == \
        fingerprint.WEIGHTS["no_asset_fetch"], "重置后权重未还原"


# --------------------------------------------------------------------------
# 处置阈值可配置
# --------------------------------------------------------------------------

def test_thresholds_are_configurable():
    import config as config_mod
    import respond

    default = respond.resolved_thresholds()
    assert respond.action_for_score(45, default) == "serve_watch"
    assert respond.action_for_score(60, default) == "tarpit"
    assert respond.action_for_score(90, default) == "lockdown"

    strict = {"serve_watch": 30, "tarpit": 55, "deceive_inject": 75, "lockdown": 90}
    assert respond.action_for_score(45, strict) == "serve_watch"
    assert respond.action_for_score(60, strict) == "tarpit"
    assert respond.action_for_score(80, strict) == "deceive_inject"
    assert respond.action_for_score(89, strict) != "lockdown"

    raw = config_mod.Config({})
    raw._data["respond"] = {"thresholds": strict}
    assert respond.resolved_thresholds(raw) == strict, "配置里的阈值未被读取"


def test_thresholds_forced_monotonic():
    import respond
    import config as config_mod
    broken = config_mod.Config({})
    broken._data["respond"] = {"thresholds": {
        "serve_watch": 50, "tarpit": 30, "deceive_inject": 20, "lockdown": 10}}
    fixed = respond.resolved_thresholds(broken)
    values = [fixed["serve_watch"], fixed["tarpit"],
              fixed["deceive_inject"], fixed["lockdown"]]
    assert values == sorted(values) and len(set(values)) == 4, \
        "非单调阈值未被修正: %s" % fixed
