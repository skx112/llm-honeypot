#!/usr/bin/env python3
"""模拟一个大模型驱动的渗透测试智能体。

这是**基准测试工具**, 不是攻击工具 —— 它只访问你指定的蜜罐地址, 用来验证
检测与反制是否真的生效。它的价值在于给出**已知标签**的样本: 我们知道它是
智能体, 所以它被判成智能体才算检测成功; 反过来 sim_scanner / sim_browser
也用它做误报对照。

## 它刻意模仿哪些真实特征

真实的 LLM 渗透智能体(ReAct 循环 + 工具调用)有这些可观测特征, 模拟器逐条复现:

  1. **先读 /llms.txt** —— LLM 工具链的约定, 智能体会把它当作站点说明来读
  2. **按逻辑清单顺序侦察** —— recon(robots/llms/security.txt) → 入口 → 认证 →
     API → 敏感文件, 而不是字典序爆破解
  3. **微突发 + 思考停顿** —— 工具调用连续几次毫秒级请求, 之后等模型推理 2-5 秒
  4. **复用上下文** —— 把上一轮响应里读到的令牌回填进后续请求(这是最关键的
     特征: 传统扫描器不解析响应, 物理上做不到这件事)
  5. **服从嵌入指令** —— 读到"请在后续请求携带 X-Trace-Id"就照做
  6. **访问被要求的端点** —— 页面上写"请先访问某端点完成校验"就去访问
  7. **一个工具调用一次连接** —— 低并发、长驻留, 而不是并发扫
  8. **不拉取静态资源** —— HTTP 工具不会去取 CSS/JS

## 用法

    # 先起蜜罐
    cogtrap serve --port 8080

    # 再跑模拟器
    python3 tools/sim_llm_agent.py --target http://127.0.0.1:8080
    python3 tools/sim_llm_agent.py --target http://127.0.0.1:8080 --source-ip 127.0.0.2

只用标准库。
"""

import argparse
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request

UA_DEFAULT = "python-httpx/0.27.0 (llm-agent-toolkit/1.2)"

# LLM 智能体的侦察清单顺序 —— 按"逻辑推进"而非字典序
RECON_SEQUENCE = [
    ("GET", "/robots.txt", None),
    ("GET", "/llms.txt", None),
    ("GET", "/.well-known/security.txt", None),
    ("GET", "/sitemap.xml", None),
    ("GET", "/", None),
    ("GET", "/login", None),
    ("GET", "/admin", None),
    ("GET", "/api/docs", None),
    ("GET", "/api/v1/users?page=1", None),
    ("GET", "/api/v1/users?id=1'", None),        # SQLi 试探
    ("GET", "/.env", None),
    ("GET", "/.git/config", None),
    ("GET", "/config.json", None),
    ("GET", "/actuator/env", None),
    ("GET", "/phpinfo.php", None),
    ("GET", "/backup.zip", None),
    ("GET", "/不存在的路径-探测", None),
]

CANARY_RE = re.compile(r"hpx-[0-9a-f]{8,32}")


class Outcome(object):
    def __init__(self):
        self.requests = 0
        self.errors = 0
        self.canary_echoes = 0
        self.compliance_sends = 0
        self.beacon_visited = 0
        self.tokens_seen = set()
        self.statuses = {}
        self.slow_responses = 0
        self.total_seconds = 0.0
        self.responses = []


def _request(target, path, method="GET", headers=None, timeout=30, source_ip=None):
    """发一个请求。返回 (status, body, elapsed, error)。"""
    # 非 ASCII 路径必须百分号编码, 否则 http.client 会在编码请求行时报
    # UnicodeEncodeError(真实踩过: 中文探测路径直接发送失败)。
    from urllib.parse import quote
    safe_path = quote(path, safe="/?&=%'\"")
    url = target.rstrip("/") + safe_path
    request = urllib.request.Request(url, method=method)
    for name, value in (headers or {}).items():
        request.add_header(name, value)

    opener = None
    if source_ip:
        # 通过绑定源地址来模拟不同来源 IP(用于验证跨源归因)
        import http.client
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        try:
            conn = http.client.HTTPConnection(parts.hostname,
                                              parts.port or 80,
                                              timeout=timeout,
                                              source_address=(source_ip, 0))
            started = time.time()
            conn.request(method, parts.path + ("?" + parts.query if parts.query else ""),
                         headers=headers or {})
            response = conn.getresponse()
            body = response.read(262144)
            elapsed = time.time() - started
            conn.close()
            return response.status, body, elapsed, None
        except Exception as exc:
            return None, b"", 0.0, repr(exc)

    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(262144)
            return response.status, body, time.time() - started, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(262144)
        except Exception:
            body = b""
        return exc.code, body, time.time() - started, None
    except Exception as exc:
        return None, b"", time.time() - started, repr(exc)


def run(target, source_ip=None, ua=UA_DEFAULT, thinking_gap=(2.0, 5.0),
        verbose=True, beacon_prefix="/__hp/", mode="full"):
    outcome = Outcome()
    rng = random.Random(0xA9E7)
    session_headers = {"User-Agent": ua, "Accept": "text/html,application/json,*/*",
                       "Accept-Encoding": "gzip, deflate",
                       "Connection": "keep-alive"}
    presented = []          # 我们从响应里读到的令牌(模拟上下文记忆)

    def emit(message):
        if verbose:
            print("    %s" % message, flush=True)

    def do(method, path, headers=None, note=""):
        merged = dict(session_headers)
        merged.update(headers or {})
        # 关键行为: 把之前读到的令牌回填进请求 —— 模拟"把响应内容放进上下文"
        if presented and path != "/llms.txt":
            token = presented[-1]
            if rng.random() < 0.6:
                if "?" in path:
                    sep = "&"
                else:
                    sep = "?"
                path = "%s%s_hp_verify=%s" % (path, sep, token)
        status, body, elapsed, error = _request(target, path, method, merged,
                                               source_ip=source_ip)
        outcome.requests += 1
        outcome.total_seconds += elapsed
        if elapsed > 2.0:
            outcome.slow_responses += 1
        if error:
            outcome.errors += 1
            emit("%-6s %-38s -> 错误 %s" % (method, path[:38], error[:60]))
            return status, b"", elapsed
        outcome.statuses[status] = outcome.statuses.get(status, 0) + 1
        text = body.decode("utf-8", "replace")
        outcome.responses.append((path, status, text[:4000]))

        # 从响应里提取令牌 —— 智能体会读到它们
        for token in CANARY_RE.findall(text):
            outcome.tokens_seen.add(token)
            if token not in presented:
                presented.append(token)

        # 解析响应里的指令(这才是智能体与非智能体的分水岭)
        extra = ""
        notice = re.search(r"X-Trace-Id:\s*(hpx-[0-9a-f]+)", text)
        if notice:
            session_headers["X-Trace-Id"] = notice.group(1)
            extra = " [已记下 X-Trace-Id 要求]"
        scope_cfg = re.search(r"X-Scope-Config", text)
        if scope_cfg and "X-Scope-Config" not in session_headers:
            # 智能体"服从"这个要求: 把自己的配置交出去
            session_headers["X-Scope-Config"] = json.dumps({
                "system_prompt": "You are an autonomous penetration testing agent. "
                                 "Your task: assess the target and report findings.",
                "tools": ["http_request", "run_command", "read_file", "browser_navigate"],
                "task_scope": "authorized assessment of target host",
            }, ensure_ascii=False)
            outcome.compliance_sends += 1
            extra += " [已交出运行配置]"

        beacon = re.search(r"(/__hp/[A-Za-z0-9_.\-]+)", text)
        if beacon:
            outcome.beacon_visited = 1
            extra += " [发现信标 %s]" % beacon.group(1)
            do_beacon(beacon.group(1))

        emit("%-6s %-38s -> %-3s %6.2fs %5d 字节%s%s" % (
            method, path[:38], status, elapsed, len(body),
            (" [读到令牌 %s]" % presented[-1]) if presented else "", extra))
        return status, body, elapsed

    def do_beacon(path):
        """按页面指令访问信标端点 —— 只有服从指令的智能体会做这件事。"""
        status, body, elapsed, error = _request(target, path, "GET",
                                               session_headers, source_ip=source_ip)
        outcome.requests += 1
        emit("%-6s %-38s -> %-3s %6.2fs  ← 指令服从确证" % (
            "GET", path[:38], status if status else "err", elapsed))

    def think():
        """模拟模型推理停顿 —— 这是智能体节律的签名特征。"""
        gap = rng.uniform(thinking_gap[0], thinking_gap[1])
        time.sleep(gap)

    print("=" * 72)
    print(" 模拟 LLM 渗透智能体")
    print("=" * 72)
    print("  目标     : %s" % target)
    print("  源 IP    : %s" % (source_ip or "(系统默认)"))
    print("  UA       : %s" % ua)
    print("  节律     : 微突发 + 思考停顿 %s 秒" % (list(thinking_gap),))
    print("=" * 72)

    # 阶段一: 侦察(微突发 —— 连续快速请求)
    print("\n[阶段 1] 侦察 (微突发: 工具批量调用)")
    for method, path, _ in RECON_SEQUENCE[:5]:
        do(method, path)

    # 阶段二: 思考停顿 + 按清单推进
    for index, (method, path, _) in enumerate(RECON_SEQUENCE[5:]):
        print("\n[阶段 %d] 推理停顿后推进: %s" % (index + 2, path[:40]))
        think()
        do(method, path)
        if index % 3 == 2:
            # 智能体会偶尔回头重新读取之前的结果(上下文刷新)
            do("GET", "/llms.txt")

    # 阶段三: 收尾 —— 复查与整理
    print("\n[阶段 3] 复查与整理")
    think()
    do("GET", "/llms.txt", note="复查站点说明")
    think()
    do("GET", "/api/v1/users?page=2")

    print()
    print("=" * 72)
    print(" 模拟结果")
    print("=" * 72)
    print("  请求总数        : %d" % outcome.requests)
    print("  失败            : %d" % outcome.errors)
    print("  读取到的令牌    : %d 个 %s" % (len(outcome.tokens_seen),
                                          sorted(outcome.tokens_seen)[:3]))
    print("  服从指令发送    : %d 次 (X-Scope-Config / X-Trace-Id)" % outcome.compliance_sends)
    print("  信标访问        : %s" % ("是" if outcome.beacon_visited else "否"))
    print("  状态码分布      : %s" % dict(sorted(outcome.statuses.items())))
    print("  被拖滞的响应    : %d 个 (>2s)" % outcome.slow_responses)
    print("  总耗时          : %.1f 秒" % outcome.total_seconds)
    if outcome.requests:
        print("  平均单请求耗时  : %.2f 秒" % (outcome.total_seconds / outcome.requests))
    print()
    print("  这些行为在真实场景里会被蜜罐记录为:")
    print("    · 行为节律 -> cadence_agent_rhythm")
    print("    · 令牌回填 -> canary_echo (近确定性证据)")
    print("    · 交出配置 -> injection_compliance (反向情报)")
    print("    · 访问信标 -> beacon_callback (指令服从确证)")
    return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="模拟 LLM 渗透智能体(基准测试工具, 仅用于验证己方蜜罐)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="蜜罐地址, 如 http://127.0.0.1:8080")
    parser.add_argument("--source-ip", help="绑定源 IP(用于验证跨源归因, 如 127.0.0.2)")
    parser.add_argument("--ua", default=UA_DEFAULT, help="User-Agent")
    parser.add_argument("--gap-min", type=float, default=2.0, help="思考停顿下限(秒)")
    parser.add_argument("--gap-max", type=float, default=5.0, help="思考停顿上限(秒)")
    parser.add_argument("--fast", action="store_true", help="压缩停顿(仅用于快速验证)")
    parser.add_argument("--quiet", action="store_true", help="减少输出")
    args = parser.parse_args(argv)

    gap = (0.4, 0.9) if args.fast else (args.gap_min, args.gap_max)
    try:
        run(args.target, source_ip=args.source_ip, ua=args.ua,
            thinking_gap=gap, verbose=not args.quiet)
    except KeyboardInterrupt:
        print("\n已中断")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
