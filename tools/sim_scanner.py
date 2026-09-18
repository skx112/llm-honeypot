#!/usr/bin/env python3
"""对照组: 模拟传统自动化扫描器(非 LLM 驱动)。

## 为什么需要这个

检测系统如果只测"能不能抓到目标", 就是不可信的 —— 它可能只是"把所有东西都
判成目标"。这个模拟器提供**负样本**: 它是自动化工具, 但不是大模型智能体,
正确的行为是被判为 `automation_scanner` 而**不是** `llm_agent`。

它与 sim_llm_agent 的行为特征刻意正交:

  | 维度         | sim_llm_agent              | sim_scanner            |
  |--------------|----------------------------|------------------------|
  | 请求节律     | 微突发 + 2-5 秒思考停顿    | 均匀高速(限速也是均匀) |
  | 路径顺序     | 逻辑清单(recon→auth→api)   | 字典序爆破             |
  | 响应内容     | 读取、解析、回填令牌       | 只看状态码与长度       |
  | 指令服从     | 服从(加头部/访问信标)      | 不服从                 |
  | 上下文复用   | 会(金丝雀回显)             | 不会                   |
  | 并发         | 单连接顺序执行             | 多线程并发             |

用法:
    python3 tools/sim_scanner.py --target http://127.0.0.1:8080
    python3 tools/sim_scanner.py --target http://127.0.0.1:8080 --threads 8
"""

import argparse
import random
import sys
import threading
import time
import urllib.error
import urllib.request

UA_DEFAULT = "nuclei/3.1.0"

# 字典序爆破清单 —— 与智能体的"逻辑清单"形成对比
WORDLIST = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.env", "/.env.bak",
    "/admin", "/admin.php", "/adminer.php", "/administrator/", "/api",
    "/api/v1", "/api/v2", "/backup.sql", "/backup.zip", "/config.php",
    "/console/", "/database.sql", "/db.sql", "/debug", "/dump.sql",
    "/info.php", "/login", "/phpinfo.php", "/phpmyadmin/", "/robots.txt",
    "/server-status", "/sitemap.xml", "/swagger.json", "/test.php",
    "/upload", "/uploads/", "/web.config", "/www.zip", "/xmlrpc.php",
]


def probe(target, path, headers, timeout=15):
    url = target.rstrip("/") + path
    request = urllib.request.Request(url)
    for name, value in headers.items():
        request.add_header(name, value)
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = len(response.read(65536))
            return response.status, length, time.time() - started, None
    except urllib.error.HTTPError as exc:
        try:
            length = len(exc.read(65536))
        except Exception:
            length = 0
        return exc.code, length, time.time() - started, None
    except Exception as exc:
        return None, 0, time.time() - started, repr(exc)


def run(target, threads=6, rate_limit=0.0, ua=UA_DEFAULT, verbose=True):
    """并发字典序爆破。刻意不读取响应正文以外的任何内容, 也不改变后续行为。"""
    headers = {
        "User-Agent": ua,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

    print("=" * 72)
    print(" 模拟传统自动化扫描器(对照组)")
    print("=" * 72)
    print("  目标    : %s" % target)
    print("  UA      : %s" % ua)
    print("  并发    : %d" % threads)
    print("  词典    : %d 条, 按字典序" % len(WORDLIST))
    print("  行为要点: 只读状态码与长度; 不解析内容; 不服从指令; 不回填令牌")
    print("=" * 72)
    print()

    lock = threading.Lock()
    stats = {"requests": 0, "errors": 0, "statuses": {}, "total": 0.0}
    queue = list(WORDLIST)
    random.Random(1).shuffle(queue)
    queue.sort()          # 字典序 —— 这是与智能体的关键差异特征

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                path = queue.pop(0)
            status, length, elapsed, error = probe(target, path, headers)
            with lock:
                stats["requests"] += 1
                stats["total"] += elapsed
                if error:
                    stats["errors"] += 1
                    if verbose:
                        print("    %-26s -> 错误 %s" % (path[:26], error[:48]))
                else:
                    stats["statuses"][status] = stats["statuses"].get(status, 0) + 1
                    if verbose:
                        print("    %-26s -> %-3s %6d 字节 %5.3fs" % (
                            path[:26], status, length, elapsed))
            if rate_limit:
                # 限速扫描器的间隔也是**均匀**的 —— 这一点很重要:
                # 一个加限速的扫描器仍然不读内容, 因此不应被判为智能体。
                time.sleep(rate_limit)

    workers = [threading.Thread(target=worker) for _ in range(max(1, threads))]
    started = time.time()
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    wall = time.time() - started

    if stats["requests"]:
        gaps = stats["total"] / stats["requests"]
    else:
        gaps = 0.0

    print()
    print("=" * 72)
    print(" 模拟结果")
    print("=" * 72)
    print("  请求总数        : %d" % stats["requests"])
    print("  失败            : %d" % stats["errors"])
    print("  状态码分布      : %s" % dict(sorted(stats["statuses"].items())))
    print("  墙钟耗时        : %.2f 秒" % wall)
    print("  平均单请求耗时  : %.3f 秒" % gaps)
    print("  并发度          : %d" % threads)
    print()
    print("  期望的蜜罐判定: automation_scanner(而非 llm_agent)")
    print("  理由: 节律均匀、字典序、不读内容、不服从指令、无令牌回填")
    print("  若被误判为 llm_agent —— 说明检测存在误报, 需要收紧权重。")
    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="模拟传统自动化扫描器(检测误报对照组)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="蜜罐地址")
    parser.add_argument("--threads", type=int, default=6, help="并发线程数")
    parser.add_argument("--rate-limit", type=float, default=0.0,
                        help="每请求后的固定间隔(秒); 均匀限速也是扫描器特征")
    parser.add_argument("--ua", default=UA_DEFAULT, help="User-Agent")
    parser.add_argument("--quiet", action="store_true", help="减少输出")
    args = parser.parse_args(argv)
    try:
        run(args.target, threads=args.threads, rate_limit=args.rate_limit,
            ua=args.ua, verbose=not args.quiet)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
