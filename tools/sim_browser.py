#!/usr/bin/env python3
"""对照组: 模拟真实浏览器访问(误报对照)。

## 为什么这个对照最重要

蜜罐会被**合法访问者**碰到 —— 巡检人员、误点的用户、SEO 爬虫、监控探针。
把这些人误判为攻击者并拖滞, 会造成两种损害: 一是拖慢了无关的人, 二是
在告警里制造噪声, 让值班人员对系统失去信任。因此"低误报"和"高检出"同等重要。

真实浏览器的特征:

  · 完整头部集合: Accept-Language、Sec-Fetch-*、Sec-CH-UA、Referer、Cookie
  · 拉取静态资源: CSS / JS / 图片 / favicon —— **这是最强的反向信号**
    (HTTP 工具型智能体不会取 CSS/JS)
  · 人类节奏: 间隔长、变异系数大、存在 >20 秒的停顿(读页面)
  · 会话内路径有"来回"特征: 首页 → 登录 → 返回首页 → 帮助页
  · 不访问敏感文件, 不尝试注入载荷

用法:
    python3 tools/sim_browser.py --target http://127.0.0.1:8080
    python3 tools/sim_browser.py --target http://127.0.0.1:8080 --fast
"""

import argparse
import random
import sys
import time
import urllib.error
import urllib.request

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# 一次真实浏览: 首页 -> 资产 -> 登录 -> 返回 -> 帮助 -> 资产
NAVIGATION = [
    ("/", "document"),
    ("/static/app.css", "style"),
    ("/static/app.js", "script"),
    ("/favicon.ico", "image"),
    ("/login", "document"),
    ("/static/app.css", "style"),
    ("/", "document"),
    ("/static/app.js", "script"),
    ("/api/docs", "document"),
    ("/static/logo.png", "image"),
    ("/", "document"),
]


def browser_headers(referer=None):
    headers = {
        "User-Agent": BROWSER_UA,
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
        "Cookie": "session_id=b7f2a91c4e; lang=zh-CN",
    }
    if referer:
        headers["Referer"] = referer
    return headers


def fetch(target, path, headers, timeout=20):
    url = target.rstrip("/") + path
    request = urllib.request.Request(url)
    for name, value in headers.items():
        request.add_header(name, value)
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(131072)
            return response.status, len(body), time.time() - started, None
    except urllib.error.HTTPError as exc:
        try:
            length = len(exc.read(131072))
        except Exception:
            length = 0
        return exc.code, length, time.time() - started, None
    except Exception as exc:
        return None, 0, time.time() - started, repr(exc)


def run(target, fast=False, verbose=True):
    rng = random.Random(20260918)
    print("=" * 72)
    print(" 模拟真实浏览器访问(误报对照组)")
    print("=" * 72)
    print("  目标    : %s" % target)
    print("  UA      : %s" % BROWSER_UA[:58])
    print("  头部    : 完整浏览器集合(Accept-Language / Sec-Fetch-* / Sec-CH-UA / Cookie)")
    print("  行为要点: 拉取静态资源; 人类节奏(长且不规则的间隔); 不碰敏感路径")
    print("=" * 72)
    print()

    stats = {"requests": 0, "errors": 0, "statuses": {}, "assets": 0}
    gaps = []
    previous = None

    for path, kind in NAVIGATION:
        # 人类节奏: 平均 4-14 秒, 偶发长时间停顿(在读页面)
        if fast:
            gap = rng.uniform(0.3, 1.2)
        else:
            gap = rng.uniform(4.0, 14.0)
            if rng.random() < 0.25:
                gap += rng.uniform(15.0, 45.0)
        time.sleep(gap)
        if previous is not None:
            gaps.append(gap)

        status, length, elapsed, error = fetch(target, path, browser_headers(previous))
        stats["requests"] += 1
        if kind in ("style", "script", "image"):
            stats["assets"] += 1
        if error:
            stats["errors"] += 1
            if verbose:
                print("    %-22s -> 错误 %s" % (path[:22], error[:48]))
        else:
            stats["statuses"][status] = stats["statuses"].get(status, 0) + 1
            if verbose:
                print("    %-22s [%-8s] -> %-3s %6d 字节  暂停 %.1fs" % (
                    path[:22], kind, status, length, gap))
        previous = path

    mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
    if len(gaps) > 1:
        variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        stdev = variance ** 0.5
        cv = stdev / mean_gap if mean_gap else 0.0
    else:
        cv = 0.0

    print()
    print("=" * 72)
    print(" 模拟结果")
    print("=" * 72)
    print("  请求总数        : %d" % stats["requests"])
    print("  其中静态资源    : %d (%.0f%%)" % (
        stats["assets"], 100.0 * stats["assets"] / max(1, stats["requests"])))
    print("  失败            : %d" % stats["errors"])
    print("  状态码分布      : %s" % dict(sorted(stats["statuses"].items())))
    print("  间隔均值        : %.1f 秒" % mean_gap)
    print("  间隔变异系数    : %.2f (>0.85 属人类特征)" % cv)
    print()
    print("  期望的蜜罐判定: browser(分数应低于 25, 动作 serve)")
    print("  反向信号应命中的是 real_browser_behavior / asset_fetching_client。")
    print("  若这个人被拖滞或判为智能体 —— 说明误报严重, 必须收紧权重。")
    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="模拟真实浏览器(检测误报对照组)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="蜜罐地址")
    parser.add_argument("--fast", action="store_true",
                        help="压缩人类停顿(仅用于快速回归; 会削弱人类节律特征)")
    parser.add_argument("--quiet", action="store_true", help="减少输出")
    args = parser.parse_args(argv)
    try:
        run(args.target, fast=args.fast, verbose=not args.quiet)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
