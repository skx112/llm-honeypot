#!/usr/bin/env python3
"""零依赖测试运行器。

为什么不用 pytest: 本项目承诺零第三方依赖, 而"测试需要装东西"会让贡献者和
使用者在隔离环境里跑不起测试 —— 那等于没有测试。这个运行器约 40 行, 足够跑
我们的用例; 同时所有用例都是标准的 `test_*` 函数, pytest 也能直接采集。

用法:
    python3 tests/run.py              # 跑全部
    python3 tests/run.py detection    # 只跑名字含 detection 的模块
"""

import importlib
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "honeypot"))
sys.path.insert(0, HERE)


def discover(filter_text=None):
    names = []
    for name in sorted(os.listdir(HERE)):
        if not name.startswith("test_") or not name.endswith(".py"):
            continue
        if filter_text and filter_text not in name:
            continue
        names.append(name[:-3])
    return names


def run_module(module_name):
    module = importlib.import_module(module_name)
    cases = sorted(name for name in dir(module) if name.startswith("test_"))
    passed = 0
    failed = []
    for case in cases:
        function = getattr(module, case)
        if not callable(function):
            continue
        try:
            function()
            passed += 1
            print("    \033[32m✓\033[0m %s" % case)
        except AssertionError as exc:
            failed.append((case, str(exc) or "断言失败"))
            print("    \033[31m✗\033[0m %s" % case)
        except Exception:
            failed.append((case, traceback.format_exc(limit=6)))
            print("    \033[31m✗\033[0m %s (异常)" % case)
    return passed, failed


def main(argv):
    filter_text = argv[1] if len(argv) > 1 else None
    modules = discover(filter_text)
    if not modules:
        print("没有找到测试模块")
        return 1

    total_pass = 0
    total_fail = []
    print("=" * 68)
    print(" CogTrap 测试")
    print("=" * 68)
    for name in modules:
        print()
        print("  %s" % name)
        try:
            passed, failed = run_module(name)
        except Exception:
            print("    \033[31m模块导入失败\033[0m")
            print(traceback.format_exc(limit=6))
            total_fail.append((name, "导入失败"))
            continue
        total_pass += passed
        total_fail.extend(("%s::%s" % (name, case), msg) for case, msg in failed)

    print()
    print("=" * 68)
    if total_fail:
        print(" \033[31m失败 %d 项\033[0m / 通过 %d 项" % (len(total_fail), total_pass))
        for case, message in total_fail:
            print()
            print("  ✗ %s" % case)
            for line in message.splitlines()[:8]:
                print("      %s" % line)
    else:
        print(" \033[32m全部通过\033[0m (%d 项)" % total_pass)
    print("=" * 68)
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
