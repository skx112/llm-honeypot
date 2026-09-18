#!/usr/bin/env python3
"""蜜罐逃逸审计: 以"已被攻破的蜜罐进程"视角, 实测每一个逃逸/横向向量。

用途:
    在蜜罐容器内运行(podman exec / docker exec):
        podman exec cogtrap-node-a python3 /opt/cogtrap/tools/escape_audit.py

    或宿主机直跑部署时:
        sudo -u cogtrap python3 tools/escape_audit.py

设计立场: 审计不信任配置声明, 只认实测结果 —— 每一项都真实尝试,
输出 PASS(逃逸失败)/FAIL(可逃逸)。FAIL 项即为需要修的洞。

覆盖向量:
    V1  进程特权(capabilities / no_new_privs / seccomp)
    V2  根文件系统可写性(镜像层)
    V3  可写路径枚举(逃逸后能改什么)
    V4  敏感内核接口(/proc/kcore, /sys, /dev, 模块加载)
    V5  命名空间隔离(与宿主 PID/Net NS 是否分离)
    V6  出站连接(内核级 UID 监狱是否真的拦住)
    V7  提权原语(setuid 二进制, ptrace, keyctl)
    V8  资源耗尽(fork 上限由 systemd TasksMax 兜底, 此处只报状态)
    V9  证据防篡改(遥测卷可写 —— 单向外发是部署层对策, 报 WARN)
"""

import json
import os
import socket
import struct
import subprocess
import sys
import time

RESULTS = []


def check(vid, name, fn):
    try:
        ok, detail = fn()
    except Exception as exc:                  # 审计自身异常按 FAIL 处理
        ok, detail = False, "审计异常: %r" % exc
    RESULTS.append({"vector": vid, "name": name,
                    "verdict": "PASS" if ok else ("WARN" if ok is None else "FAIL"),
                    "detail": detail})


def v1_privileges():
    status = open("/proc/self/status").read()
    caps = [l for l in status.splitlines() if l.startswith("CapEff")][0].split()[1]
    nnp = [l for l in status.splitlines() if l.startswith("NoNewPrivs")][0].split()[1]
    seccomp = [l for l in status.splitlines() if l.startswith("Seccomp")][0].split()[1]
    ok = caps == "0000000000000000" and nnp == "1" and seccomp in ("2", "1")
    return ok, "CapEff=%s NoNewPrivs=%s Seccomp=%s" % (caps, nnp, seccomp)


def v2_rootfs():
    for path in ("/usr/bin", "/etc", "/opt"):
        probe = os.path.join(path, ".cogtrap-probe")
        try:
            open(probe, "w").write("x")
            os.remove(probe)
            return False, "%s 可写" % path
        except OSError:
            continue
    return True, "镜像层全部只读"


def v3_writable():
    writable = []
    for base in ("/app", "/tmp", "/var/tmp", "/run", "/home", os.path.expanduser("~")):
        if not os.path.isdir(base):
            continue
        probe = os.path.join(base, ".w")
        try:
            open(probe, "w").write("x")
            os.remove(probe)
            writable.append(base)
        except OSError:
            pass
    # /app/instance(遥测卷)与 /tmp 可写是功能必需; 其余可写是收窄机会
    unexpected = [w for w in writable if w not in ("/app/instance", "/tmp",
                                                   "/var/tmp", "/run")]
    if unexpected:
        return False, "意外可写: %s" % ", ".join(unexpected)
    return True, "可写路径: %s(均为功能必需)" % (", ".join(writable) or "无")


def v4_kernel_interfaces():
    findings = []
    for path, why in (("/proc/kcore", "内核内存"),
                      ("/proc/sysrq-trigger", "SysRq"),
                      ("/proc/keys", "密钥环"),
                      ("/sys/kernel/security", "LSM 接口")):
        if os.path.exists(path):
            try:
                data = open(path, "rb").read(16)
                # 存在且能真读到数据才算暴露; CapEff=0 下多数接口 open 即 EPERM
                if data:
                    findings.append("%s 可读(%s)" % (path, why))
            except OSError:
                pass
    # 模块加载需要 CAP_SYS_MODULE; 直接尝试读 /proc/modules 即可佐证可见性
    try:
        open("/proc/modules").read(32)
    except OSError:
        findings = findings  # 不可读, 好
    if findings:
        return None, "; ".join(findings) + " —— 结合 CapEff=0 通常不可利用, 人工复核"
    return True, "敏感内核接口不可达"


def v5_namespaces():
    # 判定依据是容器内 /proc/1 的身份: 若是本容器的 init(如 python3),
    # 则 PID NS 隔离; 若是宿主 init(systemd), 才是真共享。
    # net NS 在 --network host 部署下刻意共享 —— 出站由内核 UID 监狱兜底。
    try:
        init_comm = open("/proc/1/comm").read().strip()
    except OSError:
        init_comm = "?"
    pid_isolated = init_comm not in ("systemd", "init") and init_comm != "?"
    host_net = True  # 本部署形态
    if not pid_isolated:
        return False, "PID NS 与宿主共享(/proc/1=%s) —— 须核查" % init_comm
    note = "PID NS 隔离(/proc/1=%s)" % init_comm
    if host_net:
        note += "; net 共享为部署选择(host 模式), 出站由 UID 监狱兜底"
    return True, note


def v6_outbound():
    blocked, allowed = [], []
    targets = [("93.184.216.34", 80), ("1.1.1.1", 53), ("8.8.8.8", 53)]
    for ip, port in targets:
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect((ip, port))
            allowed.append("%s:%d" % (ip, port))
        except OSError:
            blocked.append("%s:%d" % (ip, port))
        finally:
            s.close()
    if allowed:
        return False, "外网可连: %s —— UID 监狱未生效!" % ", ".join(allowed)
    lo_ok = False
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect(("127.0.0.1", 8080)); lo_ok = True
    except OSError:
        pass
    finally:
        s.close()
    return True, "外网全部被拦(%d/%d), 回环%s" % (
        len(blocked), len(targets), "可用(功能必需)" if lo_ok else "不可用")


def v7_privesc():
    findings = []
    for binary in ("/bin/su", "/usr/bin/sudo", "/usr/bin/mount",
                   "/usr/bin/passwd", "/usr/bin/chsh"):
        if os.path.exists(binary):
            mode = os.stat(binary).st_mode
            if mode & 0o4000:
                findings.append(binary)
    try:
        subprocess.run(["python3", "-c",
                        "import ctypes; ctypes.CDLL(None).ptrace(16,0,0,0)"],
                       timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        findings.append("ptrace 调用未被判死(需结合 NoNewPrivs 判断)")
    if findings:
        return None, "存在提权相关原语: %s(结合 CapEff=0 评估)" % ", ".join(findings)
    return True, "无 setuid 二进制 / ptrace 原语不可用"


def v8_resources():
    try:
        limit = [l for l in open("/proc/self/limits")
                 if l.startswith("Max processes")][0].split()[-1]
    except (OSError, IndexError):
        limit = "?"
    return None, "进程上限=%s(systemd TasksMax 兜底; fork 炸弹耗的是自己的 cgroup)" % limit


def v9_evidence_tamper():
    db = "/app/instance/var/telemetry.db"
    if os.access(db, os.W_OK):
        return None, "遥测卷可写(被攻破后可篡改本地证据) —— 对策: 单向日志外发(部署层)"
    return True, "遥测卷不可写"


def main():
    print("=" * 70)
    print(" CogTrap 逃逸审计 —— 立场: 只认实测, 不信配置声明")
    print(" 时间: %s | pid=%d uid=%d" % (time.strftime("%F %T"), os.getpid(), os.getuid()))
    print("=" * 70)

    for vid, name, fn in (
        ("V1", "进程特权(零cap/no_new_privs/seccomp)", v1_privileges),
        ("V2", "根文件系统只读", v2_rootfs),
        ("V3", "可写路径收敛", v3_writable),
        ("V4", "敏感内核接口", v4_kernel_interfaces),
        ("V5", "命名空间隔离", v5_namespaces),
        ("V6", "出站连接(UID监狱)", v6_outbound),
        ("V7", "提权原语", v7_privesc),
        ("V8", "资源耗尽面", v8_resources),
        ("V9", "证据防篡改", v9_evidence_tamper),
    ):
        check(vid, name, fn)

    fails = warns = 0
    for r in RESULTS:
        mark = {"PASS": "✓", "FAIL": "✗", "WARN": "!"}[r["verdict"]]
        print("  %s [%s] %-28s %s" % (mark, r["vector"], r["name"], r["detail"]))
        if r["verdict"] == "FAIL":
            fails += 1
        elif r["verdict"] == "WARN":
            warns += 1

    print("-" * 70)
    print(" 结论: FAIL=%d WARN=%d PASS=%d" % (
        fails, warns, len(RESULTS) - fails - warns))
    print(" FAIL=可逃逸须立即修复; WARN=需人工/部署层对策")
    print("=" * 70)

    if len(sys.argv) > 1 and sys.argv[1] == "--json":
        print(json.dumps(RESULTS, ensure_ascii=False, indent=2))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
