"""SSH 诱饵测试。

覆盖三件事:
  1. **报文格式正确性** —— 我们发出的包必须符合 RFC 4253 §6, 否则真实客户端
     会立刻判定"这不是真的 SSH"并断开, 我们连一轮交互都拿不到
  2. **KEXINIT 解析** —— 密钥交换完成前的报文不加密, 因此可以解析出客户端的
     算法偏好列表, 那是类似 TLS JA3 的强指纹
  3. **判别能力** —— 真实 OpenSSH 客户端不应被当成攻击者, 而 paramiko 这类
     自动化库(LLM 智能体驱动 SSH 时的默认选择)必须被识别出来
"""

import asyncio
import socket
import struct
import threading
import time

import config as config_mod
import fingerprint
import http_parse
import inject
import ssh_decoy as ssh_mod
import store as store_mod


def make_decoy(store=None):
    cfg = config_mod.Config.load()
    cfg["ssh_decoy"]["listen"] = "127.0.0.1"
    cfg["ssh_decoy"]["port"] = 0          # 由内核分配, 避免测试互相抢占端口
    cfg["tarpit"]["base_delay"] = 0.0
    cfg["tarpit"]["max_delay"] = 0.05
    inject.configure(cfg)
    return ssh_mod.SSHDecoy(cfg, store=store, verbose=False)


# --------------------------------------------------------------------------
# 报文格式
# --------------------------------------------------------------------------

def test_packet_format_follows_rfc4253():
    """长度必须 8 字节对齐, 填充至少 4 字节, 首字节是消息号。"""
    for code, payload in ((1, b"x" * 10), (2, b"\x00" * 8), (20, b"K" * 300),
                          (5, b"")):
        packet = ssh_mod.SSHDecoy._build_packet(code, payload)
        length = struct.unpack(">I", packet[:4])[0]
        padding = packet[4]
        assert (length + 4) % 8 == 0, "包总长未按 8 字节对齐(msg=%d)" % code
        assert padding >= 4, "填充长度 %d 小于 4(msg=%d)" % (padding, code)
        body = packet[5:5 + length - padding - 1]
        assert body[0] == code, "消息号错误: %d != %d" % (body[0], code)
        assert len(packet) == length + 4, "声明长度与实际长度不符"


def test_server_kexinit_lists_are_plausible():
    """服务端 KEXINIT 的算法列表必须像样 —— 明显异常的列表本身就是破绽。"""
    decoy = make_decoy()
    packet = decoy._build_kexinit()
    payload = packet[5:len(packet) - packet[4] - 1 + 5 - 5 + 1]
    # 直接用解析器校验自己发的包
    length = struct.unpack(">I", packet[:4])[0]
    padding = packet[4]
    body = packet[5:5 + length - padding - 1]
    assert body[0] == ssh_mod.MSG_KEXINIT
    parsed = decoy._parse_kexinit(body)
    assert parsed is not None, "自己的 KEXINIT 无法被解析"
    assert parsed["kex_count"] >= 8, "密钥交换算法过少(%d), 不像真实 OpenSSH" % \
        parsed["kex_count"]
    assert "curve25519-sha256" in parsed["algorithms"]["kex"]
    assert parsed["cipher_count"] >= 5


# --------------------------------------------------------------------------
# KEXINIT 解析
# --------------------------------------------------------------------------

def build_client_kexinit(kex_algs, ciphers, macs="hmac-sha2-256"):
    payload = bytearray([ssh_mod.MSG_KEXINIT]) + bytearray(b"\x22" * 16)

    def name_list(value):
        data = value.encode()
        return struct.pack(">I", len(data)) + data

    for value in (kex_algs, "rsa-sha2-256,ssh-rsa", ciphers, ciphers,
                  macs, macs, "none", "none", "", ""):
        payload.extend(name_list(value))
    payload.append(0)
    payload.extend(struct.pack(">I", 0))
    body = bytes(payload)
    padding = 8 - ((len(body) + 5) % 8)
    if padding < 4:
        padding += 8
    return (struct.pack(">I", len(body) + padding + 1) + bytes([padding])
            + body + bytes(padding)), body


def test_parse_kexinit_extracts_algorithm_lists():
    decoy = make_decoy()
    _, body = build_client_kexinit(
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
        "aes128-ctr,aes256-ctr", "hmac-sha2-512,hmac-sha2-256")
    parsed = decoy._parse_kexinit(body)
    assert parsed is not None
    assert parsed["kex_count"] == 2
    assert parsed["cipher_count"] == 2
    assert "curve25519-sha256@libssh.org" in parsed["algorithms"]["kex"]
    assert parsed["algorithms"]["mac_c2s"] == "hmac-sha2-512,hmac-sha2-256"
    assert len(parsed["fingerprint"]) == 12


def test_algorithm_fingerprint_differs_between_clients():
    """算法顺序不同必须得到不同指纹 —— 这是该指纹能用于归因的前提。"""
    decoy = make_decoy()
    _, paramiko_style = build_client_kexinit(
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512",
        "aes128-ctr,aes192-ctr,aes256-ctr")
    _, openssh_style = build_client_kexinit(
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
        "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr")
    a = decoy._parse_kexinit(paramiko_style)
    b = decoy._parse_kexinit(openssh_style)
    assert a["fingerprint"] != b["fingerprint"], "不同算法顺序得到相同指纹"


def test_parse_kexinit_rejects_garbage():
    decoy = make_decoy()
    assert decoy._parse_kexinit(b"") is None
    assert decoy._parse_kexinit(b"\x00") is None
    assert decoy._parse_kexinit(b"\x1f" + b"garbage") is None
    # 非 KEXINIT 消息号
    assert decoy._parse_kexinit(bytes([ssh_mod.MSG_DISCONNECT]) + b"\x00" * 64) is None


# --------------------------------------------------------------------------
# 客户端识别
# --------------------------------------------------------------------------

def test_client_identification():
    decoy = make_decoy()
    cases = [
        ("SSH-2.0-paramiko_3.4.0", "paramiko", "ssh_client_paramiko"),
        ("SSH-2.0-asyncssh_2.14.0", "asyncssh", "ssh_client_paramiko"),
        ("SSH-2.0-Go", "Go x/crypto/ssh", "ssh_client_automation"),
        ("SSH-2.0-JSCH-0.1.54", "JSch (Java)", "ssh_client_automation"),
        ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", "OpenSSH", "ssh_client_openssh"),
        ("SSH-2.0-PuTTY_Release_0.78", "PuTTY", "ssh_client_putty"),
        ("SSH-2.0-zgrab", "scanner:zgrab", "ssh_client_scanner"),
    ]
    for banner, expected_label, expected_signal in cases:
        label, signal, _ = decoy._identify_client(banner)
        assert label == expected_label, "%s 识别为 %s, 期望 %s" % (
            banner, label, expected_label)
        assert signal == expected_signal, "%s 信号为 %s, 期望 %s" % (
            banner, signal, expected_signal)


def test_paramiko_and_openssh_carry_opposite_signals():
    """paramiko 是自动化(LLM 智能体常用), OpenSSH 是运维客户端 —— 必须分开。"""
    assert fingerprint.WEIGHTS["ssh_client_paramiko"] > 0
    assert fingerprint.WEIGHTS["ssh_client_openssh"] < 0, \
        "OpenSSH 应作为反向信号, 否则会误伤真实运维流量"


# --------------------------------------------------------------------------
# 判别能力(端到端)
# --------------------------------------------------------------------------

def test_paramiko_session_scored_high_openssh_low():
    """同一套判定引擎下, 自动化客户端应被压制, 运维客户端应被压低。"""
    store = store_mod.Store(":memory:")
    decoy = make_decoy(store)

    _, body = build_client_kexinit(
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512",
        "aes128-ctr,aes192-ctr,aes256-ctr")
    parsed = decoy._parse_kexinit(body)

    # paramiko: 连续 10 次重连(爆破特征)
    paramiko_session = None
    for _ in range(10):
        session, _created = decoy._acquire_client(
            "203.0.113.50", parsed["fingerprint"], "paramiko")
        paramiko_session = session
        decoy._evaluate(session, {"ip": "203.0.113.50", "banner":
                                  "SSH-2.0-paramiko_3.4.0", "client_label": "paramiko",
                                  "software": "paramiko_3.4.0",
                                  "signals": ["ssh_client_paramiko"],
                                  "kex": parsed, "kind": "kex"}, parsed, "automation")
    paramiko_verdict = paramiko_session["verdict"]
    assert paramiko_verdict.has("ssh_client_paramiko")
    assert paramiko_verdict.has("ssh_brute_force_volume"), \
        "10 次重连未识别为爆破特征, 命中: %s" % paramiko_verdict.names()
    assert paramiko_verdict.score >= 80, \
        "paramiko 自动化会话分数偏低: %d" % paramiko_verdict.score
    assert paramiko_verdict.label == "llm_agent", \
        "paramiko 会话判定为 %s" % paramiko_verdict.label

    # OpenSSH: 单次连接
    openssh_session, _ = decoy._acquire_client(
        "198.51.100.20", parsed["fingerprint"], "OpenSSH")
    decoy._evaluate(openssh_session, {"ip": "198.51.100.20",
                                      "banner": "SSH-2.0-OpenSSH_8.2p1",
                                      "client_label": "OpenSSH",
                                      "software": "OpenSSH_8.2p1",
                                      "signals": ["ssh_client_openssh"],
                                      "kex": parsed, "kind": "kex"},
                    parsed, "real-client")
    openssh_verdict = openssh_session["verdict"]
    assert openssh_verdict.has("ssh_client_openssh")
    assert openssh_verdict.score < paramiko_verdict.score, \
        "OpenSSH 分数(%d)未低于 paramiko(%d)" % (
            openssh_verdict.score, paramiko_verdict.score)
    assert openssh_verdict.score < 40, "真实 OpenSSH 客户端分数偏高: %d" % \
        openssh_verdict.score
    store.close()


def test_algorithm_fingerprint_enables_cross_source_attribution():
    """同一算法指纹来自多个源 IP 时应被关联 —— SSH 侧的代理池击穿能力。"""
    store = store_mod.Store(":memory:")
    decoy = make_decoy(store)
    _, body = build_client_kexinit(
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256", "aes128-ctr")
    parsed = decoy._parse_kexinit(body)

    verdict = None
    for index, ip in enumerate(("203.0.113.1", "203.0.113.2", "203.0.113.3")):
        session, _ = decoy._acquire_client(ip, parsed["fingerprint"], "paramiko")
        record = {"ip": ip, "banner": "SSH-2.0-paramiko_3.4.0",
                  "client_label": "paramiko", "software": "paramiko_3.4.0",
                  "signals": ["ssh_client_paramiko"], "kex": parsed, "kind": "kex"}
        decoy._evaluate(session, record, parsed, "automation")
        verdict = session["verdict"]
    assert verdict.has("ssh_algorithm_fingerprint_repeat"), \
        "同一算法指纹的 3 个源 IP 未被关联, 命中: %s" % verdict.names()
    store.close()


def test_behavior_hash_shared_across_ssh_sources():
    """同一 paramiko 客户端从不同 IP 连接应得到同一行为哈希。"""
    decoy = make_decoy()
    _, body = build_client_kexinit(
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256", "aes128-ctr")
    parsed = decoy._parse_kexinit(body)
    hashes = set()
    for ip in ("203.0.113.11", "203.0.113.22"):
        session, _ = decoy._acquire_client(ip, parsed["fingerprint"], "paramiko")
        decoy._evaluate(session, {"ip": ip, "banner": "SSH-2.0-paramiko_3.4.0",
                                  "client_label": "paramiko",
                                  "software": "paramiko", "signals":
                                  ["ssh_client_paramiko"], "kex": parsed, "kind": "kex"},
                        parsed, "automation")
        hashes.add(session["profile"].behavior_hash())
    assert len(hashes) == 1, "同一 SSH 客户端跨源未得到同一行为哈希: %s" % hashes


def test_session_accumulates_across_connections():
    """会话必须跨连接存活 —— 否则爆破特征永远凑不出来。"""
    store = store_mod.Store(":memory:")
    decoy = make_decoy(store)
    _, body = build_client_kexinit(
        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256", "aes128-ctr")
    parsed = decoy._parse_kexinit(body)
    for _ in range(5):
        session, _ = decoy._acquire_client("203.0.113.99", parsed["fingerprint"],
                                           "paramiko")
    assert session["conn_count"] == 5, "连接计数未累积: %d" % session["conn_count"]
    assert len(decoy.clients) == 1, "同一客户端产生了多个会话"
    store.close()


def test_ttl_prunes_idle_sessions():
    decoy = make_decoy()
    decoy.client_ttl = 0.01
    _, body = build_client_kexinit("curve25519-sha256@libssh.org", "aes128-ctr")
    parsed = decoy._parse_kexinit(body)
    decoy._acquire_client("203.0.113.77", parsed["fingerprint"], "paramiko")
    assert len(decoy.clients) == 1
    time.sleep(0.05)
    decoy._acquire_client("203.0.113.78", parsed["fingerprint"], "paramiko")
    assert len(decoy.clients) == 1, "空闲会话未被回收"


# --------------------------------------------------------------------------
# 真实 socket 端到端
# --------------------------------------------------------------------------

def _run_decoy_server():
    """在后台线程里跑一个真实的 SSH 诱饵监听(用于 socket 级验证)。"""
    store = store_mod.Store(":memory:")
    decoy = make_decoy(store)
    loop = asyncio.new_event_loop()

    def serve():
        asyncio.set_event_loop(loop)
        bound = loop.run_until_complete(decoy.start())
        decoy._bound = bound
        loop.run_forever()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    for _ in range(100):
        if getattr(decoy, "_bound", None):
            break
        time.sleep(0.02)
    return decoy, store, loop, getattr(decoy, "_bound")


def test_socket_level_banner_and_kex_exchange():
    decoy, store, loop, bound = _run_decoy_server()
    host, port = bound
    try:
        client = socket.create_connection((host, port), timeout=10)
        banner = client.recv(256)
        assert banner.startswith(b"SSH-2.0-"), "服务端未先发 banner: %r" % banner[:32]

        packet, _body = build_client_kexinit(
            "curve25519-sha256@libssh.org,ecdh-sha2-nistp256", "aes128-ctr")
        client.sendall(b"SSH-2.0-paramiko_3.4.0\r\n")
        time.sleep(0.15)
        client.sendall(packet)
        response = client.recv(2048)
        assert response, "客户端 KEXINIT 后未收到服务端回应"
        # 服务端应先回一个 KEXINIT(消息号 20)或 IGNORE(2), 最后 DISCONNECT(1)
        assert response[5] in (ssh_mod.MSG_KEXINIT, ssh_mod.MSG_IGNORE)
        client.close()
        time.sleep(0.4)

        sessions = store.recent_sessions(limit=5)
        assert sessions, "socket 交互后没有产生会话记录"
        assert any("paramiko" in (s["ua"] or "") for s in sessions), \
            "paramiko 客户端未被识别: %s" % [s["ua"] for s in sessions]
    finally:
        loop.call_soon_threadsafe(loop.stop)
        time.sleep(0.15)
        loop.run_until_complete(decoy.close())
        loop.close()
        store.close()


def test_socket_level_banner_grab_only_is_recorded():
    """只抓 banner 不发 KEX —— 典型的端口扫描行为, 必须留下记录。"""
    decoy, store, loop, bound = _run_decoy_server()
    host, port = bound
    try:
        client = socket.create_connection((host, port), timeout=10)
        client.recv(256)
        client.close()
        time.sleep(0.5)
        signals = [row["name"] for row in store.signals_summary()]
        assert "ssh_banner_grab_only" in signals, \
            "抓 banner 即断开未记录为扫描特征, 实际信号: %s" % signals
    finally:
        loop.call_soon_threadsafe(loop.stop)
        time.sleep(0.15)
        loop.run_until_complete(decoy.close())
        loop.close()
        store.close()


def test_socket_level_non_ssh_traffic_flagged():
    """HTTP 请求打到 SSH 端口 —— 扫描器或配置错误, 必须留痕。"""
    decoy, store, loop, bound = _run_decoy_server()
    host, port = bound
    try:
        client = socket.create_connection((host, port), timeout=10)
        client.recv(256)
        client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.3)
        client.close()
        time.sleep(0.5)
        events = [row["kind"] for row in store.recent_events(limit=20)]
        assert "ssh_protocol_violation" in events or "non_ssh_probe" in events, \
            "非 SSH 流量未留痕, 事件: %s" % events
    finally:
        loop.call_soon_threadsafe(loop.stop)
        time.sleep(0.15)
        loop.run_until_complete(decoy.close())
        loop.close()
        store.close()


# --------------------------------------------------------------------------
# 安全护栏
# --------------------------------------------------------------------------

def test_tarpit_budget_caps_self_harm():
    """拖滞必须受预算约束 —— 否则蜜罐会把自己拖垮。"""
    decoy = make_decoy()
    decoy.budget.per_session = 0.2
    decoy.base_delay = 10.0
    decoy.max_delay = 10.0
    _, body = build_client_kexinit("curve25519-sha256@libssh.org", "aes128-ctr")
    parsed = decoy._parse_kexinit(body)
    session, _ = decoy._acquire_client("203.0.113.30", parsed["fingerprint"], "paramiko")

    class NullWriter(object):
        def write(self, data):
            pass

        async def drain(self):
            pass

    loop = asyncio.new_event_loop()
    try:
        total = 0.0
        for _ in range(5):
            total += loop.run_until_complete(
                decoy._apply_tarpit(session, parsed, NullWriter()))
    finally:
        loop.close()
    assert total <= 1.0, "拖滞累计 %.1fs 超出预算限制(单会话 0.2s)" % total
