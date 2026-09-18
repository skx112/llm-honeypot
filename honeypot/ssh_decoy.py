"""SSH 协议诱饵: 只做握手前半段, 但把客户端的指纹榨干。

## 为什么不做完整的 SSH 交互式诱捕

完整 SSH 诱捕(Cowrie 那种)需要一套完整的加密传输: 曲线密钥交换、对称加密、
消息认证。这些都要密码学库, 而本项目**零第三方依赖**是硬约束 —— 在专门用于
诱捕攻击者的主机上装依赖, 等于自愿扩大供应链攻击面。

## 那还能拿到什么

关键事实: **SSH 在密钥交换完成之前, 报文是不加密的**(RFC 4253 §6 的二进制包
格式在加密启用前不含 MAC)。这给了我们一段完全可解析的窗口, 足以做到:

  1. **客户端实现识别** —— 从客户端 banner 判定是 paramiko、libssh、
     Go x/crypto/ssh、PuTTY、JSCH 还是 OpenSSH。**LLM 智能体驱动 SSH 时
     几乎必然用 paramiko 或某个库**, 这一条直接指向"自动化"而非"运维"。
  2. **算法偏好指纹** —— 解析客户端 KEXINIT 的九个算法名列表。不同客户端库的
     算法顺序高度稳定且难以随意更改, 这是**类似 TLS JA3 的强指纹**。
  3. **真实客户端 vs 扫描器** —— 只连不发、或抓完 banner 就走的是扫描器;
     真正发起 KEX 的是可交互客户端。
  4. **爆破特征** —— 同一来源高频重连, 即使拿不到口令也构成口令爆破行为。

## 与检测引擎的复用(关键设计)

把 SSH 的算法偏好列表塞进 `SessionProfile` 已有的 `header_sig` 槽位。这样:

  · 跨源行为哈希归因**对 SSH 也自动生效** —— 攻击者换 IP 但继续用同一个
    paramiko 客户端时, 两个来源会被关联成同一战役
  · 不需要为 SSH 另写一套判定引擎, 权重与场景覆盖也一并复用

这比"再写一个独立判定器"正确得多: 判定逻辑只有一份, 就不会出现两套阈值
互相矛盾的情况。

## 已知局限(如实声明)

  · **拿不到用户名与口令** —— 它们在 KEX 之后, 而我们无法完成 KEX。
    这是零依赖的必然代价, 不是实现疏漏。
  · 因此本模块的价值在**归因与行为识别**, 不在凭据采集。凭据采集由 HTTP 侧的
    蜜标承担(见 deception.py 的凭据蜜标与 templates 的 credentials 段)。
"""

import hashlib
import struct
import time
import uuid

import fingerprint
import http_parse
import inject
import tarpit as tarpit_mod

# SSH 消息号(RFC 4253 / 4252)
MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_KEXINIT = 20
MSG_SERVICE_REQUEST = 5

# 我们对外声称的 KEXINIT 算法列表 —— 取自 OpenSSH 8.2p1 的真实顺序。
# 必须"像那么回事": 一个算法列表明显异常的 SSH 服务本身就是破绽。
SERVER_KEX_ALGORITHMS = (
    "curve25519-sha256,curve25519-sha256@libssh.org,"
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,"
    "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
    "diffie-hellman-group14-sha256"
)
SERVER_HOST_KEY_ALGORITHMS = (
    "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,"
    "ssh-ed25519,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"
)
SERVER_CIPHERS = (
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com"
)
SERVER_MACS = (
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1"
)
SERVER_COMPRESSION = "none,zlib@openssh.com"
SERVER_LANGUAGES = ""

# 客户端 banner 特征 -> (信号名, 工具链标签)
#
# 顺序有意义: 先匹配到的优先。paramiko 放在最前是因为它最值得关注 ——
# LLM 智能体与 Python 自动化工具默认用它, 而真实运维人员不用。
CLIENT_SIGNATURES = (
    ("paramiko", "paramiko", "ssh_client_paramiko", "automation"),
    ("asyncssh", "asyncssh", "ssh_client_paramiko", "automation"),
    ("netmiko", "netmiko", "ssh_client_paramiko", "automation"),
    ("fabric", "fabric", "ssh_client_paramiko", "automation"),
    ("spur", "spur", "ssh_client_paramiko", "automation"),
    ("libssh", "libssh", "ssh_client_automation", "automation"),
    ("libssh2", "libssh2", "ssh_client_automation", "automation"),
    ("go", "Go x/crypto/ssh", "ssh_client_automation", "automation"),
    ("golang", "Go x/crypto/ssh", "ssh_client_automation", "automation"),
    ("node", "node ssh2", "ssh_client_automation", "automation"),
    ("ssh2js", "node ssh2", "ssh_client_automation", "automation"),
    ("jsch", "JSch (Java)", "ssh_client_automation", "automation"),
    ("apache sshd", "Apache MINA SSHD", "ssh_client_automation", "automation"),
    ("moba", "MobaXterm", "ssh_client_putty", "real-client"),
    ("putty", "PuTTY", "ssh_client_putty", "real-client"),
    ("winscp", "WinSCP", "ssh_client_putty", "real-client"),
    ("securecrt", "SecureCRT", "ssh_client_putty", "real-client"),
    ("xshell", "Xshell", "ssh_client_putty", "real-client"),
    ("finalshell", "FinalShell", "ssh_client_putty", "real-client"),
    ("dropbear", "Dropbear", "ssh_client_automation", "automation"),
    ("bitvise", "Bitvise", "ssh_client_putty", "real-client"),
    ("openssh", "OpenSSH", "ssh_client_openssh", "real-client"),
)

# 扫描器的 SSH 探测模块
SCANNER_SIGNATURES = ("zgrab", "nmap", "masscan", "zmap", "nc", "netcat")


class SSHDecoy(object):
    """SSH 协议诱饵。接口与 dashboard 一致: start() / close() 皆为协程。"""

    def __init__(self, config, store=None, verbose=True):
        self.cfg = config
        self.store = store
        self.verbose = verbose
        self.host = config.get("ssh_decoy.listen", "0.0.0.0")
        self.port = int(config.get("ssh_decoy.port", 2222))
        self.banner = config.get("ssh_decoy.banner",
                                 "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11")
        self.instance_name = config.get("instance", "honeypot")

        self.canary = inject.CanaryManager()
        self.index = fingerprint.CrossIndex()
        self.budget = tarpit_mod.TarpitBudget(
            per_session=config.get("limits.max_tarpit_seconds_per_session", 300.0),
            global_per_min=config.get("limits.global_tarpit_budget_per_min", 900.0),
            load_threshold=config.get("limits.load_shed_threshold", 0.92),
        )

        self.max_connections = int(config.get("limits.max_connections", 2048))
        self.max_per_ip = int(config.get("limits.max_per_ip", 24))
        self.banner_timeout = float(config.get("ssh_decoy.banner_timeout", 20.0))
        self.kex_timeout = float(config.get("ssh_decoy.kex_timeout", 15.0))
        self.base_delay = float(config.get("tarpit.base_delay", 0.4))
        self.growth = float(config.get("tarpit.growth", 1.32))
        self.max_delay = float(config.get("tarpit.max_delay", 8.0))

        self.conn_by_ip = {}
        self.clients = {}          # key = "<ip>|<算法指纹>" -> Session
        self.client_ttl = float(config.get("limits.client_session_ttl", 1800))
        self._server = None
        self.stats = {
            "connections": 0, "banner_grab_only": 0, "kex_attempts": 0,
            "non_ssh": 0, "rejected": 0, "tarpit_seconds": 0.0, "alerts": 0,
        }

    # ---- 生命周期 ------------------------------------------------------

    async def start(self):
        import asyncio
        loop = asyncio.get_event_loop()
        self._server = await asyncio.start_server(
            self._handle, host=self.host, port=self.port, reuse_address=True)
        for sock in (self._server.sockets or ()):
            try:
                return sock.getsockname()
            except OSError:
                pass
        return (self.host, self.port)

    async def close(self):
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None

    # ---- 会话(跨连接复用, 与 HTTP 侧同一套逻辑) ------------------------

    def _acquire_client(self, ip, algorithm_fingerprint, client_label):
        now = time.time()
        stale = [key for key, session in self.clients.items()
                 if now - session["last_seen"] > self.client_ttl]
        for key in stale:
            self.clients.pop(key, None)

        key = "%s|%s" % (ip, algorithm_fingerprint or "-")
        session = self.clients.get(key)
        if session is not None:
            session["conn_count"] += 1
            session["last_seen"] = now
            session["profile"].concurrency_peak = max(
                session["profile"].concurrency_peak, self.conn_by_ip.get(ip, 1))
            return session, False

        sid = "ssh-%s-%s" % (ip.replace(":", "_"), uuid.uuid4().hex[:10])
        profile = fingerprint.SessionProfile(sid, ip, self.port)
        profile.concurrency_peak = self.conn_by_ip.get(ip, 1)
        profile.ip_seen_count = self.conn_by_ip.get(ip, 1)
        token = self.canary.issue(sid, ip)
        ctx = inject.PayloadContext(token, ip, self.instance_name)
        profile.payload_ctx = ctx

        session = {
            "sid": sid, "ip": ip, "profile": profile, "canary": token,
            "ctx": ctx, "expectations": [], "seen": set(),
            "compliance_hits": 0, "inject_hits": 0, "alerted": False,
            "start_ts": now, "last_seen": now, "conn_count": 1,
            "client_label": client_label, "algorithm_fingerprint": algorithm_fingerprint,
        }
        self.clients[key] = session

        if self.store is not None:
            self.store.start_session(sid, ip, self.port,
                                     "SSH/%s" % client_label,
                                     fingerprint.sha1_short(client_label),
                                     algorithm_fingerprint, None)
        return session, True

    # ---- 连接处理 ------------------------------------------------------

    async def _handle(self, reader, writer):
        import asyncio

        peer = "0.0.0.0", 0
        try:
            info = writer.get_extra_info("peername")
            if isinstance(info, tuple) and len(info) >= 2:
                peer = str(info[0]), int(info[1])
        except Exception:
            pass
        ip, port = peer
        if self.stats["connections"] >= self.max_connections or \
                self.conn_by_ip.get(ip, 0) >= self.max_per_ip:
            self.stats["rejected"] += 1
            if self.store is not None:
                self.store.log_event("conn_limit", None, ip,
                                     "SSH 单 IP 连接上限 %d" % self.max_per_ip, "warning")
            writer.close()
            return

        self.conn_by_ip[ip] = self.conn_by_ip.get(ip, 0) + 1
        self.stats["connections"] += 1
        started = time.time()
        record = {
            "ip": ip, "port": port, "banner": "", "client_label": "unknown",
            "signals": [], "software": "", "kex": None, "kind": "unknown",
            "username_hint": "",
        }

        try:
            record = await self._exchange(ip, port, reader, writer)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as exc:
            if self.verbose:
                print("  SSH 诱饵处理异常 %s: %r" % (ip, exc))
        finally:
            self.conn_by_ip[ip] = max(0, self.conn_by_ip.get(ip, 1) - 1)
            if self.conn_by_ip.get(ip) == 0:
                self.conn_by_ip.pop(ip, None)
            try:
                writer.close()
            except Exception:
                pass
            self._persist(record, ip, started)

    def _admit(self, ip):
        if self.stats["connections"] >= self.max_connections:
            return False
        if self.conn_by_ip.get(ip, 0) >= self.max_per_ip:
            if self.store is not None:
                self.store.log_event("conn_limit", None, ip,
                                     "SSH 单 IP 连接上限 %d" % self.max_per_ip, "warning")
            return False
        return True

    async def _exchange(self, ip, port, reader, writer):
        """banner 交换 -> KEXINIT 解析 -> 拖滞 -> 断开。

        OpenSSH 在连接建立后立即发送 banner, 因此我们先发再收 —— 顺序反过来会
        让真实客户端等待, 那是个明显的破绽。
        """
        import asyncio

        record = {"ip": ip, "port": 0, "banner": "", "client_label": "unknown",
                  "software": "", "signals": [], "kex": None, "kind": "unknown"}

        # 1) 先发 banner
        try:
            writer.write((self.banner + "\r\n").encode("ascii", "replace"))
            await writer.drain()
        except Exception:
            return record

        # 2) 收客户端 banner(可能是非 SSH 流量)
        try:
            raw = await asyncio.wait_for(reader.readline(), self.banner_timeout)
        except asyncio.TimeoutError:
            # 收不到对方 banner 却也不断开: 只读不写的典型抓取行为
            record["kind"] = "banner_grab"
            record["signals"].append("ssh_banner_grab_only")
            self.stats["banner_grab_only"] += 1
            return record
        except Exception:
            return record

        if not raw:
            # 我们已先发了 banner。对方连上什么都不发就断开 —— 只可能是
            # 读了我们的 banner 就走(端口扫描/指纹采集), 或纯粹的空连接探测。
            # 这与"发了非 SSH 数据"是不同情形, 分开记录才便于分析。
            record["kind"] = "banner_grab"
            record["signals"].append("ssh_banner_grab_only")
            self.stats["banner_grab_only"] += 1
            return record

        line = raw.decode("utf-8", "replace").strip()

        # 非 SSH 流量打到 SSH 端口 —— 扫描器/配置错误的强特征
        if not line.startswith("SSH-"):
            record["kind"] = ("tls_probe" if http_parse.looks_like_tls(raw)
                              else "non_ssh")
            record["banner"] = line[:200]
            record["signals"].append("ssh_no_banner")
            self.stats["non_ssh"] += 1
            if self.store is not None:
                self.store.log_event("non_ssh_probe", None, ip,
                                     "SSH 端口收到非 SSH 流量: %s" % line[:160], "info")
            return record

        record["banner"] = line[:200]
        record["software"] = line.split("-", 2)[-1] if line.count("-") >= 2 else line
        label, signal, family = self._identify_client(line)
        record["client_label"] = label
        record["signals"].append(signal)

        # 3) 解析 KEXINIT(未加密, 可解析) 并取算法指纹
        kex = await self._read_kexinit(reader)
        if kex is None:
            # 交换了 banner 却不发起密钥交换: 指纹采集工具或严重残缺的客户端
            record["kind"] = "kex_absent"
            record["signals"].append("ssh_kex_absent")
            self.stats["kex_absent"] = self.stats.get("kex_absent", 0) + 1
            return record

        record["kex"] = kex
        record["kind"] = "kex"
        record["signals"].append("ssh_kex_attempt")
        self.stats["kex_attempts"] += 1

        # 发出我们的 KEXINIT, 让客户端认为握手在推进。
        # 这一点影响捕获质量: 真实的 SSH 客户端在收到服务端 KEXINIT 之前不会
        # 继续下一步, 不发它对方会立刻判定服务端异常并断开 —— 那样我们就少拿到
        # 一轮交互观测(而且更容易被识别为"这不是真的 SSH")。
        try:
            writer.write(self._build_kexinit())
            await writer.drain()
        except Exception:
            pass

        # 4) 记录会话与判定(复用 HTTP 侧的判定引擎)
        session, created = self._acquire_client(
            ip, kex["fingerprint"], record["client_label"])
        self._evaluate(session, record, kex, family)

        # 5) 拖滞: 用与 HTTP 侧同一套预算与熔断
        delay = await self._apply_tarpit(session, kex, writer)

        # 6) 以合理的理由断开 —— 真实服务器也会在协议错误时这么做
        reason = 2 if delay > 2.0 else 11     # 2=协议错误, 11=by application
        text = self._disconnect_text(ip, session)
        await self._send_disconnect(writer, reason, text)
        return record

    # ---- 客户端识别 ----------------------------------------------------

    def _identify_client(self, banner):
        """从 banner 判定客户端实现。返回 (标签, 信号名, 家族)。"""
        lowered = banner.lower()
        for needle, label, signal, family in CLIENT_SIGNATURES:
            if needle in lowered:
                return label, signal, family
        for needle in SCANNER_SIGNATURES:
            if needle in lowered:
                return "scanner:%s" % needle, "ssh_client_scanner", "scanner"
        return banner[:40], "ssh_old_or_anomalous_client", "unknown"

    # ---- KEXINIT 解析 --------------------------------------------------

    async def _read_kexinit(self, reader):
        """读取并解析客户端 KEXINIT。

        报文格式(RFC 4253 §6, 加密前不含 MAC):
            uint32  packet_length
            byte    padding_length
            byte[n] payload          n = packet_length - padding_length - 1
            byte[m] random padding   m = padding_length
        """
        import asyncio

        try:
            header = await asyncio.wait_for(reader.readexactly(4), self.kex_timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, Exception):
            return None
        if len(header) < 4:
            return None
        length = struct.unpack(">I", header)[0]
        # 合理的 KEXINIT 长度在数百字节; 过小过大都不是它
        if length < 16 or length > 8192:
            return None
        try:
            body = await asyncio.wait_for(reader.readexactly(length), self.kex_timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, Exception):
            return None

        padding_length = body[0]
        payload = body[1:length - padding_length]
        if not payload or payload[0] != MSG_KEXINIT:
            return None
        return self._parse_kexinit(payload)

    def _parse_kexinit(self, payload):
        """解析 KEXINIT 载荷, 抽取算法名列表并生成指纹。

        必须严格校验: 载荷首字节是 KEXINIT 消息号, 且密钥交换算法列表非空。
        否则一串零字节也能"解析成功"并产出一个伪造指纹, 污染指纹空间 ——
        那样跨源归因会把无关来源关联到一起(真实踩过)。
        """
        if not payload or payload[0] != MSG_KEXINIT:
            return None
        offset = 17                     # msg(1) + cookie(16)
        names = ("kex", "host_key", "cipher_c2s", "cipher_s2c",
                 "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c",
                 "lang_c2s", "lang_s2c")
        lists = {}
        try:
            for name in names:
                if offset + 4 > len(payload):
                    break
                size = struct.unpack(">I", payload[offset:offset + 4])[0]
                offset += 4
                if size > 4096 or offset + size > len(payload):
                    break
                value = payload[offset:offset + size].decode("utf-8", "replace")
                offset += size
                lists[name] = value
        except struct.error:
            return None

        if not lists.get("kex"):
            return None

        # 指纹: 对算法列表取哈希。算法顺序是客户端库的稳定特征, 且难以随意更改,
        # 因此这比 banner 更难伪造 —— 与 TLS 的 JA3 是同一思路。
        material = "|".join("%s=%s" % (name, lists.get(name, "")) for name in names)
        digest = hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()[:12]

        return {
            "algorithms": lists,
            "fingerprint": digest,
            "kex_count": len([item for item in lists.get("kex", "").split(",") if item]),
            "cipher_count": len([item for item in lists.get("cipher_c2s", "").split(",")
                                 if item]),
            "raw_size": len(payload),
        }

    # ---- 判定与遥测 ----------------------------------------------------

    def _evaluate(self, session, record, kex, family):
        """把 SSH 观测映射成信号并给出判定。

        刻意复用 HTTP 侧的判定引擎: 判定逻辑只有一份, 就不会出现两套阈值
        互相矛盾的情况; 场景包的权重覆盖也自动对 SSH 生效。
        """
        profile = session["profile"]

        # 用算法指纹填充 header_sig 槽位 —— 这是跨源归因能在 SSH 侧生效的关键。
        # 同一个 paramiko 客户端从不同 IP 发起连接时, 会得到同一个行为哈希。
        profile.header_sigs[kex["fingerprint"]] = \
            profile.header_sigs.get(kex["fingerprint"], 0) + 1

        # 构造一条观测载体, 让共享的判定引擎能处理 SSH 事件。
        #
        # 刻意**不**去伪造一条 HTTP 请求行再解析 —— 那需要拼出 `KEX ... SSH-2.0`
        # 这种非法报文, 会被容错解析器正确地拒绝(真实踩过: _evaluate 因此每次
        # 都抛 NotHTTP, SSH 侧完全没有判定产出)。Request 本就是普通数据对象,
        # 直接构造即可, 方法是 SSH、路径是观测点, 语义也更准确。
        synthetic = http_parse.Request()
        synthetic.method = "SSH"
        synthetic.target = "/ssh/kexinit"
        synthetic.path = "/ssh/kexinit"
        synthetic.version = "SSH-2.0"
        synthetic.headers = [
            ("User-Agent", "SSH/%s" % record["client_label"]),
            ("X-SSH-Algorithms", kex["fingerprint"]),
            ("X-SSH-Software", record["software"]),
        ]
        profile.record(synthetic, time.time())
        profile.asset_count = 0        # SSH 客户端不拉取静态资源
        profile.ip_seen_count = self.conn_by_ip.get(record["ip"], 1)

        verdict = fingerprint.evaluate(profile, synthetic, self.index)

        # SSH 专属信号
        for name in record["signals"]:
            if name in fingerprint.WEIGHTS:
                verdict.add(name, kind="toolchain",
                            evidence="SSH 客户端 %s" % record["client_label"])

        if kex["kex_count"] <= 3:
            verdict.add("ssh_old_or_anomalous_client", kind="toolchain",
                        evidence="KEXINIT 仅声明 %d 种密钥交换算法" % kex["kex_count"])

        # 高频重连 = 口令爆破特征(即使我们拿不到口令, 行为本身已构成证据)
        attempts = session["conn_count"]
        if attempts >= 8:
            verdict.add("ssh_brute_force_volume", kind="behavior",
                        evidence="同一来源在 %.0f 秒内建立 %d 次 SSH 连接" % (
                            time.time() - session["start_ts"], attempts))

        cross_ips = self.index.ips_for_header_sig(kex["fingerprint"])
        if len(cross_ips) >= 2:
            verdict.add("ssh_algorithm_fingerprint_repeat", kind="attribution",
                        evidence="同一 SSH 算法指纹来自 %d 个源 IP: %s" % (
                            len(cross_ips), ",".join(sorted(cross_ips)[:6])))

        # 重新汇总(SSH 信号加进来后分数可能变化)
        raw = sum(item["weight"] for item in verdict.signals)
        verdict.score = int(max(0, min(100, raw)))
        verdict.confidence = min(0.99, verdict.score / 100.0)
        if verdict.decisive:
            verdict.confidence = max(verdict.confidence, 0.97)
        llm_evidence = any(item["kind"] in ("llm", "decisive", "semantic")
                           for item in verdict.signals)
        if verdict.score >= 80 and (llm_evidence or session["client_label"].lower()
                                    .startswith(("paramiko", "asyncssh", "go "))):
            verdict.label = "llm_agent"
        elif verdict.score >= 55 and llm_evidence:
            verdict.label = "llm_agent_probable"
        elif verdict.score >= 35:
            verdict.label = "suspicious_automation"
        else:
            verdict.label = "unknown"

        session["verdict"] = verdict
        session["score"] = verdict.score

        self.index.observe(profile)

        # 战役归因: 与 HTTP 侧同一规则(行为哈希聚合, 多源 IP 并集)。
        # 此前 SSH 会话从不 upsert 战役 —— 多源归因只存在于内存索引,
        # 不落库、进不了上报与 hub(部署实测发现)。
        campaign_id = None
        if verdict.score >= 50 or len(self.index.ips_for_behavior(
                profile.behavior_hash())) >= 2:
            campaign_id = "camp-%s" % profile.behavior_hash()[:12]
            if self.store is not None:
                self.store.upsert_campaign(
                    campaign_id, profile.behavior_hash(), ip=record["ip"],
                    ua="SSH/%s" % record["client_label"],
                    toolchain="ssh:%s" % record["client_label"],
                    model_guess=None, score=verdict.score,
                    evidence={"algorithm_fp": kex["fingerprint"]})

        if self.store is not None:
            request_id = self.store.log_request(
                session["sid"], record["ip"],
                {"method": "SSH", "target": "/ssh/kexinit",
                 "path": "/ssh/kexinit", "query": "",
                 "version": "SSH-2.0", "host": record["ip"],
                 "headers": [("Client-Banner", record["banner"]),
                             ("Client-Label", record["client_label"]),
                             ("Algorithm-Fingerprint", kex["fingerprint"])],
                 "body_text": self._describe_kex(kex),
                 "body_len": kex["raw_size"], "body_truncated": False,
                 "malformed": []},
                time.time(), 0, 0, 0, self._action_for(verdict.score),
                verdict.score, verdict.signals)
            for signal in verdict.signals:
                self.store.log_signal(session["sid"], record["ip"], signal["name"],
                                      signal["weight"], signal["kind"],
                                      signal["evidence"], None, request_id)
            self.store.bump_session(session["sid"], time.time(),
                                    bytes_in=kex["raw_size"], bytes_out=len(self.banner))
            self.store.update_session(
                session["sid"],
                campaign_id=campaign_id,
                ua=("SSH/%s" % record["client_label"])[:512],
                header_sig=kex["fingerprint"], label=verdict.label,
                score=verdict.score, confidence=verdict.confidence,
                action=self._action_for(verdict.score),
                signals_json=_json([item["name"] for item in verdict.signals]),
                behavior_hash=profile.behavior_hash(),
                note="SSH 客户端 %s, 算法指纹 %s" % (record["client_label"],
                                                    kex["fingerprint"]))
            self.store.log_event(
                "ssh_client", session["sid"], record["ip"],
                "SSH 客户端=%s 算法指纹=%s KEX算法数=%d" % (
                    record["client_label"], kex["fingerprint"], kex["kex_count"]),
                "warning" if verdict.score >= 55 else "info")

        if verdict.score >= 70 and not session["alerted"]:
            session["alerted"] = True
            self.stats["alerts"] += 1
            self._alert("[%s] score=%d ip=%s ssh_client=%s fp=%s" % (
                verdict.label, verdict.score, record["ip"],
                record["client_label"], kex["fingerprint"]))

    @staticmethod
    def _action_for(score):
        import respond
        return respond.action_for_score(score)

    @staticmethod
    def _describe_kex(kex):
        lines = []
        for name in ("kex", "host_key", "cipher_c2s", "mac_c2s", "comp_c2s"):
            value = kex["algorithms"].get(name)
            if value:
                lines.append("%s = %s" % (name, value))
        return "\n".join(lines)

    # ---- 拖滞 ----------------------------------------------------------

    async def _apply_tarpit(self, session, kex, writer):
        """与 HTTP 侧同一套成本反转逻辑: 延迟随连接数指数增长, 带预算熔断。"""
        import asyncio

        steps = max(0, session["conn_count"] - 1)
        delay = min(self.base_delay * (self.growth ** min(steps, 24)), self.max_delay)
        delay = max(0.0, delay)

        granted = self.budget.reserve(session["sid"], delay * 2)
        if granted <= 0:
            return 0.0
        delay = min(delay, granted / 2)

        try:
            if delay > 0:
                await asyncio.sleep(delay)
            # 再发一个无操作消息, 让客户端认为服务端在正常处理(而不是卡死)
            writer.write(self._build_packet(MSG_IGNORE, b"\x00" * 8))
            await writer.drain()
            if delay > 0:
                await asyncio.sleep(delay * 0.5)
        except Exception:
            pass
        self.stats["tarpit_seconds"] += delay * 1.5
        return delay * 1.5

    # ---- 报文构造 ------------------------------------------------------

    def _disconnect_text(self, ip, session):
        """携带 NL 反制的断开描述(会进攻击者的 SSH 客户端日志)。"""
        base = "Connection closed by %s" % ip
        try:
            import inject as _inj
            score = getattr(session, "score", 0) or 0
            picked = _inj.select_for_tier(score, tier_hint=1, limit=1,
                                          categories=("abort", "beacon"))
            if picked:
                ctx = getattr(session, "ctx", None)
                if ctx is not None:
                    snippet = ctx.render(picked[0]["text"]).strip()
                    snippet = " ".join(snippet.split())[:180]
                    return "%s (%s)" % (base, snippet)
        except Exception:
            pass
        return base

    @staticmethod
    def _pack_raw(body_with_code):
        """按 RFC 4253 §6 打包(加密前格式, 不含 MAC)。

        总长必须是 8 的倍数, padding 至少 4 字节。填充内容客户端不会校验,
        因此填零即可。
        """
        padding_length = 8 - ((len(body_with_code) + 5) % 8)
        if padding_length < 4:
            padding_length += 8
        packet_length = len(body_with_code) + padding_length + 1
        return (struct.pack(">I", packet_length)
                + bytes(bytearray([padding_length]))
                + body_with_code
                + bytes(bytearray(padding_length)))

    @classmethod
    def _build_packet(cls, msg_code, payload):
        """构造一个带消息号的 SSH 二进制包。"""
        return cls._pack_raw(bytes(bytearray([msg_code])) + payload)

    def _build_kexinit(self):
        """构造服务端 KEXINIT。真实客户端会解析它, 因此列表必须像样。"""
        import os as _os
        payload = bytearray([MSG_KEXINIT])
        payload.extend(_os.urandom(16))                  # cookie
        for value in (SERVER_KEX_ALGORITHMS, SERVER_HOST_KEY_ALGORITHMS,
                      SERVER_CIPHERS, SERVER_CIPHERS, SERVER_MACS, SERVER_MACS,
                      SERVER_COMPRESSION, SERVER_COMPRESSION,
                      SERVER_LANGUAGES, SERVER_LANGUAGES):
            encoded = value.encode("ascii")
            payload.extend(struct.pack(">I", len(encoded)))
            payload.extend(encoded)
        payload.append(0)                                # first_kex_packet_follows
        payload.extend(struct.pack(">I", 0))             # reserved
        return self._pack_raw(bytes(payload))

    async def _send_disconnect(self, writer, reason, description):
        payload = struct.pack(">I", reason)
        text = description.encode("utf-8")
        payload += struct.pack(">I", len(text)) + text
        payload += struct.pack(">I", 0)                  # language tag
        try:
            writer.write(self._build_packet(MSG_DISCONNECT, payload))
            await writer.drain()
        except Exception:
            pass

    # ---- 落库与告警 ----------------------------------------------------

    def _persist(self, record, ip, started):
        """记录未进入完整评估路径的观测。

        三种"没走到 KEX"的情形语义不同, 不能混为一谈:

          no_banner / non_ssh / tls_probe
              客户端根本没按 SSH 协议发言 → 扫描器或配置错误的工具
          banner_grab
              按协议发了 banner 却不发起密钥交换 → 典型的端口扫描/指纹采集
        """
        kind = record.get("kind")
        elapsed = time.time() - started
        if self.verbose and kind and kind != "unknown":
            print("%s SSH %s client=%-20s kind=%-16s %.2fs" % (
                time.strftime("%H:%M:%S"), ip, record.get("client_label"),
                kind, elapsed))
        if self.store is None:
            return
        if kind in ("no_banner", "non_ssh", "tls_probe"):
            self.store.log_signal(None, ip, "ssh_no_banner",
                                  fingerprint.WEIGHTS["ssh_no_banner"],
                                  "toolchain", "SSH 端口收到 %s" % kind)
            self.store.log_event("ssh_protocol_violation", None, ip,
                                 "SSH 端口收到非 SSH 流量(%s): %s" % (
                                     kind, (record.get("banner") or "")[:150]),
                                 "warning")
        elif kind == "banner_grab":
            self.store.log_signal(None, ip, "ssh_banner_grab_only",
                                  fingerprint.WEIGHTS["ssh_banner_grab_only"],
                                  "behavior", "连接后未发送任何 SSH banner")
            self.store.log_event("ssh_banner_grab", None, ip,
                                 "只读取 banner 未发送数据(端口扫描特征)", "info")
        elif kind == "kex_absent":
            self.store.log_signal(None, ip, "ssh_kex_absent",
                                  fingerprint.WEIGHTS["ssh_kex_absent"],
                                  "behavior",
                                  "客户端 %s 交换 banner 后未发起密钥交换"
                                  % record.get("client_label"))

    def _alert(self, line):
        """与 HTTP 侧共用同一 Alerter(同队列/线程与文件)。"""
        import alerts
        alerts.get_alerter(self.cfg).emit(line, "warning")
        if self.verbose:
            print("%s [warning] [%s] %s" % (
                time.strftime("%Y-%m-%dT%H:%M:%S%z"), self.instance_name, line))

    def runtime_stats(self):
        return dict(self.stats)


def _json(value):
    import json
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return "[]"
