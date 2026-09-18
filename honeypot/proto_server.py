"""多协议诱饵服务: 把 proto_decoys 的协议处理器变成可运行的 asyncio 服务。

与 SSH 诱饵同级, 共享同一套遥测存储、信号引擎与反制框架。
"""

import asyncio
import time
import uuid

import fingerprint
import http_parse
import inject
import proto_counter
import proto_decoys
import tarpit as tarpit_mod

DEFAULT_PORTS = [21, 23, 25, 3306, 5432, 6379, 9200, 11211, 27017, 3389]


class MultiProtocolDecoy(object):
    """在多个端口上同时运行协议诱饵。"""

    def __init__(self, config, store=None, verbose=True):
        self.cfg = config
        self.store = store
        self.verbose = verbose
        self.instance_name = config.get("instance", "proto-decoy")
        self.listen_host = config.get("proto_decoy.listen", "0.0.0.0")
        self.ports = config.get("proto_decoy.ports", DEFAULT_PORTS)
        self.canary = inject.CanaryManager()
        self.index = fingerprint.CrossIndex()
        self.budget = tarpit_mod.TarpitBudget(
            per_session=config.get("limits.max_tarpit_seconds_per_session", 300.0),
            global_per_min=config.get("limits.global_tarpit_budget_per_min", 900.0),
        )
        self._servers = []
        self.stats = {"connections": 0, "credentials_captured": 0,
                      "commands_captured": 0, "by_port": {}}

    async def start(self):
        loop = asyncio.get_event_loop()
        for port in self.ports:
            proto = proto_decoys.PROTOCOLS.get(port)
            if proto is None:
                if self.verbose:
                    print("  端口 %d 无注册协议, 跳过" % port)
                continue
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self._handle(r, w, p),
                    host=self.listen_host, port=port, reuse_address=True)
                self._servers.append(server)
                bound = server.sockets[0].getsockname() if server.sockets else ("?", port)
                if self.verbose:
                    print("  诱饵 :%-6d %-14s ✓" % (port, proto["name"]))
                self.stats["by_port"][port] = 0
            except OSError as exc:
                if self.verbose:
                    print("  诱饵 :%-6d %-14s ✗ (%s)" % (port, proto["name"], exc))
        return len(self._servers)

    async def close(self):
        for server in self._servers:
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
        self._servers = []

    async def _handle(self, reader, writer, port):
        proto = proto_decoys.PROTOCOLS.get(port)
        if proto is None:
            writer.close()
            return

        peer = "0.0.0.0", 0
        try:
            info = writer.get_extra_info("peername")
            if isinstance(info, tuple) and len(info) >= 2:
                peer = str(info[0]), int(info[1])
        except Exception:
            pass
        ip, _port = peer

        self.stats["connections"] += 1
        self.stats["by_port"][port] = self.stats["by_port"].get(port, 0) + 1

        sid = "proto-%s-%s" % (ip.replace(":", "_"), uuid.uuid4().hex[:8])

        # 跨协议分数共享: 同 IP 已被 HTTP/SSH 标记为高风险 → 协议层反制拉满
        inherited_score = proto_counter.lookup_ip_score(self.store, ip)

        # 每个协议连接签发独立令牌(用于跨协议金丝雀确认)
        token = self.canary.issue(sid, ip)
        ctx = inject.PayloadContext(token, ip, self.instance_name)
        ctx.model_family = ""

        session = {
            "sid": sid, "ip": ip, "port": _port, "proto": proto["name"],
            "service_port": port, "credentials": None,
            "start_ts": time.time(),
            "ctx": ctx, "score": inherited_score,
        }

        started = time.time()
        try:
            await asyncio.wait_for(
                proto["handler"](reader, writer, session),
                timeout=60.0)
        except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
            pass
        except Exception as exc:
            if self.verbose:
                print("  proto %s 处理异常 %s: %r" % (proto["name"], ip, exc))
        finally:
            try:
                writer.close()
            except Exception:
                pass

        elapsed = time.time() - started
        self._record(session, elapsed)

    def _record(self, session, elapsed):
        """把协议级观测落库。"""
        ip = session["ip"]
        proto_name = session["proto"]

        # 有凭据/命令捕获 → 高价值事件
        if session.get("credentials"):
            self.stats["credentials_captured"] += 1
            if self.store is not None:
                self.store.log_event(
                    "credential_captured", session["sid"], ip,
                    "%s 凭据: %s" % (proto_name,
                                     json_dumps(session["credentials"])),
                    "critical")
                self.store.log_signal(
                    session["sid"], ip, "proto_credential_capture", 40,
                    "decisive", "%s: %s" % (proto_name, session["credentials"]))

        for key in ("redis_commands", "memcached_commands", "smtp_commands"):
            if session.get(key):
                self.stats["commands_captured"] += 1
                if self.store is not None:
                    self.store.log_event(
                        "commands_captured", session["sid"], ip,
                        "%s %s: %s" % (proto_name, key,
                                       str(session[key])[:300]),
                        "warning")

        if session.get("redis_exploit"):
            if self.store is not None:
                self.store.log_event(
                    "redis_exploit_attempt", session["sid"], ip,
                    "Redis 未授权 RCE 利用: %s" % session["redis_exploit"],
                    "critical")

        if session.get("es_query"):
            if self.store is not None:
                self.store.log_event(
                    "es_probed", session["sid"], ip,
                    "ES 查询: %s" % json_dumps(session["es_query"]),
                    "warning")

        # 载荷投放追踪(与 HTTP 侧同构)
        if session.get("score", 0) >= 40 and self.store is not None:
            self.store.log_event(
                "payload_delivery", session["sid"], ip,
                "投放: proto-%s(协议层错误消息)" % session["proto"], "info")

        # 通用信号
        if self.store is not None:
            self.store.log_signal(
                session["sid"], ip, "proto_probe_%s" % proto_name, 15,
                "toolchain", "端口 %d 服务探测" % session["service_port"])
            self.store.start_session(
                session["sid"], ip, session["port"],
                "%s-probe" % proto_name, "", "", None)

    def runtime_stats(self):
        return dict(self.stats)


def json_dumps(value):
    import json
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)
