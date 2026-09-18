"""蜜罐服务主程序: asyncio 原始 TCP/HTTP 服务, 串起完整处置闭环。

单连接处理流程:
    原始报文读取 -> 容错解析 -> 会话画像摄入 -> 金丝雀/期望校验
    -> 指纹判定 -> 处置决策 -> 欺骗响应 -> 自适应拖滞 -> 遥测落库 -> 战役归因

刻意自己解析 HTTP 而不用框架: 框架会把畸形请求 400 掉, 而畸形请求恰恰是
扫描器与智能体最有价值的指纹特征。
"""

import asyncio
import email.utils
import os
import socket
import time
import uuid

import deception as deception_mod
import fingerprint
import http_parse
import inject
import respond
import tarpit as tarpit_mod

STATUS_TEXT = {
    100: "Continue", 200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
    418: "I'm a teapot", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}

CHUNK_TERMINATOR = b"0\r\n\r\n"


class Session(object):
    """一个 TCP 连接对应的会话上下文。"""

    __slots__ = ("sid", "ip", "port", "profile", "ctx", "canary", "expectations",
                 "score", "verdict", "decision", "compliance_hits", "inject_hits",
                 "alerted", "start_ts", "req_count", "seen_expectations",
                 "conn_count", "last_seen")

    def __init__(self, sid, ip, port, profile, ctx, canary):
        self.sid = sid
        self.ip = ip
        self.port = port
        self.profile = profile
        self.ctx = ctx
        self.canary = canary
        self.expectations = []
        self.seen_expectations = set()
        self.score = 0
        self.verdict = None
        self.decision = None
        self.compliance_hits = 0
        self.inject_hits = 0
        self.alerted = False
        self.start_ts = time.time()
        self.req_count = 0
        self.conn_count = 0        # 该客户端建立的连接数(跨连接累计)
        self.last_seen = self.start_ts

    def add_expectations(self, items):
        """累积本会话的期望清单(按 label 去重, 避免重复投放同一指令)。"""
        for item in items or []:
            label = item.get("label")
            if label in self.seen_expectations:
                continue
            self.seen_expectations.add(label)
            self.expectations.append(item)


class HoneypotServer(object):
    def __init__(self, config, store=None, verbose=True, instance=None):
        self.cfg = config
        self.store = store
        self.verbose = verbose
        self.instance = instance      # templating.HoneypotInstance 或 None
        self.instance_name = config.get("instance", "honeypot")
        self.server_header = config.get("http.server_header", "nginx/1.24.0 (Ubuntu)")

        self.canary = inject.CanaryManager()
        self.index = fingerprint.CrossIndex()
        self.budget = tarpit_mod.TarpitBudget(
            per_session=config.get("limits.max_tarpit_seconds_per_session", 300.0),
            global_per_min=config.get("limits.global_tarpit_budget_per_min", 900.0),
            load_threshold=config.get("limits.load_shed_threshold", 0.92),
        )
        self.tarpit = tarpit_mod.Tarpit(config, budget=self.budget, store=store)
        self.deception = deception_mod.Deception(
            config, self.canary, store, instance=instance)

        self.max_connections = int(config.get("limits.max_connections", 2048))
        self.max_per_ip = int(config.get("limits.max_per_ip", 24))
        self.max_head_bytes = int(config.get("limits.max_head_bytes", 65536))
        self.max_body_bytes = int(config.get("limits.max_body_bytes", 1048576))
        self.head_timeout = float(config.get("limits.head_timeout", 15.0))
        self.idle_timeout = float(config.get("limits.idle_timeout", 60.0))
        self.max_requests_per_conn = int(config.get("limits.max_requests_per_conn", 200))

        self.conn_total = 0
        self.conn_by_ip = {}
        # 客户端会话表: key = "<ip>|<ua哈希>" -> Session
        #
        # 关键设计: 会话**跨 TCP 连接**存活。LLM 智能体每次工具调用新建连接是
        # 常态(urllib/httpx 复用行为不一致), 如果会话绑定在连接上, 那么行为节律
        # (微突发+思考停顿)、路径顺序、低并发、资源拉取比这些**防伪造能力最强的
        # 特征全部失效** —— 真实踩过的架构级问题: 一个会话只有一个请求, 节律分析
        # 永远拿不到 5 个以上间隔。
        self.clients = {}
        self.client_ttl = float(config.get("limits.client_session_ttl", 1800))
        self.started_at = time.time()
        self.stats = {
            "connections": 0, "requests": 0, "non_http": 0, "rejected": 0,
            "tarpit_seconds": 0.0, "bytes_out": 0, "alerts": 0,
        }
        self._server = None

    # ---- 生命周期 ------------------------------------------------------

    async def start(self):
        """启动 HTTP 蜜罐监听。返回已绑定的地址列表。"""
        hosts = self.cfg.get("http.listen", ["0.0.0.0"])
        port = int(self.cfg.get("http.port", 8080))
        ssl_ctx = self._build_ssl_context()

        loop = asyncio.get_event_loop()
        self._server = await asyncio.start_server(
            self._handle, host=hosts, port=port, ssl=ssl_ctx, reuse_address=True,
        )
        bound = []
        for sock in self._server.sockets or ():
            try:
                bound.append(sock.getsockname())
            except OSError:
                pass
        return bound

    def _build_ssl_context(self):
        if not self.cfg.get("http.tls.enabled", False):
            return None
        import ssl
        cert = self.cfg.path(self.cfg.get("http.tls.cert", ""))
        key = self.cfg.path(self.cfg.get("http.tls.key", ""))
        if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
            raise RuntimeError("TLS 已启用但证书/私钥路径无效: %s / %s" % (cert, key))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx

    async def close(self):
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None

    # ---- 连接处理 ------------------------------------------------------

    async def _handle(self, reader, writer):
        peer = self._peer_of(writer)
        ip, port = peer

        if not self._admit(ip):
            self.stats["rejected"] += 1
            writer.close()
            return

        self.conn_total += 1
        self.conn_by_ip[ip] = self.conn_by_ip.get(ip, 0) + 1
        self.stats["connections"] += 1

        try:
            await self._serve(ip, port, reader, writer)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as exc:      # 蜜罐绝不应因单个连接异常而退出
            self._log("连接 %s:%s 处理异常: %r" % (ip, port, exc))
        finally:
            # 注意: 这里**不**销毁会话 —— 会话跨连接存活, 由 _prune_clients 按
            # 空闲超时回收。销毁它会让攻击者只要每次新建连接就能重置所有行为分析。
            self.conn_by_ip[ip] = max(0, self.conn_by_ip.get(ip, 1) - 1)
            if self.conn_by_ip.get(ip) == 0:
                self.conn_by_ip.pop(ip, None)
            try:
                writer.close()
            except Exception:
                pass

    # ---- 客户端会话(跨连接) ------------------------------------------

    def _acquire_client(self, ip, port, req):
        """按 (源 IP, UA 哈希) 取得或创建客户端会话。

        用 UA 参与 key 是为了避免同一 NAT 出口后的不同客户端被合并; 同一操作者
        轮换 IP 时仍由 fingerprint.CrossIndex 的行为哈希完成归因。
        """
        now = time.time()
        self._prune_clients(now)

        ua = req.ua or ""
        ua_hash = fingerprint.sha1_short(ua) if ua else "-"
        key = "%s|%s" % (ip, ua_hash)

        session = self.clients.get(key)
        if session is not None:
            session.conn_count += 1
            session.last_seen = now
            concurrency = self.conn_by_ip.get(ip, 1)
            if concurrency > session.profile.concurrency_peak:
                session.profile.concurrency_peak = concurrency
            return session, False

        sid = "%s-%s" % (ip.replace(":", "_"), uuid.uuid4().hex[:10])
        profile = fingerprint.SessionProfile(sid, ip, port)
        profile.ip_seen_count = self.conn_by_ip.get(ip, 1)
        profile.concurrency_peak = self.conn_by_ip.get(ip, 1)
        token = self.canary.issue(sid, ip)
        ctx = inject.PayloadContext(token, self._request_host(req), self.instance_name)
        profile.payload_ctx = ctx
        session = Session(sid, ip, port, profile, ctx, token)
        session.conn_count = 1
        session.last_seen = now
        self.clients[key] = session

        if self.store is not None:
            self.store.start_session(sid, ip, port, ua[:512], ua_hash,
                                     req.header_order_sig, None)
        return session, True

    def _prune_clients(self, now=None):
        """回收空闲超时的客户端会话。"""
        now = now or time.time()
        stale = [key for key, session in self.clients.items()
                 if now - session.last_seen > self.client_ttl]
        for key in stale:
            session = self.clients.pop(key, None)
            if session is None:
                continue
            self._finalize(session)
            self.budget.forget_session(session.sid)

    def _request_host(self, req):
        """优先用请求里的 Host 头渲染载荷(生成实例时主机名是定制过的)。"""
        host = (req.host or "").split(":")[0].strip()
        if host:
            return host
        return self.instance_name

    def _peer_of(self, writer):
        try:
            info = writer.get_extra_info("peername")
            if isinstance(info, tuple) and len(info) >= 2:
                return str(info[0]), int(info[1])
            if isinstance(info, str):
                return info, 0
        except Exception:
            pass
        return "0.0.0.0", 0

    def _admit(self, ip):
        if self.conn_total >= self.max_connections:
            return False
        if self.conn_by_ip.get(ip, 0) >= self.max_per_ip:
            if self.store is not None:
                self.store.log_event("conn_limit", None, ip,
                                     "超出单 IP 连接上限 %d" % self.max_per_ip, "warning")
            return False
        return True

    async def _serve(self, ip, port, reader, writer):
        conn_req_count = 0
        while True:
            if conn_req_count >= self.max_requests_per_conn:
                break

            # 读请求头
            try:
                head_result = await http_parse.read_head(
                    reader, self.max_head_bytes,
                    self.idle_timeout if conn_req_count else self.head_timeout)
            except http_parse.NotHTTP as exc:
                await self._handle_non_http(ip, port, writer, exc)
                return
            except Exception:
                return
            if head_result is None:
                return
            raw_head, leftover = head_result

            # 解析
            try:
                req = http_parse.parse_head(raw_head)
            except http_parse.NotHTTP as exc:
                await self._handle_non_http(ip, port, writer, exc)
                return
            req.raw_head = raw_head[:8192]

            # 会话按 (源 IP, UA) 取得 —— 同一客户端的多次连接累积到同一画像
            session, created = self._acquire_client(ip, port, req)

            # 正文(含 100-continue 处理)
            async def _send_continue():
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await writer.drain()
            try:
                await http_parse.read_body(
                    reader, req, self.max_body_bytes, self.head_timeout,
                    leftover=leftover, on_continue=_send_continue,
                )
            except Exception:
                req.body = b""

            conn_req_count += 1
            keepalive = await self._process(session, req, writer)
            if not keepalive:
                return

    # ---- 单请求处置 ----------------------------------------------------

    async def _process(self, session, req, writer):
        profile = session.profile
        ts = time.time()
        session.req_count += 1
        session.last_seen = ts
        profile.record(req, ts, req.body_text)
        self.stats["requests"] += 1

        # 1) 金丝雀回显检测: 我们埋的令牌是否出现在对方请求里
        self._scan_canary(session, req, ts)

        # 2) 指令服从/信标校验
        hits = respond.apply_expectations(req, session, self.store)
        if hits and self.store is not None:
            for hit in hits:
                self.store.log_signal(session.sid, session.ip,
                                      "injection_compliance" if hit["kind"] == "compliance"
                                      else "beacon_callback",
                                      50 if hit["kind"] == "compliance" else 45,
                                      "decisive", hit.get("evidence", ""), ts)

        # 3) 指纹判定
        verdict = fingerprint.evaluate(profile, req, self.index, now=ts)
        session.verdict = verdict
        session.score = verdict.score
        # 模型家族随判定刷新 —— 投递面据此分化(裸模型不投护栏类载荷)
        session.ctx.model_family = verdict.model_family

        # 4) 处置决策
        decision = respond.decide(verdict, profile, self.cfg)
        session.decision = decision
        session.add_expectations(decision.expectations)

        # 5) 生成欺骗响应
        reply = None
        if req.is_asset:
            reply = self.deception.serve_static(req, session)
        if reply is None:
            reply = self.deception.handle(req, session)

        # 6) 拖滞计划
        plan = self.tarpit.plan(profile, verdict, decision.action, reply)

        # 7) 写响应
        status, bytes_out, tarpit_spent = await self._write_response(
            session, req, reply, plan, writer)

        # 8) 遥测落库
        self._persist(session, req, verdict, decision, reply, status,
                      bytes_out, tarpit_spent, ts)

        # 9) 告警
        if decision.alert and not session.alerted:
            session.alerted = True
            self.stats["alerts"] += 1
            self._alert(fingerprint.render_report_line(verdict, profile), "warning")

        # 10) 连接是否继续
        connection_header = (req.header("connection") or "").lower()
        if connection_header == "close":
            return False
        if req.version == "HTTP/1.0" and connection_header != "keep-alive":
            return False
        return True

    def _scan_canary(self, session, req, ts):
        """检索请求里是否夹带我们签发过的金丝雀令牌。"""
        haystack_parts = [req.target or "", req.query or "", req.body_text[:16384]]
        for name, value in req.headers:
            haystack_parts.append(value or "")
        haystack = " ".join(haystack_parts)

        for found in self.canary.scan(haystack):
            # 信标路径与显式校验参数由期望机制处理, 这里只记"上下文复用"
            where = "target" if found["token"] in (req.target or "") else "headers/body"
            session.profile.note_token_presented(found["token"], where)
            if self.store is not None:
                self.store.log_event(
                    "canary_echo", session.sid, session.ip,
                    "金丝雀令牌 %s 出现在后续请求(%s), 来源会话 %s / IP %s" % (
                        found["token"], where, found["sid"], found["ip"]),
                    "critical",
                )
            self._alert("金丝雀回显: token=%s 会话=%s ip=%s 模式=上下文复用" % (
                found["token"], session.sid, session.ip), "critical")

    async def _handle_non_http(self, ip, port, writer, exc):
        """非 HTTP 流量(TLS 握手/SSH 横幅/二进制探测)。

        这类探测连请求行都不完整, 因此没有会话可言 —— 直接按来源记录。
        它是扫描器的强特征: 把 TLS ClientHello 打到 HTTP 端口, 只有自动化
        工具会这么做。
        """
        self.stats["non_http"] += 1
        preview = http_parse.hex_preview(exc.raw)
        kind = "tls_handshake" if http_parse.looks_like_tls(exc.raw) else "binary_probe"
        if self.store is not None:
            self.store.log_event(kind, None, ip,
                                 "非 HTTP 探测(来自 %s:%s): %s | hex=%s" % (
                                     ip, port, exc.reason, preview), "info")
        try:
            # 假装是一个无关服务, 让扫描器把端口归类错误
            writer.write(b"HTTP/1.1 400 Bad Request\r\nServer: %s\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                         % self.server_header.encode("ascii", "replace"))
            await writer.drain()
        except Exception:
            pass

    # ---- 响应写出 ------------------------------------------------------

    async def _write_response(self, session, req, reply, plan, writer):
        started = time.time()
        status = reply.status
        status_text = STATUS_TEXT.get(status, "Unknown")

        supports_chunked = (req.version or "HTTP/1.1") == "HTTP/1.1"
        infinite = bool(plan is not None and plan.infinite)
        head_only = (req.method == "HEAD")
        body = reply.body or b""

        headers = [
            ("Server", self.server_header),
            ("Date", email.utils.formatdate(usegmt=True)),
            ("Content-Type", reply.content_type),
        ]
        if infinite:
            if supports_chunked:
                headers.append(("Transfer-Encoding", "chunked"))
            headers.append(("Connection", "close"))
        else:
            headers.append(("Content-Length", str(len(body))))
            headers.append(("Connection", "keep-alive"))
        for name, value in reply.headers:
            headers.append((name, value))
        if reply.captured:
            headers.append(("X-Debug-Id", "dbg-%s" % session.canary.replace("hpx-", "")))

        head_bytes = self._render_head(status, status_text, headers)

        sent = 0
        try:
            # 前半段延迟: 看起来像应用处理慢
            if plan is not None and plan.pre_body_delay > 0:
                await asyncio.sleep(plan.pre_body_delay * 0.6)
            writer.write(head_bytes)
            await writer.drain()
            sent += len(head_bytes)
            if plan is not None and plan.pre_body_delay > 0:
                await asyncio.sleep(plan.pre_body_delay * 0.4)

            if head_only:
                pass
            elif infinite:
                sent += await self._stream_infinite(session, writer, plan)
            elif plan is not None and plan.chunk_count > 1 and body:
                sent += await self._drip(session, writer, body, plan, supports_chunked)
            else:
                writer.write(body)
                await writer.drain()
                sent += len(body)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            self._log("写响应异常 %s: %r" % (session.sid, exc))

        spent = time.time() - started
        self.stats["bytes_out"] += sent
        self.stats["tarpit_seconds"] += spent
        # 回填本请求的注入延迟 —— 下一轮节律分析要剔除它
        session.profile.note_server_delay(spent)
        return status, sent, spent

    @staticmethod
    def _render_head(status, status_text, headers):
        lines = ["HTTP/1.1 %d %s" % (status, status_text)]
        for name, value in headers:
            lines.append("%s: %s" % (name, value))
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace")

    async def _drip(self, session, writer, body, plan, supports_chunked):
        """把响应体切成小块缓慢发送。"""
        count = max(2, plan.chunk_count)
        size = max(1, len(body) // count)
        sent = 0
        for index in range(0, len(body), size):
            chunk = body[index:index + size]
            try:
                if supports_chunked:
                    writer.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                else:
                    writer.write(chunk)
                await writer.drain()
                sent += len(chunk)
            except (ConnectionResetError, BrokenPipeError):
                break
            except Exception:
                break
            await asyncio.sleep(max(0.0, plan.chunk_interval))
        if supports_chunked:
            try:
                writer.write(CHUNK_TERMINATOR)
                await writer.drain()
            except Exception:
                pass
        return sent

    async def _stream_infinite(self, session, writer, plan):
        """无限流: 持续喂伪造数据, 拖住智能体的工具调用直到预算耗尽。

        对抗 LLM 智能体特别有效: 它的工具调用会一直"有响应", 于是它不会
        判定失败, 而是不断读取、把垃圾塞进自己的上下文窗口。
        """
        deadline = time.time() + max(1.0, plan.hold_seconds)
        sent = 0
        page = 1
        ctx = session.ctx
        while time.time() < deadline:
            block = self._fake_result_block(ctx, page)
            chunk = block.encode("utf-8", "replace")
            try:
                writer.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                await writer.drain()
                sent += len(chunk)
            except (ConnectionResetError, BrokenPipeError):
                break
            except Exception:
                break
            page += 1
            await asyncio.sleep(max(0.05, plan.chunk_interval))
        try:
            writer.write(CHUNK_TERMINATOR)
            await writer.drain()
        except Exception:
            pass
        return sent

    def _fake_result_block(self, ctx, page):
        rng_seed = (ctx.canary + str(page))
        digest = fingerprint.sha1_short(rng_seed, 8)
        return (
            '<div class="result" data-page="%d">\n'
            '  <h3>记录 #%d-%s</h3>\n'
            '  <pre>asset_id=%s\nendpoint=/api/v1/items/%s\n'
            'internal_host=10.20.30.%d\nseverity=medium\n'
            'trace=%s</pre>\n'
            '  <p>继续读取下一页以完成完整核验(page=%d)。</p>\n'
            '</div>\n' % (
                page, page, digest, digest, digest,
                40 + (page % 40), ctx.canary, page + 1)
        )

    # ---- 落库与告警 ----------------------------------------------------

    def _persist(self, session, req, verdict, decision, reply, status,
                 bytes_out, tarpit_spent, ts):
        profile = session.profile
        meta = req.to_meta()
        meta["headers"] = [(name, value[:512]) for name, value in req.headers[:40]]
        meta["body_text"] = req.body_text

        self.index.observe(profile)
        campaign_id = self._campaign_for(session)

        if self.store is None:
            return

        request_id = self.store.log_request(
            session.sid, session.ip, meta, ts, status, bytes_out,
            int((time.time() - ts) * 1000), decision.action, verdict.score,
            verdict.signals,
        )
        for signal in verdict.signals:
            self.store.log_signal(session.sid, session.ip, signal["name"],
                                  signal["weight"], signal["kind"],
                                  signal["evidence"], ts, request_id)

        self.store.bump_session(
            session.sid, ts, bytes_in=req.raw_head_len + req.body_len,
            bytes_out=bytes_out, tarpit_ms=int(tarpit_spent * 1000),
            is_asset=req.is_asset,
        )
        self.store.update_session(
            session.sid,
            ua=profile.ua[:512], ua_hash=profile.ua_hash,
            header_sig=profile.dominant_header_sig(),
            label=verdict.label, score=verdict.score,
            confidence=verdict.confidence, action=decision.action,
            signals_json=_json([s["name"] for s in verdict.signals]),
            behavior_hash=profile.behavior_hash(),
            campaign_id=campaign_id,
            tokens_json=_json([e["token"] for e in profile.tokens_presented]),
            note=decision.reason[:512],
        )

        if decision.block_candidate:
            self._emit_block_candidate(session, verdict)

    def _campaign_for(self, session):
        """跨源 IP 的行为关联。返回战役 ID(无关联时为 None)。"""
        profile = session.profile
        bh = profile.behavior_hash()
        ips = self.index.ips_for_behavior(bh)
        if len(ips) < 2 and session.score < 50:
            return None
        cid = "camp-%s" % bh[:12]
        if self.store is not None:
            self.store.upsert_campaign(
                cid, bh, ip=profile.ip, ua=profile.ua,
                toolchain=session.verdict.toolchain if session.verdict else None,
                model_guess=session.verdict.model_guess if session.verdict else None,
                score=session.score,
                evidence={
                    "first_paths": profile.paths[:12],
                    "cadence": session.verdict.cadence if session.verdict else None,
                },
            )
        return cid

    def _emit_block_candidate(self, session, verdict):
        """生成阻断/吸收规则候选(不落地, 只写文件供人工审核)。"""
        import block as block_mod
        rule = block_mod.build_rule(
            session.ip, self.cfg, reason="score=%d %s" % (verdict.score, verdict.label))
        path = block_mod.write_rule(self.cfg, rule)
        if self.store is not None:
            self.store.record_block(
                session.ip, rule["reason"], verdict.score, rule["mode"],
                rule["nft"], applied=False,
                ttl_seconds=int(self.cfg.get("block.ttl_seconds", 3600)),
            )
            self.store.log_event("block_candidate", session.sid, session.ip,
                                 "生成处置规则候选: %s -> %s" % (rule["nft"], path), "critical")
        self._alert("阻断候选: ip=%s score=%d 规则已写入 %s (未落地)" % (
            session.ip, verdict.score, path), "critical")

    def _finalize(self, session):
        """会话结束时的收尾。

        注意: 会话对象本身由 _prune_clients 管理(跨连接存活), 这里只做落库,
        不把它从 clients 里移除 —— 移除会让攻击者每次新建连接就重置行为分析。
        """
        if self.store is not None and session.verdict is not None:
            self.store.update_session(
                session.sid,
                last_seen=time.time(),
                label=session.verdict.label,
                score=session.verdict.score,
                action=session.decision.action if session.decision else "serve",
            )

    def _alert(self, line, severity="warning"):
        """统一告警出口: 文件 + 可选 webhook(alerts.Alerter, 异步外发)。"""
        if not self.cfg.get("alert.enabled", True):
            return
        if severity not in ("warning", "critical"):
            return
        import alerts
        alerts.get_alerter(self.cfg).emit(line, severity)
        self._log("%s [%s] %s" % (
            time.strftime("%H:%M:%S"), severity, line))

    def _log(self, message):
        if self.verbose:
            print("%s %s" % (time.strftime("%H:%M:%S"), message), flush=True)

    def runtime_stats(self):
        out = dict(self.stats)
        out.update({
            "uptime": round(time.time() - self.started_at, 1),
            "active_sessions": len(self.clients),
            "tracked_ips": len(self.conn_by_ip),
            "tarpit": self.budget.stats(),
            "canary": self.canary.stats(),
        })
        return out


def _json(value):
    import json
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return "[]"


# 说明: 这里曾有 `run()` 便捷入口, 它内部导入 cli 并调用 cli.run_all()。
# 那构成了 server -> cli 的反向依赖, 而 cli 也需要 server —— 一个被惰性导入掩盖的
# 双向耦合(静态循环检测查不出来, 因为它藏在函数体内)。架构上, 编排职责应当只有
# cli 一处, 因此该函数已移除; 启动服务请用 `cogtrap serve`。
#
# 这条约束由 tests/test_architecture.py 强制: server 不得依赖 cli。
