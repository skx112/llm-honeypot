"""本地仪表盘: 值守界面(仅监听回环地址)。

## 为什么是"设计系统"而不只是"一个页面"

护网期间这个界面会被值班人员**盯着看几天**, 所以它不是调试输出, 而是产品的主界面。
因此这里刻意做了三件事:

  1. **视觉语言与判定语义绑定**: 五个处置档(观察/拖滞/注入/锁定)各有固定色彩,
     值班人员扫一眼颜色就知道严重程度, 不需要读文字。
  2. **确证证据置于最显眼位置**: 金丝雀回显、指令服从、攻击方配置泄漏、蜜标读取、
     信标回调 —— 这五类是本系统最有价值的产出(上报材料主体), 因此单独成区并置顶。
  3. **零依赖实现**: 图表用手写 SVG, 样式与脚本是独立静态文件, 不引入任何 CDN
     或构建步骤 —— 诱饵环境常常是隔离网络, 页面必须能离线打开。

## 安全约束

只监听 127.0.0.1(配置项 `dashboard.host` 默认如此)。遥测库里含攻击者 IP、捕获的
凭据与配置, 把它暴露到网络上等于给攻击方开了一扇窗。需要远程查看时请走 SSH 隧道:

    ssh -L 8899:127.0.0.1:8899 user@honeypot-host
"""

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}

# 处置档 -> 语义色键(前端据此着色, 与设计系统一致)
ACTION_ORDER = ("serve", "serve_watch", "tarpit", "deceive_inject", "lockdown")

EVIDENCE_KINDS = {
    "canary_echo": "金丝雀回显",
    "injection_compliance": "指令服从",
    "agent_config_captured": "攻击方配置泄漏",
    "honeytoken_read": "蜜标读取",
    "beacon_callback": "信标回调",
    "attacker_fingerprint": "攻击者指纹",
    "mcp_manifest_fetch": "MCP 清单拉取",
}


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Python 3.6 没有 ThreadingHTTPServer, 自行组合。"""
    daemon_threads = True
    allow_reuse_address = True


class Dashboard(object):
    def __init__(self, config, store=None, server=None, verbose=True):
        self.cfg = config
        self.store = store
        self.server = server            # HoneypotServer, 用于取运行时统计
        self.verbose = verbose
        self.host = config.get("dashboard.host", "127.0.0.1")
        self.port = int(config.get("dashboard.port", 8899))
        self._httpd = None
        self._thread = None
        self.started_at = time.time()

    # ---- 生命周期 ------------------------------------------------------

    async def start(self):
        handler = _make_handler(self)
        try:
            self._httpd = _ThreadingHTTPServer((self.host, self.port), handler)
        except OSError as exc:
            raise RuntimeError("仪表盘监听失败 %s:%s —— %s" % (self.host, self.port, exc))
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        kwargs={"poll_interval": 0.5})
        self._thread.daemon = True
        self._thread.start()
        return self._httpd.server_address

    async def close(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    # ---- 数据接口 ------------------------------------------------------

    # stats 段的完整键集, 与 store.stats() 的返回保持一致
    STATS_KEYS = ("sessions", "sessions_llm", "sessions_scanner", "requests",
                  "signals", "events", "campaigns", "high_score", "distinct_ips")

    # runtime 段的完整键集。即使没有 server 引用(独立使用仪表盘, 或服务启动失败),
    # 也必须把这些键以零值提供 —— 否则前端读到 undefined 会显示 NaN,
    # 而"NaN"与"0"在值守时是完全不同的信息。
    RUNTIME_KEYS = ("connections", "requests", "active_sessions", "alerts",
                    "tarpit_seconds", "non_http", "shed_events", "load_ratio",
                    "budget_used", "budget_total")

    def payload_summary(self):
        data = {
            "instance": self.cfg.get("instance", "honeypot"),
            "uptime": round(time.time() - self.started_at, 1),
            "actions": list(ACTION_ORDER),
            "evidence_kinds": EVIDENCE_KINDS,
            "runtime": dict((key, 0) for key in self.RUNTIME_KEYS),
            "stats": {},
            "tokens": {},
            "scenario": (self.cfg.get("honeypot_instance") or {}).get("scenario"),
            "template": (self.cfg.get("honeypot_instance") or {}).get("template"),
        }
        # stats 与 tokens 同样必须键集完整
        data["stats"] = dict((key, 0) for key in self.STATS_KEYS)
        data["tokens"] = {"total": 0, "touched": 0, "reads": 0}
        if self.server is not None:
            runtime = self.server.runtime_stats()
            data["runtime"].update({
                "connections": runtime.get("connections", 0),
                "requests": runtime.get("requests", 0),
                "active_sessions": runtime.get("active_sessions", 0),
                "alerts": runtime.get("alerts", 0),
                "tarpit_seconds": round(runtime.get("tarpit_seconds", 0.0), 1),
                "non_http": runtime.get("non_http", 0),
                "shed_events": runtime.get("tarpit", {}).get("shed_events", 0),
                "load_ratio": runtime.get("tarpit", {}).get("load_ratio", 0.0),
                "budget_used": runtime.get("tarpit", {}).get("window_seconds", 0.0),
                "budget_total": runtime.get("tarpit", {}).get("budget_per_min", 0),
            })
        if self.store is not None:
            data["stats"].update(self.store.stats())
            data["tokens"].update(self.store.token_stats())
        return data

    def payload_sessions(self, limit=60):
        if self.store is None:
            return {"sessions": []}
        rows = []
        for row in self.store.recent_sessions(limit=limit):
            rows.append({
                "id": row["id"],
                "ip": row["ip"],
                "ua": (row["ua"] or "")[:120],
                "label": row["label"],
                "score": row["score"] or 0,
                "action": row["action"] or "serve",
                "requests": row["req_count"] or 0,
                "tarpit_ms": row["tarpit_ms"] or 0,
                "behavior_hash": row["behavior_hash"] or "",
                "campaign": row["campaign_id"] or "",
                "last_seen": row["last_seen"],
                "first_seen": row["first_seen"],
                "confidence": row["confidence"] or 0,
                "note": (row["note"] or "")[:160],
            })
        return {"sessions": rows}

    def payload_signals(self, limit=24):
        if self.store is None:
            return {"signals": []}
        return {"signals": [
            {"name": s["name"], "weight": s["weight"], "hits": s["hits"],
             "sessions": s["sessions"]}
            for s in self.store.signals_summary(limit=limit)
        ]}

    def payload_evidence(self, limit=40):
        """确证证据 —— 上报材料的主体, 单独成区。"""
        if self.store is None:
            return {"evidence": [], "counts": {}}
        counts = {}
        evidence = []
        for kind in EVIDENCE_KINDS:
            rows = self.store.recent_events(limit=limit, kind=kind)
            counts[kind] = len(rows)
            for row in rows:
                evidence.append({
                    "kind": kind, "label": EVIDENCE_KINDS[kind],
                    "severity": row["severity"], "ts": row["ts"],
                    "ip": row["ip"], "session": row["session_id"],
                    "detail": (row["detail"] or "")[:400],
                })
        # 同一 kind 的计数需要独立的聚合(上面的 limit 会截断)
        for kind in EVIDENCE_KINDS:
            counts[kind] = self._count_events(kind)
        evidence.sort(key=lambda item: item["ts"] or 0, reverse=True)
        return {"evidence": evidence[:limit], "counts": counts}

    def _count_events(self, kind):
        rows = self.store.recent_events(limit=5000, kind=kind)
        return len(rows)

    def payload_campaigns(self, limit=20):
        if self.store is None:
            return {"campaigns": []}
        out = []
        for row in self.store.campaigns(limit=limit):
            try:
                ips = json.loads(row["ips_json"] or "[]")
            except ValueError:
                ips = []
            out.append({
                "id": row["id"], "ips": ips, "score_max": row["score_max"] or 0,
                "session_count": row["session_count"] or 0,
                "toolchain": row["toolchain"] or "",
                "model_guess": row["model_guess"] or "",
                "behavior_hash": row["behavior_hash"] or "",
                "last_seen": row["last_seen"],
            })
        return {"campaigns": out}

    def payload_alerts(self, limit=30):
        path = self.cfg.path(self.cfg.get("alert.log_path", "logs/alerts.log"))
        lines = []
        try:
            with open(path, "r") as handle:
                lines = handle.readlines()[-limit:]
        except IOError:
            pass
        return {"alerts": [line.rstrip() for line in reversed(lines)]}


def _make_handler(dashboard):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CogTrap-Dashboard"

        def log_message(self, fmt, *args):
            if dashboard.verbose:
                BaseHTTPRequestHandler.log_message(self, fmt, *args)

        # ---- 路由 ----

        def do_GET(self):
            path = urlparse(self.path).path
            if path.startswith("/api/"):
                return self._serve_api(path)
            return self._serve_static(path)

        def _serve_api(self, path):
            try:
                if path == "/api/summary":
                    payload = dashboard.payload_summary()
                elif path == "/api/sessions":
                    payload = dashboard.payload_sessions()
                elif path == "/api/signals":
                    payload = dashboard.payload_signals()
                elif path == "/api/evidence":
                    payload = dashboard.payload_evidence()
                elif path == "/api/campaigns":
                    payload = dashboard.payload_campaigns()
                elif path == "/api/alerts":
                    payload = dashboard.payload_alerts()
                else:
                    return self._send_json({"error": "unknown endpoint"}, 404)
            except Exception as exc:
                return self._send_json({"error": repr(exc)}, 500)
            return self._send_json(payload)

        def _serve_static(self, path):
            name = "index.html" if path in ("/", "") else path.lstrip("/")
            # 只允许 web/ 目录内的文件, 阻断路径穿越
            safe = os.path.normpath(os.path.join(WEB_DIR, name))
            if not safe.startswith(WEB_DIR + os.sep) and safe != WEB_DIR:
                return self._send_bytes(b"forbidden", "text/plain", 403)
            if not os.path.isfile(safe):
                return self._send_bytes(b"not found", "text/plain", 404)
            try:
                with open(safe, "rb") as handle:
                    body = handle.read()
            except IOError:
                return self._send_bytes(b"read error", "text/plain", 500)
            extension = os.path.splitext(safe)[1].lower()
            return self._send_bytes(body, CONTENT_TYPES.get(extension, "application/octet-stream"))

        # ---- 输出 ----

        def _send_json(self, payload, status=200):
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self._send_bytes(body, "application/json; charset=utf-8", status)

        def _send_bytes(self, body, content_type, status=200):
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                # 遥测数据不缓存, 避免值班界面看到过期状态
                self.send_header("Cache-Control", "no-store, must-revalidate")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler
