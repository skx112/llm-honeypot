"""多节点聚合 hub: 接收各蜜罐实例推送的遥测, 合并为统一视图。

## 定位

单实例蜜罐各自为战时, 攻击者换源 IP 打不同诱饵, 每个实例只看到局部。
hub 把各实例的增量遥测合并进一个中心库 —— 因为**战役按 behavior_hash
聚合**(不依赖 IP 与实例), 多实例的同一操作者在 hub 上自动并成一个战役,
跨实例归因因此"免费"获得, 不需要新表或新协议。

## 信任与边界

  · hub **只在己方内网**运行, 实例经出站白名单(在 isolate.sh 里为 hub 地址
    单独放行)向它推送 —— 这不违反"蜜罐不外连"原则: hub 是己方设施。
  · 鉴权: 实例与 hub 共享 token(配置生成时随机), 无 token 的推送被拒。
  · hub 自身不监听公网; 它的 /api 仅供内网运维查询。

## 传输

    POST /ingest  (header: X-Hub-Token)
    Body: export_since() 的 JSON(可 gzip, Content-Encoding 标明)

    GET  /stats            -> {"sessions": N, "campaigns": N, ...}
    GET  /api/campaigns    -> 战役列表(含跨实例 IP 并集)

## 用法

    hub 侧:  cogtrap hub --db var/hub.db --token <随机串> --port 9443
    实例侧:  cogtrap push --hub http://hub内网:9443 --token <同一串>

    (cron 示例: */2 * * * * cogtrap push --hub ... --token ... )
"""

import gzip
import json
import os
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Hub(object):
    """聚合节点。生命周期与 dashboard 一致: start()/close() 协程。"""

    def __init__(self, config, store=None, token=None, verbose=True):
        self.cfg = config
        self.store = store
        self.token = token or config.get("hub.token", "")
        self.verbose = verbose
        self.host = config.get("hub.host", "127.0.0.1")
        self.port = int(config.get("hub.port", 9443))
        self.db_path = config.get("hub.db", "var/hub.db")
        self.started_at = time.time()
        self.stats = {"ingests": 0, "rows_imported": 0, "rows_skipped": 0,
                      "rejected": 0}
        self._lock = threading.Lock()
        self._httpd = None

    async def start(self, store=None):
        """启动监听。store 由调用方注入(与 dashboard 同一模式) —— 本模块
        刻意不依赖 store, 保持 L0 自足; store 生命周期归调用方。"""
        if self.store is None:
            self.store = store
        if self.store is None:
            raise RuntimeError("Hub 需要 store: Hub(config, store=...) 或 start(store=...)")
        handler = _make_handler(self)
        self._httpd = _ThreadingHTTPServer((self.host, self.port), handler)
        thread = threading.Thread(target=self._httpd.serve_forever,
                                  kwargs={"poll_interval": 0.5})
        thread.daemon = True
        thread.start()
        return self._httpd.server_address

    async def close(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    # ---- 数据面 --------------------------------------------------------

    def ingest(self, bundle):
        """校验并导入一份推送。返回 (ok, message, counts)。"""
        meta = (bundle.get("_meta") or {}) if isinstance(bundle, dict) else {}
        if not isinstance(bundle, dict) or meta.get("schema") != 1:
            return False, "载荷不是合法的导出包(schema!=1)", None
        imported, skipped = self.store.import_records(bundle)
        with self._lock:
            self.stats["ingests"] += 1
            self.stats["rows_imported"] += imported
            self.stats["rows_skipped"] += skipped
        return True, "imported=%d skipped=%d" % (imported, skipped), (imported, skipped)

    def summary(self):
        data = {"uptime": round(time.time() - self.started_at, 1),
                "hub": dict(self.stats)}
        try:
            data["store"] = self.store.stats()
        except Exception:
            pass
        return data

    def campaigns_payload(self):
        rows = self.store.campaigns(limit=100)
        out = []
        for row in rows:
            try:
                ips = json.loads(row["ips_json"] or "[]")
            except ValueError:
                ips = []
            out.append({
                "id": row["id"], "ips": ips,
                "behavior_hash": row["behavior_hash"],
                "score_max": row["score_max"], "session_count": row["session_count"],
                "toolchain": row["toolchain"], "model_guess": row["model_guess"],
                "last_seen": row["last_seen"],
            })
        return {"campaigns": out}


def _make_handler(hub):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CogTrap-Hub/1.0"

        def log_message(self, fmt, *args):
            if hub.verbose:
                print("[hub] " + (fmt % args), flush=True)

        # ---- 鉴权 ----

        def _authorized(self):
            if not hub.token:
                return True                 # 显式空 token = 内网无鉴权(不推荐)
            supplied = self.headers.get("X-Hub-Token", "")
            # 常数时间比较, 避免时序侧信道
            import hmac
            return hmac.compare_digest(supplied.encode(), hub.token.encode())

        # ---- 路由 ----

        def do_POST(self):
            if self.path != "/ingest":
                return self._send(404, {"error": "unknown endpoint"})
            if not self._authorized():
                with hub._lock:
                    hub.stats["rejected"] += 1
                return self._send(401, {"error": "bad or missing X-Hub-Token"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(min(length, 64 * 1024 * 1024))
                if self.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                bundle = json.loads(raw.decode("utf-8", "replace"))
            except (ValueError, OSError) as exc:
                return self._send(400, {"error": "bad payload: %s" % exc})
            ok, message, _counts = hub.ingest(bundle)
            return self._send(200 if ok else 400,
                              {"ok": ok, "message": message})

        def do_GET(self):
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            if self.path == "/stats":
                return self._send(200, hub.summary())
            if self.path == "/api/campaigns":
                return self._send(200, hub.campaigns_payload())
            return self._send(404, {"error": "unknown endpoint"})

        def _send(self, status, payload):
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return Handler


# --------------------------------------------------------------------------
# 实例侧推送(push)
# --------------------------------------------------------------------------

def push_bundle(config, hub_url, token, store, watermark_path=None,
                timeout=30.0, gzip_body=True):
    """把实例自上次水位线以来的新遥测推送给 hub。

    store 由调用方传入并持有(本模块不依赖 store —— L0 自足)。
    成功才推进水位线 —— 失败时下轮重推(幂等导入, 重复无害)。
    返回 (ok, message)。
    """
    import urllib.error
    import urllib.request

    watermark_path = watermark_path or config.path("var/.push-watermark")
    since = 0.0
    if os.path.exists(watermark_path):
        try:
            since = float(open(watermark_path).read().strip() or 0)
        except (ValueError, IOError):
            since = 0.0

    bundle = store.export_since(since)
    total = sum(len(bundle.get(t) or []) for t in store._EXPORT_TABLES)

    if total == 0 and since > 0:
        return True, "无新数据"

    body = json.dumps(bundle, ensure_ascii=False, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "X-Hub-Token": token or ""}
    if gzip_body:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"

    request = urllib.request.Request(hub_url.rstrip("/") + "/ingest",
                                     data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return False, "hub 拒绝(HTTP %d): %s" % (exc.code, exc.read()[:200])
    except Exception as exc:
        return False, "推送失败: %r" % exc

    if not result.get("ok"):
        return False, "hub 报告失败: %s" % result.get("message")

    # 成功才推进水位线(留 1 秒重叠, 容忍时钟边界)
    now = time.time() - 1.0
    directory = os.path.dirname(watermark_path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(watermark_path, "w") as handle:
        handle.write(str(now))
    return True, "%s (%d 行)" % (result.get("message"), total)
