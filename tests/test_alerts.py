"""告警外发测试: 文件兼容性、webhook 投递、级别门控、失败容忍。"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import alerts
import config as config_mod


def make_config(tmpdir, webhook=""):
    data = config_mod.Config.load().as_dict()
    data["instance"] = "test-instance"
    data["alert"]["webhook_url"] = webhook
    data["alert"]["log_path"] = os.path.join(tmpdir, "alerts.log")
    return config_mod.Config(data, root=tmpdir)


def test_emit_without_webhook_matches_legacy_file_format():
    """无 webhook 时行为与旧实现一致: 只写文件, 格式不变(dashboard 依赖)。"""
    alerts.reset_for_tests()
    tmpdir = "/tmp/test-alerts-legacy"
    os.makedirs(tmpdir, exist_ok=True)
    log = os.path.join(tmpdir, "alerts.log")
    if os.path.exists(log):
        os.remove(log)

    alerter = alerts.Alerter(make_config(tmpdir))
    alerter.emit("金丝雀回显 token=hpx-1", "critical")
    alerter.close()

    content = open(log).read()
    assert "金丝雀回显 token=hpx-1" in content
    assert "[critical] [test-instance]" in content, "格式应保持 旧格式: %r" % content
    assert alerter.stats()["webhook_enabled"] is False


class _Receiver(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _Receiver.received.append(json.loads(body.decode("utf-8")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def start_receiver():
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d/hook" % server.server_address[1]


def test_webhook_delivers_payload_json():
    alerts.reset_for_tests()
    _Receiver.received = []
    server, url = start_receiver()
    try:
        tmpdir = "/tmp/test-alerts-hook"
        os.makedirs(tmpdir, exist_ok=True)
        cfg = make_config(tmpdir, webhook=url)
        alerter = alerts.Alerter(cfg)

        started = time.time()
        alerter.emit("确证: 指令服从 48 次", "critical")
        elapsed = time.time() - started
        assert elapsed < 0.5, "emit 必须立即返回(不阻塞蜜罐路径), 实际 %.2fs" % elapsed

        alerter.close()          # close 会 flush 队列
        assert len(_Receiver.received) >= 1
        payload = _Receiver.received[0]
        assert payload["schema"] == 1
        assert payload["instance"] == "test-instance"
        assert payload["severity"] == "critical"
        assert "指令服从" in payload["message"]
        assert payload["iso"].endswith("Z")
    finally:
        server.shutdown()


def test_severity_gating_filters_info():
    """默认 warning 起外发; info 只落文件。"""
    alerts.reset_for_tests()
    _Receiver.received = []
    server, url = start_receiver()
    try:
        tmpdir = "/tmp/test-alerts-gate"
        os.makedirs(tmpdir, exist_ok=True)
        alerter = alerts.Alerter(make_config(tmpdir, webhook=url))
        alerter.emit("仅提示", "info")
        alerter.emit("需要外发", "warning")
        alerter.close()
        severities = [p["severity"] for p in _Receiver.received]
        assert "info" not in severities
        assert "warning" in severities
    finally:
        server.shutdown()


def test_webhook_failure_never_raises_and_keeps_file():
    """对端不可达: emit 不抛异常, 文件照写, 失败被节流记录。"""
    alerts.reset_for_tests()
    tmpdir = "/tmp/test-alerts-dead"
    os.makedirs(tmpdir, exist_ok=True)
    # 端口 1 几乎必然拒绝连接
    cfg = make_config(tmpdir, webhook="http://127.0.0.1:1/hook")
    alerter = alerts.Alerter(cfg)
    try:
        alerter.emit("第一条", "critical")
        alerter.emit("第二条", "critical")
    except Exception as exc:
        raise AssertionError("emit 不应因 webhook 故障抛异常: %r" % exc)
    alerter.close()

    log = os.path.join(tmpdir, "alerts.log")
    content = open(log).read()
    assert "第一条" in content and "第二条" in content, "文件告警不能丢"
    assert alerter.stats()["delivery_failures"] >= 1


def test_singleton_shares_one_worker():
    """server 与 ssh_decoy 共用同一 Alerter(同队列同线程)。"""
    alerts.reset_for_tests()
    cfg = make_config("/tmp/test-alerts-single")
    a1 = alerts.get_alerter(cfg)
    a2 = alerts.get_alerter(cfg)
    assert a1 is a2
    a1.close()
    alerts.reset_for_tests()
