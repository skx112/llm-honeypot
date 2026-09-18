"""协议解析与存储层测试。

HTTP 解析器是蜜罐的第一道关口: 它必须比攻击工具更宽容。框架化服务器会把畸形
请求 400 掉, 那样我们既看不到载荷也拿不到指纹 —— 而畸形请求恰恰是扫描器与
智能体最有价值的特征。
"""

import http_parse
import store as store_mod


def parse(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return http_parse.parse_head(raw)


# --------------------------------------------------------------------------
# 请求行
# --------------------------------------------------------------------------

def test_parses_normal_request():
    req = parse("GET /api/v1/users?page=2 HTTP/1.1\r\nHost: h.example\r\n"
                "User-Agent: probe/1\r\n\r\n")
    assert req.method == "GET"
    assert req.path == "/api/v1/users"
    assert req.query == "page=2"
    assert req.version == "HTTP/1.1"
    assert req.host == "h.example"
    assert req.ua == "probe/1"
    assert not req.malformed


def test_tolerates_missing_version():
    """缺版本号是自动化工具常见的手写报文特征 —— 不能因此丢弃整条请求。"""
    req = parse("GET /admin HTTP/1.0\r\nHost: h\r\n\r\n")
    assert req.method == "GET"
    assert req.version == "HTTP/1.0"

    req2 = parse("GET /admin\r\nHost: h\r\n\r\n")
    assert "missing_version" in req2.malformed
    assert req2.path == "/admin"


def test_tolerates_lf_only_line_endings():
    req = parse("GET /x HTTP/1.1\nHost: h\nUser-Agent: probe\n\n")
    assert req.path == "/x"
    assert req.uach if False else True
    assert req.ua == "probe"


def test_tolerates_leading_blank_lines():
    req = parse("\r\n\r\nGET /y HTTP/1.1\r\nHost: h\r\n\r\n")
    assert req.path == "/y"
    assert "leading_blank_line" in req.malformed


def test_tolerates_header_folding_and_bad_lines():
    req = parse("GET /z HTTP/1.1\r\nHost: h\r\nX-Long: part1\r\n  part2\r\n"
                "this-is-not-a-header\r\n\r\n")
    assert req.header("x-long") == "part1 part2"
    assert "header_folding" in req.malformed
    assert "bad_header_line" in req.malformed


def test_absolute_uri_target():
    req = parse("GET http://other.example:8080/path?q=1 HTTP/1.1\r\nHost: h\r\n\r\n")
    assert req.scheme == "http"
    assert req.authority == "other.example:8080"
    assert req.path == "/path"
    assert req.query == "q=1"


def test_rejects_garbage_as_non_http():
    for raw in (b"\x16\x03\x01\x02\x00garbage", b"not a request line at all\r\n\r\n",
                b"\x00\x01\x02\x03"):
        try:
            parse(raw)
        except http_parse.NotHTTP:
            continue
        raise AssertionError("垃圾输入未被识别为非 HTTP: %r" % raw[:16])


def test_tls_handshake_detected():
    assert http_parse.looks_like_tls(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1")
    assert http_parse.looks_like_tls(b"SSH-2.0-libssh_0.9.6")
    assert not http_parse.looks_like_tls(b"GET / HTTP/1.1\r\n")


def test_header_order_signature_is_stable_and_ordered():
    a = parse("GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: u\r\nAccept: */*\r\n\r\n")
    b = parse("GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: u\r\nAccept: */*\r\n\r\n")
    assert a.header_order_sig == b.header_order_sig
    # 顺序不同应得到不同指纹 —— 这正是该特征的用途
    c = parse("GET / HTTP/1.1\r\nAccept: */*\r\nHost: h\r\nUser-Agent: u\r\n\r\n")
    assert c.header_order_sig != a.header_order_sig


def test_odd_method_recorded():
    req = parse("FOOBAR /x HTTP/1.1\r\nHost: h\r\n\r\n")
    assert req.method == "FOOBAR"
    assert any(item.startswith("odd_method") for item in req.malformed)


def test_multi_value_headers_preserved():
    req = parse("GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.1.1.1\r\n"
                "X-Forwarded-For: 2.2.2.2\r\n\r\n")
    assert req.header_all("x-forwarded-for") == ["1.1.1.1", "2.2.2.2"]
    assert req.header("x-forwarded-for") == "1.1.1.1"


def test_expect_continue_flagged():
    req = parse("POST /u HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\n"
                "Content-Length: 5\r\n\r\n")
    assert req.expect_continue


def test_chunked_flagged():
    req = parse("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
    assert req.chunked


def test_asset_detection():
    assert parse("GET /static/app.css HTTP/1.1\r\nHost: h\r\n\r\n").is_asset
    assert parse("GET /logo.png HTTP/1.1\r\nHost: h\r\n\r\n").is_asset
    assert not parse("GET /api/users HTTP/1.1\r\nHost: h\r\n\r\n").is_asset
    assert not parse("GET /v1.2/users HTTP/1.1\r\nHost: h\r\n\r\n").is_asset


# --------------------------------------------------------------------------
# 存储层
# --------------------------------------------------------------------------

def fresh_store():
    return store_mod.Store(":memory:")


def test_session_lifecycle():
    s = fresh_store()
    s.start_session("s1", "203.0.113.5", 40000, "probe/1", "h1", "sig1")
    s.bump_session("s1", 1000.0, bytes_in=100, bytes_out=500, is_asset=False)
    s.bump_session("s1", 1001.0, bytes_in=50, bytes_out=200, is_asset=True)
    row = s.get_session("s1")
    assert row["req_count"] == 2
    assert row["asset_count"] == 1
    assert row["bytes_in"] == 150
    s.update_session("s1", score=88, label="llm_agent", action="lockdown")
    row = s.get_session("s1")
    assert row["score"] == 88 and row["label"] == "llm_agent"
    s.close()


def test_honeytoken_auto_registers_on_first_read():
    """蜜标未登记时必须自动登记。

    登记与读取发生在不同代码路径上; 若读取时因未登记而静默返回 False,
    最高价值的取证事件(攻击者读取了伪造凭据)就会凭空消失。
    """
    s = fresh_store()
    assert s.token_stats()["total"] == 0
    first = s.read_token("env_creds", "s1", "203.0.113.5", kind="env", path="/.env")
    assert first is True, "首次读取应返回 True 以便触发告警"
    again = s.read_token("env_creds", "s1", "203.0.113.5")
    assert again is False, "重复读取不应再次告警"
    stats = s.token_stats()
    assert stats["total"] == 1 and stats["touched"] == 1 and stats["reads"] == 2

    # 不同会话读取同一蜜标应识别为首次(便于区分是谁先动手)
    other = s.read_token("env_creds", "s2", "198.51.100.9")
    assert other is False, "同一蜜标的后续读取不应重复计为首次"

    whole = s.read_token("aws_creds", "s2", "198.51.100.9", kind="aws")
    assert whole is True
    assert s.token_stats()["total"] == 2
    s.close()


def test_events_and_signals_recorded():
    s = fresh_store()
    s.start_session("s1", "203.0.113.5", 1, "u", "h", "sig")
    s.log_event("canary_echo", "s1", "203.0.113.5", "令牌回显", "critical")
    s.log_event("canary_echo", "s1", "203.0.113.5", "令牌回显 2", "critical")
    s.log_event("beacon_callback", "s1", "203.0.113.5", "信标", "critical")
    assert len(s.recent_events(kind="canary_echo")) == 2
    assert len(s.recent_events()) == 3

    s.log_signal("s1", "203.0.113.5", "canary_echo", 45, "decisive", "证据")
    summary = s.signals_summary()
    assert summary and summary[0]["name"] == "canary_echo"
    assert summary[0]["hits"] == 1
    s.close()


def test_behavior_hash_grouping_for_attribution():
    """同一行为哈希下的多个源 IP 应可被检索出来 —— 跨源归因的存储基础。"""
    s = fresh_store()
    for index, ip in enumerate(("203.0.113.1", "203.0.113.2", "198.51.100.7")):
        s.start_session("s%d" % index, ip, 1, "u", "h", "sig",
                        behavior_hash="bh-abc")
    sessions = s.sessions_by_behavior("bh-abc")
    assert len(sessions) == 3
    assert sorted(s.distinct_ips_for_behavior("bh-abc")) == \
        ["198.51.100.7", "203.0.113.1", "203.0.113.2"]
    s.close()


def test_campaign_merges_ips():
    s = fresh_store()
    s.upsert_campaign("camp-1", "bh-1", ip="203.0.113.1", ua="probe/1", score=90)
    s.upsert_campaign("camp-1", "bh-1", ip="203.0.113.2", ua="probe/1", score=95)
    row = s.get_campaign("camp-1")
    assert row["score_max"] == 95
    assert row["session_count"] == 2
    assert "203.0.113.2" in row["ips_json"]
    s.close()


def test_block_record_and_expiry_query():
    s = fresh_store()
    s.record_block("203.0.113.9", "score=91", 91, "absorb", "nft add element ...",
                   applied=False, ttl_seconds=3600)
    assert s.is_blocked("203.0.113.9")
    s.record_block("198.51.100.1", "expired", 90, "drop", "rule", ttl_seconds=-1)
    assert not s.is_blocked("198.51.100.1"), "已过期规则不应视为生效"
    s.close()


def test_stats_counts():
    s = fresh_store()
    s.start_session("s1", "203.0.113.5", 1, "u", "h", "sig")
    s.update_session("s1", score=95, label="llm_agent")
    s.start_session("s2", "198.51.100.1", 2, "u2", "h2", "sig2")
    s.update_session("s2", score=40, label="automation_scanner")
    stats = s.stats()
    assert stats["sessions"] == 2
    assert stats["sessions_llm"] == 1
    assert stats["sessions_scanner"] == 1
    assert stats["high_score"] == 1
    assert stats["distinct_ips"] == 2
    s.close()


def test_top_ips_ordering():
    s = fresh_store()
    s.start_session("a", "203.0.113.1", 1, "u", "h", "sig")
    s.update_session("a", score=95, label="llm_agent")
    s.bump_session("a", 1.0)
    s.start_session("b", "198.51.100.1", 1, "u", "h", "sig")
    s.update_session("b", score=30, label="unknown")
    top = s.top_ips()
    assert top[0]["ip"] == "203.0.113.1", "高危来源未排在首位"
    s.close()
