"""多节点聚合测试: 导出/导入、跨实例战役合并、hub 鉴权与推送闭环。"""

import json
import os
import threading
import time
import urllib.request

import config as config_mod
import hub as hub_mod
import store as store_mod


def make_store(path=":memory:"):
    return store_mod.Store(path)


def seed_instance(store, sid, ip, behavior_hash, campaign_id=None):
    """造一个会话 + 若干事件, 模拟一个蜜罐实例的本地遥测。"""
    store.start_session(sid, ip, 40000, "python-httpx", "ua-%s" % sid,
                        "sig-%s" % sid, behavior_hash)
    store.update_session(sid, score=95, label="llm_agent",
                         campaign_id=campaign_id)
    if campaign_id:
        # 会话的 campaign_id 只是外键引用; 战役行本身必须 upsert,
        # 否则导出包里没有 campaigns 数据(测试曾因此误报"推送失败")
        store.upsert_campaign(campaign_id, behavior_hash, ip=ip,
                              ua="python-httpx", score=95)
    store.log_event("canary_echo", sid, ip, "令牌回显", "critical")
    store.log_signal(sid, ip, "canary_echo", 45, "decisive", "e")
    return store


# --------------------------------------------------------------------------
# 导出 / 导入
# --------------------------------------------------------------------------

def test_export_since_returns_only_new_rows():
    store = make_store()
    store.start_session("old", "203.0.113.1", 1, "u", "h", "s")
    store.log_event("canary_echo", "old", "203.0.113.1", "旧事件", "critical")
    cutoff = time.time()
    time.sleep(0.05)
    store.log_event("beacon_callback", "old", "203.0.113.1", "新事件", "critical")

    bundle = store.export_since(cutoff)
    events = [e for e in bundle["events"] if e["detail"] == "新事件"]
    old = [e for e in bundle["events"] if e["detail"] == "旧事件"]
    assert events and not old, "水位线增量导出失效"
    assert bundle["_meta"]["schema"] == 1
    store.close()


def test_import_is_idempotent():
    """重复导入同一份包不产生重复行 —— 推送重试因此无害。"""
    source = make_store()
    seed_instance(source, "s1", "203.0.113.1", "bh-1")
    bundle = source.export_since(0)

    central = make_store()
    first = central.import_records(bundle)
    again = central.import_records(bundle)
    assert first[0] > 0
    assert again[0] == 0, "重复导入产生了新行: %s" % (again,)
    assert central.stats()["sessions"] == 1
    source.close(); central.close()


def test_campaigns_merge_across_instances():
    """两个实例的同一行为指纹 → hub 上并成一个战役(IP 取并集)。

    这是多节点聚合的核心价值: 攻击者换源 IP 打不同诱饵, 每个实例只看到
    局部; 而 behavior_hash 不依赖 IP 与实例, hub 合并后自动还原全貌。
    """
    inst_a = make_store(); inst_b = make_store()
    inst_a.upsert_campaign("camp-shared", "bh-x", ip="203.0.113.1",
                           ua="python-httpx", score=90)
    inst_a.log_event("canary_echo", "a", "203.0.113.1", "A 实例证据", "critical")
    inst_b.upsert_campaign("camp-shared", "bh-x", ip="198.51.100.7",
                           ua="python-httpx", score=95)
    inst_b.log_event("canary_echo", "b", "198.51.100.7", "B 实例证据", "critical")

    central = make_store()
    central.import_records(inst_a.export_since(0))
    central.import_records(inst_b.export_since(0))

    campaigns = central.campaigns()
    assert len(campaigns) == 1, "跨实例战役未合并: %s 个" % len(campaigns)
    merged = campaigns[0]
    ips = json.loads(merged["ips_json"])
    assert set(ips) == {"203.0.113.1", "198.51.100.7"}, "IP 未取并集: %s" % ips
    assert merged["score_max"] == 95
    inst_a.close(); inst_b.close(); central.close()


# --------------------------------------------------------------------------
# hub 服务与鉴权
# --------------------------------------------------------------------------

def make_hub_config(tmpdir, token=""):
    data = config_mod.Config.load().as_dict()
    data["hub"] = {"token": token, "host": "127.0.0.1", "port": 0,
                   "db": os.path.join(tmpdir, "hub.db")}
    data["alert"]["log_path"] = os.path.join(tmpdir, "a.log")
    return config_mod.Config(data, root=tmpdir)


def start_hub(tmpdir, token=""):
    import asyncio
    cfg = make_hub_config(tmpdir, token)
    store = store_mod.Store(os.path.join(tmpdir, "hub.db"))
    node = hub_mod.Hub(cfg, store=store, token=token, verbose=False)
    loop = asyncio.new_event_loop()

    def serve():
        asyncio.set_event_loop(loop)
        bound = loop.run_until_complete(node.start())
        node._bound = bound
        loop.run_forever()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    for _ in range(100):
        if getattr(node, "_bound", None):
            break
        time.sleep(0.02)
    return node, store, loop


def stop_hub(node, store, loop):
    loop.call_soon_threadsafe(loop.stop)
    time.sleep(0.15)
    loop.run_until_complete(node.close())
    loop.close()
    store.close()


def post(url, body, token=None, gzip_body=False):
    import gzip as gz
    data = json.dumps(body, ensure_ascii=False, default=str).encode()
    headers = {"Content-Type": "application/json"}
    if gzip_body:
        data = gz.compress(data)
        headers["Content-Encoding"] = "gzip"
    if token is not None:
        headers["X-Hub-Token"] = token
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def test_hub_ingest_with_token_auth():
    import shutil
    tmpdir = "/tmp/test-hub-auth"
    shutil.rmtree(tmpdir, ignore_errors=True)   # 跨运行残留会让计数断言失真
    os.makedirs(tmpdir, exist_ok=True)
    node, store, loop = start_hub(tmpdir, token="secret-1")
    try:
        base = "http://127.0.0.1:%d" % node._bound[1]
        good = {"_meta": {"schema": 1}, "sessions": [], "events": [
            {"ts": time.time(), "kind": "canary_echo", "session_id": "x",
             "ip": "203.0.113.9", "detail": "d", "severity": "critical"}]}

        status, _ = post(base + "/ingest", good, token="wrong")
        assert status == 401, "错误 token 应被拒, 实际 %s" % status

        status, body = post(base + "/ingest", good, token="secret-1")
        assert status == 200 and body["ok"], "正确 token 的推送被拒: %s" % body
        assert store.stats()["events"] == 1

        # gzip 推送同样有效(实例侧默认走 gzip)
        status, body = post(base + "/ingest", good, token="secret-1",
                            gzip_body=True)
        assert status == 200 and body["ok"]

        request = urllib.request.Request(base + "/stats",
                                         headers={"X-Hub-Token": "secret-1"})
        with urllib.request.urlopen(request, timeout=10) as response:
            stats = json.loads(response.read().decode())
        assert stats["hub"]["ingests"] >= 2
        # 查询接口同样要求 token
        try:
            urllib.request.urlopen(base + "/stats", timeout=10)
            raise AssertionError("无 token 的 /stats 不应放行")
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
    finally:
        stop_hub(node, store, loop)


def test_hub_rejects_malformed_bundle():
    tmpdir = "/tmp/test-hub-bad"; os.makedirs(tmpdir, exist_ok=True)
    node, store, loop = start_hub(tmpdir, token="")
    try:
        base = "http://127.0.0.1:%d" % node._bound[1]
        status, body = post(base + "/ingest", {"schema": 99})
        assert status == 400, "非法 schema 应被拒, 实际 %s" % status
    finally:
        stop_hub(node, store, loop)


# --------------------------------------------------------------------------
# 实例侧推送闭环(push)
# --------------------------------------------------------------------------

def test_push_roundtrip_advances_watermark_only_on_success():
    """成功才推进水位线; hub 不可达时水位线不动, 数据不丢。"""
    import shutil
    tmpdir = "/tmp/test-hub-push"
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.makedirs(tmpdir)

    # 实例侧: 独立目录 + 独立遥测库
    data = config_mod.Config.load().as_dict()
    data["store"]["path"] = os.path.join(tmpdir, "var/telemetry.db")
    data["alert"]["log_path"] = os.path.join(tmpdir, "a.log")
    instance_cfg = config_mod.Config(data, root=tmpdir)
    instance_cfg.ensure_dirs()

    instance = store_mod.Store(instance_cfg.store_path())
    seed_instance(instance, "push-1", "203.0.113.5", "bh-push",
                  campaign_id="camp-push")
    instance.close()

    watermark = os.path.join(tmpdir, "var/.push-watermark")

    # 1) hub 未启动 → 失败, 水位线不动
    inst_store = store_mod.Store(instance_cfg.store_path())
    ok_flag, _ = hub_mod.push_bundle(instance_cfg, "http://127.0.0.1:1",
                                     "t", inst_store, watermark_path=watermark)
    inst_store.close()
    assert not ok_flag
    assert not os.path.exists(watermark), "失败时不应推进水位线"

    # 2) 启动 hub → 推送成功, 水位线推进
    node, store, loop = start_hub(os.path.join(tmpdir, "hub"), token="t")
    try:
        base = "http://127.0.0.1:%d" % node._bound[1]
        inst_store = store_mod.Store(instance_cfg.store_path())
        ok_flag, message = hub_mod.push_bundle(instance_cfg, base, "t",
                                               inst_store,
                                               watermark_path=watermark)
        inst_store.close()
        assert ok_flag, "推送失败: %s" % message
        assert os.path.exists(watermark)

        campaigns = store.campaigns()
        assert any(c["id"] == "camp-push" for c in campaigns), \
            "推送后 hub 未见实例战役"

        # 3) 再次推送必须安全: 要么"无新数据", 要么幂等重推(水位线回退 1 秒
        #    容差会带上边界旧行, 由 INSERT OR IGNORE 跳过 —— 两种都正确)
        inst_store = store_mod.Store(instance_cfg.store_path())
        ok_flag, message = hub_mod.push_bundle(instance_cfg, base, "t",
                                               inst_store,
                                               watermark_path=watermark)
        inst_store.close()
        assert ok_flag, "重复推送不应失败: %s" % message
        assert ("无新数据" in message) or ("skipped" in message), message
    finally:
        stop_hub(node, store, loop)
