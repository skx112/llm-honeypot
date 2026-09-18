"""反制方式库与场景包测试。

重点验证:
  · 插件机制能拒绝坏条目并给出可行动的报错(使用者会犯错, 报错质量决定体验)
  · 层级门控生效(低分区不能投放露骨载荷)
  · 场景包的阈值/权重/白名单是**真正落到运行时**的, 而不只是显示
  · 反制方式的覆盖率 —— 宣称有 N 条, 就要有 N 条真的能被投出去
"""

import os
import tempfile

import config as config_mod
import countermeasures as CM
import fingerprint
import inject
import respond
import scenarios as S


# --------------------------------------------------------------------------
# 反制方式库
# --------------------------------------------------------------------------

def test_builtin_registry_loads():
    registry, report = CM.build_default_registry()
    assert report["builtin"] >= 20, "内置反制方式过少: %d" % report["builtin"]
    assert not report["errors"], "内置语料有错误: %s" % report["errors"]
    stats = registry.stats()
    assert stats["total"] == report["builtin"]


def test_all_categories_populated():
    """九类反制方式都应有内容 —— 空的类别等于承诺了一份没兑现的清单。"""
    registry, _ = CM.build_default_registry()
    counts = registry.stats()["by_category"]
    missing = [name for name in CM.CATEGORIES if not counts.get(name)]
    assert not missing, "以下类别没有任何反制方式: %s" % missing


def test_tier_gating():
    registry, _ = CM.build_default_registry()
    assert registry.select(30) == [], "低分区不应投放任何载荷"
    assert all(item.tier == 1 for item in registry.select(55)), \
        "55 分区只应投放层级 1"
    tiers = set(item.tier for item in registry.select(92))
    assert len(tiers) >= 2, "高分区应覆盖多个层级"


def test_plugin_validation_rejects_bad_entries():
    bad_entries = [
        ({"id": "BAD ID", "category": "abort", "text_zh": "x"}, "id"),
        ({"id": "ok-1", "category": "没有这类", "text_zh": "x"}, "category"),
        ({"id": "ok-2", "category": "abort"}, "text_zh"),
        ({"id": "ok-3", "category": "abort", "tier": 9, "text_zh": "x"}, "tier"),
        ({"id": "ok-4", "category": "abort", "stealth": 5.0, "text_zh": "x"}, "stealth"),
        ({"id": "ok-5", "category": "abort", "text_zh": "用了 {unknown_ph}"}, "占位符"),
    ]
    for entry, expect in bad_entries:
        try:
            CM.validate_countermeasure(entry, "test")
        except ValueError as exc:
            assert expect in str(exc), "报错未指出 %s: %s" % (expect, exc)
            continue
        raise AssertionError("坏条目未被拒绝: %s" % entry)


def test_plugin_loading_reports_errors_without_blocking():
    directory = tempfile.mkdtemp()
    with open(os.path.join(directory, "good.json"), "w") as handle:
        handle.write('[{"id":"my-cm","category":"abort","tier":1,"weight":99,'
                     '"text_zh":"自定义 {canary}"}]')
    with open(os.path.join(directory, "bad.json"), "w") as handle:
        handle.write('[{"id":"BAD!","category":"abort","text_zh":"x"}]')

    registry = CM.Registry()
    for entry in CM.BUILTIN:
        registry.register(entry, source="builtin")
    loaded, errors = registry.load_plugins(directory)
    assert loaded == 1, "有效插件未加载"
    assert len(errors) == 1, "坏插件未被报告"
    assert registry.get("my-cm") is not None


def test_placeholder_documentation_matches_code():
    """语料里用到的占位符必须都在白名单里, 否则会渲染出 {foo} 这种明显痕迹。"""
    registry, _ = CM.build_default_registry()
    used = set()
    for item in registry.all():
        used |= item.placeholders()
    unknown = used - CM.KNOWN_PLACEHOLDERS
    assert not unknown, "语料使用了未声明的占位符: %s" % unknown


# --------------------------------------------------------------------------
# 投放覆盖率
# --------------------------------------------------------------------------

def test_every_countermeasure_can_be_delivered():
    """宣称的每一条都必须真的能被投出去。

    纯权重排序会导致永远只投最高的几条, 二十多条弹药库实际只用到六七条 ——
    那是"功能清单上的数字"与"实际能力"不一致。轮换机制就是为了消除这个偏差。
    """
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    surfaces = [
        lambda c: inject.select_for_tier(95, limit=4, per_category_limit=1),
        lambda c: inject.select_for_tier(95, limit=3, rotate_seed=c + ":html"),
        lambda c: inject.select_for_tier(95, tier_hint=1, limit=2, rotate_seed=c + ":robots"),
        lambda c: inject.select_for_tier(95, tier_hint=2, limit=2, rotate_seed=c + ":env"),
        lambda c: inject.select_for_tier(95, limit=1, categories=("leak", "beacon"),
                                         rotate_seed=c + ":meta"),
    ]
    delivered = set()
    for index in range(200):
        canary = "hpx-run%03d" % index
        for surface in surfaces:
            for item in surface(canary):
                delivered.add(item["id"])

    everything = set(item["id"] for item in inject.PAYLOADS)
    missing = everything - delivered
    assert not missing, "以下反制方式在 200 个会话中从未被投放: %s" % sorted(missing)


def test_rotation_is_stable_within_session():
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    first = [i["id"] for i in inject.select_for_tier(95, limit=3, rotate_seed="hpx-x:html")]
    second = [i["id"] for i in inject.select_for_tier(95, limit=3, rotate_seed="hpx-x:html")]
    assert first == second, "同一会话的投放组合不稳定(攻击者刷新会看到内容变化)"


def test_rotation_differs_across_sessions():
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    combos = set()
    for index in range(12):
        picked = inject.select_for_tier(95, limit=3, rotate_seed="hpx-s%02d:html" % index)
        combos.add(tuple(sorted(i["id"] for i in picked)))
    assert len(combos) > 1, "不同会话看到完全相同的投放组合, 攻击方可据此写稳定特征"


def test_surface_limits_are_plausible():
    """单个投递面的条数必须受限 —— 二十多条通告堆在一个页面本身就极其可疑。"""
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    ctx = inject.PayloadContext("hpx-demo", "h.example.com", "inst")
    llms = inject.render_llms_txt(ctx, 95)
    sections = [line for line in llms.splitlines() if line.startswith("## ")]
    # 2 个固定段落(资产信息/使用限制) + 最多 4 条载荷
    assert len(sections) <= 8, "llms.txt 段落过多(%d), 不像真实站点文档" % len(sections)
    assert "{{" not in llms and "}" not in llms.replace("{", "", 0), \
        "llms.txt 存在未替换的占位符"


def test_no_residual_placeholders_on_any_surface():
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    ctx = inject.PayloadContext("hpx-demo2", "h.example.com", "inst")
    surfaces = {
        "llms.txt": inject.render_llms_txt(ctx, 95),
        "robots.txt": inject.render_robots_txt(ctx, 95),
        "security.txt": inject.render_security_txt(ctx, 95),
        "html": inject.render_html_comment(ctx, 95),
        "error": inject.render_error_page(ctx, 95, 404, "未找到"),
        "env": inject.render_fake_env(ctx, 95),
    }
    for name, text in surfaces.items():
        # 允许 {{ }} 之外的配对花括号出现在正文里(如 JSON), 只查未替换的 {name} 形态
        import re
        leftover = [m for m in re.findall(r"\{[a-z_]+\}", text)
                    if m[1:-1] in CM.KNOWN_PLACEHOLDERS]
        assert not leftover, "%s 存在未替换占位符: %s" % (name, leftover[:4])


# --------------------------------------------------------------------------
# 场景包
# --------------------------------------------------------------------------

def test_scenarios_load_and_are_consistent():
    cfg = config_mod.Config.load()
    items = S.list_scenarios(cfg)
    assert len(items) >= 4, "内置场景过少: %d" % len(items)
    for scenario in items:
        S.validate(scenario.raw, scenario.id)
        assert scenario.template_ref, "%s 未指定模板" % scenario.id
        assert scenario.description, "%s 缺少说明" % scenario.id


def test_scenario_rejects_non_monotonic_thresholds():
    bad = S.scaffold("bad-thresholds")
    bad["detection"]["thresholds"] = {"serve_watch": 80, "tarpit": 40}
    try:
        S.validate(bad, "bad-thresholds")
    except S.ScenarioError as exc:
        assert "递增" in str(exc)
        return
    raise AssertionError("非单调阈值未被拒绝")


def test_scenario_lint_warns_about_armed_firewall():
    risky = S.scaffold("risky")
    risky["blocking"]["armed"] = True
    risky["blocking"]["apply"] = True
    issues = S.lint(risky, "risky")
    assert any(item["level"] == "warning" and "防火墙" in item["message"]
               for item in issues), "armed+apply 同时为真时未给出告警"


def test_scenarios_produce_different_runtime_behavior():
    """不同场景必须产生**不同**的运行时行为, 否则场景层形同虚设。"""
    cfg = config_mod.Config.load()
    seen = {}
    for scenario_id in ("hw-drill-dmz", "daily-decoy", "scanner-sink"):
        scenario = S.load_scenario(scenario_id, cfg)
        merged = scenario.apply_to_config(cfg)
        thresholds = respond.resolved_thresholds(config_mod.Config(merged))
        seen[scenario_id] = tuple(sorted(thresholds.items()))
        # 分数 45 在不同场景下应落到不同处置档
        seen[scenario_id + ":action@45"] = respond.action_for_score(45, thresholds)
    assert len(set(seen.values())) > 1, "不同场景给出了相同的阈值与行为"
    assert seen["hw-drill-dmz:action@45"] != seen["daily-decoy:action@45"], \
        "演练场景与长期诱饵场景在分数 45 上处置相同, 场景没有起到区分作用"


def test_scenario_weight_overrides_reach_fingerprint():
    cfg = config_mod.Config.load()
    scenario = S.load_scenario("hw-drill-dmz", cfg)
    baseline = fingerprint.effective_weight("cadence_agent_rhythm")
    applied = fingerprint.configure(weight_overrides=scenario.weight_overrides(),
                                    reset=True)
    try:
        assert applied, "场景声明的权重覆盖未生效"
        boosted = fingerprint.effective_weight("cadence_agent_rhythm")
        assert boosted != baseline, "权重覆盖没有改变实际权重"
    finally:
        fingerprint.configure(reset=True)
    assert fingerprint.effective_weight("cadence_agent_rhythm") == baseline, \
        "重置后权重未还原"


def test_scenario_countermeasure_whitelist_applied():
    cfg = config_mod.Config.load()
    inject.configure(cfg)
    total = len(inject.PAYLOADS)

    scenario = S.load_scenario("agent-hunter", cfg)
    payload = scenario.countermeasures
    inject.apply_profile(include=payload.get("include"), exclude=payload.get("exclude"),
                         max_tier=payload.get("max_tier"))
    assert len(inject.PAYLOADS) < total, "场景白名单未收窄投放范围"
    assert not any(item["id"] == "defender_notice" for item in inject.PAYLOADS), \
        "场景黑名单未生效"

    # 完全关闭载荷的场景
    tripwire = S.load_scenario("internal-tripwire", cfg)
    inject.apply_profile(max_tier=tripwire.countermeasures.get("max_tier"))
    assert inject.PAYLOADS == [], "max_tier=0 时仍可投放载荷"
    assert inject.select_for_tier(95) == []

    inject.apply_profile(include=[], exclude=[], max_tier=3)
    assert len(inject.PAYLOADS) == total, "恢复全量失败"


def test_high_value_countermeasures_present():
    """支撑整个反制体系的关键几条必须在库里, 且带 high-value 标记。"""
    registry, _ = CM.build_default_registry()
    required = ("scope_verification_prompt", "integrity_beacon", "remediation_tracker")
    for item_id in required:
        item = registry.get(item_id)
        assert item is not None, "缺少关键反制方式: %s" % item_id
        assert "high-value" in item.tags, "%s 未标注 high-value" % item_id
