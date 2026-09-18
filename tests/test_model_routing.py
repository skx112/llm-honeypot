"""按模型分化的反制测试。

背景: 反制方式并非对一切大模型同等有效 —— 对齐 API 模型(claude/gpt/qwen…)
有可被触发的合规护栏, 而本地裸模型(ollama/vllm/llama.cpp)通常没有。
给裸模型投护栏类载荷等于浪费最宝贵的投递面。
"""

import http_parse
import fingerprint
import countermeasures as CM
import inject


def family_for(ua, extra_headers=""):
    raw = ("GET /api/v1/users HTTP/1.1\r\nHost: h\r\nUser-Agent: %s\r\n%s\r\n"
           % (ua, extra_headers)).encode()
    request = http_parse.parse_head(raw)
    profile = fingerprint.SessionProfile("s", "203.0.113.1", 1)
    profile.record(request, 1.0)
    return fingerprint.evaluate(profile, request, None).model_family


GUARDRAIL_IDS = None


def guardrail_ids():
    global GUARDRAIL_IDS
    if GUARDRAIL_IDS is None:
        registry, _ = CM.build_default_registry()
        GUARDRAIL_IDS = set(c.id for c in registry.all()
                            if c.category == "guardrail")
    return GUARDRAIL_IDS


# --------------------------------------------------------------------------
# 家族归一化
# --------------------------------------------------------------------------

def test_local_runtime_uas_map_to_bare_family():
    """ollama/vllm/llama-cpp 等本地运行时 → 裸模型家族。"""
    for ua in ("ollama/0.1.30", "vllm/0.4 agent", "llama-cpp/2312"):
        family = family_for(ua)
        assert family in CM.BARE_MODEL_FAMILIES, \
            "%r 应归入裸模型家族, 实际 %r" % (ua, family)


def test_api_model_mentions_map_to_aligned_family():
    """正文/头部中的显式型号 → 对齐家族。"""
    cases = [
        ("X-Model: claude-3.5-sonnet", "claude"),
        ("X-Agent-Runtime: qwen2.5-72b", "qwen"),
        ("X-Note: deepseek-r1", "deepseek"),
        ("X-K: glm-4.5", "glm"),
    ]
    for header, expected in cases:
        family = family_for("python-httpx/0.27", header)
        assert family == expected, "%r 应为 %r, 实际 %r" % (header, expected, family)


def test_ollama_not_misread_as_llama_family():
    """子串回归: "ollama" 含 "llama", 词边界缺失会误判家族。"""
    assert family_for("ollama/0.1.30") == "local-llm"


def test_browser_version_numbers_do_not_pollute_family():
    """浏览器 UA 里的版本号(Chrome/124.0.0.0)不得误报为模型家族。"""
    assert family_for("Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36") == ""


def test_family_keys_are_consistent_across_modules():
    """fingerprint 的家族键集合必须覆盖 countermeasures 的两个家族集合。

    两处刻意不互相导入(L0 自足), 因此用测试交叉校验 —— 分叉意味着
    某个家族被检测到了却无法用于反制路由。
    """
    assert CM.ALIGNED_MODEL_FAMILIES | CM.BARE_MODEL_FAMILIES \
        <= fingerprint.MODEL_FAMILY_KEYS


# --------------------------------------------------------------------------
# 分化选择
# --------------------------------------------------------------------------

def registry():
    instance, _ = CM.build_default_registry()
    return instance


def test_guardrail_payloads_skip_bare_models():
    """裸模型家族不投 guardrail 类 —— 没有可触发的对齐护栏。"""
    reg = registry()
    picked = set(c.id for c in reg.select(95, model_family="local-llm"))
    assert not (guardrail_ids() & picked), \
        "guardrail 载荷 %s 被投给了裸模型" % (guardrail_ids() & picked)


def test_guardrail_payloads_still_reach_aligned_models():
    reg = registry()
    picked = set(c.id for c in reg.select(95, model_family="claude"))
    assert guardrail_ids() & picked, "对齐模型应仍能收到 guardrail 载荷"


def test_content_agnostic_payloads_reach_every_family():
    """拖滞/预算耗尽/数据污染与模型无关 —— 任何家族都必须拿得到。"""
    reg = registry()
    for family in ("local-llm", "claude", "", "llama"):
        picked = set(c.id for c in reg.select(95, model_family=family))
        for required in ("pagination_maze", "fake_topology"):
            assert required in picked, \
                "家族 %r 未能获得内容无关载荷 %s" % (family or "(空)", required)


def test_target_and_exclude_model_fields():
    """插件的模型定向字段必须真实生效。"""
    reg = CM.Registry()
    reg.register({
        "id": "only-claude-probe", "category": "abort", "tier": 1,
        "text_zh": "x {canary}", "target_models": ["claude"],
    }, "t")
    reg.register({
        "id": "never-gpt-probe", "category": "abort", "tier": 1,
        "text_zh": "x {canary}", "exclude_models": ["gpt"],
    }, "t")

    claude = set(c.id for c in reg.select(95, model_family="claude"))
    gpt = set(c.id for c in reg.select(95, model_family="gpt"))
    assert "only-claude-probe" in claude
    assert "only-claude-probe" not in gpt
    assert "never-gpt-probe" in claude and "never-gpt-probe" not in gpt


def test_unknown_family_is_conservative():
    """未知家族保守放行(按可能是对齐模型处理), 不误伤。"""
    reg = registry()
    picked = set(c.id for c in reg.select(95, model_family=""))
    assert guardrail_ids() & picked, "未知家族不应被过滤掉 guardrail 载荷"


# --------------------------------------------------------------------------
# 校验器
# --------------------------------------------------------------------------

def test_validator_rejects_unknown_model_families():
    for field in ("target_models", "exclude_models"):
        try:
            CM.validate_countermeasure({
                "id": "bad-model", "category": "abort", "text_zh": "x",
                field: ["gpt5-turbo-nonexistent"],
            }, "t")
        except ValueError as exc:
            assert "未知模型家族" in str(exc)
            continue
        raise AssertionError("%s 的未知家族未被拒绝" % field)


# --------------------------------------------------------------------------
# 端到端: 判定 → 投递面
# --------------------------------------------------------------------------

def test_llms_txt_omits_guardrail_for_bare_models():
    inject.configure()
    ctx_local = inject.PayloadContext("hpx-l", "h.example.com", "i")
    ctx_local.model_family = "local-llm"
    text = inject.render_llms_txt(ctx_local, 95)
    leaked = [gid for gid in guardrail_ids() if gid in text]
    assert not leaked, "llms.txt 对裸模型泄漏了护栏载荷: %s" % leaked
    # 且正文仍应有载荷(分化不是清空)
    assert "## " in text


def test_verdict_exposes_model_family_for_downstream():
    verdict_family = family_for("python-httpx", "X-Model: gemini-1.5")
    assert verdict_family == "gemini"
    raw = ("GET /x HTTP/1.1\r\nHost: h\r\nUser-Agent: python-httpx\r\n"
           "X-Model: gemini-1.5\r\n\r\n").encode()
    request = http_parse.parse_head(raw)
    profile = fingerprint.SessionProfile("s", "203.0.113.1", 1)
    profile.record(request, 1.0)
    verdict = fingerprint.evaluate(profile, request, None)
    assert verdict.to_dict()["model_family"] == "gemini", \
        "to_dict 必须导出 model_family(上报与遥测依赖)"
