"""架构强制测试: 让架构文档无法与代码脱节。

## 为什么需要这个

架构文档会腐化, 除非有东西**强制**它对。传统的做法是"提交时记得更新文档",
这在实践中必然失败 —— 半年后文档描述的是一套不存在的系统, 比没有文档更糟。

因此这里把架构的**结构性事实**变成可执行的断言:

  1. **分层与依赖规则**(R1–R4) —— 新增模块或改变依赖方向会立刻失败
  2. **文档列出的模块清单与实际文件一致** —— 新增/删除模块而不更新文档会失败
  3. **文档列出的公开接口确实存在** —— 重命名接口而不更新文档会失败
  4. **文档的分层表与测试强制的分层一致** —— 两处定义不许分叉

## 一个关键细节: 惰性导入也要算依赖

代码里有 `__import__("server")` 这类惰性导入(为了在缺失可选模块时优雅降级)。
它们是 `Call` 节点而非 `Import` 节点, **只扫 Import 的静态分析看不见它们** ——
而 `server → cli` 的双向耦合正是这样被藏住的, 循环检测因此漏报。

所以本测试同时识别四种形式:
    import x      /  from x import y
    __import__("x")  /  importlib.import_module("x")
"""

import ast
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKAGE = os.path.join(ROOT, "honeypot")
ARCHITECTURE_DOC = os.path.join(ROOT, "docs", "ARCHITECTURE.zh-CN.md")

# 按职责定义的分层。这是**权威定义**: 文档里的分层表必须与之一致。
LAYERS = {
    0: ["__init__", "config", "http_parse", "store", "fingerprint",
        "countermeasures", "scenarios", "block", "tarpit", "report",
        "dashboard", "alerts", "hub"],
    1: ["templating", "inject"],
    2: ["respond", "deception", "ssh_decoy", "server"],
    3: ["cli"],
}

LAYER_OF = {}
for _level, _modules in LAYERS.items():
    for _module in _modules:
        LAYER_OF[_module] = _level

# 显式禁止的依赖边(除通用分层规则外的额外约束)
FORBIDDEN_EDGES = {
    ("server", "cli"): "编排职责只在 cli 一处; server 依赖 cli 会构成双向耦合",
}


def package_modules():
    return sorted(name[:-3] for name in os.listdir(PACKAGE)
                  if name.endswith(".py") and name != "__init__.py")


def extract_dependencies(module):
    """抽取一个模块依赖的全部内部模块(含惰性导入)。"""
    path = os.path.join(PACKAGE, module + ".py")
    source = open(path, encoding="utf-8").read()
    tree = ast.parse(source)
    known = set(package_modules()) | {"__init__"}
    found = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in known:
                    found.add(top)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in known:
                found.add(top)
        elif isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name not in ("__import__", "import_module"):
                continue
            for arg in node.args:
                # Python 3.6/3.7 用 ast.Str, 3.8+ 用 ast.Constant
                if isinstance(arg, ast.Str):
                    target = arg.s
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    target = arg.value
                else:
                    continue
                top = target.split(".")[0]
                if top in known:
                    found.add(top)
    found.discard(module)
    return sorted(found)


def dependency_graph():
    return dict((module, extract_dependencies(module))
                for module in package_modules())


def architecture_doc():
    return open(ARCHITECTURE_DOC, encoding="utf-8").read()


# --------------------------------------------------------------------------
# R1–R4: 依赖规则
# --------------------------------------------------------------------------

def test_r1_no_circular_dependencies():
    """R1: 依赖图不得有环。

    有环意味着两个模块无法独立理解与测试, 初始化顺序也会变得依赖巧合。
    """
    graph = dependency_graph()
    cycles = []
    for start in graph:
        stack = [(start, (start,))]
        while stack:
            node, path = stack.pop()
            for nxt in graph.get(node, ()):
                if nxt == start and len(path) > 1:
                    cycles.append(" -> ".join(path + (start,)))
                elif nxt not in path:
                    stack.append((nxt, path + (nxt,)))
    assert not cycles, "存在循环依赖:\n    " + "\n    ".join(sorted(set(cycles))[:6])


def test_r2_dependencies_point_downward_only():
    """R2: 依赖只能指向不高于自己的层。

    依赖方向的唯一性让"改上层不影响下层"成立, 这是可维护性的基础。
    """
    graph = dependency_graph()
    violations = []
    for module, deps in graph.items():
        level = LAYER_OF.get(module)
        if level is None:
            continue
        for dep in deps:
            dep_level = LAYER_OF.get(dep)
            if dep_level is None:
                continue
            if dep_level > level:
                violations.append("%s(L%d) -> %s(L%d)" % (module, level, dep, dep_level))
    assert not violations, (
        "依赖方向违反分层(应指向更低层):\n    " + "\n    ".join(violations))


def test_r3_foundation_layer_is_self_sufficient():
    """R3: L0 基础层不得依赖任何内部模块。

    基础层是判定的地基(解析、判定、存储、配置)。若它可以依赖上层, 上层的任何
    改动都会波及判定正确性, 而这恰恰是最不能出问题的部分。
    """
    graph = dependency_graph()
    offenders = []
    for module in LAYERS[0]:
        if module == "__init__":
            continue
        deps = graph.get(module, [])
        if deps:
            offenders.append("%s -> %s" % (module, ", ".join(deps)))
    assert not offenders, "L0 基础层出现内部依赖:\n    " + "\n    ".join(offenders)


def test_r4_no_forbidden_edges():
    """R4: 显式禁止的依赖边。"""
    graph = dependency_graph()
    violations = []
    for (source, target), reason in FORBIDDEN_EDGES.items():
        if target in graph.get(source, []):
            violations.append("%s -> %s (%s)" % (source, target, reason))
    assert not violations, "存在被禁止的依赖:\n    " + "\n    ".join(violations)


def test_every_module_is_assigned_a_layer():
    """新增模块必须归入某一层 —— 否则它就不受分层规则约束, 规则会出现盲区。"""
    unassigned = [m for m in package_modules()
                  if m not in LAYER_OF and m != "__init__"]
    assert not unassigned, (
        "以下模块未归入任何层(请在 LAYERS 里登记, 并同步架构文档):\n    "
        + ", ".join(unassigned))


# --------------------------------------------------------------------------
# 文档与代码一致性
# --------------------------------------------------------------------------

def test_documented_module_list_matches_code():
    """架构文档列出的模块必须与实际文件一致。

    这条防的是最常见的腐化: 新增了模块但没更新文档, 或删了模块留下幽灵条目。
    """
    doc = architecture_doc()
    documented = set(re.findall(r"^#### `([a-z_]+)\.py`", doc, re.M))
    documented.discard("__init__")
    actual = set(package_modules())

    missing_from_doc = actual - documented
    ghosts_in_doc = documented - actual
    assert not missing_from_doc, (
        "以下模块存在于代码但未写入架构文档 §3:\n    "
        + ", ".join(sorted(missing_from_doc)))
    assert not ghosts_in_doc, (
        "以下模块写在架构文档里但代码中不存在(已删除?):\n    "
        + ", ".join(sorted(ghosts_in_doc)))


def test_documented_layer_table_matches_enforced_layers():
    """架构文档的分层表必须与测试强制的分层一致。

    两处定义分叉就会出现"文档说在 L1、测试按 L0 校验"的荒谬状态。
    """
    doc = architecture_doc()
    # 匹配文档 §4.1 的分层表行: | **L0 基础** | `config` `http_parse` ... | ... |
    rows = re.findall(r"^\|\s*\*\*L(\d)[^|]*\*\*\s*\|([^|]+)\|", doc, re.M)
    assert rows, "未能在架构文档中解析出分层表(格式是否被改动?)"

    documented = {}
    for level, names in rows:
        found = set(re.findall(r"`([a-z_]+)`", names))
        found.discard("__init__")
        documented[int(level)] = found

    for level, modules in LAYERS.items():
        expected = set(m for m in modules if m != "__init__")
        actual = documented.get(level, set())
        assert actual == expected, (
            "架构文档 L%d 与强制分层不一致:\n      文档: %s\n      测试: %s"
            % (level, sorted(actual), sorted(expected)))


def test_documented_public_interfaces_exist():
    """架构文档列出的公开接口必须在代码中真实存在。

    防的是重命名接口后文档变成幻想 —— 贡献者照着文档写代码会直接失败。
    """
    doc = architecture_doc()
    # 逐个模块取它的 §3 段落, 抽出反引号里的标识符
    sections = re.split(r"^#### `([a-z_]+)\.py`", doc, flags=re.M)
    # sections = [前文, mod1, 段落1, mod2, 段落2, ...]
    checked = 0
    problems = []

    for index in range(1, len(sections) - 1, 2):
        module = sections[index]
        body = sections[index + 1]
        # 只看"公开接口"那一段, 避免把散文里的词也当接口
        match = re.search(r"\*\*公开接口\*\*[：:](.*?)(?:\n- \*\*|\n\n####|\Z)",
                          body, re.S)
        if not match:
            continue
        interface_text = match.group(1)
        # 提取形如 `name(` 或 `name(...)` 或 `Class` 的标识符
        identifiers = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)\s*\(", interface_text))
        identifiers |= set(re.findall(r"`([A-Z][A-Za-z0-9_]*)\b(?!\s*\()", interface_text))

        if not identifiers:
            continue
        try:
            module_obj = __import__(module)
        except ImportError as exc:
            problems.append("%s: 无法导入 (%s)" % (module, exc))
            continue

        # 接口可能在两处: 模块级(函数/类/常量) 或 类的成员(方法与属性)。
        # 只查模块级会把 SessionProfile.record 这类文档明确列出的方法误报为缺失。
        names = set(dir(module_obj))
        for attribute in dir(module_obj):
            member = getattr(module_obj, attribute, None)
            if isinstance(member, type) and member.__module__ == module:
                names |= set(dir(member))
        # 模块级字典常量(如 PAYLOADS)的键也算接口
        for attribute in dir(module_obj):
            member = getattr(module_obj, attribute, None)
            if isinstance(member, dict):
                names |= set(member.keys())

        for attribute in identifiers:
            checked += 1
            if attribute not in names:
                problems.append("%s: 文档列出的接口 %r 不存在" % (module, attribute))

    assert checked > 20, "解析出的接口过少(%d), 文档格式可能已变, 检查逻辑需更新" % checked
    assert not problems, "文档与代码接口不一致:\n    " + "\n    ".join(problems[:12])


def test_documented_extension_points_are_enforced():
    """文档宣称的扩展点必须有真实的强制实现。

    "契约由 validate() 强制"这句话如果 validate 不存在或不生效, 就是空头承诺。
    """
    import countermeasures
    import scenarios
    import templating

    # 三个数据扩展点各自的强制入口
    assert callable(templating.validate), "模板校验入口缺失"
    assert callable(templating.lint), "模板 lint 入口缺失"
    assert callable(countermeasures.validate_countermeasure), "反制方式校验入口缺失"
    assert callable(scenarios.validate), "场景校验入口缺失"

    # 注册表与模板发现必须可用(扩展点的实际接入方式)
    registry, report = countermeasures.build_default_registry()
    assert registry.stats()["total"] > 0
    assert isinstance(report.get("errors"), list)
    assert templating.list_templates(), "模板发现返回空, 扩展点未接通"
    assert scenarios.list_scenarios(), "场景发现返回空, 扩展点未接通"


def test_documented_defaults_match_configuration():
    """文档 C3 表格宣称的默认安全值必须与真实配置一致。

    这几项配错会出安全事故(防火墙误落地 / 遥测库暴露), 因此文档的说法必须有
    代码依据, 不能只是写在纸上的承诺。
    """
    import config as config_mod
    cfg = config_mod.Config.load()

    assert cfg.get("block.armed") is False, "防火墙应默认不落地"
    assert cfg.get("block.apply") is False, "防火墙应默认不落地"
    assert cfg.get("dashboard.host") == "127.0.0.1", "仪表盘应默认仅回环"
    for key in ("limits.max_connections", "limits.max_per_ip",
                "limits.max_tarpit_seconds_per_session",
                "limits.global_tarpit_budget_per_min",
                "limits.load_shed_threshold"):
        assert cfg.get(key) is not None, "缺少资源上限配置 %s" % key
    # 白名单必须非空, 否则有误封内网风险
    assert cfg.get("block.whitelist"), "处置白名单为空"


# --------------------------------------------------------------------------
# 稳定契约的兼容性: 只允许增加, 不允许删除
# --------------------------------------------------------------------------
#
# 架构文档 §7.1 把三份数据格式（模板 / 场景 / 反制方式）定为**稳定契约**, 并承诺
# "键只增不删"。但声称了政策却不强制, 比不声称更糟 —— 使用者会以为自己的私有资产
# 不会被破坏, 而一次疏忽就能把他们的模板全部废掉。
#
# 下面的基线是"已发布给使用者的契约面"。规则:
#
#     当前面 ⊇ 基线面      → 通过（新增字段/枚举值/占位符都是向后兼容的）
#     基线面中缺了任何一项  → 失败（这是对使用者已有资产的破坏性变更）
#
# 确实需要删除时, 正确做法是: 先在架构文档里记录迁移路径, 再显式修改这里的基线并
# 说明原因 —— 让破坏性变更成为一个被评审的动作, 而不是一次疏忽。
#
# 必填字段不是从文档抄的, 而是**经验推导**: 拿一份合法文档逐个删除字段, 校验失败
# 即说明该字段必填。因此它测的是代码的真实行为, 不是文档的说法。

STABLE_CONTRACT_BASELINE = {
    # 模板（templating）
    "template_required_fields": ["id", "name"],
    "template_categories": [
        "government", "enterprise", "ecommerce", "ops", "healthcare",
        "finance", "education", "industrial", "generic",
    ],
    "route_kinds": [
        "home", "login", "admin", "dashboard", "api", "api_docs", "openapi",
        "error", "listing", "debug", "config", "credential", "backup",
        "console", "health", "static", "custom",
    ],
    "payload_profiles": ["passive", "balanced", "aggressive"],
    "tarpit_profiles": ["light", "standard", "heavy"],

    # 反制方式（countermeasures）
    "countermeasure_categories": [
        "abort", "misdirect", "pollute", "leak", "beacon", "exhaust",
        "guardrail", "temporal", "credibility",
    ],
    "countermeasure_placeholders": [
        "beacon", "big_pages", "big_total", "canary", "fake_cve", "fake_cve2",
        "fake_date", "host", "instance", "lure_host", "lure_port", "now_utc",
        "registry_id", "session_hint", "trace",
    ],

    # 场景（scenarios）
    "scenario_required_fields": ["id", "template"],

    # 配置顶层键
    "config_top_level_keys": [
        "alert", "block", "countermeasures_unused", "dashboard", "honeytokens",
        "http", "inject", "instance", "limits", "ssh_decoy", "store", "tarpit",
    ],
}


def _required_fields(scaffold_fn, validate_fn, error_type, label):
    """经验推导必填字段: 逐个删除, 校验失败即必填。

    比从文档抄可靠 —— 文档会写错(实测发现架构文档曾把有默认值的字段写成必填)。
    """
    import copy
    base = scaffold_fn("probe-contract")
    required = []
    for key in sorted(base.keys()):
        if key.startswith("_"):          # _help 是说明段, 不参与校验
            continue
        probe = copy.deepcopy(base)
        probe.pop(key, None)
        try:
            validate_fn(probe, "probe")
        except error_type:
            required.append(key)
    return sorted(required)


def test_stable_contracts_are_additive_only():
    """稳定契约只允许增加, 不允许删除（架构文档 §7.3 的政策由本测试强制）。"""
    import countermeasures
    import config as config_mod
    import scenarios
    import templating

    current = {
        "template_required_fields": _required_fields(
            templating.scaffold, templating.validate, templating.TemplateError,
            "template"),
        "template_categories": sorted(templating.CATEGORIES),
        "route_kinds": sorted(templating.ROUTE_KINDS),
        "payload_profiles": sorted(templating.PAYLOAD_PROFILES),
        "tarpit_profiles": sorted(templating.TARPIT_PROFILES),
        "countermeasure_categories": sorted(countermeasures.CATEGORIES),
        "countermeasure_placeholders": sorted(countermeasures.KNOWN_PLACEHOLDERS),
        "scenario_required_fields": _required_fields(
            scenarios.scaffold, scenarios.validate, scenarios.ScenarioError,
            "scenario"),
        "config_top_level_keys": sorted(config_mod.Config.load().as_dict().keys()),
    }

    regressions = []

    # 两类契约的兼容性规则**不同**, 这点容易搞错:
    #
    #   枚举 / 白名单 / 配置键  →  **超集即可**。新增一个枚举值、一个占位符、
    #      一个配置段都是向后兼容的; 只有删除/重命名会破坏使用者资产。
    #
    #   必填字段集            →  **必须严格相等**。除删除之外, **新增必填字段同样
    #      是破坏性的**: 使用者现有的模板里没有这个字段, 会突然校验失败。
    #      (这条是负向验证发现的: 最初写成"超集即可", 于是把 category 改成必填
    #       也没被拦住 —— 而那会让所有未显式声明 category 的模板失效。)
    EXACT_KEYS = ("template_required_fields", "scenario_required_fields")

    for key, baseline in STABLE_CONTRACT_BASELINE.items():
        if key == "config_top_level_keys":
            # 配置允许出现之前不存在的新段(如后加的 countermeasures)
            baseline = [item for item in baseline
                        if not item.endswith("_unused")]
        now = set(current.get(key, ()))
        baseline_set = set(baseline)

        if key in EXACT_KEYS:
            removed = sorted(baseline_set - now)
            added = sorted(now - baseline_set)
            if removed:
                regressions.append(
                    "%s 中缺失: %s（使用者现有文档将校验失败）"
                    % (key, ", ".join(removed)))
            if added:
                regressions.append(
                    "%s 中新增了必填字段: %s（使用者现有文档里没有该字段, "
                    "会突然失效）" % (key, ", ".join(added)))
        else:
            missing = sorted(baseline_set - now)
            if missing:
                regressions.append("%s 中缺失: %s" % (key, ", ".join(missing)))

    assert not regressions, (
        "稳定契约出现破坏性变更(使用者已有资产会失效):\n    "
        + "\n    ".join(regressions)
        + "\n\n若确为有意变更, 请先在架构文档 §7.3 记录迁移路径, 再更新本测试的基线。")


def test_contract_additions_are_allowed():
    """反向确认: 新增是可接受的（否则这个门禁会阻碍正常的扩展）。

    做法: 取一份合法的模板, 加一个此前不存在的字段与一个枚举值的新成员,
    校验应当仍然通过 —— 证明门禁只在"删除"时失败, 不误伤"增加"。
    """
    import templating

    data = templating.scaffold("additive-probe")
    data["future_field"] = {"some": "value"}
    data["variables"]["future_var"] = "x"
    templating.validate(data, "additive-probe")   # 不应抛异常

    # 未知字段不报错是刻意设计: 使用者可以先在模板里放自己的元数据,
    # 等引擎支持了再启用。因此这条断言保护的正是这种工作方式。
