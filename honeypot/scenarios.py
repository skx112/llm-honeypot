"""场景包: 把"模板 + 反制策略 + 拖滞强度 + 检测调优"打包成一个可一键部署的预设。

为什么需要场景层 —— 模板只解决"看起来像什么系统", 但实战部署要决定的远不止这个:

  · 这次是护网演练还是日常诱饵? 演练要高强度反制, 日常诱饵要低调长期观测。
  · 这台上线在 DMZ 还是内网? DMZ 适合吸收重定向, 内网适合静默取证。
  · 目标是抓智能体还是抓扫描器? 决定检测阈值与载荷层级。
  · 允许投放到多露骨? 决定反制方式的白名单与最大层级。

场景包就是这些决策的**可复用、可评审、可分享的载体**。使用者在演练前选定一个
场景, 而不是现场调二十个参数 —— 这是产品成熟度的一部分: 把专家判断固化成预设。

场景 JSON 结构(schema=1):

    {
      "schema": 1,
      "id": "hw-drill-dmz",
      "name": "护网演练 · DMZ 诱饵",
      "description": "...",
      "template": "gov-portal",          # 模板 id 或路径
      "overrides": { ... },              # 覆盖模板的任意字段
      "countermeasures": {
        "enabled": true,
        "min_score": 45,
        "max_tier": 3,
        "include": [...], "exclude": [...]   # 精确控制投放哪些反制方式
      },
      "tarpit": { "profile": "heavy", "base_delay": 0.6, "growth": 1.45 },
      "detection": {
        "thresholds": {"serve_watch": 20, "tarpit": 45, "deceive_inject": 65, "lockdown": 80},
        "weight_overrides": {"cadence_agent_rhythm": 35},
        "path_playbook": [...]
      },
      "blocking": { "mode": "absorb", "auto_threshold": 85, "ttl_seconds": 3600 },
      "notes": "..."
    }
"""

import copy
import json
import os

SCHEMA_VERSION = 1

# 内置场景的动作阈值默认值(与 respond.py 的梯度保持一致)
DEFAULT_THRESHOLDS = {
    "serve_watch": 25,
    "tarpit": 50,
    "deceive_inject": 70,
    "lockdown": 85,
}

ACTION_ORDER = ("serve_watch", "tarpit", "deceive_inject", "lockdown")

_ID_RE_OK = "abcdefghijklmnopqrstuvwxyz0123456789._-"

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios")
CUSTOM_DIR_NAME = "scenarios/custom"


class ScenarioError(Exception):
    def __init__(self, message, path=None, hint=None):
        self.path = path
        self.hint = hint
        parts = [message]
        if path:
            parts.append("字段: %s" % path)
        if hint:
            parts.append("建议: %s" % hint)
        Exception.__init__(self, "\n  ".join(parts))


def validate(data, source="<inline>"):
    """校验场景定义。不通过抛 ScenarioError。"""
    if not isinstance(data, dict):
        raise ScenarioError("场景根节点必须是对象", source)

    if data.get("schema", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise ScenarioError("schema 版本不支持: %r" % data.get("schema"), "schema")

    scenario_id = data.get("id")
    if not scenario_id or not isinstance(scenario_id, str):
        raise ScenarioError("缺少 id", "id")
    if len(scenario_id) < 2 or len(scenario_id) > 64:
        raise ScenarioError("id 长度需在 2-64 之间", "id")
    for char in scenario_id:
        if char not in _ID_RE_OK:
            raise ScenarioError(
                "id 只能包含小写字母/数字/点/连字符/下划线: %r" % scenario_id, "id")

    if not data.get("template"):
        raise ScenarioError("缺少 template", "template",
                            "填写模板 id(如 gov-portal)或 .json 文件路径")

    for section in ("overrides", "countermeasures", "tarpit", "detection", "blocking"):
        if section in data and not isinstance(data[section], dict):
            raise ScenarioError("必须是对象", section)

    cm = data.get("countermeasures") or {}
    if "min_score" in cm:
        score = cm["min_score"]
        if not isinstance(score, int) or not (0 <= score <= 100):
            raise ScenarioError("min_score 必须是 0-100 的整数", "countermeasures.min_score")
    if "max_tier" in cm:
        tier = cm["max_tier"]
        if tier not in (0, 1, 2, 3):
            raise ScenarioError("max_tier 必须是 0-3", "countermeasures.max_tier",
                                "0 表示关闭反制载荷投放")
    for key in ("include", "exclude"):
        if key in cm:
            value = cm[key]
            if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                raise ScenarioError("%s 必须是字符串数组" % key, "countermeasures.%s" % key)

    detection = data.get("detection") or {}
    thresholds = detection.get("thresholds") or {}
    previous = None
    for action in ACTION_ORDER:
        if action not in thresholds:
            continue
        value = thresholds[action]
        if not isinstance(value, int) or not (0 <= value <= 100):
            raise ScenarioError("阈值必须是 0-100 的整数",
                                "detection.thresholds.%s" % action)
        if previous is not None and value <= previous:
            raise ScenarioError(
                "阈值必须严格递增: %s=%d 不大于前一项 %d" % (action, value, previous),
                "detection.thresholds.%s" % action,
                "否则该档动作永远不会被触发")
        previous = value

    weights = detection.get("weight_overrides") or {}
    if weights:
        if not isinstance(weights, dict):
            raise ScenarioError("必须是对象", "detection.weight_overrides")
        for key, value in weights.items():
            if not isinstance(value, int) or not (-100 <= value <= 100):
                raise ScenarioError(
                    "权重必须是 -100 到 100 的整数", "detection.weight_overrides.%s" % key)

    blocking = data.get("blocking") or {}
    if "mode" in blocking and blocking["mode"] not in ("absorb", "drop"):
        raise ScenarioError("blocking.mode 只能是 absorb 或 drop", "blocking.mode")
    return True


class Scenario(object):
    """一个已解析的场景。"""

    def __init__(self, data, source="<inline>"):
        validate(data, source)
        self.raw = copy.deepcopy(data)
        self.source = source
        self.id = data["id"]
        self.name = data.get("name") or self.id
        self.description = data.get("description", "")
        self.author = data.get("author", "")
        self.tags = list(data.get("tags") or [])
        self.template_ref = data["template"]
        self.overrides = dict(data.get("overrides") or {})
        self.countermeasures = dict(data.get("countermeasures") or {})
        self.tarpit = dict(data.get("tarpit") or {})
        self.detection = dict(data.get("detection") or {})
        self.blocking = dict(data.get("blocking") or {})
        self.notes = data.get("notes", "")
        self.intended_use = data.get("intended_use", "")

    # ---- 派生配置 ----

    def thresholds(self):
        merged = dict(DEFAULT_THRESHOLDS)
        merged.update(self.detection.get("thresholds") or {})
        return merged

    def weight_overrides(self):
        return dict(self.detection.get("weight_overrides") or {})

    def countermeasure_filter(self):
        """返回一个 (允许的 id 集合 或 None, 禁止的 id 集合)。"""
        include = self.countermeasures.get("include")
        exclude = set(self.countermeasures.get("exclude") or [])
        allowed = set(include) if include else None
        return allowed, exclude

    def allows_countermeasure(self, cm_id):
        allowed, excluded = self.countermeasure_filter()
        if cm_id in excluded:
            return False
        if allowed is not None and cm_id not in allowed:
            return False
        return True

    def payload_enabled(self):
        return bool(self.countermeasures.get("enabled", True)) \
            and int(self.countermeasures.get("max_tier", 3)) > 0

    def stats(self):
        return {
            "id": self.id, "name": self.name, "template": self.template_ref,
            "thresholds": self.thresholds(),
            "payload_enabled": self.payload_enabled(),
            "max_tier": self.countermeasures.get("max_tier", 3),
            "tarpit_profile": self.tarpit.get("profile", "standard"),
            "blocking_mode": self.blocking.get("mode", "absorb"),
            "overrides": sorted(self.overrides.keys()),
            "tags": self.tags,
        }

    def to_dict(self):
        return copy.deepcopy(self.raw)

    def describe(self):
        return "%-20s %-28s template=%-16s 反制=%-5s 拖滞=%-8s 处置=%s" % (
            self.id, self.name, self.template_ref,
            "开" if self.payload_enabled() else "关",
            self.tarpit.get("profile", "standard"),
            self.blocking.get("mode", "absorb"))

    # ---- 应用到运行时配置 ----

    def apply_to_config(self, config, instance=None):
        """把场景合并进运行时配置(返回新 dict, 不改动原对象)。

        只覆盖场景明确声明的项, 其余保持 config.json 的值 —— 场景是"预设",
        不是"全量配置", 使用者仍可在 config.json 里覆盖单点。
        """
        data = config.as_dict()

        if self.tarpit:
            tarpit = data.setdefault("tarpit", {})
            for key, value in self.tarpit.items():
                if key == "profile":
                    continue
                tarpit[key] = value

        if self.countermeasures:
            inject = data.setdefault("inject", {})
            if "enabled" in self.countermeasures:
                inject["enabled"] = bool(self.countermeasures["enabled"])
            if "min_score" in self.countermeasures:
                inject["min_score"] = int(self.countermeasures["min_score"])
            if "max_tier" in self.countermeasures:
                inject["max_tier"] = int(self.countermeasures["max_tier"])

        if self.blocking:
            block = data.setdefault("block", {})
            for key, value in self.blocking.items():
                block[key] = value

        if self.detection.get("thresholds"):
            data.setdefault("respond", {})["thresholds"] = self.thresholds()

        if self.detection.get("weight_overrides"):
            data.setdefault("respond", {})["weight_overrides"] = self.weight_overrides()

        if instance is not None:
            data["instance"] = getattr(instance, "instance_id", data.get("instance"))
            data.setdefault("honeypot_instance", {})
            data["honeypot_instance"] = {
                "scenario": self.id,
                "template": instance.template.id,
                "branding": instance.effective.branding,
                "network": instance.effective.network,
                "server": instance.effective.server,
            }
        return data


def _load_json(path):
    try:
        with open(path, "r") as handle:
            return json.load(handle)
    except ValueError as exc:
        raise ScenarioError("JSON 解析失败: %s" % exc, path,
                            "检查第 %d 行附近" % getattr(exc, "lineno", 0))
    except IOError as exc:
        raise ScenarioError("无法读取文件: %s" % exc, path)


def search_dirs(config=None):
    dirs = [BUILTIN_DIR]
    if config is not None:
        dirs.append(config.path(CUSTOM_DIR_NAME))
    return [d for d in dirs if os.path.isdir(d)]


def list_scenarios(config=None):
    """列出可用场景。自定义场景覆盖同 id 的内置场景。"""
    found = {}
    for directory in search_dirs(config):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                scenario = Scenario(_load_json(os.path.join(directory, name)),
                                    source=os.path.join(directory, name))
            except ScenarioError:
                continue
            found[scenario.id] = scenario
    return [found[key] for key in sorted(found)]


def load_scenario(identifier, config=None):
    if os.path.sep in identifier or identifier.endswith(".json"):
        path = identifier
        if not os.path.isabs(path) and config is not None:
            candidate = config.path(path)
            if os.path.exists(candidate):
                path = candidate
        return Scenario(_load_json(path), source=path)
    for scenario in list_scenarios(config):
        if scenario.id == identifier:
            return scenario
    raise ScenarioError(
        "找不到场景 %r" % identifier, None,
        "用 `cogtrap scenario list` 查看可用场景, 或给出 .json 文件路径")


def scaffold(scenario_id):
    """生成场景骨架。

    先校验 id 本身, 避免生成一个连自己都通不过校验的脚手架 —— 那会让使用者
    在第一步就困惑。
    """
    if not scenario_id or len(scenario_id) < 2 or len(scenario_id) > 64:
        raise ScenarioError("场景 id 长度需在 2-64 之间: %r" % scenario_id, "id")
    for char in scenario_id:
        if char not in _ID_RE_OK:
            raise ScenarioError(
                "场景 id 只能包含小写字母/数字/点/连字符/下划线: %r" % scenario_id, "id")
    return {
        "schema": SCHEMA_VERSION,
        "id": scenario_id,
        "name": "请填写场景名称",
        "description": "请描述这个场景的用途与适用环境",
        "author": "",
        "tags": [],
        "intended_use": "请说明适用环境, 例如: 护网演练期间的 DMZ 诱饵网段",
        "_help": {
            "说明": "场景 = 模板 + 反制策略 + 拖滞强度 + 检测阈值, 可一键部署。"
                  "删除 _help 段不影响使用。",
            "template": "填模板 id(用 `cogtrap template list` 查看)或 .json 路径",
            "overrides": "覆盖模板的任意字段, 例如 {\"branding\": {\"site_name\": \"XX集团\"}}",
            "max_tier": "0=关闭载荷投放, 1=仅隐蔽载荷, 2=+反向情报与信标, 3=全部"
                       "(含报告投毒); 层级越高反制越强, 但也越容易被识别为蜜罐",
            "阈值": "四个阈值必须严格递增, 否则某档动作永远不会触发",
            "校验": "改完后运行 `cogtrap scenario validate 本文件`",
        },
        "template": "gov-portal",
        "overrides": {
            "branding": {"site_name": "示例业务系统"},
        },
        "countermeasures": {
            "enabled": True,
            "min_score": 50,
            "max_tier": 3,
            "include": [],
            "exclude": [],
        },
        "tarpit": {
            "profile": "standard",
            "base_delay": 0.4,
            "growth": 1.32,
            "max_delay": 8.0,
        },
        "detection": {
            "thresholds": dict(DEFAULT_THRESHOLDS),
            "weight_overrides": {},
            "path_playbook": [],
        },
        "blocking": {
            "mode": "absorb",
            "auto_threshold": 85,
            "ttl_seconds": 3600,
            "armed": False,
            "apply": False,
        },
        "notes": "",
    }


def lint(data, source="<inline>"):
    """比 validate 更宽松的检查, 返回问题列表。"""
    issues = []
    try:
        validate(data, source)
    except ScenarioError as exc:
        return [{"level": "error", "message": str(exc)}]

    scenario = Scenario(data, source)
    if not scenario.description:
        issues.append({"level": "info", "message": "建议填写 description, 便于团队选场景"})
    if not scenario.intended_use:
        issues.append({"level": "info",
                       "message": "建议填写 intended_use, 说明适用环境"})

    tier = int(scenario.countermeasures.get("max_tier", 3))
    if tier == 3:
        issues.append({
            "level": "info",
            "message": "max_tier=3 会投放报告投毒等露骨载荷; 长期诱饵场景建议用 2 或 1",
        })
    if scenario.blocking.get("armed") and scenario.blocking.get("apply"):
        issues.append({
            "level": "warning",
            "message": "blocking 里 armed 与 apply 都为 true —— 场景一加载就会真实修改"
                       "防火墙。确认这是你要的, 否则请置为 false 并在演练开始后再开启",
        })
    if scenario.detection.get("thresholds"):
        values = scenario.thresholds()
        if values.get("lockdown", 100) > 95:
            issues.append({"level": "info",
                           "message": "lockdown 阈值偏高, 几乎不会触发锁定处置"})
    if not scenario.detection.get("path_playbook"):
        issues.append({"level": "info",
                       "message": "未定义 path_playbook, 将使用模板自带的路径清单"})
    return issues
