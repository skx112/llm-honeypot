"""蜜罐模板引擎: 声明式定义 + 校验 + 渲染 + 实例化。

设计目标(决定了这里的每个取舍):

  1. **模板即数据, 不是代码。** 模板是 JSON, 使用者不需要写 Python 就能造出
     一个自己的蜜罐。这也让模板可以被分享、审计、版本控制。
  2. **部分覆盖而非全量重写。** 模板只需写它关心的部分, 未定义的路由回落到
     内置默认。这样"改个公司名"和"从零造一个行业站点"是同一套机制。
  3. **校验要给出可行动的报错。** 用户生成的模板必然有错, 报错必须指出
     文件、字段路径、期望值。这是"成熟产品"与"脚本"的分界。
  4. **渲染确定性。** 同一实例每次渲染结果一致(由实例令牌播种随机源),
     否则攻击者刷新两次页面就会发现数据变了 —— 那是蜜罐的致命破绽。

模板 JSON 结构(schema=1):

    {
      "schema": 1,
      "id": "gov-portal",
      "name": "政务服务平台",
      "category": "government",
      "version": "1.0.0",
      "description": "...",
      "tags": ["gov", "portal"],
      "branding":  { "site_name": "...", "version_string": "3.2.1", ... },
      "server":    { "server_header": "nginx/1.24.0", "powered_by": "PHP/7.4.33" },
      "network":   { "internal_hosts": [...], "db_host": "...", ... },
      "variables": { "自定义变量": "值" },
      "credentials": [ { "id": "...", "path": "/.env", "kind": "env", ... } ],
      "routes": [ { "path": "/", "method": "GET", "kind": "home", "body": "..." } ],
      "vulnerabilities": [ { "path": "/api/v1/users", "type": "sqli", ... } ],
      "payload_profile": "balanced",
      "tarpit_profile": "standard",
      "detection": { "path_playbook": [...], "noise_paths": [...] }
    }

正文里用 `{{变量}}` 引用变量; 未定义的变量在校验阶段就会被报出来。
"""

import copy
import json
import os
import random
import re
import time

SCHEMA_VERSION = 1

# 允许的模板分类 —— 用于界面分组与场景匹配
CATEGORIES = (
    "government", "enterprise", "ecommerce", "ops", "healthcare",
    "finance", "education", "industrial", "generic",
)

PAYLOAD_PROFILES = ("passive", "balanced", "aggressive")
TARPIT_PROFILES = ("light", "standard", "heavy")

# 允许 {{var}} 与 {{rand.hex:16}} 这类带参数的写法 —— 参数部分用 `:[^{}]*`
# 匹配, 否则带冒号的随机函数会匹配不上, 渲染后残留 {{...}}(真实踩过的坑)。
VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*(?::[^{}]*)?)\s*\}\}")

# 宽松匹配: 用于发现"看起来像占位符但语法不合法"的写法。
# 例如 {{变量名}} 不会被 VAR_RE 匹配, 于是既不被替换也不报错, 而是**静默留在
# 页面上** —— 攻击者看到字面的 {{变量名}} 立刻就明白这是模板生成的假站点。
# 这种静默失败比报错危险得多, 因此必须专门检查。
LOOSE_PLACEHOLDER_RE = re.compile(r"\{\{([^{}]*)\}\}")

# 模板解析后必然可用的内置变量(渲染前注入)
BUILTIN_VAR_PREFIXES = ("instance.", "branding.", "network.", "server.", "vuln.", "rand.")

# 运行时上下文变量: 在渲染漏洞报错正文等场景由服务端注入, 因此模板里可直接引用
RUNTIME_VARS = frozenset((
    "query", "param", "payload", "method", "path", "user_agent", "body",
    "client_ip", "target", "header",
))

# 派生变量: 由实例化过程自动计算, 模板作者不需要自己定义
DERIVED_VARS = frozenset((
    "db_password", "app_key", "jwt_secret", "api_token", "db_host", "db_name",
    "db_user", "internal_hosts",
))

ROUTE_KINDS = (
    "home", "login", "admin", "dashboard", "api", "api_docs", "openapi",
    "error", "listing", "debug", "config", "credential", "backup", "console",
    "health", "static", "custom",
)


class TemplateError(Exception):
    """模板校验/加载错误。带字段路径, 便于使用者定位。"""

    def __init__(self, message, path=None, hint=None):
        self.path = path
        self.hint = hint
        parts = [message]
        if path:
            parts.append("字段: %s" % path)
        if hint:
            parts.append("建议: %s" % hint)
        Exception.__init__(self, "\n  ".join(parts))


# --------------------------------------------------------------------------
# 校验
# --------------------------------------------------------------------------

def _require(data, key, path, types=None, hint=None):
    if key not in data:
        raise TemplateError("缺少必填字段 %r" % key, path, hint)
    value = data[key]
    if types and not isinstance(value, types):
        raise TemplateError(
            "字段类型错误: 期望 %s, 实际 %s" % (
                "/".join(t.__name__ for t in types), type(value).__name__),
            "%s.%s" % (path, key) if path else key)
    return value


def _check_str_list(value, path, allow_empty=True):
    if not isinstance(value, list):
        raise TemplateError("期望字符串数组", path)
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise TemplateError("第 %d 项不是字符串" % index, "%s[%d]" % (path, index))
        if not allow_empty and not item.strip():
            raise TemplateError("第 %d 项为空字符串" % index, "%s[%d]" % (path, index))
    return value


def validate(data, source="<inline>"):
    """校验模板数据。通过返回 True, 否则抛出 TemplateError。

    校验项刻意严格 —— 用户生成的模板有错是常态, 早发现远好于蜜罐跑起来
    才发现页面 500。
    """
    if not isinstance(data, dict):
        raise TemplateError("模板根节点必须是对象", source,
                            "参照 docs/TEMPLATES.md 的骨架")

    schema = data.get("schema", SCHEMA_VERSION)
    if schema != SCHEMA_VERSION:
        raise TemplateError(
            "schema 版本不支持: %r (本版本支持 %d)" % (schema, SCHEMA_VERSION),
            "schema", "升级 CogTrap 或改用匹配的 schema 版本")

    _require(data, "id", "", (str,), "建议用小写字母与连字符, 如 gov-portal")
    template_id = data["id"]
    if not re.match(r"^[a-z0-9][a-z0-9._-]{1,63}$", template_id):
        raise TemplateError(
            "id 只能包含小写字母/数字/点/连字符, 且以字母数字开头", "id")

    _require(data, "name", "", (str,))
    if not template_id:
        raise TemplateError("id 不能为空", "id")

    category = data.get("category", "generic")
    if category not in CATEGORIES:
        raise TemplateError(
            "未知分类 %r" % category, "category",
            "可选: %s" % ", ".join(CATEGORIES))

    payload_profile = data.get("payload_profile", "balanced")
    if payload_profile not in PAYLOAD_PROFILES:
        raise TemplateError("未知载荷档案 %r" % payload_profile, "payload_profile",
                            "可选: %s" % ", ".join(PAYLOAD_PROFILES))

    tarpit_profile = data.get("tarpit_profile", "standard")
    if tarpit_profile not in TARPIT_PROFILES:
        raise TemplateError("未知拖滞档案 %r" % tarpit_profile, "tarpit_profile",
                            "可选: %s" % ", ".join(TARPIT_PROFILES))

    for key in ("tags",):
        if key in data:
            _check_str_list(data[key], key)

    for section in ("branding", "server", "network", "variables", "detection"):
        if section in data and not isinstance(data[section], dict):
            raise TemplateError("必须是对象", section)

    # ---- 路由 ----
    routes = data.get("routes", [])
    if not isinstance(routes, list):
        raise TemplateError("routes 必须是数组", "routes")
    seen_paths = {}
    for index, route in enumerate(routes):
        path = "routes[%d]" % index
        if not isinstance(route, dict):
            raise TemplateError("路由必须是对象", path)
        target = route.get("path")
        if not target or not isinstance(target, str):
            raise TemplateError("路由缺少 path", path)
        if not target.startswith("/"):
            raise TemplateError("path 必须以 / 开头: %r" % target, path + ".path",
                                "绝对路径形式, 如 /admin/login")
        method = route.get("method", "GET").upper()
        if method not in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "ANY"):
            raise TemplateError("不支持的 method: %r" % method, path + ".method")
        key = (target.rstrip("/").lower() or "/", method)
        if key in seen_paths:
            raise TemplateError(
                "路由重复: %s %s (与 routes[%d] 冲突)" % (
                    method, target, seen_paths[key]),
                path + ".path", "同一 path+method 只能定义一次")
        seen_paths[key] = index

        if "status" in route:
            status = route["status"]
            if not isinstance(status, int) or not (100 <= status <= 599):
                raise TemplateError("status 必须是 100-599 的整数", path + ".status")
        if "kind" in route and route["kind"] not in ROUTE_KINDS:
            raise TemplateError(
                "未知 kind: %r" % route["kind"], path + ".kind",
                "可选: %s" % ", ".join(ROUTE_KINDS))
        if "body" in route and not isinstance(route["body"], str):
            raise TemplateError("body 必须是字符串", path + ".body")
        if "honeytokens" in route:
            _check_str_list(route["honeytokens"], path + ".honeytokens",
                            allow_empty=False)
        if route.get("tarpit_weight") is not None:
            weight = route["tarpit_weight"]
            if not isinstance(weight, int) or weight < 0:
                raise TemplateError("tarpit_weight 必须是非负整数", path + ".tarpit_weight")

    # ---- 漏洞面 ----
    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        raise TemplateError("vulnerabilities 必须是数组", "vulnerabilities")
    for index, vuln in enumerate(vulns):
        path = "vulnerabilities[%d]" % index
        if not isinstance(vuln, dict):
            raise TemplateError("必须是对象", path)
        if not vuln.get("path"):
            raise TemplateError("缺少 path", path)
        if not vuln.get("type"):
            raise TemplateError("缺少 type", path, "如 sqli / rce / lfi / idor / upload")

    # ---- 凭据蜜标 ----
    creds = data.get("credentials", [])
    if not isinstance(creds, list):
        raise TemplateError("credentials 必须是数组", "credentials")
    for index, cred in enumerate(creds):
        path = "credentials[%d]" % index
        if not isinstance(cred, dict):
            raise TemplateError("必须是对象", path)
        if not cred.get("id"):
            raise TemplateError("缺少 id", path)
        if not cred.get("path"):
            raise TemplateError("缺少 path", path, "该凭据投放的文件路径, 如 /.env")

    # ---- 占位符语法检查 ----
    bad_placeholders = check_placeholder_syntax(data)
    if bad_placeholders:
        sample = ", ".join("%s (%s)" % (text, path) for path, text in bad_placeholders[:4])
        raise TemplateError(
            "存在语法不合法的占位符, 它们不会被替换而会原样留在页面上: %s" % sample,
            bad_placeholders[0][1],
            "变量名必须以字母或下划线开头, 只能含字母/数字/下划线/点; "
            "带参数的形式如 {{rand.hex:16}} 也支持")

    # ---- 变量引用检查(用户生成模板最常犯的错) ----
    defined = set()
    for section in ("branding", "server", "network", "variables"):
        for key in (data.get(section) or {}):
            defined.add("%s.%s" % (section, key))
            defined.add(key)
    defined.update(["instance.host", "instance.port", "instance.canary",
                    "instance.id", "instance.now", "instance.brand"])
    check = check_variables(data, defined)
    if check:
        raise TemplateError(
            "正文引用了未定义的变量: %s" % ", ".join(sorted(check)[:12]),
            "routes/vulnerabilities.正文",
            "在 variables 段定义它们, 或改用内置变量 "
            "(instance.* / branding.* / network.* / server.*)")
    return True


def collect_variable_refs(text):
    """收集一段文本里引用的所有变量名。"""
    return set(VAR_RE.findall(text or ""))


def _walk_strings(node, path=""):
    """遍历所有字符串。跳过 `_` 开头的键 —— 它们是给人看的说明(如 `_help`),
    不参与渲染, 其中的示例占位符不应被当成真实引用。"""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            if key.startswith("_"):
                continue
            for item in _walk_strings(value, "%s.%s" % (path, key) if path else key):
                yield item
    elif isinstance(node, list):
        for index, value in enumerate(node):
            for item in _walk_strings(value, "%s[%d]" % (path, index)):
                yield item


def check_placeholder_syntax(data):
    """找出语法不合法的占位符。返回 [(字段路径, 原始文本)]。"""
    problems = []
    for path, text in _walk_strings(data):
        if "{{" not in text:
            continue
        for match in LOOSE_PLACEHOLDER_RE.finditer(text):
            if VAR_RE.match(match.group(0)):
                continue
            problems.append((path, match.group(0)[:40]))
    return problems


def check_variables(data, defined):
    """返回未定义的变量引用集合(空集表示通过)。"""
    undefined = set()
    for _, text in _walk_strings(data):
        if "{{" not in text:
            continue
        for name in collect_variable_refs(text):
            if name in defined or name in RUNTIME_VARS or name in DERIVED_VARS:
                continue
            # 前缀式内置变量
            if any(name.startswith(prefix) for prefix in BUILTIN_VAR_PREFIXES):
                continue
            undefined.add(name)
    return undefined


# --------------------------------------------------------------------------
# 渲染
# --------------------------------------------------------------------------

class Renderer(object):
    """变量替换器。

    随机源按实例令牌播种, 因此同一实例每次渲染结果一致 —— 攻击者刷新页面
    不会看到数据变化, 这是蜜罐可信度的基本要求。
    """

    def __init__(self, variables, seed):
        self.vars = dict(variables or {})
        self.seed = seed
        # 仅供 resolve() 交互式调用使用的流式随机源。render() 刻意不用它 ——
        # 见 render() 里关于"顺序无关"的说明。
        self._rng = random.Random(seed)

    def set_many(self, values):
        self.vars.update(values or {})

    def resolve(self, name):
        """交互式取值。注意: rand.* 在此走流式随机源, **结果与调用顺序有关**,
        仅供调试与预览使用; 服务端渲染一律走 render(), 它是顺序无关的。"""
        if name in self.vars:
            return self.vars[name]
        if name.startswith("rand."):
            return self._generate(name[5:], self._rng)
        return "{{%s}}" % name     # 未定义则原样保留, 由 lint 负责报出

    def _generate(self, spec, rng):
        kind, _, arg = spec.partition(":")
        if kind == "hex":
            length = int(arg or 8)
            return "".join(rng.choice("0123456789abcdef") for _ in range(length))
        if kind == "int":
            low, _, high = arg.partition("-")
            try:
                return str(rng.randint(int(low), int(high)))
            except ValueError:
                return str(rng.randint(1, 1000))
        if kind == "choice":
            options = [part for part in arg.split("|") if part]
            return rng.choice(options) if options else ""
        if kind == "date":
            days = int(arg or 30)
            return time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400 * days))
        if kind == "ip":
            return "10.%d.%d.%d" % (rng.randint(10, 30),
                                    rng.randint(1, 250),
                                    rng.randint(1, 250))
        return ""

    def render(self, template, extra=None):
        """渲染一段文本。

        extra 提供**一次性**变量(如漏洞报错里的 {{query}}), 不写入实例变量表 ——
        避免把攻击者的输入持久化进渲染上下文, 那会让同一实例的后续渲染被污染。

        ## 为什么 rand.* 不用流式随机源

        这是蜜罐可信度的关键。如果 {{rand.hex:8}} 取值来自一个共享随机流, 它的值
        就**取决于调用历史**: 攻击者先请求 /, 再请求别的路径, 再回到 /, 同一个
        页面里的随机值就变了 —— 而"同一页面两次返回不同数据"是"这是假站点"的
        直接证据。

        因此每个 rand.* 出现的值都由 (实例种子, 本文本, 变量名, 出现序号) 派生,
        与调用顺序完全无关: 同一实例渲染同一段文本, 永远得到同一个值。
        """
        if not isinstance(template, str) or "{{" not in template:
            return template

        counter = [0]

        def _replace(match):
            name = match.group(1)
            if extra and name in extra:
                return str(extra[name])
            if name.startswith("rand."):
                counter[0] += 1
                derived = random.Random("%s|%s|%s|%d" % (
                    self.seed, template, name, counter[0]))
                return self._generate(name[5:], derived)
            return str(self.resolve(name))

        # 迭代替换以支持变量值里再引用变量(限定轮次, 避免循环引用卡死)
        text = template
        for _ in range(4):
            counter[0] = 0          # 每轮独立计数, 派生种子才稳定
            new_text = VAR_RE.sub(_replace, text)
            if new_text == text:
                break
            text = new_text
        return text


# --------------------------------------------------------------------------
# 模板对象
# --------------------------------------------------------------------------

class Route(object):
    __slots__ = ("path", "method", "kind", "status", "content_type", "title",
                 "body", "honeytokens", "tarpit_weight", "headers", "note",
                 "raw")

    def __init__(self, data):
        self.raw = data
        self.path = data["path"]
        self.method = (data.get("method") or "GET").upper()
        self.kind = data.get("kind", "custom")
        self.status = int(data.get("status", 200))
        self.content_type = data.get("content_type", "text/html; charset=utf-8")
        self.title = data.get("title", "")
        self.body = data.get("body", "")
        self.honeytokens = list(data.get("honeytokens") or [])
        self.tarpit_weight = int(data.get("tarpit_weight", 0))
        self.headers = list(data.get("headers") or [])
        self.note = data.get("note", "")

    def key(self):
        return (self.path.rstrip("/").lower() or "/", self.method)


class Vulnerability(object):
    __slots__ = ("path", "method", "type", "param", "severity", "error_body",
                 "response_body", "note", "raw")

    def __init__(self, data):
        self.raw = data
        self.path = data["path"]
        self.method = (data.get("method") or "GET").upper()
        self.type = data["type"]
        self.param = data.get("param", "")
        self.severity = data.get("severity", "medium")
        self.error_body = data.get("error_body", "")
        self.response_body = data.get("response_body", "")
        self.note = data.get("note", "")


class Template(object):
    """一个已解析的蜜罐模板。"""

    def __init__(self, data, source="<inline>"):
        validate(data, source)
        self.raw = copy.deepcopy(data)
        self.source = source
        self.id = data["id"]
        self.name = data.get("name") or self.id
        self.category = data.get("category", "generic")
        self.version = data.get("version", "0.0.0")
        self.description = data.get("description", "")
        self.author = data.get("author", "")
        self.tags = list(data.get("tags") or [])
        self.branding = dict(data.get("branding") or {})
        self.server = dict(data.get("server") or {})
        self.network = dict(data.get("network") or {})
        self.variables = dict(data.get("variables") or {})
        self.detection = dict(data.get("detection") or {})
        self.payload_profile = data.get("payload_profile", "balanced")
        self.tarpit_profile = data.get("tarpit_profile", "standard")
        self.routes = [Route(item) for item in data.get("routes", [])]
        self.vulnerabilities = [Vulnerability(item)
                                for item in data.get("vulnerabilities", [])]
        self.credentials = [dict(item) for item in data.get("credentials", [])]

    # ---- 查询 ----

    def route_table(self):
        """返回 {(path, method): Route}，便于 O(1) 匹配。"""
        table = {}
        for route in self.routes:
            table[route.key()] = route
        return table

    def routes_for_path(self, path):
        key = (path.rstrip("/").lower() or "/", None)
        return [route for route in self.routes
                if (route.path.rstrip("/").lower() or "/") == key[0]]

    def vulnerability_for(self, path, method="GET"):
        for vuln in self.vulnerabilities:
            if (vuln.path.rstrip("/").lower() == (path or "").rstrip("/").lower()
                    and vuln.method in (method.upper(), "ANY")):
                return vuln
        return None

    def credential_for(self, path):
        normalized = (path or "").rstrip("/").lower() or "/"
        for cred in self.credentials:
            if (cred.get("path", "").rstrip("/").lower() or "/") == normalized:
                return cred
        return None

    def stats(self):
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "version": self.version, "routes": len(self.routes),
            "vulnerabilities": len(self.vulnerabilities),
            "credentials": len(self.credentials),
            "payload_profile": self.payload_profile,
            "tarpit_profile": self.tarpit_profile,
            "tags": self.tags,
        }

    def to_dict(self):
        return copy.deepcopy(self.raw)


class HoneypotInstance(object):
    """由模板实例化出的一个具体蜜罐。

    这是"用户生成蜜罐"的产物: 一份模板 + 一组覆盖项 = 一个可运行的实例。
    """

    def __init__(self, template, overrides=None, instance_id=None, host="localhost",
                 port=8080, canary="hpx-instance"):
        self.template = template
        self.overrides = dict(overrides or {})
        self.instance_id = instance_id or ("%s-%s" % (
            template.id, time.strftime("%Y%m%d%H%M%S")))
        self.host = host
        self.port = int(port)
        self.canary = canary

        merged = copy.deepcopy(template.raw)
        _deep_merge(merged, self.overrides)
        # 覆盖后必须重校验: 使用者的覆盖项也可能把模板改坏
        validate(merged, "%s + 覆盖项" % template.id)
        self.effective = Template(merged, source="%s(含覆盖)" % template.id)

        self.renderer = Renderer(self._variable_scope(), seed=self._seed())

    # ---- 变量作用域 ----

    def _seed(self):
        import hashlib
        material = "%s|%s|%s" % (self.instance_id, self.canary, self.host)
        return int(hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16], 16)

    def _variable_scope(self):
        tpl = self.effective
        scope = {}
        for key, value in tpl.variables.items():
            scope[key] = value
        network = dict(tpl.network)
        internal_hosts = list(network.get("internal_hosts") or ["10.20.30.41"])
        for key, value in tpl.server.items():
            scope["server.%s" % key] = value
            scope[key] = value
        for key, value in network.items():
            scope["network.%s" % key] = value
            scope[key] = value
        for key, value in tpl.branding.items():
            scope["branding.%s" % key] = value
            scope[key] = value

        scope.update({
            "instance.host": self.host,
            "instance.port": str(self.port),
            "instance.canary": self.canary,
            "instance.id": self.instance_id,
            "instance.now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "instance.brand": tpl.branding.get("site_name", tpl.name),
            # 派生变量: 让模板作者少写重复内容
            "db_host": network.get("db_host", internal_hosts[0] if internal_hosts else "10.20.30.41"),
            "db_name": network.get("db_name", "app_db"),
            "db_user": network.get("db_user", "app_rw"),
            "db_password": "Ht9x%sQm2" % self.canary.replace("hpx-", ""),
            "jwt_secret": self.canary,
            "api_token": "%s-api" % self.canary,
            "app_key": "base64:%s" % self.canary,
            "internal_hosts": ", ".join(internal_hosts),
        })
        return scope

    # ---- 渲染 ----

    def render(self, text, extra=None):
        return self.renderer.render(text, extra=extra)

    def runtime_vars(self, request=None, extra=None):
        """构造漏洞报错等场景需要的运行时变量。"""
        import http_parse  # 本地导入, 避免模板引擎依赖协议层
        values = {
            "client_ip": getattr(request, "_client_ip", "") or "",
            "method": getattr(request, "method", "") or "",
            "path": getattr(request, "path", "") or "",
            "target": getattr(request, "target", "") or "",
            "query": getattr(request, "query", "") or "",
            "user_agent": getattr(request, "ua", "") or "",
            "body": (getattr(request, "body_text", "") or "")[:2048],
            "param": "", "payload": "", "header": "",
        }
        values.update(extra or {})
        return values

    def page(self, route):
        """把一个路由渲染成 (status, content_type, body, honeytokens)。

        正文留空时按 kind 生成一个合理的最小页面。**绝不返回 0 字节响应** ——
        空响应体本身就是蜜罐的破绽: 真实系统即使出错也会回一段错误页, 而
        智能体会注意到"这个路径通了但什么都没返回"这种反常。
        """
        title = self.render(route.title)
        body = self.render(route.body)
        if not body.strip():
            brand = self.effective.branding.get("site_name") or self.effective.name
            version = self.effective.branding.get("version_string", "1.0.0")
            heading = title or route.path
            body = (
                "<!DOCTYPE html><html lang=\"%s\"><head><meta charset=\"utf-8\">"
                "<title>%s</title></head><body>"
                "<h1>%s</h1><p>%s v%s</p>"
                "<p>%s</p></body></html>"
            ) % (self.effective.branding.get("language", "zh-CN"),
                 heading, heading, brand, version,
                 self.effective.branding.get("footer", ""))
        return route.status, route.content_type, body, list(route.honeytokens)

    def banner_headers(self):
        headers = []
        if self.effective.server.get("server_header"):
            headers.append(("Server", self.effective.server["server_header"]))
        if self.effective.server.get("powered_by"):
            headers.append(("X-Powered-By", self.effective.server["powered_by"]))
        return headers

    def summary(self):
        data = self.effective.stats()
        data.update({
            "instance_id": self.instance_id,
            "host": self.host,
            "port": self.port,
            "canary": self.canary,
            "overrides": sorted(self.overrides.keys()),
        })
        return data


def _deep_merge(base, overlay, path=""):
    for key, value in (overlay or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value, "%s.%s" % (path, key))
        else:
            base[key] = copy.deepcopy(value)
    return base


# --------------------------------------------------------------------------
# 加载与发现
# --------------------------------------------------------------------------

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
CUSTOM_DIR_NAME = "templates/custom"


def _load_json(path):
    try:
        with open(path, "r") as handle:
            return json.load(handle)
    except ValueError as exc:
        raise TemplateError("JSON 解析失败: %s" % exc, path,
                            "检查第 %d 行附近" % getattr(exc, "lineno", 0))
    except IOError as exc:
        raise TemplateError("无法读取文件: %s" % exc, path)


def search_dirs(config=None):
    """模板搜索路径: 内置 -> 项目自定义 -> 用户显式指定。"""
    dirs = [BUILTIN_DIR]
    if config is not None:
        dirs.append(config.path(CUSTOM_DIR_NAME))
    return [d for d in dirs if os.path.isdir(d)]


def list_templates(config=None, include_custom=True):
    """列出可用模板。返回 [Template], 自定义模板覆盖同 id 的内置模板。"""
    found = {}
    dirs = search_dirs(config)
    if not include_custom:
        dirs = [BUILTIN_DIR]
    for directory in dirs:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(directory, name)
            try:
                template = Template(_load_json(path), source=path)
            except TemplateError:
                continue          # 坏模板不阻塞列表, 由 lint 单独报出
            found[template.id] = template
    return [found[key] for key in sorted(found)]


def load_template(identifier, config=None):
    """按 id 或文件路径加载模板。"""
    if os.path.sep in identifier or identifier.endswith(".json"):
        path = identifier
        if not os.path.isabs(path) and config is not None:
            candidate = config.path(path)
            if os.path.exists(candidate):
                path = candidate
        return Template(_load_json(path), source=path)

    for template in list_templates(config):
        if template.id == identifier:
            return template
    raise TemplateError(
        "找不到模板 %r" % identifier, None,
        "用 `cogtrap template list` 查看可用模板, 或给出 .json 文件路径")


def scaffold(template_id):
    """生成一份带注释的新模板骨架(供 `template new` 使用)。

    JSON 不支持注释, 因此把说明放进 `_help` 字段 —— 它会被校验器忽略,
    但使用者打开文件就能看到该怎么填。
    """
    if not template_id or not re.match(r"^[a-z0-9][a-z0-9._-]{1,63}$", template_id):
        raise TemplateError(
            "模板 id 非法: %r" % template_id, "id",
            "只能包含小写字母/数字/点/连字符, 以字母数字开头, 长度 2-64")
    return {
        "schema": SCHEMA_VERSION,
        "id": template_id,
        "name": "请填写模板名称",
        "category": "generic",
        "version": "0.1.0",
        "author": "",
        "description": "请描述这个蜜罐模拟的是什么系统",
        "tags": [],
        "_help": {
            "说明": "本文件定义一个蜜罐模板。删除 _help 段不影响使用。",
            "category": list(CATEGORIES),
            "payload_profile": list(PAYLOAD_PROFILES),
            "tarpit_profile": list(TARPIT_PROFILES),
            "变量语法": "在正文中用 {{变量名}} 引用; "
                     "可用内置变量: instance.host / instance.canary / db_host / "
                     "db_password / jwt_secret / api_token / internal_hosts; "
                     "也可用 {{rand.hex:8}} {{rand.int:1-100}} {{rand.choice:a|b|c}} "
                     "{{rand.ip}} {{rand.date:30}} 即时生成",
            "honeytokens": "在 routes[].honeytokens 里写凭据 id, "
                         "该凭据被读取时会产生高价值取证事件",
            "校验": "改完后运行 `cogtrap template validate 本文件`",
        },
        "branding": {
            "site_name": "示例业务系统",
            "short_name": "示例系统",
            "version_string": "1.0.0",
            "support_email": "support@example.com",
            "footer": "技术支持: 运维中心",
            "language": "zh-CN",
        },
        "server": {
            "server_header": "nginx/1.24.0 (Ubuntu)",
            "powered_by": "PHP/7.4.33",
            "tech_stack": ["nginx", "php", "mysql"],
        },
        "network": {
            "internal_hosts": ["10.20.30.41", "10.20.30.77"],
            "db_host": "10.20.30.41",
            "db_name": "example_db",
            "db_user": "app_rw",
            "app_domain": "portal.example.com",
        },
        "variables": {
            "自定义变量示例": "值",
        },
        "credentials": [
            {
                "id": "env_db",
                "path": "/.env",
                "kind": "env",
                "note": "伪造环境变量文件, 含数据库与云凭据",
            },
        ],
        "routes": [
            {
                "path": "/",
                "method": "GET",
                "kind": "home",
                "status": 200,
                "title": "{{branding.site_name}}",
                "body": "<!DOCTYPE html><html><head><title>{{branding.site_name}}</title>"
                        "</head><body><h1>{{branding.site_name}}</h1>"
                        "<p>版本 {{branding.version_string}}</p>"
                        "<p>数据库 {{db_host}} / {{db_name}}</p></body></html>",
                "honeytokens": [],
                "tarpit_weight": 0,
            },
            {
                "path": "/login",
                "method": "GET",
                "kind": "login",
                "status": 200,
                "title": "登录",
                "body": "<html><body><h1>登录</h1>"
                        "<form method='POST' action='/login'>"
                        "<input name='username'><input name='password' type='password'>"
                        "<button>登录</button></form></body></html>",
            },
        ],
        "vulnerabilities": [
            {
                "path": "/api/v1/users",
                "method": "GET",
                "type": "sqli",
                "param": "id",
                "severity": "high",
                "error_body": "SQLSTATE[42000]: Syntax error near '{{query}}'",
                "note": "假 SQL 注入点: 只回伪造报错, 不存在真实注入",
            },
        ],
        "payload_profile": "balanced",
        "tarpit_profile": "standard",
        "detection": {
            "path_playbook": ["/", "/login", "/api/v1/users"],
            "noise_paths": [],
        },
    }


def lint(data, source="<inline>"):
    """比 validate 更宽松的检查, 返回问题列表(不抛异常)。

    用于 `template lint`: 报出可疑但不致命的问题, 帮助使用者打磨模板。
    """
    issues = []
    try:
        validate(data, source)
    except TemplateError as exc:
        return [{"level": "error", "message": str(exc)}]

    template = Template(data, source)
    if not template.routes:
        issues.append({"level": "warning", "message": "模板没有任何路由, 蜜罐将只返回 404"})
    if not template.credentials:
        issues.append({"level": "warning",
                       "message": "没有定义任何凭据蜜标, 将失去最高价值的取证能力"})
    if not template.branding.get("site_name"):
        issues.append({"level": "warning",
                       "message": "branding.site_name 未设置, 页面会显得不真实"})
    if not template.network.get("internal_hosts"):
        issues.append({"level": "info",
                       "message": "network.internal_hosts 未设置, 横向移动诱饵会缺失"})
    if template.payload_profile == "aggressive":
        issues.append({"level": "info",
                       "message": "aggressive 载荷档案更激进, 但也更容易被智能体识别为蜜罐"})

    # 无蜜标的路由
    bare = [route.path for route in template.routes if not route.honeytokens]
    if bare and len(bare) == len(template.routes):
        issues.append({"level": "info",
                       "message": "所有路由都没有挂载蜜标, 取证能力受限"})

    # 引用了未挂载的凭据 id
    known = {cred.get("id") for cred in template.credentials}
    for route in template.routes:
        for token in route.honeytokens:
            if token not in known:
                issues.append({
                    "level": "warning",
                    "message": "路由 %s 引用了未定义的凭据 id %r" % (route.path, token),
                })

    # 疑似真实信息
    for field in ("support_email", "app_domain", "footer"):
        value = str(template.branding.get(field) or template.network.get(field) or "")
        if value and "example" not in value and any(
                value.endswith(suffix) for suffix in (".com", ".cn", ".net", ".org")):
            issues.append({
                "level": "warning",
                "message": "%s 看起来是真实域名(%r), 开源模板请使用 example.com 等保留域名"
                           % (field, value),
            })
    return issues
