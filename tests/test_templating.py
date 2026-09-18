"""模板引擎测试: 校验、渲染、定制、实例化。

重点验证两条"蜜罐可信度"的硬要求:
  · 渲染确定性 —— 同一实例渲染同一文本必须得到同一结果
  · **顺序无关性** —— 结果不能取决于调用历史, 否则攻击者来回访问会看到数据变化
"""

import json

import templating as T


def test_scaffold_passes_validation():
    T.validate(T.scaffold("demo-template"), "scaffold")


def test_scaffold_rejects_bad_id():
    for bad in ("", "A", "有中文", "has space", "x" * 80, "-leading"):
        try:
            T.scaffold(bad)
        except T.TemplateError:
            continue
        raise AssertionError("非法 id %r 未被拒绝" % bad)


def test_validation_rejects_undefined_variable():
    """语法合法但未定义的变量 —— 会在页面上原样残留 {{name}}。"""
    data = T.scaffold("t-vars")
    data["routes"][0]["body"] = "引用 {{undefined_thing}} 与 {{another_one}}"
    try:
        T.validate(data, "t-vars")
    except T.TemplateError as exc:
        assert "未定义的变量" in str(exc)
        return
    raise AssertionError("未定义变量未被校验拦下")


def test_validation_rejects_invalid_placeholder_syntax():
    """语法**不合法**的占位符是更隐蔽的失败: 它既不匹配变量正则, 也不报未定义,
    于是被静默留在页面上 —— 攻击者看到字面的 {{中文名}} 就明白这是假站点。

    中文变量名、含空格、数字开头、含连字符都属于这一类。
    """
    for bad in ("{{不存在的变量}}", "{{ var with space }}", "{{123abc}}", "{{a-b}}"):
        data = T.scaffold("t-ph")
        data["routes"][0]["body"] = "值: %s" % bad
        try:
            T.validate(data, "t-ph")
        except T.TemplateError as exc:
            assert "不合法的占位符" in str(exc), "报错类型不符: %s" % exc
            continue
        raise AssertionError("非法占位符 %r 未被拦下(会静默残留在页面上)" % bad)


def test_help_fields_are_exempt_from_placeholder_checks():
    """`_help` 是给人看的说明, 不参与渲染, 其中的示例占位符不应触发校验错误。"""
    data = T.scaffold("t-help")
    text = json.dumps(data, ensure_ascii=False)
    assert "{{变量名}}" in text or "{{" in text, "脚手架应含占位符示例"
    T.validate(data, "t-help")


def test_validation_rejects_duplicate_route():
    data = T.scaffold("t-dup")
    data["routes"].append(dict(data["routes"][0]))
    try:
        T.validate(data, "t-dup")
    except T.TemplateError as exc:
        assert "重复" in str(exc)
        return
    raise AssertionError("重复路由未被拒绝")


def test_validation_rejects_bad_enum_values():
    cases = [
        ({"category": "不存在"}, "未知分类"),
        ({"payload_profile": "狂暴"}, "未知载荷档案"),
        ({"tarpit_profile": "极重"}, "未知拖滞档案"),
    ]
    for patch, expect in cases:
        data = T.scaffold("t-enum")
        data.update(patch)
        try:
            T.validate(data, "t-enum")
        except T.TemplateError as exc:
            assert expect in str(exc), "报错不符: %s" % exc
            continue
        raise AssertionError("%s 未被拒绝" % patch)


def test_validation_rejects_invalid_route_fields():
    data = T.scaffold("t-route")
    data["routes"][0]["status"] = 9999
    try:
        T.validate(data, "t-route")
    except T.TemplateError:
        pass
    else:
        raise AssertionError("非法 status 未被拒绝")

    data = T.scaffold("t-route2")
    data["routes"][0]["path"] = "no-leading-slash"
    try:
        T.validate(data, "t-route2")
    except T.TemplateError:
        pass
    else:
        raise AssertionError("缺少前导斜杠的 path 未被拒绝")


def test_rendering_is_deterministic():
    template = T.Template(T.scaffold("t-det"), "t-det")
    args = dict(instance_id="i", host="h.example.com", port=8080, canary="hpx-c001")
    first = T.HoneypotInstance(template, **args)
    second = T.HoneypotInstance(template, **args)
    assert first.render("{{rand.hex:24}}") == second.render("{{rand.hex:24}}"), \
        "重建同参数实例得到不同随机值"


def test_rendering_is_order_independent():
    """核心回归: 渲染结果不得取决于调用历史。

    如果 {{rand.hex:8}} 的值来自共享随机流, 那么攻击者先访问 A 页、再访问 B 页、
    再回到 A 页, 会发现同一页面的数据变了 —— 那是"这是假站点"的直接证据。
    """
    template = T.Template(T.scaffold("t-order"), "t-order")
    instance = T.HoneypotInstance(template, instance_id="x", host="h", port=1,
                                  canary="hpx-k")
    page = "<p>{{rand.hex:12}}</p><p>{{rand.ip}}</p>"
    first = instance.render(page)
    for _ in range(40):
        instance.render("{{rand.hex:64}}{{rand.ip}}{{rand.int:1-999}}")
    assert instance.render(page) == first, "渲染结果受调用顺序影响"


def test_same_page_random_values_differ():
    data = T.scaffold("t-page")
    data["routes"][0]["body"] = "<p>A={{rand.hex:8}}</p>\n<p>B={{rand.hex:8}}</p>"
    instance = T.HoneypotInstance(T.Template(data, "t-page"), instance_id="p",
                                  host="h", port=1, canary="hpx-p")
    body = instance.page(instance.effective.routes[0])[2]
    assert "{{" not in body, "渲染后残留占位符: %s" % body
    lines = [line for line in body.splitlines() if line.startswith("<p>")]
    assert lines[0] != lines[1], "同页面内两个 rand.hex:8 得到相同值"


def test_random_functions_supported():
    """带参数的随机函数必须能真正渲染 —— 文档里宣传了它们。"""
    instance = T.HoneypotInstance(T.Template(T.scaffold("t-rand"), "t-rand"),
                                  instance_id="r", host="h", port=1, canary="hpx-r")
    cases = ["{{rand.hex:8}}", "{{rand.hex:32}}", "{{rand.int:1-100}}",
             "{{rand.choice:a|b|c}}", "{{rand.ip}}", "{{rand.date:30}}"]
    for text in cases:
        out = instance.render(text)
        assert "{{" not in out, "%s 未被替换(得到 %r)" % (text, out)
        assert out.strip(), "%s 渲染为空" % text


def test_overrides_take_effect_and_are_revalidated():
    template = T.Template(T.scaffold("t-ov"), "t-ov")
    instance = T.HoneypotInstance(template,
                                  overrides={"branding": {"site_name": "示例集团"}},
                                  instance_id="o", host="h", port=1, canary="hpx-o")
    assert instance.effective.branding["site_name"] == "示例集团"
    assert "示例集团" in instance.page(instance.effective.routes[0])[2]

    try:
        T.HoneypotInstance(template, overrides={"category": "不存在"}, instance_id="bad")
    except T.TemplateError:
        return
    raise AssertionError("覆盖项把模板改坏时未被拦截")


def test_no_zero_byte_responses():
    """任何路由都不能返回 0 字节 —— 空响应体本身就是蜜罐破绽。"""
    data = T.scaffold("t-empty")
    data["routes"].append({"path": "/empty", "method": "GET", "kind": "admin",
                           "status": 200, "body": "", "title": "管理后台"})
    instance = T.HoneypotInstance(T.Template(data, "t-empty"), instance_id="e",
                                  host="h", port=1, canary="hpx-e")
    for route in instance.effective.routes:
        body = instance.page(route)[2]
        assert body and body.strip(), "路由 %s 返回空正文" % route.path


def test_credentials_are_watermarked_per_instance():
    """凭据蜜标必须逐实例不同, 否则无法溯源到具体实例。"""
    data = T.scaffold("t-cred")
    template = T.Template(data, "t-cred")
    a = T.HoneypotInstance(template, instance_id="a", host="h", port=1, canary="hpx-aaa")
    b = T.HoneypotInstance(template, instance_id="b", host="h", port=1, canary="hpx-bbb")
    assert a.renderer.resolve("db_password") != b.renderer.resolve("db_password")
    assert "aaa" in a.renderer.resolve("db_password")
    assert "bbb" in b.renderer.resolve("db_password")


def test_lint_reports_actionable_issues():
    issues = T.lint(T.scaffold("t-lint"), "t-lint")
    assert isinstance(issues, list)
    levels = set(item["level"] for item in issues)
    assert levels <= {"info", "warning", "error"}

    bare = T.scaffold("t-bare")
    bare.pop("credentials", None)
    problems = T.lint(bare, "t-bare")
    assert any("蜜标" in item["message"] for item in problems), \
        "缺少蜜标时未给出提示"


def test_extra_vars_do_not_pollute_instance():
    """漏洞报错用的运行时变量必须是一次性的, 不能写进实例变量表。"""
    instance = T.HoneypotInstance(T.Template(T.scaffold("t-extra"), "t-extra"),
                                  instance_id="x", host="h", port=1, canary="hpx-x")
    with_extra = instance.render("id={{query}}", extra={"query": "1' OR 1=1"})
    assert with_extra == "id=1' OR 1=1"
    assert instance.render("id={{query}}") == "id={{query}}", \
        "一次性变量污染了实例上下文"


def test_runtime_vars_include_request_context():
    import http_parse
    instance = T.HoneypotInstance(T.Template(T.scaffold("t-rt"), "t-rt"),
                                  instance_id="x", host="h", port=1, canary="hpx-x")
    raw = b"GET /api/users?id=1' HTTP/1.1\r\nHost: h\r\nUser-Agent: probe/1\r\n\r\n"
    request = http_parse.parse_head(raw)
    values = instance.runtime_vars(request)
    assert values["path"] == "/api/users"
    assert values["query"] == "id=1'"
    assert values["user_agent"] == "probe/1"
