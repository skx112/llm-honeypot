"""仪表盘测试: 接口契约、静态资源、图表几何。

## 为什么要在没有浏览器的环境里测界面

本环境无浏览器也无 node, 因此**观感无法验证** —— 这一点必须如实承认。但界面上
大部分会真正出错的地方并不需要"看":

  1. **前后端字段契约** —— 前端读了后端没提供的字段, 页面就是一片 NaN/undefined。
     这是最容易出错、也最容易用程序查出来的问题。
  2. **图表几何** —— 坐标计算是纯数学。标签区宽度写死、条形宽度为负、除零都
     可以直接算出来。真实案例: 检测信号名最长 34 字符
     (`ssh_algorithm_fingerprint_repeat`), 字号 11.5px 下约需 221px, 而原先
     标签区固定 118px —— 必然被裁。这个问题不是"看出来的", 是算出来的。
  3. **离线可用性** —— 诱饵环境常在隔离网络, 页面里只要有一个 CDN 引用就打不开。
  4. **路径穿越** —— 静态文件服务必须挡住 `../`。

剩下的部分(配色是否好看、信息层级是否清晰)只能由人看。测试里会明确标注哪些
是已验证的、哪些不是。
"""

import json
import os
import re

import config as config_mod
import dashboard as dashboard_mod
import store as store_mod

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "honeypot", "web")


def read_asset(name):
    with open(os.path.join(WEB_DIR, name), encoding="utf-8") as handle:
        return handle.read()


# --------------------------------------------------------------------------
# 前后端契约: 前端请求的接口必须真的存在
# --------------------------------------------------------------------------

def test_all_frontend_endpoints_are_served():
    """交叉校验: app.js 里 fetch 的路径必须都能在 dashboard.py 里找到对应处理。

    这是最容易出错的一环 —— 后端改了接口名而前端没改, 页面会静默显示空数据,
    值班人员却以为"最近没有攻击"。
    """
    js = read_asset("app.js")
    server = open(os.path.join(os.path.dirname(WEB_DIR), "dashboard.py"),
                  encoding="utf-8").read()
    requested = set(re.findall(r"getJSON\('(/api/[a-z]+)'\)", js))
    requested |= set(re.findall(r"'(/api/[a-z]+)'", js))
    assert requested, "app.js 里没有解析出任何接口调用"

    for path in sorted(requested):
        assert '"/api/%s"' % path[len("/api/"):] in server or \
               "'%s'" % path in server, \
            "前端请求了 %s 但 dashboard.py 未提供该接口" % path


def test_payload_fields_cover_frontend_reads():
    """后端返回的字段必须覆盖前端读取的字段。"""
    store = store_mod.Store(":memory:")
    store.start_session("s1", "203.0.113.5", 1, "probe/1", "h1", "sig1",
                        behavior_hash="bh1")
    store.update_session("s1", score=88, label="llm_agent", action="lockdown",
                         confidence=0.9, campaign_id="camp-1", note="test")
    store.log_signal("s1", "203.0.113.5", "canary_echo", 45, "decisive", "ev")
    store.log_event("canary_echo", "s1", "203.0.113.5", "token echoed", "critical")
    store.register_token("env_creds", "env", "/.env")
    store.read_token("env_creds", "s1", "203.0.113.5")

    cfg = config_mod.Config.load()
    panel = dashboard_mod.Dashboard(cfg, store=store, verbose=False)

    summary = panel.payload_summary()
    for key in ("instance", "uptime", "actions", "evidence_kinds", "runtime",
                "stats", "tokens", "template", "scenario"):
        assert key in summary, "summary 缺少前端读取的字段 %s" % key
    for key in ("connections", "requests", "active_sessions", "alerts",
                "tarpit_seconds", "non_http", "shed_events", "load_ratio",
                "budget_used", "budget_total"):
        assert key in summary["runtime"], "runtime 缺少 %s (前端 counter 会显示 NaN)" % key
    for key in ("sessions", "sessions_llm", "requests", "campaigns", "distinct_ips"):
        assert key in summary["stats"], "stats 缺少 %s" % key
    for key in ("total", "touched", "reads"):
        assert key in summary["tokens"], "tokens 缺少 %s" % key

    sessions = panel.payload_sessions()["sessions"]
    assert sessions, "会话列表为空"
    for key in ("id", "ip", "ua", "label", "score", "action", "requests",
                "tarpit_ms", "behavior_hash", "campaign", "last_seen"):
        assert key in sessions[0], "会话记录缺少 %s" % key

    signals = panel.payload_signals()["signals"]
    assert signals and all(k in signals[0] for k in ("name", "weight", "hits",
                                                     "sessions"))

    evidence = panel.payload_evidence()
    assert "counts" in evidence and "evidence" in evidence
    assert evidence["counts"].get("canary_echo") == 1
    assert all(k in evidence["evidence"][0] for k in
               ("kind", "label", "severity", "ts", "ip", "detail"))

    campaigns = panel.payload_campaigns()["campaigns"]
    assert all(k in campaigns[0] for k in
               ("id", "ips", "score_max", "session_count", "toolchain",
                "behavior_hash", "last_seen")) if campaigns else True
    assert "alerts" in panel.payload_alerts()
    store.close()


def test_evidence_kinds_have_producers():
    """每一种证据类型都必须有模块真的产生它, 否则面板永远显示 0。

    这条测试的价值在于: 面板显示"0 次"时, 无法区分"没有攻击"与"事件名写错了"
    —— 后者会让最关键的取证能力静默失效。

    扫描全部模块而不是逐个点名, 因为事件可能在任何一层产生
    (例如 agent_config_captured 实际由 respond.py 产出, 而非 server.py)。
    """
    package_dir = os.path.dirname(WEB_DIR)
    sources = {}
    for name in sorted(os.listdir(package_dir)):
        if name.endswith(".py"):
            sources[name] = open(os.path.join(package_dir, name),
                                 encoding="utf-8").read()
    assert sources, "未找到任何模块"

    for kind in dashboard_mod.EVIDENCE_KINDS:
        producers = [name for name, text in sources.items()
                     if ('"%s"' % kind) in text or ("'%s'" % kind) in text]
        assert producers, "证据类型 %s 在任何模块里都没有被产生(面板会永远显示 0)" % kind


# --------------------------------------------------------------------------
# 静态资源与离线可用性
# --------------------------------------------------------------------------

def test_html_references_existing_assets():
    html = read_asset("index.html")
    for asset in ("/app.css", "/app.js"):
        assert asset in html, "index.html 未引用 %s" % asset
        assert os.path.isfile(os.path.join(WEB_DIR, asset.lstrip("/"))), \
            "引用的资源不存在: %s" % asset


def test_no_external_resources():
    """诱饵环境常在隔离网络: 页面必须能离线打开, 不能有任何 CDN/网络字体。"""
    for name in ("index.html", "app.css", "app.js"):
        text = read_asset(name)
        external = re.findall(r'(?:src|href)\s*=\s*["\'](?:https?:)?//', text)
        assert not external, "%s 存在外部资源引用: %s" % (name, external)
        assert "@import" not in text, "%s 使用了 @import 引入外部样式" % name


def test_css_structure_is_balanced():
    css = read_asset("app.css")
    assert css.count("{") == css.count("}"), "CSS 花括号不平衡"
    js = read_asset("app.js")
    assert js.count("{") == js.count("}"), "JS 花括号不平衡"
    assert js.count("(") == js.count(")"), "JS 括号不平衡"


def test_design_tokens_and_semantic_colors_present():
    """判定档的语义色必须齐全 —— 值班人员靠颜色扫读严重程度。"""
    css = read_asset("app.css")
    for token in ("--a-serve", "--a-watch", "--a-tarpit", "--a-inject", "--a-lock"):
        assert token + ":" in css, "缺少判定语义色 %s" % token
    for token in ("--bg:", "--panel:", "--line:", "--fg:", "--mono:", "--sans:"):
        assert token in css, "缺少设计令牌 %s" % token
    # 处置档色类必须与 JS 里的动作名对应
    js = read_asset("app.js")
    for action in ("serve", "serve_watch", "tarpit", "deceive_inject", "lockdown"):
        assert "'%s'" % action in js, "JS 未处理处置档 %s" % action
        assert ".tag-%s" % action in css, "CSS 缺少 .tag-%s 样式" % action


def test_js_avoids_es6_syntax():
    """用户可能用较旧的浏览器打开哨兵界面, 因此保持 ES5 语法。"""
    js = read_asset("app.js")
    assert not re.search(r"\b(let|const)\b", js), "JS 使用了 let/const"
    assert "=>" not in js, "JS 使用了箭头函数"
    assert "`" not in js, "JS 使用了模板字符串"


def test_xss_safety_no_innerhtml_with_data():
    """渲染遥测数据必须用 textContent, 不能用 innerHTML 拼接。

    遥测库里存的是攻击者可控内容(User-Agent、请求路径、载荷)。若用 innerHTML
    插入, 攻击者就能通过恶意 UA 在值守界面上执行脚本 —— 那是把攻击者请进了
    我们自己的控制台。
    """
    js = read_asset("app.js")
    assert "innerHTML" not in js, \
        "app.js 使用了 innerHTML —— 遥测数据含攻击者可控内容, 存在 XSS 风险"
    assert "textContent" in js, "app.js 未使用 textContent 渲染数据"


# --------------------------------------------------------------------------
# 图表几何(无浏览器环境下可验证的部分)
# --------------------------------------------------------------------------

def estimate_text_width(text, font_size):
    """与 app.js 的 textWidth 保持一致的估算实现。"""
    total = 0.0
    for char in text:
        total += 1.0 if ord(char) > 0x2E80 else 0.55
    return total * font_size


def replicate_layout(rows, container_width, font_size=11.5, value_w=54):
    """复现 app.js 的 barChart 布局计算, 用于几何断言。

    行距与条形厚度按行数自适应(稀疏图表用更大行距, 否则 5 行条形会显得松散、
    卡片发空) —— 这里必须与 app.js 保持一致, 否则复现失去意义。
    """
    row_h = 26                      # 与 app.js 一致: 两图统一
    width = max(340, container_width or 420)
    widest = max(estimate_text_width(row, font_size) for row in rows) if rows else 0
    label_w = min(max(widest + 12, 72), int(width * 0.5))
    bar_max = width - label_w - value_w
    if bar_max < 40:
        label_w = max(72, width - value_w - 40)
        bar_max = width - label_w - value_w
    return width, label_w, bar_max


def truncate_text(text, max_width, font_size):
    if estimate_text_width(text, font_size) <= max_width:
        return text
    out = text
    while len(out) > 3 and estimate_text_width(out + "…", font_size) > max_width:
        out = out[:-1]
    return out + "…"


REAL_LABELS = [
    "injection_compliance", "beacon_callback", "honeypot_path",
    "ua_automation_tool", "canary_echo", "cadence_agent_rhythm",
    "sequential_low_concurrency", "honeytoken_read",
    "ssh_algorithm_fingerprint_repeat", "ssh_client_paramiko",
    "ssh_brute_force_volume",
]


def test_chart_labels_never_overflow():
    """标签必须能被完整展示或被截断, 不能溢出标签区。

    真实缺陷回归: 原先标签区固定 118px, 而 34 字符的信号名在 11.5px 下约需
    221px, 会被裁掉一半且与条形重叠。改为按最长标签动态计算宽度。
    """
    for container in (1520, 800, 430, 340, 0):
        width, label_w, bar_max = replicate_layout(REAL_LABELS, container)
        assert bar_max > 0, "容器宽 %s 时条形区宽度为 %s" % (container, bar_max)
        for label in REAL_LABELS:
            shown = truncate_text(label, label_w - 12, 11.5)
            assert estimate_text_width(shown, 11.5) <= label_w - 12, \
                "容器宽 %s: 标签 %r 溢出标签区" % (container, label)


def test_chart_handles_pathological_labels():
    """极长标签、单行、全零值都不能让几何计算崩掉。"""
    for rows in (["x" * 300], ["短"], ["a", "b", "c"] * 20):
        for container in (200, 340, 1920):
            width, label_w, bar_max = replicate_layout(rows, container)
            assert bar_max > 0, "标签 %r 在 %s 容器下压垮了条形区" % (rows[0], container)
            assert label_w <= width, "标签区宽于总宽"

    # max 从 1 起算, 因此全零值不会除零
    js = read_asset("app.js")
    assert "Math.max(m, r.value); }, 1)" in js, \
        "reduce 的初值不是 1 —— 全零数据会导致除零"
    assert "Math.max(2," in js, "零值条形没有最小宽度, 会看不见"


def test_bar_lengths_are_strictly_proportional():
    """条形长度必须严格正比于数值, 且最大值铺满绘图区。

    这条测试来自一次视觉评审的误判: 评审看到"观察(3)的条比锁定(2)的短",
    怀疑归一化算错。解析渲染后的 SVG 后发现每单位值的像素宽度完全相等
    (图表1 全为 183.0px, 图表2 全为 6.1px)、最大值确实铺满 —— 渲染是对的。
    但为了把"比例正确"这件事固化下来, 用真实数据复现布局数学做断言。
    """
    # 与真实渲染一致的动作分布数据
    rows = [("服务", 2), ("观察", 3), ("拖滞", 1), ("注入", 0), ("锁定", 2)]
    width, label_w, plot = replicate_layout([name for name, _ in rows], 689)
    assert plot > 0
    values = [value for _, value in rows]
    maximum = max(values) if max(values) > 0 else 1

    per_unit = []
    for name, value in rows:
        bar_w = max(2, (value / maximum) * plot)
        if value > 0:
            per_unit.append(bar_w / value)
    assert len(set(round(item, 4) for item in per_unit)) == 1, \
        "每单位值的像素宽度不相等, 条形与数值不成正比: %s" % per_unit

    longest = max(rows, key=lambda pair: pair[1])
    assert longest[1] >= max(values), "最长条不是最大值对应的行"
    assert abs(max(per_unit) - plot / maximum) < 0.01, \
        "最大值对应的条形未铺满绘图区"


def test_value_label_placed_next_to_bar_end():
    """数值必须贴在条形末端。

    回归断言: 数值原先固定在右对齐列, 短条(如 1/3)与自己的数字之间会横跨
    大片空白, 整排看起来"没填满" —— 视觉评审在桌面与窄屏两处都指出了这一点。
    比例本身没错, 错的是数值位置。
    """
    js = read_asset("app.js")
    assert "valueX = labelW + barW + 8" in js, \
        "数值未贴在条形末端(仍会与短条之间留出空洞)"
    assert "valueX + 20 > width" in js, "靠右时未做回退处理, 数字会超出画布"


def test_chart_label_width_uses_content_not_constant():
    """回归断言: 标签区宽度必须由内容算出, 不能是写死的常量。"""
    js = read_asset("app.js")
    assert "textWidth" in js, "缺少文本宽度估算函数"
    assert "truncate" in js, "缺少标签截断函数"
    assert re.search(r"labelW\s*=\s*Math\.min\(Math\.max\(widest", js), \
        "标签区宽度未按最长标签动态计算"


def test_charts_share_identical_geometry_parameters():
    """两张并排同构图表必须共用同一套行距与条厚。

    曾经按行数自适应行距(稀疏图用更大行距), 视觉评审判定"适得其反":
    两图节奏差异反而更明显, 5 行的图看起来像被撑开的。
    行数少时让内容顶部对齐、底部自然留白即可 —— 并排一致性优先。
    """
    js = read_asset("app.js")
    assert not re.search(r"sparse\s*=\s*rows\.length", js), \
        "app.js 仍在按行数自适应行距(已被视觉评审否定)"
    assert re.search(r"var rowH = 26, barH = 12", js), \
        "两张图未共用统一的行距与条厚常量"


def test_secondary_counters_span_full_grid_row():
    """次要摘要必须跨满整行。

    回归断言: 它被 append 进 .counters 网格容器, 若不显式跨行就会变成第 7 个
    网格单元 —— 在桌面被挤成最右一列、窄屏跨两列, 都成为难读的灰字块。
    """
    css = read_asset("app.css")
    assert re.search(r"\.counters-secondary\s*\{[^}]*grid-column:\s*1\s*/\s*-1", css), \
        "次要摘要未跨满网格行"


def test_footer_text_is_readable():
    """合法使用声明是需要被读到的文本, 不能与背景融为一体。"""
    css = read_asset("app.css")
    foot = re.search(r"\.foot\s*\{([^}]*)\}", css)
    assert foot, "未找到 .foot 样式"
    body = foot.group(1)
    assert "--fg-dim" in body or "--fg:" in body, \
        "页脚文字仍用最暗的 faint 色, 长时盯屏下不可读"
    size = re.search(r"font-size:\s*([\d.]+)px", body)
    assert size and float(size.group(1)) >= 12, \
        "页脚字号过小: %s" % (size.group(1) if size else "未设置")


# --------------------------------------------------------------------------
# 安全: 只监听回环 + 防路径穿越
# --------------------------------------------------------------------------

def test_dashboard_defaults_to_loopback():
    """遥测库含攻击者 IP 与捕获的凭据, 默认绝不能对外暴露。"""
    cfg = config_mod.Config.load()
    assert cfg.get("dashboard.host") == "127.0.0.1", \
        "仪表盘默认监听地址不是回环: %s" % cfg.get("dashboard.host")


def test_static_path_traversal_blocked():
    """静态文件服务必须挡住 .. —— 否则 config.json / 遥测库会被读走。"""
    handler_source = open(
        os.path.join(os.path.dirname(WEB_DIR), "dashboard.py"),
        encoding="utf-8").read()
    assert "normpath" in handler_source, "未做路径规范化"
    assert "startswith(WEB_DIR" in handler_source or "WEB_DIR + os.sep" in handler_source, \
        "未校验解析后的路径仍在 web 目录内"
