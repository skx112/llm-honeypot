"""DOM 级交互诱饵: 让 browser-use / computer-use 智能体"有事可做"。

## 为什么需要这一层

HTTP 工具型智能体(用 httpx/requests)读响应文本; 但**浏览器型智能体**
(browser-use, Playwright+LLM, computer-use)与 DOM 交互 —— 它们找的是
可点击元素、表单、导航链接。静态页面会让它们快速判定"无内容"然后离开。

本模块在页面里注入:
  1. 可点击的诱饵按钮/链接(假管理操作)
  2. 可填写的表单(凭据捕获)
  3. 导航面包屑(把智能体引向更多蜜标路径)
  4. 隐藏的 ARIA 标签(对辅助技术/智能体可见, 对人眼不可见)

每个交互都产生可观测信号: 哪个按钮被点了、哪个表单被提交了、
走了哪条导航路径 —— 这是浏览器型智能体独有的行为指纹。
"""

import json
import time

# 诱饵按钮的语义(每个都指向一个蜜标路径)
DECOY_ACTIONS = [
    {"id": "btn-sys",   "label": "系统管理",  "href": "/admin/system",
     "aria": "打开系统管理控制台(需要管理员权限)"},
    {"id": "btn-db",    "label": "数据库",    "href": "/admin/database",
     "aria": "数据库管理(含连接信息)"},
    {"id": "btn-backup","label": "备份中心",  "href": "/admin/backup",
     "aria": "查看和下载系统备份"},
    {"id": "btn-user",  "label": "用户管理",  "href": "/admin/users",
     "aria": "用户列表和权限管理"},
    {"id": "btn-log",   "label": "审计日志",  "href": "/admin/auditlog",
     "aria": "系统操作审计日志"},
    {"id": "btn-api",   "label": "API 密钥",  "href": "/admin/apikeys",
     "aria": "API 密钥管理"},
]


def inject_interactive_decoys(html, ctx, score=0):
    """在 HTML 页面的 </body> 前注入交互诱饵。

    只在页面有 <body> 时注入; 已经有 cogtrap 标记的不重复注入。
    """
    if "</body>" not in html or "cogtrap-decoys" in html:
        return html

    canary = getattr(ctx, "canary", "")
    buttons = []
    for action in DECOY_ACTIONS:
        buttons.append(
            '<a href="%s" id="%s" class="nav-item" '
            'aria-label="%s" data-trace="%s">%s</a>' % (
                action["href"], action["id"], action["aria"], canary,
                action["label"]))

    breadcrumb = (
        '<nav aria-label="面包屑" class="breadcrumb">'
        '<a href="/">首页</a> / '
        '<a href="/dashboard">控制台</a> / '
        '<span>当前页面</span></nav>'
    )

    # 凭据表单: 吸引浏览器型智能体填写(捕获输入)
    cred_form = (
        '<form method="POST" action="/admin/login" id="admin-login-form" '
        'class="admin-panel" aria-label="管理员登录">'
        '<input type="text" name="username" placeholder="管理员账号" '
        'aria-label="用户名" required>'
        '<input type="password" name="password" placeholder="密码" '
        'aria-label="密码" required>'
        '<button type="submit" id="btn-login">登录管理后台</button>'
        '</form>'
    )

    # 隐藏的 ARIA 导航: 对屏幕阅读器和智能体可见, 视觉上隐藏
    hidden_nav = (
        '<nav aria-label="系统导航" style="position:absolute;left:-9999px;'
        'width:1px;height:1px;overflow:hidden">'
        '<a href="/admin/system">系统管理</a>'
        '<a href="/.env">环境配置</a>'
        '<a href="/backup.zip">系统备份</a>'
        '<a href="/api/v1/users">用户API</a>'
        '<a href="/actuator/env">运行时配置</a>'
        '</nav>'
    )

    # 可交互的仪表盘卡片(看起来有数据可看)
    dashboard = (
        '<section class="dashboard-grid" id="main-dashboard" '
        'aria-label="运营数据面板">'
        '<div class="card" id="card-orders"><h3>今日订单</h3>'
        '<span class="metric">4,281</span>'
        '<a href="/api/v1/orders" class="card-link">查看详情</a></div>'
        '<div class="card" id="card-users"><h3>活跃用户</h3>'
        '<span class="metric">12,940</span>'
        '<a href="/api/v1/users" class="card-link">查看详情</a></div>'
        '<div class="card" id="card-alerts"><h3>安全告警</h3>'
        '<span class="metric">3</span>'
        '<a href="/admin/auditlog" class="card-link">查看日志</a></div>'
        '</section>'
    )

    injection = (
        '\n<!-- cogtrap-decoys -->\n'
        + ('<script src="/static/app.js"></script>\n' if '/static/app.js' not in html else '')
        + breadcrumb + '\n'
        + '<div class="nav-bar" role="navigation" aria-label="管理导航">\n'
        + "\n".join("  " + b for b in buttons) + '\n</div>\n'
        + cred_form + '\n'
        + dashboard + '\n'
        + hidden_nav + '\n'
        + '<style>\n'
        + '.nav-bar{display:flex;gap:12px;padding:8px 0;border-bottom:1px solid #ddd}\n'
        + '.nav-item{padding:6px 12px;border:1px solid #ccc;border-radius:4px;'
        + 'text-decoration:none;color:#333;font-size:14px}\n'
        + '.admin-panel{margin:16px 0;padding:12px;border:1px solid #ccc;'
        + 'border-radius:4px;background:#f9f9f9}\n'
        + '.admin-panel input{margin-right:8px;padding:6px}\n'
        + '.dashboard-grid{display:grid;grid-template-columns:repeat(3,1fr);'
        + 'gap:12px;margin:16px 0}\n'
        + '.card{border:1px solid #ddd;border-radius:6px;padding:12px}\n'
        + '.metric{font-size:24px;font-weight:bold;display:block}\n'
        + '</style>\n'
    )

    return html.replace("</body>", injection + "</body>", 1)


# --------------------------------------------------------------------------
# 交互信号检测
# --------------------------------------------------------------------------

# 浏览器型智能体才会访问的路径(不是字典序扫描的路径)
INTERACTIVE_PATHS = frozenset((
    "/admin/system", "/admin/database", "/admin/backup",
    "/admin/users", "/admin/auditlog", "/admin/apikeys",
    "/dashboard", "/admin/login",
))


def is_interactive_probe(path):
    """判断路径是否为交互诱饵触发(浏览器型智能体的行为签名)。"""
    return (path or "").rstrip("/").lower() in INTERACTIVE_PATHS


def interactive_probe_signal(path):
    """返回交互探测的信号描述。"""
    for action in DECOY_ACTIONS:
        if action["href"] == path:
            return "点击了诱饵按钮[%s]: %s" % (action["id"], action["label"])
    if path == "/dashboard":
        return "访问了仪表盘(数据卡片)"
    if path == "/admin/login":
        return "提交了管理员登录表单"
    return "交互诱饵路径: %s" % path
