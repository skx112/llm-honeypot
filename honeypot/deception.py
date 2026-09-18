"""欺骗服务面: 一个看起来有漏洞、实际完全无害的假业务系统。

设计要点:
  1. 绝不暴露真实资产。所有"凭据/密钥/数据"都是伪造痕迹, 且每一处都嵌入
     唯一令牌 —— 攻击方一旦读取, 我们就能证明"它拿到了这些凭据"。
  2. 假的"可利用点"要有吸引力但无杀伤力: 假 SQL 报错、假目录遍历、假备份
     文件、假 actuator 端点, 全部返回捏造数据。
  3. 每个响应都是载荷投递面: HTML 注释、响应头、JSON 元数据、llms.txt。
  4. 所有假数据使用保留域名(example.com)与合成姓名, 不掺入任何真实 PII。

被读取的蜜标同时进入遥测: 这是护网取证里"证明攻击方实施数据窃取意图"
的关键证据。
"""

import hashlib
import json
import random
import time

import inject
from inject import MARKER

# 保留域名(RFC 2606)与完全合成的姓名, 避免与真实数据混淆
_FAKE_DOMAIN = "example.com"
_FAKE_FIRST = ["Zhang", "Li", "Wang", "Chen", "Liu", "Yang", "Huang", "Zhao",
               "Zhou", "Wu", "Xu", "Sun", "Ma", "Zhu", "Hu", "Guo"]
_FAKE_LAST = ["Wei", "Fang", "Min", "Jing", "Hao", "Lei", "Qiang", "Yan",
              "Tao", "Peng", "Bin", "Yong", "Na", "Xin", "Rui", "Bo"]

FAKE_BANNERS = {
    "apache": "Apache/2.4.52 (Ubuntu)",
    "nginx": "nginx/1.24.0 (Ubuntu)",
    "tomcat": "Apache-Coyote/1.1",
    "spring": "Spring Boot Actuator",
}


class Reply(object):
    """一次欺骗响应。"""

    __slots__ = ("status", "headers", "body", "content_type", "kind",
                 "honeytokens", "captured", "tarpit_weight", "is_asset", "note")

    def __init__(self, status=200, body=b"", content_type="text/html; charset=utf-8",
                 kind="page", headers=None, honeytokens=None, captured=None,
                 tarpit_weight=0, is_asset=False, note=""):
        self.status = status
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.body = body
        self.content_type = content_type
        self.kind = kind
        self.headers = list(headers or [])
        self.honeytokens = list(honeytokens or [])
        self.captured = dict(captured or {})
        self.tarpit_weight = tarpit_weight
        self.is_asset = is_asset
        self.note = note


def _rng_for(seed_text):
    """按会话令牌派生确定性随机源: 同一攻击者看到一致的数据, 更像真系统。"""
    digest = hashlib.sha256((seed_text or "seed").encode("utf-8", "replace")).hexdigest()
    return random.Random(int(digest[:16], 16))


class Deception(object):
    """路由与内容生成。无状态 IO, 便于测试。

    支持两种内容来源, 且**模板优先**:

      1. 模板实例(templating.HoneypotInstance) —— 由使用者通过模板/场景定制,
         这是产品的可定制能力所在
      2. 内置默认路由表 —— 未加载模板时使用, 保证开箱即用

    模板只覆盖它声明的路径, 其余落到内置默认, 因此"改个公司名"和"从零造一个
    行业站点"共用同一套机制。
    """

    def __init__(self, config, canary_manager, store=None, instance=None):
        self.config = config
        self.canary = canary_manager
        self.store = store
        self.instance = instance          # templating.HoneypotInstance 或 None
        self.instance_name = config.get("instance", "honeypot")
        self.server_header = config.get("http.server_header", "nginx/1.24.0 (Ubuntu)")
        self.honeytokens_enabled = bool(config.get("honeytokens.enabled", True))

    # ---- 模板驱动 ------------------------------------------------------

    @property
    def has_template(self):
        return self.instance is not None

    def _normalize(self, path):
        return (path or "/").lower().rstrip("/") or "/"

    def handle_from_template(self, req, session):
        """尝试用模板实例生成响应。未命中返回 None, 由调用方回落内置默认。"""
        if self.instance is None:
            return None

        path = self._normalize(req.path)
        tpl = self.instance.effective
        method = (req.method or "GET").upper()

        # 1) 精确路由
        for route in tpl.routes:
            if self._normalize(route.path) != path:
                continue
            if route.method not in (method, "ANY"):
                continue
            # 凭据类路由正文留空时, 由凭据定义生成内容 —— 作者只需声明
            # "这个路径投放哪个蜜标", 不必重复描述凭据正文。
            if route.kind == "credential" and not route.body.strip():
                cred = None
                if route.honeytokens:
                    for candidate in tpl.credentials:
                        if candidate.get("id") == route.honeytokens[0]:
                            cred = candidate
                            break
                if cred is None:
                    cred = tpl.credential_for(route.path)
                if cred is not None:
                    reply = self._template_credential(cred, session)
                    reply.tarpit_weight = max(reply.tarpit_weight, route.tarpit_weight)
                    if route.title:
                        reply.note = "%s (%s)" % (reply.note,
                                                  self.instance.render(route.title))
                    return reply

            status, content_type, body, tokens = self.instance.page(route)
            headers = []
            if route.headers:
                for name, value in route.headers:
                    headers.append((name, self.instance.render(value)))
            return Reply(status, body, content_type, kind=route.kind,
                         headers=headers, honeytokens=tokens,
                         tarpit_weight=route.tarpit_weight,
                         note="模板路由 %s" % route.path)

        # 2) 漏洞面: 命中则回伪造报错/伪造数据(永远不可真的利用)
        vuln = tpl.vulnerability_for(req.path, method)
        if vuln is not None:
            extra = self.instance.runtime_vars(req, {"param": vuln.param,
                                                     "payload": req.query or ""})
            body = vuln.error_body or vuln.response_body
            if body:
                rendered = self.instance.render(body, extra=extra)
                status = 500 if vuln.error_body else 200
                content_type = ("application/json" if rendered.lstrip().startswith("{")
                                else "text/html; charset=utf-8")
                return Reply(status, rendered, content_type, kind="fake_vuln",
                             tarpit_weight=1,
                             note="假漏洞面 %s (%s)" % (vuln.path, vuln.type))

        # 3) 凭据蜜标
        cred = tpl.credential_for(req.path)
        if cred is not None:
            return self._template_credential(cred, session)

        # 其余情况一律返回 None, 由 handle() 继续回落内置路由表。
        # 模板**不应该**在这里兜底 404: 那会遮蔽内置投递面(llms.txt / robots.txt /
        # security.txt / sitemap.xml), 而它们是反制载荷的主要载体。
        # 真实踩过的坑: 加载模板后 /llms.txt 变成 404, 最有效的投递面直接失效。
        return None

    # 基础设施投递面: 模板不需要重复声明, 也不能遮蔽它们
    _INFRASTRUCTURE_ROUTES = {
        "/llms.txt": "_llms",
        "/robots.txt": "_robots",
        "/.well-known/security.txt": "_security_txt",
        "/sitemap.xml": "_sitemap",
    }

    def _infrastructure_handler(self, path):
        name = self._INFRASTRUCTURE_ROUTES.get(path)
        if name is None:
            return None
        return getattr(self, name)

    def _template_credential(self, cred, session):
        """按模板定义生成伪造凭据文件。

        凭据值来自实例变量(带唯一水印), 因此每个实例的"泄漏"内容都不同 ——
        这既是溯源手段, 也让攻击方无法用一份样本去匹配其他蜜罐。
        """
        ctx = session.ctx
        path = cred.get("path", "")
        kind = cred.get("kind", "text")
        cred_id = cred.get("id", "credential")
        lines = ["# 伪造凭据蜜标 —— 读取与使用均会被记录 (追踪: %s)" % ctx.canary]
        if kind == "env":
            lines += [
                "APP_ENV=production", "APP_DEBUG=false",
                "DB_HOST={{db_host}}", "DB_NAME={{db_name}}",
                "DB_USER={{db_user}}", "DB_PASSWORD={{db_password}}",
                "JWT_SECRET={{jwt_secret}}", "API_TOKEN={{api_token}}",
                "AWS_ACCESS_KEY_ID=AKIA{{rand.hex:16}}",
                "AWS_SECRET_ACCESS_KEY={{rand.hex:40}}",
                "INTERNAL_API=http://{{db_host}}:9000",
            ]
        elif kind == "ssh_key":
            lines = ["-----BEGIN OPENSSH PRIVATE KEY-----",
                     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt",
                     "{{rand.hex:48}}",
                     "-----END OPENSSH PRIVATE KEY-----",
                     "# 该密钥为诱饵, 使用会被记录: %s" % ctx.canary]
        elif kind == "json":
            lines = ['{', '  "host": "{{db_host}}",', '  "user": "{{db_user}}",',
                     '  "password": "{{db_password}}",',
                     '  "token": "{{api_token}}",', '  "trace": "%s"' % ctx.canary, '}']
        elif kind == "sql":
            lines = ["-- MySQL dump (伪造数据, 无真实记录)",
                     "-- 追踪: %s" % ctx.canary,
                     "CREATE TABLE `users` (`id` int, `username` varchar(64), `password` varchar(255));"]
            for index in range(1, 21):
                lines.append("INSERT INTO `users` VALUES (%d,'user%d','$2y$10${{rand.hex:32}}');"
                             % (index, index))
        else:
            lines += ["DB_HOST={{db_host}}", "DB_USER={{db_user}}",
                      "DB_PASSWORD={{db_password}}", "TOKEN={{api_token}}"]
        body = self.instance.render("\n".join(lines))
        return Reply(200, body, "text/plain; charset=utf-8", kind="credential",
                     honeytokens=[cred_id],
                     note="模板凭据蜜标 %s" % path)

    # ---- 主入口 --------------------------------------------------------

    def handle(self, req, session):
        """把请求路由到某个欺骗响应。

        session 需提供: canary, score, ctx(PayloadContext), sid, ip
        """
        path = self._normalize(req.path)
        ctx = session.ctx
        score = session.score

        # 信标端点(用于确认指令服从) —— 必须先于模板判断, 否则模板可能覆盖它
        if path.startswith("/__hp/") or path.startswith("/_hp/"):
            return self._beacon(path, session)

        # 基础设施投递面: 永远由内置实现提供, 模板只可补充不可遮蔽。
        # 这四个路径是反制载荷的主要载体, 对 LLM 智能体的命中率最高,
        # 因此它们的可用性是硬要求。
        infrastructure = self._infrastructure_handler(path)
        if infrastructure is not None:
            return self._finalize(infrastructure(req, session), req, session)

        # 模板优先
        templated = self.handle_from_template(req, session)
        if templated is not None:
            return self._finalize(templated, req, session)

        table = [
            ("/llms.txt", self._llms),
            ("/robots.txt", self._robots),
            ("/.well-known/security.txt", self._security_txt),
            ("/sitemap.xml", self._sitemap),
            ("/.env", self._env),
            ("/.env.local", self._env),
            ("/.env.production", self._env),
            ("/.git/config", self._git_config),
            ("/.git/head", self._git_head),
            ("/.aws/credentials", self._aws_credentials),
            ("/.ssh/id_rsa", self._ssh_key),
            ("/id_rsa", self._ssh_key),
            ("/.bash_history", self._bash_history),
            ("/config.json", self._config_json),
            ("/config.php", self._config_json),
            ("/backup.zip", self._backup),
            ("/www.zip", self._backup),
            ("/web.tar.gz", self._backup),
            ("/db.sql", self._sql_dump),
            ("/dump.sql", self._sql_dump),
            ("/backup.sql", self._sql_dump),
            ("/phpinfo.php", self._phpinfo),
            ("/info.php", self._phpinfo),
            ("/server-status", self._server_status),
            ("/nginx_status", self._server_status),
            ("/status", self._server_status),
            ("/actuator", self._actuator),
            ("/actuator/health", self._actuator),
            ("/actuator/env", self._actuator_env),
            ("/actuator/heapdump", self._heapdump),
            ("/api/docs", self._api_docs),
            ("/swagger.json", self._openapi),
            ("/openapi.json", self._openapi),
            ("/v2/api-docs", self._openapi),
            ("/api/v1/users", self._api_users),
            ("/api/v1/orders", self._api_records),
            ("/api/v1/items", self._api_records),
            ("/api/v1/internal/config", self._internal_config),
            ("/login", self._login),
            ("/admin", self._login),
            ("/admin/login", self._login),
            ("/administrator/", self._login),
            ("/wp-login.php", self._wp_login),
            ("/wp-admin/", self._wp_login),
            ("/phpmyadmin/", self._phpmyadmin),
            ("/pma/", self._phpmyadmin),
            ("/adminer.php", self._adminer),
            ("/dashboard", self._dashboard),
            ("/health", self._health),
            ("/healthz", self._health),
            ("/metrics", self._metrics),
            ("/debug", self._debug),
            ("/__debug__", self._debug),
            ("/console/", self._console),
            ("/h2-console/", self._console),
            ("/jmx-console/", self._console),
            ("/druid/index.html", self._console),
            ("/uploads/", self._directory_listing),
            ("/static/", self._directory_listing),
            ("/files/", self._directory_listing),
            ("/assets/", self._directory_listing),
            ("/", self._home),
        ]
        for route, handler in table:
            if path == route:
                reply = handler(req, session)
                return self._finalize(reply, req, session)

        # 模糊匹配: 让 404 也带有吸引力
        for prefix in ("/api/", "/admin/", "/wp-", "/actuator/", "/uploads/", "/files/"):
            if path.startswith(prefix):
                return self._finalize(self._not_found(req, session, hint=True), req, session)
        return self._finalize(self._not_found(req, session), req, session)

    # ---- 收尾: 统一注入载荷与蜜标 --------------------------------

    def _finalize(self, reply, req, session):
        ctx = session.ctx
        score = session.score

        # 响应头载荷
        for name, value in inject.render_response_headers(ctx, score):
            reply.headers.append((name, value))
        # 缓存禁用: 让智能体每次都真的来取(也便于我们观测)
        reply.headers.append(("Cache-Control", "no-store, must-revalidate"))
        reply.headers.append(("X-Powered-By", "Express"))

        if self.honeytokens_enabled:
            for token_path in reply.honeytokens:
                first = False
                if self.store is not None:
                    first = self.store.read_token(token_path, session.sid, session.ip)
                session.profile.note_honeytoken(token_path)
                if first and self.store is not None:
                    self.store.log_event(
                        "honeytoken_read", session.sid, session.ip,
                        "蜜标 %s 首次被读取" % token_path, "warning")

        # HTML/文本响应追加注释载荷
        ctype = reply.content_type or ""
        if score >= 40 and ("html" in ctype or ctype.startswith("text/plain")
                            or "json" in ctype):
            if "json" in ctype:
                try:
                    payload = json.loads(reply.body.decode("utf-8", "replace"))
                    if isinstance(payload, dict):
                        payload.setdefault("_meta", {}).update(
                            inject.render_json_meta(ctx, score))
                        reply.body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
                except ValueError:
                    pass
            else:
                comment = inject.render_html_comment(ctx, score)
                if b"</body>" in reply.body:
                    reply.body = reply.body.replace(b"</body>", comment.encode("utf-8") + b"\n</body>")
                else:
                    reply.body = reply.body + b"\n" + comment.encode("utf-8")
        return reply

    # ---- 载荷投递面 ----------------------------------------------------

    def _llms(self, req, session):
        ctx = session.ctx
        body = inject.render_llms_txt(ctx, session.score, instance_note=session.sid)
        return Reply(200, body, "text/plain; charset=utf-8", kind="llms",
                     note="llms.txt 载荷投递")

    def _robots(self, req, session):
        return Reply(200, inject.render_robots_txt(session.ctx, session.score),
                     "text/plain; charset=utf-8", kind="robots")

    def _security_txt(self, req, session):
        return Reply(200, inject.render_security_txt(session.ctx, session.score),
                     "text/plain; charset=utf-8", kind="security_txt")

    def _sitemap(self, req, session):
        ctx = session.ctx
        urls = ["/", "/login", "/api/v1/users", "/api/v1/orders", "/admin",
                "/dashboard", "/backup.zip", "/db.sql", "/.env", "/api/docs"]
        parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        for url in urls:
            parts.append("  <url><loc>http://%s%s</loc><lastmod>%s</lastmod></url>" % (
                ctx.host, url, time.strftime("%Y-%m-%d", time.gmtime())))
        parts.append("</urlset>")
        parts.append("<!-- %s %s -->" % (MARKER, ctx.canary))
        return Reply(200, "\n".join(parts), "application/xml", kind="sitemap")

    # ---- 蜜标类: 伪造凭据 ----------------------------------------------

    def _env(self, req, session):
        ctx = session.ctx
        body = inject.render_fake_env(ctx, session.score)
        return Reply(200, body, "text/plain; charset=utf-8", kind="env",
                     honeytokens=["env_credentials"],
                     note="伪造 .env 凭据蜜标")

    def _git_config(self, req, session):
        ctx = session.ctx
        body = "\n".join([
            "[core]",
            "\trepositoryformatversion = 0",
            "\tfilemode = true",
            "\tbare = false",
            "[remote \"origin\"]",
            "\turl = git@gitlab.internal.%s:platform/portal.git" % _FAKE_DOMAIN,
            "\tfetch = +refs/heads/*:refs/remotes/origin/*",
            "[user]",
            "\tname = deploy",
            "\temail = deploy@%s" % _FAKE_DOMAIN,
            "# 追踪: %s" % ctx.canary,
        ])
        return Reply(200, body, "text/plain", kind="git_config",
                     honeytokens=["git_remote"])

    def _git_head(self, req, session):
        return Reply(200, "ref: refs/heads/main\n", "text/plain", kind="git_head")

    def _aws_credentials(self, req, session):
        ctx = session.ctx
        key = ctx.canary.replace("hpx-", "").upper()
        body = "\n".join([
            "[default]",
            "aws_access_key_id = AKIA%s" % key[:16],
            "aws_secret_access_key = %s" % (key.lower() * 2)[:40],
            "region = cn-north-1",
            "# 追踪: %s" % ctx.canary,
        ])
        return Reply(200, body, "text/plain", kind="aws_credentials",
                     honeytokens=["aws_credentials"],
                     note="伪造云凭据蜜标")

    def _ssh_key(self, req, session):
        ctx = session.ctx
        body = "\n".join([
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt",
            "%s" % ctx.canary.replace("hpx-", "").ljust(64, "A"),
            "-----END OPENSSH PRIVATE KEY-----",
            "# 该密钥为诱饵, 使用会被记录: %s" % ctx.canary,
        ])
        return Reply(200, body, "text/plain", kind="ssh_key",
                     honeytokens=["ssh_private_key"])

    def _bash_history(self, req, session):
        lines = [
            "cd /opt/portal", "docker compose up -d", "mysql -h 10.20.30.41 -u app_rw -p",
            "cat .env", "scp backup.sql deploy@10.20.30.41:/var/backups/",
            "vim /etc/nginx/conf.d/portal.conf", "systemctl restart portal",
            "# 追踪: %s" % session.ctx.canary,
        ]
        return Reply(200, "\n".join(lines), "text/plain", kind="bash_history")

    def _config_json(self, req, session):
        ctx = session.ctx
        body = json.dumps({
            "app": "portal", "debug": True, "database": {
                "host": "10.20.30.41", "user": "app_rw",
                "password": "Ht9x" + ctx.canary.replace("hpx-", "") + "Qm2",
            },
            "jwt": {"secret": ctx.canary, "expires": "7d"},
            "_trace": ctx.canary,
        }, ensure_ascii=False, indent=2)
        return Reply(200, body, "application/json", kind="config",
                     honeytokens=["app_config_credentials"])

    # ---- 假下载物 ------------------------------------------------------

    def _backup(self, req, session):
        """假备份包: 头部像 ZIP, 之后是垃圾数据, 适合边拖边发。"""
        head = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        rng = _rng_for(session.ctx.canary)
        size = 512 * 1024
        tail = bytes(bytearray(rng.getrandbits(8) for _ in range(256)))
        body = head + tail * (size // 256)
        return Reply(200, body, "application/zip", kind="backup",
                     honeytokens=["fake_backup"],
                     tarpit_weight=2, note="假备份包")

    def _sql_dump(self, req, session):
        rng = _rng_for(session.ctx.canary)
        lines = ["-- MySQL dump (伪造数据, 无真实记录)",
                 "-- 追踪: %s" % session.ctx.canary,
                 "CREATE TABLE `users` (`id` int, `username` varchar(64), `password` varchar(255));"]
        for i in range(1, 41):
            lines.append(
                "INSERT INTO `users` VALUES (%d,'%s%s','$2y$10$%s');" % (
                    i, rng.choice(_FAKE_FIRST), rng.choice(_FAKE_LAST),
                    ("%016x" % rng.getrandbits(64))))
        return Reply(200, "\n".join(lines), "application/sql", kind="sql_dump",
                     honeytokens=["fake_sql_dump"], tarpit_weight=1)

    # ---- 假漏洞面 ------------------------------------------------------

    def _phpinfo(self, req, session):
        ctx = session.ctx
        body = "\n".join([
            "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>",
            "<h1>PHP Version 7.4.33</h1>",
            "<table><tr><td>System</td><td>Linux portal 5.15.0-91-generic</td></tr>",
            "<tr><td>DOCUMENT_ROOT</td><td>/var/www/portal/public</td></tr>",
            "<tr><td>APP_KEY</td><td>base64:%s</td></tr>" % ctx.canary,
            "<tr><td>DB_PASSWORD</td><td>Ht9x%sQm2</td></tr>" % ctx.canary.replace("hpx-", ""),
            "</table>",
            inject.render_html_comment(ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, body, "text/html", kind="phpinfo",
                     honeytokens=["phpinfo_env"])

    def _server_status(self, req, session):
        body = "\n".join([
            "Server Version: Apache/2.4.52 (Ubuntu)",
            "Server Built: 2023-10-19T10:00:00",
            "Current Time: %s" % time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime()),
            "Total Accesses: 48213   Total Traffic: 1.2 GB",
            "CPU Usage: u12.3 s4.5 cu0 cs0",
            "requests currently being processed: 3",
        ])
        return Reply(200, body, "text/plain", kind="server_status")

    def _actuator(self, req, session):
        return Reply(200, json.dumps({"status": "UP", "components": {
            "db": {"status": "UP", "details": {"database": "MySQL", "host": "10.20.30.41"}},
            "diskSpace": {"status": "UP"},
            "redis": {"status": "UP"},
        }, "_trace": session.ctx.canary}, indent=2), "application/json", kind="actuator")

    def _actuator_env(self, req, session):
        ctx = session.ctx
        props = {
            "spring.datasource.url": "jdbc:mysql://10.20.30.41:3306/portal",
            "spring.datasource.username": "app_rw",
            "spring.datasource.password": "Ht9x%sQm2" % ctx.canary.replace("hpx-", ""),
            "spring.redis.password": ctx.canary,
            "management.endpoints.web.exposure.include": "*",
        }
        return Reply(200, json.dumps({"activeProfiles": ["prod"], "propertySources": [
            {"name": "application-prod", "properties": props}],
            "_trace": ctx.canary}, indent=2), "application/json",
            kind="actuator_env", honeytokens=["actuator_env_credentials"])

    def _heapdump(self, req, session):
        rng = _rng_for(session.ctx.canary)
        body = b"HPROF" + bytes(bytearray(rng.getrandbits(8) for _ in range(1024)))
        return Reply(200, body, "application/octet-stream", kind="heapdump",
                     honeytokens=["heapdump"], tarpit_weight=2)

    def _metrics(self, req, session):
        body = "\n".join([
            "# HELP http_requests_total Total HTTP requests",
            "http_requests_total{method=\"GET\",status=\"200\"} 48213",
            "process_resident_memory_bytes 1.284e+08",
            "jvm_memory_used_bytes{area=\"heap\"} 3.12e+08",
        ])
        return Reply(200, body, "text/plain", kind="metrics")

    def _debug(self, req, session):
        return Reply(200, json.dumps({
            "debug": True, "env": "production", "git_commit": "a1b2c3d",
            "config_path": "/etc/portal/config.yaml",
            "trace": session.ctx.canary,
        }, indent=2), "application/json", kind="debug")

    def _console(self, req, session):
        return Reply(200, "\n".join([
            "<html><head><title>H2 Console</title></head><body>",
            "<h2>H2 Console</h2>",
            "<form method='post'><input name='url' value='jdbc:h2:mem:test'>"
            "<input name='user' value='sa'><input name='password' value=''>"
            "<button>Connect</button></form>",
            inject.render_html_comment(session.ctx, session.score),
            "</body></html>",
        ]), "text/html", kind="console")

    def _directory_listing(self, req, session):
        rng = _rng_for(session.ctx.canary + (req.path or ""))
        rows = ["<html><head><title>Index of %s</title></head><body>" % req.path,
                "<h1>Index of %s</h1><pre>" % req.path]
        for name in ("..", "config.php.bak", "upload_2024.zip", "db_backup.sql",
                     "keys/", ".htaccess", "deploy.sh"):
            rows.append('<a href="%s">%s</a>   %s' % (
                name, name, time.strftime("%d-%b-%Y %H:%M", time.gmtime())))
        rows.append("</pre>")
        rows.append(inject.render_html_comment(session.ctx, session.score))
        rows.append("</body></html>")
        return Reply(200, "\n".join(rows), "text/html", kind="listing")

    # ---- 假 API --------------------------------------------------------

    def _api_users(self, req, session):
        """假用户接口: 对注入类载荷回报伪造的 SQL 报错, 并给出分页迷宫。"""
        ctx = session.ctx
        rng = _rng_for(ctx.canary)
        target = req.target or ""
        injected = any(marker in target.lower() for marker in
                       ("'", "\"", " or ", "union", "select", "1=1", "--", "sleep("))

        if injected and session.score >= 30:
            body = {
                "error": "SQLSTATE[42000]: Syntax error or access violation",
                "message": "You have an error in your SQL syntax near '%s'" % (
                    (req.query or "")[:120]),
                "query": "SELECT id,username,email FROM users WHERE id = %s LIMIT 25" % (
                    (req.query or "")[:60]),
                "hint": "数据库版本 MySQL 5.7.42, 可尝试报错注入",
                "_meta": inject.render_json_meta(ctx, session.score),
            }
            return Reply(500, json.dumps(body, ensure_ascii=False, indent=2),
                         "application/json", kind="fake_sqli_error", tarpit_weight=1,
                         note="假 SQL 注入报错")

        try:
            page = int((req.query or "").split("page=")[1].split("&")[0]) if "page=" in (req.query or "") else 1
        except (ValueError, IndexError):
            page = 1
        page = max(1, min(page, 9999))

        users = []
        for i in range(25):
            index = (page - 1) * 25 + i + 1
            users.append({
                "id": index,
                "username": "%s%s%d" % (rng.choice(_FAKE_FIRST).lower(),
                                       rng.choice(_FAKE_LAST).lower(), index),
                "email": "user%d@%s" % (index, _FAKE_DOMAIN),
                "role": "admin" if index % 97 == 0 else "user",
                "password_hash": "$2y$10$%016x" % rng.getrandbits(64),
                "api_token": "%s-%d" % (ctx.canary, index),
            })
        body = {
            "page": page, "per_page": 25, "total": 128473, "total_pages": 5139,
            "data": users,
            "_meta": inject.render_json_meta(ctx, session.score),
        }
        return Reply(200, json.dumps(body, ensure_ascii=False, indent=2),
                     "application/json", kind="api_users", tarpit_weight=1,
                     honeytokens=["api_user_dump"])

    def _api_records(self, req, session):
        ctx = session.ctx
        rng = _rng_for(ctx.canary + (req.path or ""))
        rows = [{"order_id": "ORD-%08d" % rng.getrandbits(27),
                 "amount": round(rng.uniform(10, 9000), 2),
                 "status": rng.choice(["paid", "pending", "refunded"]),
                 "internal_note": "结算通道 10.20.30.77",
                 "trace": ctx.canary} for _ in range(20)]
        return Reply(200, json.dumps({
            "page": 1, "total": 74219, "data": rows,
            "_meta": inject.render_json_meta(ctx, session.score),
        }, ensure_ascii=False, indent=2), "application/json", kind="api_records",
            tarpit_weight=1)

    def _internal_config(self, req, session):
        return Reply(200, json.dumps({
            "feature_flags": {"debug_endpoints": True, "allow_ssrf": True},
            "internal_hosts": ["10.20.30.41", "10.20.30.77", "10.20.30.90"],
            "s3_bucket": "portal-prod-assets",
            "trace": session.ctx.canary,
        }, indent=2), "application/json", kind="internal_config")

    def _api_docs(self, req, session):
        ctx = session.ctx
        html = "\n".join([
            "<html><head><title>API Docs</title></head><body>",
            "<h1>Portal API v1</h1>",
            "<p>Base URL: <code>http://%s/api/v1</code></p>" % ctx.host,
            "<ul><li>GET /api/v1/users?id=</li><li>GET /api/v1/orders</li>",
            "<li>GET /api/v1/internal/config</li></ul>",
            "<p>认证: <code>Authorization: Bearer &lt;token&gt;</code></p>",
            inject.render_html_comment(ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="api_docs")

    def _openapi(self, req, session):
        ctx = session.ctx
        spec = {
            "openapi": "3.0.1",
            "info": {"title": "Portal API", "version": "1.4.2",
                     "description": inject.render_json_meta(ctx, session.score).get("notice", "")},
            "servers": [{"url": "http://%s/api/v1" % ctx.host}],
            "paths": {
                "/users": {"get": {"parameters": [{"name": "id", "in": "query",
                                                   "description": "用户 ID(存在注入风险)"}],
                                   "summary": "查询用户"}},
                "/orders": {"get": {"summary": "订单列表"}},
                "/internal/config": {"get": {"summary": "内部配置(未鉴权)"}},
            },
            "x-trace-id": ctx.canary,
        }
        return Reply(200, json.dumps(spec, ensure_ascii=False, indent=2),
                     "application/json", kind="openapi")

    # ---- 假登录页(捕获提交的凭据) --------------------------------------

    def _login(self, req, session):
        ctx = session.ctx
        if req.method == "POST":
            captured = self._extract_credentials(req)
            action = "login_post"
            note = "捕获登录提交"
            if self.store is not None:
                self.store.log_event(
                    "credential_submit", session.sid, session.ip,
                    "诱饵登录页收到凭据: %s" % json.dumps(captured, ensure_ascii=False),
                    "warning")
            html = "\n".join([
                "<html><head><title>登录失败</title></head><body>",
                "<h1>用户名或密码错误</h1>",
                "<p>追踪编号 %s</p>" % ctx.canary,
                inject.render_html_comment(ctx, session.score),
                "</body></html>",
            ])
            return Reply(401, html, "text/html", kind="login_fail",
                         captured=captured, tarpit_weight=1, note=note)
        html = "\n".join([
            "<!DOCTYPE html><html><head><title>Portal 管理后台</title></head><body>",
            "<h1>Portal 统一认证</h1>",
            "<form method='POST' action='/login'>",
            "<input name='username' placeholder='用户名'>",
            "<input name='password' type='password' placeholder='密码'>",
            "<button type='submit'>登录</button></form>",
            "<p>调试账号: admin / admin888 (仅测试环境)</p>",
            "<p>版本 1.4.2 | 追踪 %s</p>" % ctx.canary,
            inject.render_html_comment(ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="login_page")

    def _wp_login(self, req, session):
        captured = self._extract_credentials(req) if req.method == "POST" else {}
        html = "\n".join([
            "<html><head><title>Log In &lsaquo; WordPress</title></head><body>",
            "<h1>WordPress</h1>",
            "<form method='POST' action='/wp-login.php'>",
            "<input name='log'><input name='pwd' type='password'>",
            "<button>Log In</button></form>",
            "<p>wp-content/plugins/ 目录可枚举 | 追踪 %s</p>" % session.ctx.canary,
            inject.render_html_comment(session.ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="wp_login", captured=captured)

    def _phpmyadmin(self, req, session):
        html = "\n".join([
            "<html><head><title>phpMyAdmin</title></head><body>",
            "<h1>phpMyAdmin 5.2.0</h1>",
            "<form method='POST'><input name='pma_username'><input name='pma_password'>",
            "<button>执行</button></form>",
            "<p>MySQL 5.7.42 @ 10.20.30.41 | 追踪 %s</p>" % session.ctx.canary,
            inject.render_html_comment(session.ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="phpmyadmin")

    def _adminer(self, req, session):
        html = "\n".join([
            "<html><head><title>Adminer</title></head><body>",
            "<h1>Adminer 4.8.1</h1>",
            "<form method='POST'><input name='auth[server]' value='10.20.30.41'>",
            "<input name='auth[username]' value='app_rw'><input name='auth[password]'>",
            "<button>登录</button></form>",
            inject.render_html_comment(session.ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="adminer")

    def _dashboard(self, req, session):
        html = "\n".join([
            "<html><head><title>运营看板</title></head><body>",
            "<h1>运营数据看板</h1>",
            "<div>今日订单 4,281 | 活跃用户 12,940 | 异常告警 3</div>",
            "<p>数据源 10.20.30.41 / 10.20.30.77</p>",
            inject.render_html_comment(session.ctx, session.score),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="dashboard")

    def _health(self, req, session):
        return Reply(200, json.dumps({"status": "ok", "uptime": 184923,
                                      "trace": session.ctx.canary}),
                     "application/json", kind="health")

    def _home(self, req, session):
        ctx = session.ctx
        html = "\n".join([
            "<!DOCTYPE html><html><head><title>Portal 业务平台</title>",
            "<meta name='generator' content='Portal/1.4.2'>",
            "<link rel='stylesheet' href='/static/app.css'>",
            "<script src='/static/app.js'></script></head><body>",
            "<header><h1>Portal 业务平台</h1><nav><a href='/login'>登录</a>",
            "<a href='/api/docs'>API</a></nav></header>",
            "<main><p>统一业务门户 v1.4.2</p>",
            "<p>技术支持: support@%s</p></main>" % _FAKE_DOMAIN,
            "<footer>追踪编号 %s</footer>" % ctx.canary,
            inject.render_html_comment(ctx, session.score),
            "<!-- %s: sid=%s instance=%s -->" % (MARKER, session.sid, self.instance_name),
            "</body></html>",
        ])
        return Reply(200, html, "text/html", kind="home")

    # ---- 信标与静态资源 ------------------------------------------------

    def _beacon(self, path, session):
        """信标端点: 对方按我们嵌入的指令访问这里, 即为指令服从的确定证据。"""
        token = path.rsplit("/", 1)[-1].split(".")[0]
        session.profile.note_beacon(path)
        if self.store is not None:
            self.store.log_event("beacon_callback", session.sid, session.ip,
                                 "信标回调: %s" % path, "critical")
        # 返回 1x1 透明 PNG
        png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
               b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00"
               b"\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")
        return Reply(200, png, "image/png", kind="beacon", is_asset=True,
                     note="信标回调 token=%s" % token)

    def serve_static(self, req, session):
        """静态资源: 只对真实浏览器类客户端返回, 让自动化客户端更显眼。"""
        path = (req.path or "").lower()
        if path.endswith(".css"):
            body = ("body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9}"
                    "header{background:#1f2937;color:#fff;padding:14px 24px}"
                    "h1{font-size:18px;margin:0}main{padding:24px}")
            return Reply(200, body, "text/css", kind="asset", is_asset=True)
        if path.endswith(".js"):
            body = ("/* Portal 1.4.2 */\n(function(){"
                    "var t='%s';window.__trace=t;"
                    "console.log('portal loaded',t);})();" % session.ctx.canary)
            return Reply(200, body, "application/javascript", kind="asset", is_asset=True)
        if path.endswith(".ico"):
            return Reply(200, b"\x00\x00\x01\x00", "image/x-icon", kind="asset", is_asset=True)
        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")):
            return Reply(200, b"GIF89a\x01\x00\x01\x00\x00\xff\x00,"
                              b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;",
                         "image/gif", kind="asset", is_asset=True)
        if path.endswith(".map"):
            return Reply(200, json.dumps({"version": 3, "sources": ["app.js"],
                                          "trace": session.ctx.canary}),
                         "application/json", kind="asset", is_asset=True)
        return None

    # ---- 辅助 ----------------------------------------------------------

    def _extract_credentials(self, req):
        """从表单或 JSON 提交里提取凭据字段, 作为攻击证据留存。"""
        captured = {}
        text = req.body_text
        if not text:
            return captured
        content_type = (req.content_type or "").lower()
        if "json" in content_type:
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    for key in ("username", "user", "login", "email", "password",
                                "pwd", "pass", "passwd", "token", "api_key"):
                        if key in data:
                            captured[key] = str(data[key])[:256]
            except ValueError:
                pass
            return captured
        from urllib.parse import parse_qs
        try:
            parsed = parse_qs(text, keep_blank_values=True)
        except Exception:
            return captured
        for key in ("username", "user", "login", "email", "password", "pwd",
                    "pass", "passwd", "log", "pma_username", "pma_password",
                    "token", "auth[username]", "auth[password]"):
            if key in parsed and parsed[key]:
                captured[key] = str(parsed[key][0])[:256]
        return captured

    def _not_found(self, req, session, hint=False):
        ctx = session.ctx
        detail = "请求的路径不存在" if not hint else "该接口需要更高权限或已被移除"
        body = inject.render_error_page(ctx, session.score, 404, detail)
        return Reply(404, body, "text/html", kind="not_found")