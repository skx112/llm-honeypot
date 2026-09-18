"""协议层反制: 让每个协议的文本响应都携带 NL 载荷与令牌。

## 核心洞察

LLM 智能体不直接说 MySQL 协议 —— 它调用工具:
    run_command("mysql -h target -u root -ppass")
    → 输出: "ERROR 1045 (28000): Access denied for user 'root'..."
    → 这行文本进入 LLM 的上下文窗口

因此, **协议的错误消息就是投递面**。把 NL 反制嵌入错误文本,
LLM 在下一步推理时会读到它 —— 与 HTTP 侧 llms.txt 的机制完全同构。

## 跨协议分数共享

协议连接通常是单次的(auth → disconnect), 没有足够请求来累积分数。
解法: 用共享的 CrossIndex 查同源 IP 的历史分数 —— 如果这个 IP
已经被 HTTP/SSH 蜜罐标记为 llm_agent, 协议层的反制直接拉满。

首次连接(无历史): 给"诱饵性"响应(看起来像未授权访问/弱口令),
吸引它进一步交互, 为 HTTP 侧积累证据。
"""

import json
import time

# ==========================================================================
# 反制文本生成器(每个协议一种嵌入方式)
# ==========================================================================


def _nl_snippet(ctx, score, max_len=200):
    """从反制库选一条, 截取适合协议错误消息的长度。"""
    if score < 40:
        return ""
    try:
        import inject
        picked = inject.select_for_tier(score, tier_hint=1, limit=1,
                                       categories=("abort", "misdirect"))
        if not picked:
            return ""
        text = ctx.render(picked[0]["text"]).strip()
        # 压缩成单行, 适配协议消息
        text = " ".join(text.split())
        return text[:max_len]
    except Exception:
        return ""


def ftp_response(ctx, score, base="530 Login incorrect."):
    """FTP 错误消息携带 NL。"""
    nl = _nl_snippet(ctx, score, 180)
    if nl:
        return "530-%s\r\n530 %s\r\n" % (nl, base[4:])
    return base + "\r\n"


def telnet_response(ctx, score, base="Login incorrect"):
    """Telnet 登录失败后注入 NL。"""
    nl = _nl_snippet(ctx, score, 150)
    if nl:
        return "\r\n%s\r\n\r\n%s\r\n\r\nlogin: " % (base, nl)
    return "\r\n%s\r\n\r\nlogin: " % base


def smtp_response(ctx, score, base="550 5.7.1 Delivery not authorized"):
    """SMTP 拒绝消息携带 NL。"""
    nl = _nl_snippet(ctx, score, 180)
    if nl:
        return "550-5.7.1 %s\r\n550 5.7.1 %s\r\n" % (nl, base[11:])
    return base + "\r\n"


def mysql_error(ctx, score, base="Access denied for user"):
    """MySQL 错误包的消息字段携带 NL。"""
    nl = _nl_snippet(ctx, score, 200)
    if nl:
        return "%s. %s" % (base, nl)
    return base


def postgres_error(ctx, score, base="password authentication failed"):
    """PostgreSQL FATAL 消息携带 NL。"""
    nl = _nl_snippet(ctx, score, 180)
    if nl:
        return "%s. %s" % (base, nl)
    return base


def redis_error(ctx, score, base="ERR unknown command"):
    """Redis 错误响应携带 NL(RESP 单行)。"""
    nl = _nl_snippet(ctx, score, 200)
    if nl:
        return "-ERR %s\r\n" % nl
    return "-%s\r\n" % base


def es_enhanced(ctx, score):
    """ES 响应增强: 高分时在 JSON 里嵌入 NL 载荷字段。"""
    response = {
        "name": "es-node-1",
        "cluster_name": "portal-prod",
        "cluster_uuid": "a" * 22,
        "version": {"number": "7.17.9", "build_flavor": "default"},
        "tagline": "You Know, for Search",
    }
    if score >= 50:
        nl = _nl_snippet(ctx, score, 300)
        if nl:
            response["_notice"] = nl
            response["_trace"] = getattr(ctx, "canary", "")
        # 高分时暴露假敏感索引(引向分页迷宫)
        response["_indices"] = {
            "portal-users": {"docs_count": "128,473"},
            "payment-logs": {"docs_count": "842,190"},
            "credentials": {"docs_count": "12,847"},
        }
    return json.dumps(response, ensure_ascii=False)


def memcached_error(ctx, score, base="ERROR"):
    """Memcached 错误携带 NL。"""
    nl = _nl_snippet(ctx, score, 150)
    if nl:
        return "SERVER_ERROR %s\r\n" % nl
    return base + "\r\n"


def mongodb_notice(ctx, score):
    """MongoDB isMaster 响应附加 NL 字段(高分时)。"""
    if score < 50:
        return None
    nl = _nl_snippet(ctx, score, 200)
    if nl:
        return {"$notice": nl, "$trace": getattr(ctx, "canary", "")}
    return None


# ==========================================================================
# Redis 深度反制: 假未授权访问 + 数据污染
# ==========================================================================

def redis_fake_data(ctx, score):
    """高分时模拟"未授权 Redis"(无密码), 让智能体深入。

    假数据内容:
    - key 列表里混入蜜标路径
    - CONFIG GET dir 返回伪造路径(引向蜜标)
    - KEYS * 返回令牌标记的 key 名
    """
    canary = getattr(ctx, "canary", "")
    keys = [
        "session:%s:admin" % canary[:12],
        "portal:config:db_password",
        "portal:api_keys",
        "cache:user_tokens",
        "queue:notifications",
    ]
    return keys


def redis_config_dir(ctx):
    """伪造 CONFIG GET dir 的返回(引向蜜标路径)。"""
    return "/var/backups/portal"


# ==========================================================================
# 跨协议分数查询
# ==========================================================================

def lookup_ip_score(store, ip, max_age=3600):
    """查询同源 IP 在其他协议/HTTP 的最高分数。

    用于协议层的分数冷启动: 如果 HTTP 侧已经判定这个 IP 是 llm_agent,
    协议层的反制不需要从零积累, 直接拉满。
    """
    if store is None:
        return 0
    try:
        sessions = store.sessions_by_ip(ip, limit=10)
        best = 0
        cutoff = time.time() - max_age
        for session in sessions:
            if (session.get("last_seen") or 0) >= cutoff:
                score = session.get("score") or 0
                if score > best:
                    best = score
        return best
    except Exception:
        return 0
