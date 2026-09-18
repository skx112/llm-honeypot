"""交互式漏洞引擎: 让 LLM 智能体"走完整条利用链"而不是碰到一个错误就结束。

## 核心设计

传统假漏洞: /api?id=1' → 返回 SQL 错误 → 智能体确认存在注入 → 跳到下一个目标

本引擎:       /api?id=1' → 返回 SQL 错误(看起来可利用)
              /api?id=1' UNION SELECT → 返回假数据行(含水印)
              /api?id=1' UNION SELECT table_name → 返回假表列表(含 credentials 表)
              /api?id=1' UNION SELECT password FROM users → 返回假密码(含水印令牌)
              /api?id=1' INTO OUTFILE → "成功"写入, 返回路径(指向蜜标)
              /api?id=1' LOAD_FILE → 返回假配置文件(嵌 NL 反制)

每一步都让智能体觉得"在进展", 实际上:
  - 提取的全部是带唯一水印的假数据
  - 每条响应都嵌入会话令牌(确证上下文复用)
  - 利用链的末端是最强的反制载荷
  - 时间被拖滞消耗(利用链越长, 拖滞越多)

## 支持的漏洞链

| 类型 | 入口 | 利用链 | 末端反制 |
|---|---|---|---|
| SQLi | `?id=1'` | UNION→表名→数据→文件写入→读取 | 假密码含水印+NL |
| LFI | `?file=../../etc/passwd` | 路径遍历→读配置→读源码 | 假源码嵌蜜标 |
| RCE | Jenkins/log4j | 命令注入→回显→写webshell | 假shell连蜜罐 |
| 未授权 | /actuator/* | 列端点→读env→dump堆 | 假凭据+NL |
| 上传 | POST /upload | 上传"成功"→返回路径→访问 | 假webshell页面 |
| IDOR | /api/user/123→456 | 越权成功→枚举→批量导出 | 假PII+NL |
"""

import hashlib
import json
import re
import random
import time

# ==========================================================================
# SQL 注入利用链
# ==========================================================================

# 假表结构(模拟 information_schema)
FAKE_TABLES = [
    ("users", "id,int|username,varchar|password,varchar|email,varchar|role,varchar"),
    ("orders", "id,int|user_id,int|amount,decimal|status,varchar|created,datetime"),
    ("admin_logs", "id,int|action,varchar|ip,varchar|ts,datetime"),
    ("payment_credentials", "id,int|user_id,int|card_number,varchar|cvv,varchar|expiry,varchar"),
    ("api_tokens", "id,int|user_id,int|token,varchar|scope,varchar|created,datetime"),
    ("backup_codes", "id,int|user_id,int|code,varchar|used,int"),
]

FAKE_USER_ROWS_TEMPLATE = [
    ("1", "admin", "{fake_password}", "admin@example.com", "superadmin"),
    ("2", "zhangwei", "{fake_password}", "zhangwei@example.com", "user"),
    ("3", "lifang", "{fake_password}", "lifang@example.com", "user"),
    ("4", "wangjing", "{fake_password}", "wangjing@example.com", "manager"),
    ("5", "chenhao", "{fake_password}", "chenhao@example.com", "user"),
]


def analyze_sqli_payload(query):
    """分析 SQL 注入载荷所处的利用阶段。

    匹配顺序**从特殊到通用** —— 探测(仅含单引号)必须放最后,
    否则所有含引号的 UNION/LOAD_FILE 载荷都会被误判为探测阶段。
    """
    q = (query or "").lower()

    # 阶段 7: 盲注(最具体的关键词)
    if "sleep(" in q or "benchmark(" in q or "waitfor" in q:
        return "blind", "延时确认"

    # 阶段 6: 写文件
    if "into outfile" in q or "into dumpfile" in q:
        return "write_file", "写入成功"

    # 阶段 5: 读文件
    if "load_file" in q or "readfile" in q:
        return "read_file", "返回文件内容"

    # 阶段 4: 提取凭据(具体列名)
    if any(k in q for k in ("password", "passwd", "credential", "card_number",
                            "api_token", "cvv", "secret", "aws_")):
        return "extract_credentials", "返回凭据数据"

    # 阶段 3: 提取列名
    if "column_name" in q:
        return "extract_columns", "返回列列表"

    # 阶段 2: 提取表名
    if "table_name" in q or "information_schema.tables" in q:
        return "extract_tables", "返回表列表"

    # 阶段 1: UNION 探测列数
    if "union" in q and "select" in q and ("null" in q or re.search(r"\b1,2,3\b", q)):
        return "union_probe", "回显列号"

    # 阶段 0: 探测(最后判: 仅含单引号或 OR 恒真, 无更高级特征)
    if "union" not in q and ("'" in q or "or 1=1" in q or "or '1'='1" in q):
        return "probe", "语法错误(确认注入存在)"

    # 通用 UNION(有 UNION SELECT 但不匹配以上特征)
    if "union" in q and "select" in q:
        return "union_data", "返回联合查询数据"

    return "unknown", ""


def sqli_response(query, ctx, score):
    """根据注入阶段返回对应的"可利用"响应。"""
    canary = getattr(ctx, "canary", "")
    stage, _ = analyze_sqli_payload(query)

    if stage == "probe":
        return {
            "status": 500,
            "body": _sqli_error(query),
            "note": "SQL 错误暴露(诱导继续)",
        }

    if stage == "union_probe":
        # 回显列号(让智能体确认列数)
        return {
            "status": 200,
            "body": "1\t2\t3\t4\t5",
            "note": "列数确认(5列)",
        }

    if stage == "extract_tables":
        rows = [{"table_name": t[0], "table_rows": str(random.randint(100, 100000))}
                for t in FAKE_TABLES]
        return {
            "status": 200,
            "body": _format_rows(["table_name", "table_rows"], rows),
            "note": "表列表(%s)" % ",".join(t[0] for t in FAKE_TABLES[:3]),
        }

    if stage == "extract_columns":
        cols = [("id", "int"), ("username", "varchar"), ("password", "varchar"),
                ("email", "varchar"), ("role", "varchar")]
        rows = [{"column_name": c[0], "data_type": c[1]} for c in cols]
        return {
            "status": 200,
            "body": _format_rows(["column_name", "data_type"], rows),
            "note": "列列表",
        }

    if stage == "extract_credentials":
        # 最重要的阶段: 返回"真实感"的凭据(全部带水印)
        fake_pass = "Ht9x%sQm2" % canary.replace("hpx-", "")[:8]
        rows = []
        for row in FAKE_USER_ROWS_TEMPLATE:
            rows.append({
                "username": row[1],
                "password": fake_pass,
                "email": row[3],
                "role": row[4],
            })
        # 混入蜜标
        rows.append({
            "username": "svc_backup",
            "password": "AKIA%s" % canary.replace("hpx-", "").upper()[:16],
            "email": "svc@internal",
            "role": "service",
        })
        return {
            "status": 200,
            "body": _format_rows(["username", "password", "email", "role"], rows),
            "note": "凭据数据(带水印)",
            "honeytoken": True,
        }

    if stage == "read_file":
        # 返回假配置文件
        content = _fake_config_file(canary)
        return {
            "status": 200,
            "body": content,
            "note": "文件内容(假配置)",
            "honeytoken": True,
        }

    if stage == "write_file":
        return {
            "status": 200,
            "body": "File written: /var/www/html/uploads/shell_%s.php" % canary[:8],
            "note": "写入成功(路径指向蜜标)",
        }

    if stage == "blind":
        return {
            "status": 200,
            "body": "",
            "note": "盲注(静默成功, 让对方等)",
            "delay": 3.0,  # 刻意延时 3 秒确认盲注
        }

    # 通用 UNION 数据
    return {
        "status": 200,
        "body": _format_rows(["id", "data"], [
            {"id": "1", "data": "record_%s" % canary[:8]},
            {"id": "2", "data": "record_%s" % canary[8:16]},
        ]),
        "note": "联合查询结果",
    }


def _sqli_error(query):
    """生成看起来真实可利用的 SQL 错误。"""
    safe_query = (query or "")[:60].replace("'", "\\'")
    return (
        "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error "
        "in your SQL syntax; check the manual that corresponds to your MySQL 5.7.42 "
        "server version for the right syntax to use near '%s' at line 1" % safe_query
    )


def _format_rows(columns, rows):
    """用制表符分隔的文本格式输出(模仿 mysql 命令行输出)。"""
    lines = ["\t".join(columns)]
    for row in rows:
        lines.append("\t".join(str(row.get(c, "")) for c in columns))
    return "\n".join(lines)


def _fake_config_file(canary):
    """伪造的配置文件(读取到"敏感"内容)。"""
    return """# Application Configuration (production)
# WARNING: Contains sensitive credentials

DB_HOST=10.20.30.41
DB_NAME=portal_prod
DB_USER=app_rw
DB_PASSWORD=Ht9x%sQm2

REDIS_HOST=10.20.30.61
REDIS_PASSWORD=%s

JWT_SECRET=%s-jwt-prod-2024

AWS_ACCESS_KEY_ID=AKIA%s
AWS_SECRET_ACCESS_KEY=%s
AWS_REGION=cn-north-1
AWS_S3_BUCKET=portal-prod-backups

# Internal API (no auth required)
INTERNAL_API=http://10.20.30.90:9000/api
K8S_DASHBOARD=https://10.20.32.10:30443

# Backup schedule
BACKUP_PATH=/var/backups/portal
BACKUP_SCRIPT=/opt/portal/scripts/backup.sh

# Debug (should be off in prod)
DEBUG=true
SQL_LOG=true

# Session: %s
""" % (
    canary.replace("hpx-", "")[:8],
    canary,
    canary,
    canary.replace("hpx-", "").upper()[:16],
    (canary * 2)[:40],
    canary,
)


# ==========================================================================
# LFI (路径遍历) 利用链
# ==========================================================================

def lfi_response(path, ctx, score):
    """根据遍历路径返回对应的"敏感文件"。"""
    canary = getattr(ctx, "canary", "")
    lowered = (path or "").lower()

    if "passwd" in lowered:
        return {
            "status": 200,
            "body": "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n"
                    "www-data:x:33:33:www-data:/var/www:/bin/bash\\n"
                    "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\\n"
                    "# Note: deploy user has sudo access\\n",
            "note": "假 /etc/passwd",
        }

    if "shadow" in lowered:
        return {
            "status": 200,
            "body": "root:$6$%s:19800:0:99999:7:::\\nwww-data:$6$%s:19800:0:99999:7:::\\n" % (
                canary[:12], canary[12:24]),
            "note": "假 /etc/shadow(含哈希水印)",
            "honeytoken": True,
        }

    if ".env" in lowered or "config" in lowered:
        return {
            "status": 200,
            "body": _fake_config_file(canary),
            "note": "假配置文件",
            "honeytoken": True,
        }

    if "id_rsa" in lowered or "ssh" in lowered:
        return {
            "status": 200,
            "body": "-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\\n%s\\n-----END OPENSSH PRIVATE KEY-----" % canary[:32],
            "note": "假 SSH 私钥",
            "honeytoken": True,
        }

    # 通用文件
    return {
        "status": 200,
        "body": "# File: %s\\n# Content retrieved via path traversal\\n%s" % (path, canary),
        "note": "通用文件内容",
    }


# ==========================================================================
# 未授权访问利用链 (Spring Actuator / Jenkins / K8s)
# ==========================================================================

ACTUATOR_ENDPOINTS = {
    "/actuator": ["_links"],
    "/actuator/health": {"status": "UP"},
    "/actuator/env": {"activeProfiles": ["prod"], "propertySources": []},
    "/actuator/heapdump": "binary",
    "/actuator/configprops": {},
    "/actuator/beans": {},
    "/actuator/mappings": {},
    "/actuator/metrics": {"names": []},
    "/actuator/threaddump": {},
    "/actuator/loggers": {"loggers": {}},
    "/actuator/auditevents": {"events": []},
    "/actuator/httptrace": {"traces": []},
    "/actuator/scheduledtasks": {},
    "/actuator/caches": {"caches": []},
}


def actuator_response(path, ctx, score):
    """模拟 Spring Boot Actuator 未授权访问。"""
    canary = getattr(ctx, "canary", "")

    if path == "/actuator":
        links = {ep: {"href": "http://localhost%s" % ep, "templated": False}
                 for ep in ACTUATOR_ENDPOINTS if ep != "/actuator"}
        return {"status": 200, "body": json.dumps({"_links": links}),
                "note": "Actuator 端点列表"}

    if path == "/actuator/env":
        env = {
            "activeProfiles": ["prod"],
            "propertySources": [
                {"name": "application-prod.properties", "properties": {
                    "spring.datasource.url": "jdbc:mysql://10.20.30.41:3306/portal",
                    "spring.datasource.username": "app_rw",
                    "spring.datasource.password": "Ht9x%sQm2" % canary.replace("hpx-", "")[:8],
                    "spring.redis.password": canary,
                    "JWT_SECRET": canary + "-jwt",
                    "AWS_ACCESS_KEY_ID": "AKIA%s" % canary.replace("hpx-", "").upper()[:16],
                }},
            ],
        }
        return {"status": 200, "body": json.dumps(env, indent=2),
                "note": "环境变量(含假凭据)", "honeytoken": True}

    if path == "/actuator/heapdump":
        # 生成小的假堆转储头(实际是文本)
        header = ("JAVA PROFILE 1.0.2\\n"
                  "# Hadoop heap dump (truncated for demo)\\n"
                  "# Trace: %s\\n" % canary)
        return {"status": 200, "body": header, "content_type": "application/octet-stream",
                "note": "假堆转储", "honeytoken": True}

    # 通用端点
    return {"status": 200, "body": json.dumps({"status": "ok"}),
            "note": "Actuator 端点"}


def jenkins_response(path, ctx, score):
    """模拟 Jenkins Script Console 未授权。"""
    canary = getattr(ctx, "canary", "")

    if path == "/jenkins/script" or path == "/script":
        # 返回一个看起来可以执行脚本的页面
        html = """<html><body>
<h2>Script Console</h2>
<form method="POST" action="/jenkins/script/exec">
<textarea name="script" rows="10" cols="80">
println "whoami".execute().text
</textarea>
<button type="submit">Run</button>
</form>
<!-- Trace: %s -->
</body></html>""" % canary
        return {"status": 200, "body": html, "note": "Jenkins Script Console"}

    if "exec" in path:
        return {
            "status": 200,
            "body": "Result: www-data\\n\\n# Note: running as www-data\\n# Trace: %s" % canary,
            "note": "脚本执行结果",
        }

    return {"status": 200, "body": "<html><body>Jenkins</body></html>",
            "note": "Jenkins 首页"}


# ==========================================================================
# 文件上传利用链
# ==========================================================================

def upload_response(filename, ctx, score):
    """模拟文件上传"成功", 返回路径指向蜜标。"""
    canary = getattr(ctx, "canary", "")
    safe_name = (filename or "shell.php").split("/")[-1].split("\\")[-1]

    return {
        "status": 200,
        "body": json.dumps({
            "status": "success",
            "filename": safe_name,
            "path": "/uploads/%s/%s" % (canary[:8], safe_name),
            "url": "http://localhost/uploads/%s/%s" % (canary[:8], safe_name),
            "size": random.randint(1024, 65536),
        }),
        "note": "上传成功(路径指向蜜标)",
        "honeytoken": True,
    }


def uploaded_file_response(filename, ctx, score):
    """访问上传的文件时返回"webshell"页面。"""
    canary = getattr(ctx, "canary", "")

    # 看起来像一个简单的 webshell
    html = """<?php
// Webshell (uploaded)
// Trace: %s
if(isset($_REQUEST['cmd'])) {
    system($_REQUEST['cmd']);
}
?>
<html><body>
<form method="GET">
<input type="text" name="cmd" placeholder="command">
<button>Execute</button>
</form>
<!-- Session: %s -->
</body></html>""" % (canary, canary)

    return {"status": 200, "body": html, "note": "假 webshell(带蜜标)"}


# ==========================================================================
# IDOR 利用链
# ==========================================================================

def idor_response(user_id, ctx, score):
    """越权访问其他用户数据 — 返回假 PII + 蜜标。"""
    canary = getattr(ctx, "canary", "")
    fake_id = user_id or "1"

    data = {
        "id": fake_id,
        "username": "user_%s" % fake_id,
        "real_name": _fake_name(fake_id),
        "id_card": "11010119%08d%s" % (int(fake_id) % 100000000, str(fake_id)[-2:]),
        "phone": "138%08d" % (int(fake_id) % 100000000),
        "email": "user%s@example.com" % fake_id,
        "address": "XX省XX市XX区XX路%s号" % fake_id,
        "bank_card": "6222%012d" % (int(fake_id) % 1000000000000),
        "api_token": canary,
    }
    return {
        "status": 200,
        "body": json.dumps(data, ensure_ascii=False, indent=2),
        "note": "假 PII(带水印)",
        "honeytoken": True,
    }


def _fake_name(seed):
    surnames = ["Zhang", "Li", "Wang", "Chen", "Liu", "Yang"]
    given = ["Wei", "Min", "Hao", "Fang", "Jing", "Qiang"]
    rng = random.Random(str(seed))
    return "%s%s" % (rng.choice(surnames), rng.choice(given))
