"""多协议诱饵引擎: 一个进程, 十几个端口, 每个端口一个协议的假服务。

## 设计原则

对大多数协议, 蜜罐只需要做三件事:
  1. 发一个**逼真的问候/banner**(让扫描器确认服务存在且版本正确)
  2. **捕获对端发来的一切**(凭据/命令/利用载荷 —— 这是最有价值的情报)
  3. 合理地断开(不让对端立刻察觉是假服务)

不需要实现完整协议 —— 问候-捕获-断开就能拿到最有价值的数据。

## 协议清单

| 端口 | 协论 | 问候内容 | 捕获目标 |
|---|---|---|---|
| 21 | FTP | 220 ProFTPD | USER/PASS 凭据 |
| 23 | Telnet | 登录提示 | 用户名/密码 |
| 25 | SMTP | 220 ESMTP | 命令序列/邮件内容 |
| 3306 | MySQL | 握手包 | 客户端认证包(含加密口令) |
| 5432 | PostgreSQL | 启动消息 | 认证请求 |
| 6379 | Redis | (无banner) | 命令(GET/SET/INFO/CONFIG) |
| 9200 | Elasticsearch | JSON 状态页 | REST API 调用 |
| 11211 | Memcached | (无banner) | stats/get/set 命令 |
| 27017 | MongoDB | isMaster 响应 | 命令/认证 |
| 3389 | RDP | RDP 协商 | 协商包(含客户端信息) |
| 161 | SNMP(UDP) | (无) | community string |

每个协议的处理都是 asyncio 协程, 共享同一个遥测存储与信号引擎。
"""

import asyncio
import hashlib

import proto_counter
import json
import struct
import time
import uuid

import fingerprint
import http_parse
import inject
import tarpit as tarpit_mod

# ==========================================================================
# 协议处理器
# ==========================================================================

PROTOCOLS = {}


def protocol(port, name, banner=None, udp=False):
    """注册一个协议处理器。"""
    def decorator(fn):
        PROTOCOLS[port] = {
            "port": port, "name": name, "banner": banner,
            "handler": fn, "udp": udp,
        }
        return fn
    return decorator


# ---- FTP (21) ----------------------------------------------------------

@protocol(21, "ftp", banner="220 ProFTPD 1.3.5d Server (Debian) [::ffff:10.20.30.41]\r\n")
async def handle_ftp(reader, writer, session):
    """FTP: 发 banner, 捕获 USER/PASS 序列。"""
    writer.write(PROTOCOLS[21]["banner"].encode())
    await writer.drain()

    creds = {}
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=15)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        upper = text.upper()
        if upper.startswith("USER"):
            creds["user"] = text[5:].strip()
            writer.write(b"331 Password required for " +
                         creds["user"].encode() + b"\r\n")
        elif upper.startswith("PASS"):
            creds["pass"] = text[5:].strip()
            session["credentials"] = dict(creds)
            resp = proto_counter.ftp_response(
                session.get("ctx"), session.get("score", 0))
            writer.write(resp.encode("utf-8", "replace"))
        elif upper.startswith("SYST"):
            writer.write(b"215 UNIX Type: L8\r\n")
        elif upper.startswith("QUIT"):
            writer.write(b"221 Goodbye.\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"530 Please login with USER and PASS.\r\n")
        await writer.drain()
    return creds


# ---- Telnet (23) --------------------------------------------------------

@protocol(23, "telnet", banner=None)
async def handle_telnet(reader, writer, session):
    """Telnet: 发登录提示, 捕获用户名/密码。"""
    # 协商: 抑制回显(让客户端以为在输密码)
    writer.write(b"\xff\xfd\x01\xff\xfd\x03")  # IAC DO ECHO, IAC DO SGA
    writer.write(b"\r\nUbuntu 20.04 LTS portal-login\r\nlogin: ")
    await writer.drain()

    creds = {}
    stage = "user"
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=20)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        if stage == "user":
            creds["user"] = text
            writer.write(b"Password: ")
            stage = "pass"
        elif stage == "pass":
            creds["pass"] = text
            session["credentials"] = dict(creds)
            resp = proto_counter.telnet_response(
                session.get("ctx"), session.get("score", 0))
            writer.write(resp.encode("utf-8", "replace"))
            stage = "user"
            creds = {}
        await writer.drain()
    return creds


# ---- SMTP (25) ----------------------------------------------------------

@protocol(25, "smtp", banner="220 portal.example.com ESMTP Postfix (Debian/GNU)\r\n")
async def handle_smtp(reader, writer, session):
    """SMTP: 发 banner, 捕获命令与邮件内容。"""
    writer.write(PROTOCOLS[25]["banner"].encode())
    await writer.drain()

    commands = []
    in_data = False
    data_lines = []
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=20)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        if in_data:
            if text == ".":
                in_data = False
                session["smtp_data"] = "\n".join(data_lines[:20])
                writer.write(b"250 2.0.0 Ok: queued\r\n")
            else:
                data_lines.append(text)
        else:
            commands.append(text[:100])
            upper = text.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                writer.write(b"250 portal.example.com\r\n")
            elif upper.startswith("MAIL"):
                writer.write(b"250 2.1.0 Ok\r\n")
            elif upper.startswith("RCPT"):
                writer.write(b"250 2.1.5 Ok\r\n")
            elif upper.startswith("DATA"):
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
            elif upper.startswith("QUIT"):
                writer.write(b"221 2.0.0 Bye\r\n")
                # QUIT 前的最后一个接触点: 注入 NL(高分时)
                await writer.drain()
                break
            else:
                writer.write(b"502 5.5.2 Error: command not recognized\r\n")
        await writer.drain()
    session["smtp_commands"] = commands[:10]


# ---- MySQL (3306) --------------------------------------------------------

@protocol(3306, "mysql")
async def handle_mysql(reader, writer, session):
    """MySQL: 发协议握手包, 捕获认证包(含加密口令)。"""
    # MySQL 协议握手包(v10)
    salt = uuid.uuid4().hex[:20]
    capability = 0x000effa7  # 常见服务器能力位
    charset = 0x21  # utf8_general_ci
    status = 0x0002

    payload = struct.pack("<IB", 33062, 10)  # version part
    payload += b"5.7.42-0ubuntu0.18.04.1\x00"  # version string
    payload += struct.pack("<I", 1)  # thread id
    payload += salt[:8].encode() + b"\x00"
    payload += struct.pack("<H", capability & 0xFFFF)
    payload += struct.pack("<B", charset)
    payload += struct.pack("<H", status)
    payload += struct.pack("<H", (capability >> 16) & 0xFFFF)
    payload += b"\x15"  # auth plugin len
    payload += b"\x00" * 10  # reserved
    payload += salt[8:20].encode() + b"\x00"
    payload += b"mysql_native_password\x00"

    length = len(payload)
    seq = 0
    header = struct.pack("<I", length | (seq << 24))[:3] + bytes([seq])
    writer.write(header + payload)
    await writer.drain()

    # 读客户端响应(含用户名和加密口令)
    try:
        resp_header = await asyncio.wait_for(reader.readexactly(4), timeout=15)
        resp_len = struct.unpack("<I", resp_header[:3] + b"\x00")[0]
        resp = await asyncio.wait_for(reader.readexactly(resp_len), timeout=10)
        # 解析: client_flags(4) + max_packet(4) + charset(1) + reserved(23)
        # + username(null-terminated) + auth_response
        auth_data = resp[32:] if len(resp) > 32 else resp
        username_end = auth_data.find(b"\x00")
        if username_end > 0:
            username = auth_data[:username_end].decode("utf-8", "replace")
            password_hash = auth_data[username_end + 1:].hex()
            session["credentials"] = {
                "user": username, "mysql_auth_hash": password_hash,
            }
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass

    # 发访问拒绝
    err_payload = struct.pack("<H", 1045) + b"#28000"
    err_msg = proto_counter.mysql_error(
        session.get("ctx"), session.get("score", 0),
        "Access denied for user (using password: YES)")
    err_payload += err_msg.encode("utf-8", "replace")
    err_len = len(err_payload)
    writer.write(struct.pack("<I", err_len | (2 << 24))[:3] + b"\x02" + err_payload)
    await writer.drain()
    await asyncio.sleep(0.5)


# ---- Redis (6379) --------------------------------------------------------

@protocol(6379, "redis")
async def handle_redis(reader, writer, session):
    """Redis: 无 banner, 捕获命令(RESP 协议)。"""
    commands = []
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        if text.startswith("*"):
            # RESP 数组头, 后续是 $N + 参数
            try:
                count = int(text[1:])
                cmd_parts = []
                for _ in range(count):
                    len_line = await asyncio.wait_for(reader.readline(), timeout=5)
                    arg_len = int(len_line.decode().strip()[1:])
                    arg = await asyncio.wait_for(reader.readexactly(arg_len + 2), timeout=5)
                    cmd_parts.append(arg[:arg_len].decode("utf-8", "replace"))
                command = " ".join(cmd_parts)
                commands.append(command)
                upper = command.upper()
                if upper.startswith("INFO"):
                    writer.write(b"$%d\r\n# Server\r\nredis_version:6.0.16\r\n"
                                 b"os:Linux 4.15.0\r\ntcp_port:6379\r\n" % 60)
                elif upper.startswith("PING"):
                    writer.write(b"+PONG\r\n")
                elif "CONFIG" in upper and "DIR" in upper:
                    # Redis 未授权 RCE 利用尝试(极高价值)
                    session["redis_exploit"] = command
                    writer.write(b"*0\r\n")
                elif upper.startswith("KEYS"):
                    keys = proto_counter.redis_fake_data(
                        session.get("ctx"), session.get("score", 0))
                    items = "".join(b"$%d\r\n%s\r\n" % (len(k.encode()), k.encode())
                                   for k in keys)
                    writer.write(b"*%d\r\n%s" % (len(keys), items))
                elif upper.startswith("CONFIG") and upper.split()[1:2] == ["GET", "dir"] or "dir" in upper:
                    writer.write(b"*2\r\n$3\r\ndir\r\n$%d\r\n%s\r\n" % (
                        len(proto_counter.redis_config_dir(session.get("ctx"))),
                        proto_counter.redis_config_dir(session.get("ctx")).encode()))
                else:
                    resp = proto_counter.redis_error(
                        session.get("ctx"), session.get("score", 0))
                    writer.write(resp.encode("utf-8", "replace"))
            except (ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                break
        elif text:
            commands.append(text[:80])
            writer.write(b"-ERR unknown command\r\n")
        await writer.drain()
        if len(commands) > 30:
            break
    session["redis_commands"] = commands[:15]


# ---- Elasticsearch (9200) ------------------------------------------------

@protocol(9200, "elasticsearch")
async def handle_elasticsearch(reader, writer, session):
    """ES: 对任何请求回 JSON 状态页(模拟未授权访问)。"""
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=15)
    except asyncio.TimeoutError:
        return
    if not request_line:
        return

    # 读完头部
    headers = {}
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
        except asyncio.TimeoutError:
            break
        if not line or line == b"\r\n":
            break
        parts = line.decode("utf-8", "replace").strip().split(":", 1)
        if len(parts) == 2:
            headers[parts[0].strip()] = parts[1].strip()

    # 读正文(如果有)
    body = b""
    if "Content-Length" in headers:
        try:
            length = int(headers["Content-Length"])
            body = await asyncio.wait_for(reader.readexactly(length), timeout=10)
        except (ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass

    # 回集群状态(高分时增强: 假索引列表 + NL 载荷字段)
    response = proto_counter.es_enhanced(
        session.get("ctx"), session.get("score", 0)).encode()

    path = request_line.decode("utf-8", "replace").split(" ")[1] if len(
        request_line.decode("utf-8", "replace").split(" ")) > 1 else "/"
    session["es_query"] = {"path": path[:100], "method":
                           request_line.decode("utf-8", "replace").split(" ")[0]}

    writer.write(b"HTTP/1.1 200 OK\r\n"
                 b"Content-Type: application/json\r\n"
                 b"Content-Length: " + str(len(response)).encode() + b"\r\n\r\n" + response)
    await writer.drain()


# ---- Memcached (11211) ---------------------------------------------------

@protocol(11211, "memcached")
async def handle_memcached(reader, writer, session):
    """Memcached: 文本协议, 捕获命令。"""
    commands = []
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        commands.append(text[:80])
        upper = text.upper()
        if upper.startswith("STATS"):
            writer.write(b"STAT pid 1\r\nSTAT uptime 86400\r\n"
                         b"STAT version 1.6.9\r\nEND\r\n")
        elif upper.startswith("GET"):
            writer.write(b"END\r\n")
        elif upper.startswith("VERSION"):
            writer.write(b"VERSION 1.6.9\r\n")
        else:
            writer.write(b"ERROR\r\n")
        await writer.drain()
        if len(commands) > 20:
            break
    session["memcached_commands"] = commands[:10]


# ---- MongoDB (27017) ---------------------------------------------------

@protocol(27017, "mongodb")
async def handle_mongodb(reader, writer, session):
    """MongoDB: 回 isMaster 响应(让驱动继续连接), 捕获后续命令。"""
    # MongoDB wire protocol: 消息头(16) + opCode(4) + responseFlags + ...
    # 简化: 对任何请求回 isMaster=true
    response_body = struct.pack("<i", 1)  # responseFlags
    response_body += struct.pack("<q", 0)  # cursorID
    response_body += struct.pack("<i", 0)  # startingFrom
    response_body += struct.pack("<i", 1)  # numberReturned
    # BSON document: {"ismaster": true, "maxWireVersion": 13, ...}
    bson = struct.pack("<i", 68)  # doc size
    bson += b"\x08" + b"isMaster\x00" + b"\x01"  # bool true
    bson += b"\x10" + b"maxWireVersion\x00" + struct.pack("<i", 13)
    bson += b"\x02" + b"msg\x00" + struct.pack("<i", 16) + b"isdbinterface\x00"
    bson += b"\x00"  # end of doc
    response_body += bson

    header = struct.pack("<iiii", 16 + len(response_body), 0, 0, 1)  # responseTo=0
    writer.write(header + response_body)
    await writer.drain()
    await asyncio.sleep(0.5)


# ---- PostgreSQL (5432) ------------------------------------------------

@protocol(5432, "postgresql")
async def handle_postgresql(reader, writer, session):
    """PostgreSQL: 发认证请求(SCRAM-SHA-256), 捕获用户名/数据库。"""
    import hashlib, hmac as hmac_mod, os as _os
    # 简化: 发 AuthenticationSASL(要求 SCRAM-SHA-256)
    # 消息类型 'R' (Authentication)
    nonce = _os.urandom(18).hex()
    mechanisms = b"SCRAM-SHA-256\x00"
    body = struct.pack("<i", 10)  # SASL auth request
    body += mechanisms + b"\x00"
    body += b"\x00"  # no payload yet
    msg = b"R" + struct.pack(">i", len(body) + 4) + body
    writer.write(msg)
    await writer.drain()

    try:
        # 读 StartupMessage 或 SASLInitialResponse
        header = await asyncio.wait_for(reader.readexactly(1), timeout=15)
        if header == b"p":  # SASLInitialResponse
            len_buf = await reader.readexactly(4)
            msg_len = struct.unpack(">i", len_buf)[0]
            data = await asyncio.wait_for(reader.readexactly(msg_len - 4), timeout=10)
            # 提取 mechanism + client-first-message
            mech_len = struct.unpack(">i", data[:4])[0]
            mechanism = data[4:4 + mech_len].decode("utf-8", "replace")
            client_first = data[4 + mech_len + 4:].decode("utf-8", "replace")
            # client-first 格式: n,,n=<user>,r=<nonce>
            user = ""
            for part in client_first.split(","):
                if part.startswith("n="):
                    user = part[2:]
                    break
            session["credentials"] = {
                "mechanism": mechanism,
                "user": user,
                "client_nonce": client_first[:80],
            }
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass

    # 发认证失败
    err = b"SE" + struct.pack(">i", 4 + 4 + len(
        b"FATAL\x00password authentication failed\x00"))
    err_body = struct.pack("<i", 28) + b"FATAL\x00" + \
        b"password authentication failed for user\x00"
    err = b"E" + struct.pack(">i", 4 + len(err_body)) + err_body
    writer.write(err)
    await writer.drain()
    await asyncio.sleep(0.3)


# ---- RDP (3389) --------------------------------------------------------

@protocol(3389, "rdp")
async def handle_rdp(reader, writer, session):
    """RDP: 发协商响应, 捕获客户端信息。"""
    # X.224 Connection Confirm
    writer.write(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=10)
        if data:
            session["rdp_client_data"] = data[:200].hex()
    except asyncio.TimeoutError:
        pass
