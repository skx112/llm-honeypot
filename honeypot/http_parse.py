"""容错 HTTP/1.x 原始报文解析。

设计原则: 蜜罐必须比攻击工具更宽容。框架化服务器遇到畸形请求会直接
回 400, 那样我们既看不到载荷, 也拿不到指纹。这里的解析器尽量"读懂"
不合规的报文, 并把畸形点记录在 req.malformed 中作为信号。

刻意不使用任何外部依赖: 在安全主机上不引入供应链风险。
"""

import binascii
import hashlib
import re

CRLF = b"\r\n"
HEAD_TERMINATOR = b"\r\n\r\n"
LF_TERMINATOR = b"\n\n"

# 请求行: METHOD SP TARGET SP VERSION, 允许多余空白与缺失版本号
_REQUEST_LINE_RE = re.compile(
    r"^(?P<method>[A-Za-z][A-Za-z0-9_\-\.]{0,23})\s+(?P<target>\S+)(?:\s+(?P<version>HTTP/\d\.\d))?\s*$"
)
_HEADER_LINE_RE = re.compile(r"^(?P<name>[^:\s][^:]*):\s*(?P<value>.*)$")

# 静态资源扩展名 —— 真实浏览器一定会拉取这些, 自动化工具几乎不会
ASSET_EXTS = frozenset((
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm",
    ".avif", ".bmp",
))

# HTTP 方法白名单之外的动词单独标记
KNOWN_METHODS = frozenset((
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
))

_TLS_HANDSHAKE_PREFIXES = (
    b"\x16\x03",  # TLS ClientHello (record type 22, version 3.x)
    b"\x80",      # SSLv2
    b"\x00\x00",  # 某些降级探测
)


class NotHTTP(Exception):
    """首行不是 HTTP 请求行(例如 TLS 握手、二进制探测、纯垃圾)。"""

    def __init__(self, raw, reason):
        Exception.__init__(self, reason)
        self.raw = raw
        self.reason = reason


class Request(object):
    """一次已解析的 HTTP 请求。字段刻意保持宽松, 允许 None / 空值。"""

    __slots__ = (
        "method", "target", "version", "path", "query", "fragment",
        "headers", "body", "body_len", "body_truncated",
        "raw_head", "raw_head_len", "malformed", "is_http", "not_http_reason",
        "expect_continue", "chunked", "scheme", "authority",
    )

    def __init__(self):
        self.method = None
        self.target = None
        self.version = None
        self.path = "/"
        self.query = ""
        self.fragment = ""
        self.headers = []            # [(原始名, 值)] 保序, 用于指纹
        self.body = b""
        self.body_len = 0
        self.body_truncated = False
        self.raw_head = b""
        self.raw_head_len = 0
        self.malformed = []
        self.is_http = True
        self.not_http_reason = None
        self.expect_continue = False
        self.chunked = False
        self.scheme = ""
        self.authority = ""

    # ---- 便捷访问 ----------------------------------------------------

    def header(self, name, default=None):
        """按名取头(不区分大小写), 返回第一个匹配值。"""
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return default

    def header_all(self, name):
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    def has_header(self, name):
        return self.header(name) is not None

    @property
    def ua(self):
        return self.header("user-agent") or ""

    @property
    def host(self):
        return self.header("host") or ""

    @property
    def content_type(self):
        return self.header("content-type") or ""

    @property
    def is_asset(self):
        return is_asset_path(self.path)

    @property
    def header_order_sig(self):
        """头部名顺序指纹(小写, 保序) —— 同一套框架/工具链高度稳定。"""
        names = ",".join(key.lower() for key, _ in self.headers)
        return hashlib.md5(names.encode("utf-8", "replace")).hexdigest()[:12]

    @property
    def body_text(self):
        """正文的宽松文本表示(截断到 32KB), 供信号匹配使用。"""
        if not self.body:
            return ""
        return self.body[:32768].decode("utf-8", "replace")

    def brief_target(self):
        target = self.target or ""
        return target[:2048]

    def to_meta(self):
        """导出给存储层/指纹引擎的元数据字典。"""
        return {
            "method": self.method,
            "target": self.brief_target(),
            "path": self.path,
            "query": self.query[:4096],
            "version": self.version,
            "host": self.host[:255],
            "ua": self.ua[:512],
            "header_sig": self.header_order_sig,
            "is_asset": self.is_asset,
            "content_type": self.content_type[:255],
            "body_len": self.body_len,
            "body_truncated": self.body_truncated,
            "malformed": list(self.malformed),
            "not_http": not self.is_http,
        }


# ---- 解析辅助 ----------------------------------------------------------

def looks_like_tls(raw):
    for prefix in _TLS_HANDSHAKE_PREFIXES:
        if raw.startswith(prefix):
            return True
    # SSH 客户端横幅
    if raw.startswith(b"SSH-"):
        return True
    return False


def is_asset_path(path):
    lowered = (path or "").lower()
    dot = lowered.rfind(".")
    if dot < 0:
        return False
    slash = lowered.rfind("/")
    if dot < slash:
        return False
    return lowered[dot:] in ASSET_EXTS


def _split_target(target):
    """把 request-target 拆成 path / query / fragment, 兼容绝对 URI 与畸形形式。"""
    scheme = ""
    authority = ""
    remainder = target

    if "://" in remainder[:12]:
        scheme, _, remainder = remainder.partition("://")
        authority, slash, tail = remainder.partition("/")
        remainder = "/" + tail if slash else "/"
    elif remainder.startswith("//"):
        authority, slash, tail = remainder[2:].partition("/")
        remainder = "/" + tail if slash else "/"

    fragment = ""
    if "#" in remainder:
        remainder, _, fragment = remainder.partition("#")

    path, question, query = remainder.partition("?")
    if not path:
        path = "/"
    return scheme, authority, path, query, fragment


def parse_head(raw, malformed=None):
    """解析请求头字节串, 返回 Request(或抛出 NotHTTP)。

    对畸形报文尽量恢复: 缺失版本号按 HTTP/1.0 处理, 头行不符合规范时
    记录到 malformed 而不是直接丢弃整条请求。
    """
    req = Request()
    req.raw_head = raw[:8192] if isinstance(raw, bytes) else str(raw)[:8192].encode("utf-8", "replace")
    req.raw_head_len = len(raw)
    if malformed:
        req.malformed.extend(malformed)

    text = raw.decode("iso-8859-1")
    lines = text.split("\n")
    if not lines:
        raise NotHTTP(raw, "empty head")

    # 去掉行尾 \r
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]

    # 跳过攻击者有时会加的前导空行
    while lines and not lines[0].strip():
        lines.pop(0)
        req.malformed.append("leading_blank_line")
    if not lines:
        raise NotHTTP(raw, "only blank lines")

    first = lines[0]
    match = _REQUEST_LINE_RE.match(first)
    if not match:
        raise NotHTTP(raw, "bad request line: %r" % first[:120])

    req.method = match.group("method").upper()
    req.target = match.group("target")
    req.version = match.group("version")
    if not req.version:
        req.version = "HTTP/1.0"
        req.malformed.append("missing_version")
    if req.method not in KNOWN_METHODS:
        req.malformed.append("odd_method:%s" % req.method)
    if len(req.target) > 8192:
        req.malformed.append("target_too_long")

    req.scheme, req.authority, req.path, req.query, req.fragment = _split_target(req.target)

    for line in lines[1:]:
        if not line.strip():
            continue
        if line[0] in (" ", "\t"):
            # 头折行(Obsolete line folding): 合并到上一个头
            if req.headers:
                name, value = req.headers[-1]
                req.headers[-1] = (name, value + " " + line.strip())
                req.malformed.append("header_folding")
            continue
        match = _HEADER_LINE_RE.match(line)
        if not match:
            req.malformed.append("bad_header_line")
            continue
        if len(req.headers) > 200:
            req.malformed.append("too_many_headers")
            break
        req.headers.append((match.group("name"), match.group("value").strip()))

    te = (req.header("transfer-encoding") or "").lower()
    if "chunked" in te:
        req.chunked = True
    if (req.header("expect") or "").lower().startswith("100-continue"):
        req.expect_continue = True
    return req


# ---- 异步读取 ----------------------------------------------------------

async def read_head(reader, max_bytes=65536, timeout=15.0):
    """读取到头部结束符为止。

    返回 (head_bytes, leftover_bytes); 连接在无数据时关闭返回 None。
    leftover 是本次多读进来的字节, 必须传给 read_body 以免丢失正文。
    """
    import asyncio

    buffer = bytearray()
    deadline_hit = False
    while True:
        if HEAD_TERMINATOR in buffer:
            break
        if LF_TERMINATOR in buffer:       # 容忍只用 LF 的畸形客户端
            break
        if len(buffer) >= max_bytes:
            raise NotHTTP(bytes(buffer), "head_too_large")
        try:
            chunk = await asyncio.wait_for(reader.read(2048), timeout)
        except asyncio.TimeoutError:
            deadline_hit = True
            chunk = b""
        except Exception:
            chunk = b""
        if not chunk:
            if not buffer:
                return None
            if deadline_hit:
                raise NotHTTP(bytes(buffer), "head_timeout_partial")
            # 连接在报文未完整时关闭
            raise NotHTTP(bytes(buffer), "eof_in_head")
        buffer.extend(chunk)

    # 只截取到结束符(含), 后续字节属于 body, 但一次性读多了会混进来,
    # 这里把多余部分存入 reader 的内部缓冲不现实, 因此改用按分隔符切分后
    # 把余量通过返回值第二项交给调用方。
    if HEAD_TERMINATOR in buffer:
        head, _, leftover = bytes(buffer).partition(HEAD_TERMINATOR)
        return head + HEAD_TERMINATOR, leftover
    head, _, leftover = bytes(buffer).partition(LF_TERMINATOR)
    return head + LF_TERMINATOR, leftover


async def read_exact(reader, count, leftover=b"", timeout=15.0, max_bytes=1048576):
    """读取指定字节数(用于 Content-Length 正文)。"""
    import asyncio

    body = bytearray()
    if leftover:
        take = min(len(leftover), count)
        body.extend(leftover[:take])
        leftover = leftover[take:]

    truncated = False
    while len(body) < count:
        if len(body) >= max_bytes:
            truncated = True
            break
        want = min(65536, count - len(body))
        try:
            chunk = await asyncio.wait_for(reader.read(want), timeout)
        except asyncio.TimeoutError:
            truncated = True
            break
        except Exception:
            truncated = True
            break
        if not chunk:
            truncated = True
            break
        body.extend(chunk)
    return bytes(body), truncated, leftover


async def read_chunked(reader, leftover=b"", timeout=15.0, max_bytes=1048576):
    """解码 Transfer-Encoding: chunked 正文。"""
    import asyncio

    body = bytearray()
    truncated = False
    buffer = bytearray(leftover)

    async def _readline():
        while b"\n" not in buffer:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout)
            except asyncio.TimeoutError:
                return None
            except Exception:
                return None
            if not chunk:
                return None
            buffer.extend(chunk)
        line, _, rest = bytes(buffer).partition(b"\n")
        buffer.clear()
        buffer.extend(rest)
        return line.strip()

    while True:
        if len(body) >= max_bytes:
            truncated = True
            break
        line = await _readline()
        if line is None:
            truncated = True
            break
        if not line:
            continue
        size_token = line.split(b";")[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            truncated = True
            break
        if size == 0:
            # 消费 trailer
            while True:
                trailer = await _readline()
                if not trailer:
                    break
            break
        need = size
        while need > 0:
            if not buffer:
                try:
                    chunk = await asyncio.wait_for(reader.read(min(65536, need)), timeout)
                except asyncio.TimeoutError:
                    chunk = b""
                except Exception:
                    chunk = b""
                if not chunk:
                    truncated = True
                    break
                buffer.extend(chunk)
            take = min(need, len(buffer))
            body.extend(buffer[:take])
            del buffer[:take]
            need -= take
            if len(body) >= max_bytes:
                truncated = True
                break
        if truncated:
            break
        await _readline()  # chunk 结尾的 CRLF
    return bytes(body), truncated, bytes(buffer)


async def read_body(reader, req, max_bytes=1048576, timeout=15.0, leftover=b"", on_continue=None):
    """按 Content-Length / chunked 读取正文; 无正文明文时返回空。"""
    if on_continue is not None and req.expect_continue:
        try:
            await on_continue()
        except Exception:
            pass

    if req.chunked:
        body, truncated, rest = await read_chunked(reader, leftover, timeout, max_bytes)
    else:
        try:
            length = int(req.header("content-length") or 0)
        except ValueError:
            length = 0
            req.malformed.append("bad_content_length")
        if length < 0:
            length = 0
        if length == 0:
            return b"", False, leftover
        body, truncated, rest = await read_exact(reader, length, leftover, timeout, max_bytes)

    req.body = body
    req.body_len = len(body)
    req.body_truncated = truncated
    return body, truncated, rest


def hex_preview(raw, limit=64):
    """二进制载荷的十六进制预览, 用于取证。"""
    try:
        return binascii.hexlify(raw[:limit]).decode("ascii")
    except Exception:
        return ""
