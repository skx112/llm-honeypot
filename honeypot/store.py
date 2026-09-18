"""遥测存储层: SQLite(WAL) 记录会话、请求、信号、战役、蜜标、事件与阻断。

线程安全说明: 服务端是单线程 asyncio, 而仪表盘在独立线程读库,
因此连接用 check_same_thread=False 并加互斥锁串行化。
"""

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    ip            TEXT,
    port          INTEGER,
    first_seen    REAL,
    last_seen     REAL,
    ua            TEXT,
    ua_hash       TEXT,
    header_sig    TEXT,
    label         TEXT,
    score         INTEGER DEFAULT 0,
    confidence    REAL DEFAULT 0,
    action        TEXT,
    signals_json  TEXT,
    req_count     INTEGER DEFAULT 0,
    asset_count   INTEGER DEFAULT 0,
    bytes_in      INTEGER DEFAULT 0,
    bytes_out     INTEGER DEFAULT 0,
    tarpit_ms     INTEGER DEFAULT 0,
    behavior_hash TEXT,
    campaign_id   TEXT,
    tokens_json   TEXT,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
CREATE INDEX IF NOT EXISTS idx_sessions_bh ON sessions(behavior_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_seen ON sessions(last_seen);

CREATE TABLE IF NOT EXISTS requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT,
    ip             TEXT,
    ts             REAL,
    method         TEXT,
    target         TEXT,
    path           TEXT,
    query          TEXT,
    version        TEXT,
    host           TEXT,
    status         INTEGER,
    resp_bytes     INTEGER,
    delay_ms       INTEGER,
    action         TEXT,
    score          INTEGER,
    signals_json   TEXT,
    headers_json   TEXT,
    body_text      TEXT,
    body_len       INTEGER,
    body_truncated INTEGER,
    malformed      TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip);

CREATE TABLE IF NOT EXISTS signals (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL,
    session_id TEXT,
    request_id INTEGER,
    ip         TEXT,
    name       TEXT,
    weight     INTEGER,
    kind       TEXT,
    evidence   TEXT
);
CREATE INDEX IF NOT EXISTS idx_signals_session ON signals(session_id);
CREATE INDEX IF NOT EXISTS idx_signals_name ON signals(name);

CREATE TABLE IF NOT EXISTS campaigns (
    id             TEXT PRIMARY KEY,
    created        REAL,
    last_seen      REAL,
    behavior_hash  TEXT,
    ips_json       TEXT,
    ua_list_json   TEXT,
    toolchain      TEXT,
    model_guess    TEXT,
    score_max      INTEGER DEFAULT 0,
    session_count  INTEGER DEFAULT 0,
    token_hits     INTEGER DEFAULT 0,
    injection_hits INTEGER DEFAULT 0,
    evidence_json  TEXT,
    notes          TEXT
);
CREATE INDEX IF NOT EXISTS idx_campaigns_bh ON campaigns(behavior_hash);

CREATE TABLE IF NOT EXISTS honeytokens (
    id            TEXT PRIMARY KEY,
    token         TEXT UNIQUE,
    kind          TEXT,
    path          TEXT,
    created       REAL,
    first_read_ts REAL,
    read_count    INTEGER DEFAULT 0,
    sessions_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON honeytokens(token);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL,
    kind       TEXT,
    session_id TEXT,
    ip         TEXT,
    detail     TEXT,
    severity   TEXT DEFAULT 'info'
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS blocks (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL,
    ip      TEXT,
    reason  TEXT,
    score   INTEGER,
    mode    TEXT,
    rule    TEXT,
    applied INTEGER DEFAULT 0,
    expires REAL
);
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip);
"""


def _now():
    return time.time()


def _dumps(value):
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


class Store(object):
    def __init__(self, path):
        self.path = path
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=0o750)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ---- 低层 ----------------------------------------------------------

    def _write(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid

    def _read(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def _read_one(self, sql, params=()):
        rows = self._read(sql, params)
        return rows[0] if rows else None

    def close(self):
        with self._lock:
            try:
                self._conn.commit()
            finally:
                self._conn.close()

    # ---- 会话 ----------------------------------------------------------

    def start_session(self, sid, ip, port, ua, ua_hash, header_sig, behavior_hash=None):
        now = _now()
        self._write(
            "INSERT OR REPLACE INTO sessions"
            " (id, ip, port, first_seen, last_seen, ua, ua_hash, header_sig,"
            "  behavior_hash, label, score, action, req_count, asset_count,"
            "  bytes_in, bytes_out, tarpit_ms, tokens_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, ip, port, now, now, ua, ua_hash, header_sig, behavior_hash,
             "unknown", 0, "serve", 0, 0, 0, 0, 0, _dumps([])),
        )
        return sid

    def update_session(self, sid, **fields):
        if not fields:
            return
        allowed = {
            "last_seen", "ua", "ua_hash", "header_sig", "label", "score",
            "confidence", "action", "signals_json", "req_count", "asset_count",
            "bytes_in", "bytes_out", "tarpit_ms", "behavior_hash", "campaign_id",
            "tokens_json", "note",
        }
        sets = []
        params = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            sets.append("%s = ?" % key)
            params.append(value)
        if not sets:
            return
        params.append(sid)
        self._write("UPDATE sessions SET %s WHERE id = ?" % ", ".join(sets), params)

    def bump_session(self, sid, ts, bytes_in=0, bytes_out=0, tarpit_ms=0, is_asset=False):
        self._write(
            "UPDATE sessions SET last_seen = ?,"
            " req_count = req_count + 1,"
            " asset_count = asset_count + ?,"
            " bytes_in = bytes_in + ?,"
            " bytes_out = bytes_out + ?,"
            " tarpit_ms = tarpit_ms + ?"
            " WHERE id = ?",
            (ts, 1 if is_asset else 0, bytes_in, bytes_out, tarpit_ms, sid),
        )

    def get_session(self, sid):
        return self._read_one("SELECT * FROM sessions WHERE id = ?", (sid,))

    def recent_sessions(self, limit=100, min_score=0):
        return self._read(
            "SELECT * FROM sessions WHERE score >= ? ORDER BY last_seen DESC LIMIT ?",
            (min_score, limit),
        )

    def sessions_by_ip(self, ip, limit=50):
        return self._read(
            "SELECT * FROM sessions WHERE ip = ? ORDER BY last_seen DESC LIMIT ?",
            (ip, limit),
        )

    def sessions_by_behavior(self, behavior_hash, limit=200):
        return self._read(
            "SELECT * FROM sessions WHERE behavior_hash = ? ORDER BY last_seen DESC LIMIT ?",
            (behavior_hash, limit),
        )

    def distinct_ips_for_behavior(self, behavior_hash):
        rows = self._read(
            "SELECT DISTINCT ip FROM sessions WHERE behavior_hash = ?", (behavior_hash,)
        )
        return [row["ip"] for row in rows]

    # ---- 请求 ----------------------------------------------------------

    def log_request(self, session_id, ip, req_meta, ts, status, resp_bytes,
                    delay_ms, action, score, signals):
        return self._write(
            "INSERT INTO requests"
            " (session_id, ip, ts, method, target, path, query, version, host,"
            "  status, resp_bytes, delay_ms, action, score, signals_json,"
            "  headers_json, body_text, body_len, body_truncated, malformed)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                session_id, ip, ts,
                req_meta.get("method"), req_meta.get("target"), req_meta.get("path"),
                req_meta.get("query"), req_meta.get("version"), req_meta.get("host"),
                status, resp_bytes, delay_ms, action, score,
                _dumps([s["name"] for s in signals]),
                _dumps(req_meta.get("headers", [])),
                req_meta.get("body_text", "")[:32768],
                req_meta.get("body_len", 0),
                1 if req_meta.get("body_truncated") else 0,
                ",".join(req_meta.get("malformed", [])),
            ),
        )

    def session_requests(self, session_id, limit=500):
        return self._read(
            "SELECT * FROM requests WHERE session_id = ? ORDER BY ts ASC LIMIT ?",
            (session_id, limit),
        )

    def recent_requests(self, limit=200):
        return self._read(
            "SELECT id, session_id, ip, ts, method, target, status, action, score"
            " FROM requests ORDER BY id DESC LIMIT ?",
            (limit,),
        )

    def requests_between(self, start_ts, end_ts, limit=5000):
        return self._read(
            "SELECT * FROM requests WHERE ts >= ? AND ts <= ? ORDER BY ts ASC LIMIT ?",
            (start_ts, end_ts, limit),
        )

    # ---- 信号与事件 ----------------------------------------------------

    def log_signal(self, session_id, ip, name, weight, kind, evidence, ts=None, request_id=None):
        return self._write(
            "INSERT INTO signals (ts, session_id, request_id, ip, name, weight, kind, evidence)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ts or _now(), session_id, request_id, ip, name, weight, kind, str(evidence)[:2048]),
        )

    def session_signals(self, session_id):
        return self._read(
            "SELECT name, weight, MAX(ts) AS ts, COUNT(*) AS hits, MAX(evidence) AS evidence"
            " FROM signals WHERE session_id = ? GROUP BY name ORDER BY weight DESC",
            (session_id,),
        )

    def signals_summary(self, limit=50, since=None):
        if since is None:
            return self._read(
                "SELECT name, weight, COUNT(*) AS hits, COUNT(DISTINCT session_id) AS sessions"
                " FROM signals GROUP BY name ORDER BY hits DESC LIMIT ?",
                (limit,),
            )
        return self._read(
            "SELECT name, weight, COUNT(*) AS hits, COUNT(DISTINCT session_id) AS sessions"
            " FROM signals WHERE ts >= ? GROUP BY name ORDER BY hits DESC LIMIT ?",
            (since, limit),
        )

    def log_event(self, kind, session_id=None, ip=None, detail="", severity="info", ts=None):
        return self._write(
            "INSERT INTO events (ts, kind, session_id, ip, detail, severity) VALUES (?,?,?,?,?,?)",
            (ts or _now(), kind, session_id, ip, str(detail)[:4096], severity),
        )

    def recent_events(self, limit=200, kind=None):
        if kind:
            return self._read(
                "SELECT * FROM events WHERE kind = ? ORDER BY id DESC LIMIT ?", (kind, limit)
            )
        return self._read("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    # ---- 蜜标 ----------------------------------------------------------

    def register_token(self, token, kind, path, meta=None):
        self._write(
            "INSERT OR REPLACE INTO honeytokens"
            " (id, token, kind, path, created, first_read_ts, read_count, sessions_json)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (token, token, kind, path, _now(), None, 0, _dumps(meta or [])),
        )

    def read_token(self, token, session_id=None, ip=None, kind=None, path=None):
        """记录一次蜜标被读取。返回 True 表示这是首次读取(可用于告警)。

        蜜标未登记时**自动登记**。这一点很关键: 蜜标定义来自模板/欺骗面,
        而登记与读取发生在不同代码路径上; 如果读取时因未登记而静默返回 False,
        最高价值的取证事件(攻击者读取了伪造凭据)就会凭空消失 —— 真实踩过。
        """
        row = self._read_one("SELECT * FROM honeytokens WHERE token = ?", (token,))
        if row is None:
            self.register_token(token, kind or "implicit", path or token)
            row = self._read_one("SELECT * FROM honeytokens WHERE token = ?", (token,))
            if row is None:
                return False
        first = row["first_read_ts"] is None
        sessions = []
        try:
            sessions = json.loads(row["sessions_json"] or "[]")
        except ValueError:
            sessions = []
        if session_id and session_id not in sessions:
            sessions.append(session_id)
        self._write(
            "UPDATE honeytokens SET first_read_ts = COALESCE(first_read_ts, ?),"
            " read_count = read_count + 1, sessions_json = ? WHERE token = ?",
            (_now(), _dumps(sessions), token),
        )
        return first

    def token_reads(self, limit=200):
        return self._read(
            "SELECT token, kind, path, first_read_ts, read_count, sessions_json"
            " FROM honeytokens WHERE read_count > 0 ORDER BY first_read_ts DESC LIMIT ?",
            (limit,),
        )

    def token_stats(self):
        return self._read_one(
            "SELECT COUNT(*) AS total,"
            " SUM(CASE WHEN read_count > 0 THEN 1 ELSE 0 END) AS touched,"
            " COALESCE(SUM(read_count),0) AS reads FROM honeytokens"
        ) or {"total": 0, "touched": 0, "reads": 0}

    # ---- 战役 ----------------------------------------------------------

    def upsert_campaign(self, cid, behavior_hash, ip=None, ua=None, toolchain=None,
                        model_guess=None, score=0, evidence=None):
        row = self._read_one("SELECT * FROM campaigns WHERE id = ?", (cid,))
        now = _now()
        if row is None:
            self._write(
                "INSERT INTO campaigns"
                " (id, created, last_seen, behavior_hash, ips_json, ua_list_json,"
                "  toolchain, model_guess, score_max, session_count, token_hits,"
                "  injection_hits, evidence_json, notes)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, now, now, behavior_hash, _dumps([ip] if ip else []),
                 _dumps([ua] if ua else []), toolchain, model_guess, score, 1, 0, 0,
                 _dumps(evidence or {}), ""),
            )
            return cid

        ips = _load_list(row["ips_json"])
        if ip and ip not in ips:
            ips.append(ip)
        uas = _load_list(row["ua_list_json"])
        if ua and ua not in uas:
            uas.append(ua)
        evidence_merged = {}
        try:
            evidence_merged = json.loads(row["evidence_json"] or "{}")
        except ValueError:
            evidence_merged = {}
        if evidence:
            evidence_merged.update(evidence)

        self._write(
            "UPDATE campaigns SET last_seen = ?, ips_json = ?, ua_list_json = ?,"
            " toolchain = COALESCE(?, toolchain), model_guess = COALESCE(?, model_guess),"
            " score_max = MAX(score_max, ?), session_count = ?, evidence_json = ?"
            " WHERE id = ?",
            (now, _dumps(ips), _dumps(uas), toolchain, model_guess, score,
             len(ips), _dumps(evidence_merged), cid),
        )
        return cid

    def bump_campaign(self, cid, token_hits=0, injection_hits=0):
        self._write(
            "UPDATE campaigns SET token_hits = token_hits + ?,"
            " injection_hits = injection_hits + ?, last_seen = ? WHERE id = ?",
            (token_hits, injection_hits, _now(), cid),
        )

    def campaigns(self, limit=100):
        return self._read(
            "SELECT * FROM campaigns ORDER BY score_max DESC, last_seen DESC LIMIT ?", (limit,)
        )

    def get_campaign(self, cid):
        return self._read_one("SELECT * FROM campaigns WHERE id = ?", (cid,))

    def campaigns_for_ip(self, ip):
        rows = self.campaigns(limit=1000)
        out = []
        for row in rows:
            if ip in _load_list(row["ips_json"]):
                out.append(row)
        return out

    # ---- 阻断 ----------------------------------------------------------

    def record_block(self, ip, reason, score, mode, rule, applied=False, ttl_seconds=3600):
        return self._write(
            "INSERT INTO blocks (ts, ip, reason, score, mode, rule, applied, expires)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (_now(), ip, reason, score, mode, rule, 1 if applied else 0, _now() + ttl_seconds),
        )

    def blocks(self, limit=200):
        return self._read("SELECT * FROM blocks ORDER BY id DESC LIMIT ?", (limit,))

    def is_blocked(self, ip):
        row = self._read_one(
            "SELECT * FROM blocks WHERE ip = ? AND expires > ? ORDER BY id DESC LIMIT 1",
            (ip, _now()),
        )
        return row is not None

    # ---- 统计与维护 ----------------------------------------------------

    def stats(self):
        out = {}
        for label, sql in (
            ("sessions", "SELECT COUNT(*) AS c FROM sessions"),
            ("sessions_llm", "SELECT COUNT(*) AS c FROM sessions WHERE label LIKE 'llm%'"),
            ("sessions_scanner", "SELECT COUNT(*) AS c FROM sessions WHERE label = 'automation_scanner'"),
            ("requests", "SELECT COUNT(*) AS c FROM requests"),
            ("signals", "SELECT COUNT(*) AS c FROM signals"),
            ("events", "SELECT COUNT(*) AS c FROM events"),
            ("campaigns", "SELECT COUNT(*) AS c FROM campaigns"),
            ("high_score", "SELECT COUNT(*) AS c FROM sessions WHERE score >= 70"),
        ):
            row = self._read_one(sql)
            out[label] = row["c"] if row else 0
        row = self._read_one("SELECT COUNT(DISTINCT ip) AS c FROM sessions")
        out["distinct_ips"] = row["c"] if row else 0
        return out

    def top_ips(self, limit=50):
        return self._read(
            "SELECT ip, COUNT(*) AS sessions, MAX(score) AS score_max,"
            " SUM(req_count) AS requests, MAX(last_seen) AS last_seen,"
            " GROUP_CONCAT(DISTINCT label) AS labels"
            " FROM sessions GROUP BY ip ORDER BY score_max DESC, requests DESC LIMIT ?",
            (limit,),
        )

    def prune(self, retention_days):
        if retention_days <= 0:
            return 0
        cutoff = _now() - retention_days * 86400
        removed = 0
        with self._lock:
            for sql in (
                "DELETE FROM requests WHERE ts < ?",
                "DELETE FROM signals WHERE ts < ?",
                "DELETE FROM events WHERE ts < ?",
                "DELETE FROM sessions WHERE last_seen < ?",
                "DELETE FROM blocks WHERE expires < ?",
            ):
                cur = self._conn.execute(sql, (cutoff,))
                removed += cur.rowcount or 0
            self._conn.commit()
        return removed


def _load_list(raw):
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except ValueError:
        return []
