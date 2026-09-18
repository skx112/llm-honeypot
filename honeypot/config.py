"""配置加载: 默认值 + config.json 深合并, 并提供路径解析与目录创建。"""

import copy
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")

DEFAULTS = {
    "instance": "hw-blue-honeypot-01",
    "http": {
        "listen": ["0.0.0.0"],
        "port": 8080,
        "server_header": "nginx/1.24.0 (Ubuntu)",
        "tls": {"enabled": False, "cert": "", "key": ""},
    },
    "ssh_decoy": {
        "enabled": True,
        "listen": "0.0.0.0",
        "port": 2222,
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
    },
    "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 8899},
    "limits": {
        "max_connections": 2048,
        "max_per_ip": 24,
        "max_head_bytes": 65536,
        "max_body_bytes": 1048576,
        "head_timeout": 15.0,
        "idle_timeout": 60.0,
        "max_requests_per_conn": 200,
        "max_tarpit_seconds_per_session": 300.0,
        "global_tarpit_budget_per_min": 900.0,
        "load_shed_threshold": 0.92,
    },
    "tarpit": {
        "base_delay": 0.4,
        "growth": 1.32,
        "max_delay": 8.0,
        "jitter": 0.35,
        "drip_chunks": 6,
        "infinite_stream_max": 120.0,
        "lockdown_keepalive": 240.0,
    },
    "inject": {
        "enabled": True,
        "min_score": 50,
        "canary_test_min_score": 62,
        "beacon_min_score": 70,
        "custom_dir": "payloads/custom",
    },
    "block": {
        "armed": False,
        "mode": "absorb",
        "apply": False,
        "auto_threshold": 85,
        "ttl_seconds": 3600,
        "absorb_target": "127.0.0.1:8080",
        "whitelist": ["127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    },
    "honeytokens": {
        "enabled": True,
        "aws_like": True,
        "github_like": True,
        "internal_api_like": True,
    },
    "store": {"path": "var/telemetry.db", "retention_days": 180},
    "alert": {"enabled": True, "min_score": 70, "log_path": "logs/alerts.log"},
}

# 运行时必须存在的目录, 由 ensure_dirs() 创建
_RUNTIME_DIRS = ("var", "out", "logs", "out/rules", "out/reports", "payloads/custom")


def _deep_merge(base, overlay):
    """把 overlay 深合并进 base 的副本; 返回新 dict。"""
    out = copy.deepcopy(base)
    for key, value in (overlay or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class Config(object):
    """点号取值的配置包装器。

    cfg.get("http.port") / cfg["http"]["port"] 两种方式都可用。
    """

    def __init__(self, data, root=PROJECT_ROOT):
        self._data = data
        self.root = root

    @classmethod
    def load(cls, path=CONFIG_PATH, root=PROJECT_ROOT):
        overlay = {}
        if os.path.exists(path):
            try:
                with open(path, "r") as handle:
                    overlay = json.load(handle)
            except (ValueError, IOError) as exc:
                raise RuntimeError("config.json 解析失败: %s" % exc)

        # 显式指定配置文件时, 相对路径以**配置文件所在目录**为基准, 而不是代码
        # 目录。这样 `cogtrap generate` 产出的实例目录是自包含的: 遥测库、日志、
        # 处置规则都落在实例目录内。否则在 /opt/decoy 部署实例时, 数据会静默写回
        # 源码树(真实踩过)。
        if path and os.path.abspath(path) != os.path.abspath(CONFIG_PATH):
            root = os.path.dirname(os.path.abspath(path)) or root
        return cls(_deep_merge(DEFAULTS, overlay), root=root)

    def get(self, dotted, default=None):
        node = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def as_dict(self):
        return copy.deepcopy(self._data)

    def path(self, relative):
        """把配置里的相对路径解析为项目内绝对路径。"""
        expanded = os.path.expanduser(relative)
        if os.path.isabs(expanded):
            return expanded
        return os.path.join(self.root, expanded)

    def store_path(self):
        return self.path(self.get("store.path", "var/telemetry.db"))

    def out_path(self, *parts):
        return os.path.join(self.root, "out", *parts)

    def ensure_dirs(self):
        for relative in _RUNTIME_DIRS:
            target = os.path.join(self.root, relative)
            if not os.path.isdir(target):
                os.makedirs(target, mode=0o750)
        # 数据库所在目录
        db_dir = os.path.dirname(self.store_path())
        if db_dir and not os.path.isdir(db_dir):
            os.makedirs(db_dir, mode=0o750)
