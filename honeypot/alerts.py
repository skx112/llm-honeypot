"""告警通道: 本地文件 + 可选 webhook 外发。

## 为什么需要独立模块

此前告警只写本地 `logs/alerts.log` —— 护网实战里蜜罐告警进不了 SOC 平台,
等于值班看不见。本模块补上外发通道, 同时坚守两条原则:

  1. **告警永远不能拖累蜜罐**。外发走后台线程 + 内存队列: 网络慢、对端挂了、
     DNS 解析失败, 都只影响告警自己(按节流记录失败), 绝不阻塞请求处理路径。
  2. **零依赖**。webhook 用 urllib POST JSON —— 对接企业微信/飞书/钉钉机器人
     或自建接收端都足够。需要重试队列/签名时再考虑可选依赖, 接口保持不变。

## 语义

  · emit(line, severity) 与原先直接写文件的行为兼容: 文件照写(dashboard 的
    告警尾部仍从文件读), 配置了 webhook 时再异步外发。
  · 级别门控: 默认 warning 及以上才外发(info 只落文件), 避免噪声打爆 SOC。
  · 进程退出时 flush 剩余队列(最多等几秒), 不丢已入队的告警。

## 配置

    "alert": {
      "webhook_url": "",                  // 空 = 不外发
      "webhook_min_severity": "warning",  // info | warning | critical
      "webhook_timeout": 5.0
    }

## webhook 载荷

    POST <webhook_url>
    Content-Type: application/json

    {"schema": 1, "instance": "...", "severity": "critical",
     "message": "……原告警行……", "ts": 1758…, "iso": "2026-09-18T…Z"}

对接飞书/企业微信机器人时通常需要包一层 {"msg_type":"text","content":…},
在接收侧做适配即可(或扩展本模块的 formatter, 接口已预留)。
"""

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request

SCHEMA = 1
SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
# 队列上限: 告警风暴时丢弃最旧的而不是无界增长(蜜罐自身保护优先)
MAX_QUEUE = 2000
FLUSH_TIMEOUT = 4.0


class Alerter(object):
    """文件 + 可选 webhook 的统一告警出口。

    线程安全; emit() 只做入队与文件追加, 网络IO 全在后台线程。
    """

    def __init__(self, config):
        self.cfg = config
        self.instance = config.get("instance", "honeypot")
        self.webhook_url = (config.get("alert.webhook_url") or "").strip()
        self.min_severity = config.get("alert.webhook_min_severity", "warning")
        self.timeout = float(config.get("alert.webhook_timeout", 5.0))
        self.log_path = config.path(config.get("alert.log_path", "logs/alerts.log"))

        self._queue = queue.Queue(maxsize=MAX_QUEUE)
        self._stop = threading.Event()
        self._worker = None
        self._fail_count = 0
        self._last_fail_note = 0.0

        if self.webhook_url:
            self._worker = threading.Thread(target=self._run, name="cogtrap-alerts")
            self._worker.daemon = True
            self._worker.start()

    # ---- 主路径(必须快且绝不抛) ----------------------------------------

    def emit(self, line, severity="warning"):
        """记录一条告警。文件同步追加, webhook 异步外发。"""
        now = time.time()
        stamped = "%s [%s] [%s] %s" % (
            time.strftime("%Y-%m-%dT%H:%M:%S%z"), severity, self.instance, line)
        self._append_file(stamped)

        if not self.webhook_url:
            return
        if SEVERITY_ORDER.get(severity, 1) < SEVERITY_ORDER.get(self.min_severity, 1):
            return
        payload = {
            "schema": SCHEMA, "instance": self.instance, "severity": severity,
            "message": line, "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            # 丢最旧再入队: 告警风暴下保新弃旧, 并在文件里记一次
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(payload)
            except (queue.Empty, queue.Full):
                pass

    def close(self):
        """停止后台线程并尽量发完已入队的告警。"""
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=FLUSH_TIMEOUT + 2.0)

    # ---- 文件 ----------------------------------------------------------

    def _append_file(self, stamped):
        try:
            directory = os.path.dirname(self.log_path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o750)
            with open(self.log_path, "a") as handle:
                handle.write(stamped + "\n")
        except IOError:
            pass                     # 文件失败不能影响蜜罐; 此前行为亦如此

    # ---- 后台发送 ------------------------------------------------------

    def _run(self):
        while not self._stop.is_set():
            try:
                payload = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._deliver(payload)
            if self._queue.empty():
                # 队列清空后顺带检查退出标志, 避免半秒空转延迟停机
                if self._stop.is_set():
                    break

    def _deliver(self, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.webhook_url, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "cogtrap-alerts/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read(4096)
            self._fail_count = 0
        except Exception as exc:                       # 网络/HTTP/解析全部容忍
            self._note_failure(exc)

    def _note_failure(self, exc):
        """失败节流: 每 60 秒最多在本地文件记一条, 不刷屏。"""
        self._fail_count += 1
        now = time.time()
        if now - self._last_fail_note >= 60.0:
            self._last_fail_note = now
            self._append_file(
                "%s [info] [%s] webhook 外发失败(累计 %d 次, 最近: %r) —— "
                "告警仍在本文件" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                    self.instance, self._fail_count, exc))

    # ---- 观测 ----------------------------------------------------------

    def stats(self):
        return {
            "webhook_enabled": bool(self.webhook_url),
            "queued": self._queue.qsize(),
            "delivery_failures": self._fail_count,
            "min_severity": self.min_severity,
        }


_DEFAULT = None


def get_alerter(config):
    """进程级单例。多个入口(server/ssh_decoy)共享同一队列与线程。"""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Alerter(config)
    return _DEFAULT


def reset_for_tests():
    """测试隔离用: 丢弃单例(会停掉旧线程)。"""
    global _DEFAULT
    if _DEFAULT is not None:
        _DEFAULT.close()
        _DEFAULT = None
