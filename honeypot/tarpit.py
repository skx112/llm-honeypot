"""自适应拖滞引擎(tarpit)。

拖滞的目标不是"把连接挂住"这么简单, 而是让自动化攻击者的成本曲线反转:
  - 它的工具超时会先到, 于是它重试; 重试让延迟继续指数增长。
  - 单次请求从 200ms 变成 8s, 一轮侦察从几分钟变成几小时。
  - LLM 智能体还会因为超时而反复"重试同一动作", 大量消耗推理预算。

同时必须保护蜜罐自身, 否则拖滞就变成了攻击者拖垮我们的手段。三重护栏:
  1. 单会话累计拖滞上限
  2. 全局每分钟拖滞预算(滚动窗口)
  3. 系统负载熔断(负载过高立即降级为即时响应并告警)
"""

import os
import random
import time


class TarpitPlan(object):
    """一次拖滞的执行计划。由服务端按此计划写字节。"""

    __slots__ = ("pre_body_delay", "chunk_count", "chunk_interval",
                 "hold_seconds", "infinite", "reason", "granted")

    def __init__(self, pre_body_delay=0.0, chunk_count=1, chunk_interval=0.0,
                 hold_seconds=0.0, infinite=False, reason="", granted=0.0):
        self.pre_body_delay = pre_body_delay
        self.chunk_count = chunk_count
        self.chunk_interval = chunk_interval
        self.hold_seconds = hold_seconds
        self.infinite = infinite
        self.reason = reason
        self.granted = granted

    def total_seconds(self):
        return (self.pre_body_delay + self.chunk_interval * max(0, self.chunk_count - 1)
                + self.hold_seconds)

    def is_noop(self):
        return (self.pre_body_delay <= 0 and self.chunk_count <= 1
                and self.chunk_interval <= 0 and not self.infinite)


class TarpitBudget(object):
    """拖滞预算与熔断。"""

    def __init__(self, per_session=300.0, global_per_min=900.0,
                 load_threshold=0.92, cpu_count=None, window=60.0):
        self.per_session = float(per_session)
        self.global_per_min = float(global_per_min)
        self.load_threshold = float(load_threshold)
        self.window = float(window)
        self.cpu_count = cpu_count or os.cpu_count() or 1
        self._session_used = {}
        self._window = []          # [(ts, seconds)]
        self._window_total = 0.0
        self._shed_until = 0.0
        self.shed_events = 0

    # ---- 窗口维护 ------------------------------------------------------

    def _prune(self, now):
        cutoff = now - self.window
        while self._window and self._window[0][0] < cutoff:
            _, seconds = self._window.pop(0)
            self._window_total -= seconds
        if self._window_total < 0:
            self._window_total = 0.0

    def _load_ratio(self):
        try:
            load1, _, _ = os.getloadavg()
        except (OSError, AttributeError):
            return 0.0
        return load1 / float(self.cpu_count)

    def shed(self, now=None):
        """是否需要熔断(降级为即时响应)。返回 (是否熔断, 原因)。"""
        now = now or time.time()
        if now < self._shed_until:
            return True, "熔断冷却中(剩余 %.0fs)" % (self._shed_until - now)
        ratio = self._load_ratio()
        if ratio >= self.load_threshold:
            self._shed_until = now + 30.0
            self.shed_events += 1
            return True, "系统负载 %.2f 超过阈值 %.2f" % (ratio, self.load_threshold)
        if self._window_total >= self.global_per_min:
            self._shed_until = now + 10.0
            self.shed_events += 1
            return True, "全局拖滞预算已用尽(%.0fs/%ds)" % (
                self._window_total, int(self.window))
        return False, ""

    # ---- 预算申请 ------------------------------------------------------

    def reserve(self, sid, seconds, now=None):
        """申请 seconds 秒拖滞预算, 返回实际获批的秒数(可能被削减为 0)。"""
        now = now or time.time()
        self._prune(now)
        shed, _ = self.shed(now)
        if shed:
            return 0.0

        used = self._session_used.get(sid, 0.0)
        room_session = max(0.0, self.per_session - used)
        room_global = max(0.0, self.global_per_min - self._window_total)
        granted = min(seconds, room_session, room_global)
        if granted <= 0:
            return 0.0

        self._session_used[sid] = used + granted
        self._window.append((now, granted))
        self._window_total += granted
        return granted

    def session_used(self, sid):
        return self._session_used.get(sid, 0.0)

    def forget_session(self, sid):
        self._session_used.pop(sid, None)

    def stats(self):
        return {
            "sessions_tracked": len(self._session_used),
            "window_seconds": round(self._window_total, 2),
            "budget_per_min": self.global_per_min,
            "shed_events": self.shed_events,
            "load_ratio": round(self._load_ratio(), 3),
        }


class Tarpit(object):
    """按会话进度与判定分数计算拖滞计划。"""

    def __init__(self, config, budget=None, store=None):
        self.cfg = config
        self.base_delay = float(config.get("tarpit.base_delay", 0.4))
        self.growth = float(config.get("tarpit.growth", 1.32))
        self.max_delay = float(config.get("tarpit.max_delay", 8.0))
        self.jitter = float(config.get("tarpit.jitter", 0.35))
        self.drip_chunks = int(config.get("tarpit.drip_chunks", 6))
        self.infinite_max = float(config.get("tarpit.infinite_stream_max", 120.0))
        self.lockdown_keepalive = float(config.get("tarpit.lockdown_keepalive", 240.0))
        self.budget = budget or TarpitBudget(
            per_session=config.get("limits.max_tarpit_seconds_per_session", 300.0),
            global_per_min=config.get("limits.global_tarpit_budget_per_min", 900.0),
            load_threshold=config.get("limits.load_shed_threshold", 0.92),
        )
        self.store = store
        self._rng = random.Random()

    def adaptive_delay(self, profile):
        """延迟随会话请求数指数增长 —— 攻击者越执着, 代价越高。"""
        steps = max(0, profile.req_count - 1)
        delay = self.base_delay * (self.growth ** min(steps, 24))
        delay = min(delay, self.max_delay)
        # 抖动: 让对方无法用固定超时绕过
        delay *= 1.0 + self._rng.uniform(-self.jitter, self.jitter)
        return max(0.0, delay)

    def plan(self, profile, verdict, action, reply=None):
        """生成拖滞计划。无拖滞需要时返回 None。"""
        if action in ("serve",):
            return None

        weight = getattr(reply, "tarpit_weight", 0) if reply is not None else 0
        if action == "serve_watch":
            requested = max(0.2, self.adaptive_delay(profile) * 0.35)
            plan = TarpitPlan(pre_body_delay=requested, reason="轻度拖滞(观察中)")
        elif action == "tarpit":
            requested = self.adaptive_delay(profile) * (1.0 + 0.5 * weight)
            plan = TarpitPlan(
                pre_body_delay=requested,
                chunk_count=max(2, self.drip_chunks + weight),
                chunk_interval=0.25 + 0.15 * weight,
                reason="分级拖滞(自动化判定)",
            )
        elif action == "deceive_inject":
            requested = self.adaptive_delay(profile) * (1.4 + 0.5 * weight)
            plan = TarpitPlan(
                pre_body_delay=requested,
                chunk_count=max(3, self.drip_chunks + 2 + weight),
                chunk_interval=0.4 + 0.2 * weight,
                hold_seconds=min(self.infinite_max, 20.0 + 10.0 * weight),
                reason="拖滞+注入(LLM 智能体判定)",
            )
        else:  # lockdown
            requested = self.adaptive_delay(profile) * 2.0
            plan = TarpitPlan(
                pre_body_delay=requested,
                chunk_count=max(4, self.drip_chunks + 4),
                chunk_interval=0.6 + 0.2 * weight,
                hold_seconds=self.lockdown_keepalive,
                infinite=True,
                reason="锁定拖滞(高置信度智能体)",
            )

        granted = self.budget.reserve(profile.sid, plan.total_seconds())
        if granted <= 0:
            return None
        if granted < plan.total_seconds():
            # 按获批额度等比压缩
            ratio = granted / plan.total_seconds()
            plan.pre_body_delay *= ratio
            plan.chunk_interval *= ratio
            plan.hold_seconds *= ratio
        plan.granted = granted
        return plan
