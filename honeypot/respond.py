"""决策引擎: 把指纹判定翻译成具体的处置动作。

处置梯度(分数 -> 动作):
  <25    serve           正常欺骗, 只记录
  25-49  serve_watch     记录 + 轻度拖滞, 观察节律
  50-69  tarpit          分级拖滞 + 第一层载荷(中止/假阴性)
  70-84  deceive_inject  重度拖滞 + 全部载荷 + 金丝雀/信标校验
  >=85   lockdown        锁定拖滞(保持连接缓慢喂数据) + 阻断候选

设计上刻意"慢启动": 前几个请求不给强反制, 一是避免惊动对方, 二是需要
足够样本才能确证。等节律与金丝雀证据到位, 再一次性把成本拉满。
"""

import fingerprint
import inject

# 默认处置梯度。场景包可以通过 config["respond"]["thresholds"] 覆盖,
# 覆盖时只改动作的触发分数, 不改动作语义。
DEFAULT_THRESHOLDS = {
    "lockdown": 85,
    "deceive_inject": 70,
    "tarpit": 50,
    "serve_watch": 25,
}

# 由高到低, 决定"从哪个档开始判定"
ACTION_ORDER = ("lockdown", "deceive_inject", "tarpit", "serve_watch")


class Decision(object):
    __slots__ = ("action", "reason", "expectations", "inject_tier", "alert",
                 "block_candidate", "tier_hint")

    def __init__(self, action, reason="", expectations=None, inject_tier=0,
                 alert=False, block_candidate=False):
        self.action = action
        self.reason = reason
        self.expectations = list(expectations or [])
        self.inject_tier = inject_tier
        self.alert = alert
        self.block_candidate = block_candidate

    def to_dict(self):
        return {"action": self.action, "reason": self.reason,
                "inject_tier": self.inject_tier, "alert": self.alert,
                "block_candidate": self.block_candidate,
                "expectations": [e.get("label", "") for e in self.expectations]}


def resolved_thresholds(config=None):
    """合并默认阈值与场景覆盖, 并保证严格递增(否则某档永远不会触发)。"""
    merged = dict(DEFAULT_THRESHOLDS)
    if config is not None:
        override = (config.get("respond", {}) or {}).get("thresholds") or {}
        for action, value in override.items():
            if action in merged:
                merged[action] = int(value)
    # 单调性兜底: 场景文件已被校验, 但配置也可能被手工改坏
    previous = None
    for action in ("serve_watch", "tarpit", "deceive_inject", "lockdown"):
        if previous is not None and merged[action] <= previous:
            merged[action] = previous + 1
        previous = merged[action]
    return merged


def action_for_score(score, thresholds=None):
    """按阈值把分数映射到处置动作。

    thresholds 为 None 时使用内置梯度, 便于单元测试与回放。
    """
    active = thresholds or DEFAULT_THRESHOLDS
    for action in ACTION_ORDER:
        if score >= active.get(action, DEFAULT_THRESHOLDS[action]):
            return action
    return "serve"


def decide(verdict, profile, config):
    """产出本请求的处置决定。"""
    cfg_inject = config.get("inject", {}) or {}
    cfg_block = config.get("block", {}) or {}
    inject_enabled = bool(cfg_inject.get("enabled", True))
    inject_min = int(cfg_inject.get("min_score", 50))

    action = action_for_score(verdict.score, resolved_thresholds(config))
    reason_bits = []
    if verdict.decisive:
        reason_bits.append("确证证据: " + ",".join(verdict.decisive))
    if verdict.cadence:
        reason_bits.append("节律: %s" % verdict.cadence)
    if verdict.toolchain:
        reason_bits.append("工具链: %s" % verdict.toolchain)
    reason = "; ".join(reason_bits) or ("分数 %d" % verdict.score)
    # 把生效阈值与权重覆盖记进处置说明, 值班时能一眼确认场景策略真的生效了
    overrides = fingerprint.active_weight_overrides()
    if overrides:
        reason += " | 权重覆盖 %d 项" % len(overrides)

    decision = Decision(action, reason)

    # 载荷层: 只对达到阈值的自动化目标投放; 已确证的智能体直接拉满
    if inject_enabled and verdict.score >= inject_min:
        decision.inject_tier = 3 if verdict.score >= 85 else (
            2 if verdict.score >= 70 else 1)
        if verdict.decisive:
            decision.inject_tier = 3
        payload_ctx = profile_ctx_get(profile)
        if payload_ctx is not None:
            decision.expectations = inject.build_expectations(
                payload_ctx, verdict.score, cfg_inject)

    alert_min = int(config.get("alert.min_score", 70))
    decision.alert = verdict.score >= alert_min or bool(verdict.decisive)

    auto_threshold = int(cfg_block.get("auto_threshold", 85))
    decision.block_candidate = (
        verdict.score >= auto_threshold
        and bool(cfg_block.get("armed", False))
    )
    return decision


def profile_ctx_get(profile):
    """Decision 需要的是 PayloadContext, 由调用方通过 session 传入。

    为了不让 decide() 依赖 server 的会话对象, 这里约定: profile 上挂一个
    `payload_ctx` 属性(由 server 在建立会话时设置)。找不到时返回 None,
    此时不产生期望项(仍会记录与拖滞)。
    """
    return getattr(profile, "payload_ctx", None)


def apply_expectations(request, session, store=None):
    """检查本请求是否满足先前投放的指令期望, 并记录证据。

    返回命中列表。命中"交出系统提示词"这类反制情报时, 会以 critical 级别
    单独落库 —— 这是上报里最有价值的一条证据。
    """
    hits = inject.check_expectations(request, session.expectations)
    if not hits:
        return hits

    for hit in hits:
        kind = hit.get("kind")
        if kind == "beacon":
            session.profile.note_beacon(hit.get("evidence", ""))
            session.inject_hits += 1
        else:
            session.profile.note_compliance(hit.get("label", ""), hit.get("evidence", ""))
            session.compliance_hits += 1

        if store is not None:
            severity = "critical" if hit.get("intel") else "warning"
            store.log_event(
                "injection_compliance" if kind == "compliance" else "beacon_callback",
                session.sid, session.ip,
                "%s | %s" % (hit.get("label", ""), hit.get("evidence", "")),
                severity,
            )
            if hit.get("intel") and hit.get("captured"):
                store.log_event(
                    "agent_config_captured", session.sid, session.ip,
                    "捕获攻击方智能体配置: %s" % hit["captured"][:2000],
                    "critical",
                )
    return hits


def should_alert(verdict, decision, already_alerted):
    if not decision.alert or already_alerted:
        return False
    return True
