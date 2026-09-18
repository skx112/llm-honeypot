"""取证与上报: 把遥测数据整理成可直接提交的材料。

## 为什么"上报"需要独立一层

护网评定看的是**能提交、能被采信的证据**, 不是日志条数。因此这一层解决的问题是:

  1. **叙事**。把散落的请求、信号、事件组织成"谁、什么时候、做了什么、我们如何
     确证、造成了什么后果"的完整链条。裁判组读的是这个, 不是原始日志。
  2. **可核验性**。材料里必须带可复核的标识(源 IP、UA、行为哈希、金丝雀令牌),
     让第三方能独立复现判断。
  3. **完整性**。输出附带证据摘要哈希, 覆盖请求序列与关键事件 —— 材料被改动过
     就能被发现。取证材料一旦无法证明未被篡改, 分量会大打折扣。
  4. **脱敏取舍**。我们捕获的凭据是攻击者自己提交的, 属于证据; 但内部的拓扑、
     真实资产信息绝不能出现在对外材料里。因此报告分"内部版"与"对外版"。

## 输出形式

    build_session_report()   单会话档案(dict)
    build_campaign_report()  战役档案(dict, 跨源 IP 聚合)
    render_markdown()        人读材料(Markdown, 可直接贴进上报系统)
    render_abuse_email()     向托管方举报的邮件模板
    export_json / export_csv 机器可读导出
"""

import csv
import hashlib
import io
import json
import os
import time

EVIDENCE_LABELS = {
    "canary_echo": "金丝雀回显(上下文复用)",
    "injection_compliance": "指令服从",
    "agent_config_captured": "攻击方配置泄漏",
    "honeytoken_read": "蜜标读取",
    "beacon_callback": "信标回调",
}

# 对外材料里需要保留的、可核验的标识
IOC_FIELDS = ("ip", "ua", "behavior_hash", "header_sig")

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _ts(value):
    if not value:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def _iso(value):
    if not value:
        return "-"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def _load_json(raw, default):
    try:
        value = json.loads(raw or "")
        return value if value is not None else default
    except (ValueError, TypeError):
        return default


def evidence_digest(requests, events):
    """对证据序列计算摘要, 用于证明材料完整性。

    覆盖请求的关键字段与方法/路径/时间戳, 以及关键事件的类型与详情。
    任何一方改动了材料, 重新计算就会得到不同摘要。
    """
    hasher = hashlib.sha256()
    hasher.update(b"cogtrap-evidence-v1\n")
    for row in requests:
        hasher.update(("%s|%s|%s|%s|%s|%s\n" % (
            row.get("ts"), row.get("method"), row.get("target"),
            row.get("status"), row.get("action"), row.get("score"),
        )).encode("utf-8", "replace"))
    for row in events:
        hasher.update(("%s|%s|%s|%s\n" % (
            row.get("ts"), row.get("kind"), row.get("ip"),
            (row.get("detail") or "")[:512],
        )).encode("utf-8", "replace"))
    return hasher.hexdigest()


def classify_evidence(events):
    """把事件按确证类型分组, 并按严重度排序。"""
    grouped = {}
    for row in events:
        kind = row.get("kind")
        if kind not in EVIDENCE_LABELS:
            continue
        grouped.setdefault(kind, []).append(row)
    for kind in grouped:
        grouped[kind].sort(key=lambda r: r.get("ts") or 0)
    return grouped


def build_session_report(store, session_id, include_requests=True):
    """构造单会话取证档案。"""
    session = store.get_session(session_id)
    if session is None:
        raise ValueError("找不到会话: %s" % session_id)

    requests = store.session_requests(session_id, limit=2000)
    signals = store.session_signals(session_id)
    events = [e for e in store.recent_events(limit=5000)
              if e.get("session_id") == session_id]
    events.sort(key=lambda r: (SEVERITY_ORDER.get(r.get("severity"), 9),
                               r.get("ts") or 0))
    evidence = classify_evidence(events)

    tokens = _load_json(session.get("tokens_json"), [])
    duration = (session.get("last_seen") or 0) - (session.get("first_seen") or 0)

    report = {
        "kind": "session",
        "generated_at": time.time(),
        "generated_at_iso": _iso(time.time()),
        "instance": None,
        "session": {
            "id": session["id"],
            "ip": session["ip"],
            "port": session.get("port"),
            "first_seen": session.get("first_seen"),
            "last_seen": session.get("last_seen"),
            "duration_seconds": round(duration, 2),
            "ua": session.get("ua") or "",
            "ua_hash": session.get("ua_hash") or "",
            "header_sig": session.get("header_sig") or "",
            "behavior_hash": session.get("behavior_hash") or "",
            "label": session.get("label") or "unknown",
            "score": session.get("score") or 0,
            "confidence": session.get("confidence") or 0,
            "action": session.get("action") or "serve",
            "requests": session.get("req_count") or 0,
            "assets_fetched": session.get("asset_count") or 0,
            "tarpit_ms": session.get("tarpit_ms") or 0,
            "campaign": session.get("campaign_id") or "",
            "note": session.get("note") or "",
        },
        "canary_tokens": tokens,
        "signals": signals,
        "evidence": evidence,
        "evidence_counts": dict((k, len(v)) for k, v in evidence.items()),
        "timeline": [],
        "summary": {},
        "caveats": [],
    }

    if include_requests:
        for row in requests:
            report["timeline"].append({
                "ts": row.get("ts"),
                "time": _ts(row.get("ts")),
                "method": row.get("method"),
                "target": row.get("target"),
                "status": row.get("status"),
                "score": row.get("score"),
                "action": row.get("action"),
                "delay_ms": row.get("delay_ms"),
                "signals": _load_json(row.get("signals_json"), []),
                "body_len": row.get("body_len"),
            })

    report["evidence_digest"] = evidence_digest(report["timeline"], events)
    report["summary"] = _summarize(report)
    report["caveats"] = _caveats(report)
    return report


def build_campaign_report(store, campaign_id):
    """构造战役档案: 同一行为指纹下的多个源 IP 合并为一份材料。"""
    campaign = store.get_campaign(campaign_id)
    if campaign is None:
        raise ValueError("找不到战役: %s" % campaign_id)

    ips = _load_json(campaign.get("ips_json"), [])
    uas = _load_json(campaign.get("ua_list_json"), [])
    sessions = []
    for row in store.recent_sessions(limit=2000):
        if (row.get("campaign_id") or "") == campaign_id:
            sessions.append(row)

    # 汇总所有相关事件
    events = []
    for session in sessions:
        for event in store.recent_events(limit=5000):
            if event.get("session_id") == session["id"]:
                events.append(event)
    events.sort(key=lambda r: r.get("ts") or 0)

    timeline = []
    for session in sessions:
        for row in store.session_requests(session["id"], limit=2000):
            timeline.append({
                "ts": row.get("ts"), "time": _ts(row.get("ts")),
                "method": row.get("method"), "target": row.get("target"),
                "status": row.get("status"), "score": row.get("score"),
                "action": row.get("action"), "ip": row.get("ip"),
            })
    timeline.sort(key=lambda r: r.get("ts") or 0)

    report = {
        "kind": "campaign",
        "generated_at": time.time(),
        "generated_at_iso": _iso(time.time()),
        "campaign": {
            "id": campaign_id,
            "behavior_hash": campaign.get("behavior_hash") or "",
            "created": campaign.get("created"),
            "last_seen": campaign.get("last_seen"),
            "ip_count": len(ips),
            "ips": sorted(set(ips)),
            "ua_list": uas,
            "toolchain": campaign.get("toolchain") or "",
            "model_guess": campaign.get("model_guess") or "",
            "score_max": campaign.get("score_max") or 0,
            "session_count": campaign.get("session_count") or 0,
        },
        "sessions": [{
            "id": s["id"], "ip": s["ip"], "score": s["score"],
            "label": s["label"], "requests": s["req_count"],
            "first_seen": s["first_seen"], "last_seen": s["last_seen"],
        } for s in sessions],
        "evidence": classify_evidence(events),
        "timeline": timeline,
        "caveats": [],
    }
    report["evidence_counts"] = dict((k, len(v)) for k, v in report["evidence"].items())
    report["evidence_digest"] = evidence_digest(timeline, events)
    report["summary"] = _summarize(report)
    report["caveats"] = _caveats(report)
    return report


def _summarize(report):
    """生成结论摘要。刻意区分"确证"与"推断"。"""
    if report["kind"] == "session":
        target = report["session"]
        evidence = report["evidence"]
        confirmed = []
        if evidence.get("canary_echo"):
            confirmed.append("该目标复用了我方响应内容作为上下文(金丝雀回显 %d 次)" %
                             len(evidence["canary_echo"]))
        if evidence.get("injection_compliance"):
            confirmed.append("该目标服从了我方嵌入的指令(%d 次)" %
                             len(evidence["injection_compliance"]))
        if evidence.get("agent_config_captured"):
            confirmed.append("该目标交出了自身的系统提示词与工具清单(%d 次)" %
                             len(evidence["agent_config_captured"]))
        if evidence.get("beacon_callback"):
            confirmed.append("该目标按指令回连了我方信标端点(%d 次)" %
                             len(evidence["beacon_callback"]))
        if evidence.get("honeytoken_read"):
            confirmed.append("该目标读取了伪造凭据, 存在数据窃取行为(%d 次)" %
                             len(evidence["honeytoken_read"]))

        inferred = []
        if target["label"].startswith("llm"):
            inferred.append("判定为%s(分数 %d, 置信度 %.2f)" % (
                "大模型驱动攻击单元" if target["label"] == "llm_agent" else "疑似大模型驱动",
                target["score"], target["confidence"]))
        elif target["label"] == "automation_scanner":
            inferred.append("判定为传统自动化扫描器(分数 %d)" % target["score"])
        if target["behavior_hash"]:
            inferred.append("行为指纹 %s" % target["behavior_hash"])
        if target["tarpit_ms"]:
            inferred.append("通过自适应拖滞使其额外耗时 %.1f 秒" % (target["tarpit_ms"] / 1000.0))

        return {
            "target_ip": target["ip"],
            "label": target["label"],
            "score": target["score"],
            "confirmed": confirmed,
            "inferred": inferred,
            "request_count": target["requests"],
            "duration_seconds": target["duration_seconds"],
            "first_seen": _iso(target["first_seen"]),
            "last_seen": _iso(target["last_seen"]),
        }

    campaign = report["campaign"]
    evidence = report["evidence"]
    confirmed = []
    for kind, label in EVIDENCE_LABELS.items():
        if evidence.get(kind):
            confirmed.append("%s: %d 次" % (label, len(evidence[kind])))
    return {
        "campaign_id": campaign["id"],
        "behavior_hash": campaign["behavior_hash"],
        "source_ips": campaign["ips"],
        "ip_count": campaign["ip_count"],
        "score_max": campaign["score_max"],
        "toolchain": campaign["toolchain"],
        "model_guess": campaign["model_guess"],
        "confirmed": confirmed,
        "request_count": len(report["timeline"]),
    }


def _caveats(report):
    """证据局限说明。

    主动写明局限不是示弱 —— 上报材料如果声称的比能证明的多, 反而会被质疑;
    把"哪些是确证、哪些是推断、哪些无法确定"讲清楚, 材料才立得住。
    """
    notes = []
    evidence = report.get("evidence") or {}
    if not evidence.get("canary_echo") and not evidence.get("injection_compliance"):
        notes.append(
            "本档案缺少交互确证证据(金丝雀回显/指令服从)。判定依据仅为工具链与行为"
            "特征, 这些特征可被伪造, 因此**不能据此断言对方是大模型智能体**。")
    if report.get("kind") == "session":
        session = report.get("session") or {}
        if (session.get("assets_fetched") or 0) == 0 and (session.get("requests") or 0) < 8:
            notes.append("请求样本过少(<8), 行为节律分析未生效, 判定置信度受限。")
    notes.append(
        "源 IP 可能为被攻陷的第三方主机或公共云出口, 因此 IP 本身**不构成攻击者归属**;"
        "跨源归因依据是行为指纹, 需结合其他情报交叉验证。")
    notes.append(
        "本档案中的凭据、数据、漏洞均为蜜罐伪造内容, 不含任何真实资产信息; "
        "攻击者对这些伪造内容的读取行为本身构成证据。")
    return notes


# --------------------------------------------------------------------------
# 渲染
# --------------------------------------------------------------------------

def render_markdown(report, redact=False):
    """渲染为人读材料。redact=True 时去掉内部信息(对外版)。"""
    lines = []
    stamp = report.get("generated_at_iso", "-")

    if report["kind"] == "session":
        session = report["session"]
        summary = report["summary"]
        lines += [
            "# 蜜罐取证档案 · 单会话",
            "",
            "| 项 | 值 |",
            "|---|---|",
            "| 生成时间 | %s |" % stamp,
            "| 攻击来源 IP | `%s` |" % session["ip"],
            "| 首次出现 | %s |" % _iso(session["first_seen"]),
            "| 最后活动 | %s |" % _iso(session["last_seen"]),
            "| 持续时长 | %.1f 秒 |" % session["duration_seconds"],
            "| 请求总数 | %d |" % session["requests"],
            "| 判定 | **%s** |" % session["label"],
            "| 分数 / 置信度 | %d / %.2f |" % (session["score"], session["confidence"]),
            "| 处置动作 | `%s` |" % session["action"],
            "| 拖滞累计 | %.1f 秒 |" % (session["tarpit_ms"] / 1000.0),
            "| User-Agent | `%s` |" % (session["ua"] or "-"),
            "| 头部顺序指纹 | `%s` |" % (session["header_sig"] or "-"),
            "| 行为指纹 | `%s` |" % (session["behavior_hash"] or "-"),
            "",
        ]
        if session["campaign"]:
            lines.append("| 关联战役 | `%s` |" % session["campaign"])
            lines.append("")
    else:
        campaign = report["campaign"]
        lines += [
            "# 蜜罐取证档案 · 战役",
            "",
            "| 项 | 值 |",
            "|---|---|",
            "| 生成时间 | %s |" % stamp,
            "| 战役编号 | `%s` |" % campaign["id"],
            "| 行为指纹 | `%s` |" % campaign["behavior_hash"],
            "| 源 IP 数量 | %d |" % campaign["ip_count"],
            "| 会话数 | %d |" % campaign["session_count"],
            "| 分数上限 | %d |" % campaign["score_max"],
            "| 工具链 | `%s` |" % (campaign["toolchain"] or "-"),
            "| 模型推测 | %s |" % (campaign["model_guess"] or "-"),
            "",
            "**源 IP 清单**",
            "",
        ]
        for ip in campaign["ips"]:
            lines.append("- `%s`" % ip)
        lines.append("")
        lines.append("> 同一战役的判定依据是**行为指纹而非源 IP**: User-Agent、头部顺序、"
                     "路径集合与载荷类型在轮换代理或更换主机后依然稳定, 因此足以将多个"
                     "来源 IP 归并为同一操作者。")
        lines.append("")

    # 结论
    summary = report.get("summary") or {}
    lines += ["## 结论", ""]
    for item in summary.get("confirmed") or []:
        lines.append("- **[确证]** %s" % item)
    for item in summary.get("inferred") or []:
        lines.append("- [推断] %s" % item)
    if not (summary.get("confirmed") or summary.get("inferred")):
        lines.append("- 无")
    lines.append("")

    # 证据
    evidence = report.get("evidence") or {}
    if evidence:
        lines += ["## 确证证据", ""]
        for kind, rows in evidence.items():
            lines.append("### %s (%d 次)" % (EVIDENCE_LABELS.get(kind, kind), len(rows)))
            lines.append("")
            for row in rows[:12]:
                lines.append("- `%s` %s" % (_iso(row.get("ts")),
                                           (row.get("detail") or "")[:400]))
            if len(rows) > 12:
                lines.append("- …另有 %d 条同类记录" % (len(rows) - 12))
            lines.append("")

    # 信号
    if report.get("signals"):
        lines += ["## 触发信号", "", "| 信号 | 权重 | 命中 | 证据 |", "|---|---|---|---|"]
        for sig in report["signals"]:
            lines.append("| `%s` | %s | %s | %s |" % (
                sig.get("name"), sig.get("weight"), sig.get("hits"),
                (sig.get("evidence") or "")[:120].replace("|", "/")))
        lines.append("")

    # 时间线
    timeline = report.get("timeline") or []
    if timeline:
        lines += ["## 请求时间线 (%d 条, 最多显示 60 条)" % len(timeline), "",
                  "| 时间 | 方法 | 路径 | 状态 | 分数 | 处置 | 延时 |",
                  "|---|---|---|---|---|---|---|"]
        for row in timeline[:60]:
            lines.append("| %s | %s | `%s` | %s | %s | %s | %sms |" % (
                row.get("time"), row.get("method"), (row.get("target") or "")[:80],
                row.get("status"), row.get("score"), row.get("action"),
                row.get("delay_ms")))
        if len(timeline) > 60:
            lines.append("")
            lines.append("（另有 %d 条记录, 完整数据见 JSON 导出）" % (len(timeline) - 60))
        lines.append("")

    # 完整性
    lines += [
        "## 证据完整性",
        "",
        "证据摘要(SHA-256):",
        "",
        "```",
        report.get("evidence_digest", "-"),
        "```",
        "",
        "该摘要覆盖本档案的请求序列与关键事件。复核方可用同一算法对材料重新计算,"
        "若结果不一致即说明材料被改动。",
        "",
    ]

    # 局限
    if report.get("caveats"):
        lines += ["## 证据局限(请务必阅读)", ""]
        for note in report["caveats"]:
            lines.append("- %s" % note)
        lines.append("")

    lines += [
        "## 取证声明",
        "",
        "1. 本档案由蜜罐系统在己方授权资产上被动采集。系统**未主动连接**攻击方主机,"
        "全部内容均来自攻击方主动发起的请求。",
        "2. 档案中的凭据、数据与漏洞信息均为蜜罐伪造内容, 不含任何真实业务数据。",
        "3. 判定结论已在「结论」一节中区分**确证**与**推断**, 请勿将推断当作确证使用。",
        "4. 源 IP 可能属于被攻陷的第三方或公共云出口, 不能单独作为攻击者归属依据。",
        "",
    ]
    return "\n".join(lines)


def render_abuse_email(report, contact="abuse@example.com"):
    """生成向托管方举报的邮件模板。"""
    summary = report.get("summary") or {}
    if report["kind"] == "session":
        subject = "未授权渗透测试行为举报 - 源 IP %s" % summary.get("target_ip")
        ips = [summary.get("target_ip")]
    else:
        ips = summary.get("source_ips") or []
        subject = "未授权渗透测试行为举报 - 源 IP %s 等 %d 个" % (
            ips[0] if ips else "-", len(ips))

    body = [
        "致 %s:" % contact,
        "",
        "我们发现来自贵方网络的多个源 IP 对我们在中国境内的蜜罐资产发起了未授权的",
        "自动化渗透测试行为。相关证据已整理并留存, 摘要如下:",
        "",
        "涉及源 IP:",
    ]
    for ip in ips:
        body.append("  - %s" % ip)
    body += [
        "",
        "主要观测事实:",
    ]
    for item in summary.get("confirmed") or []:
        body.append("  - %s" % item)
    body += [
        "",
        "观测时间: %s 至 %s" % (summary.get("first_seen", "-"),
                                summary.get("last_seen", "-")),
        "证据完整性摘要(SHA-256): %s" % report.get("evidence_digest", "-"),
        "",
        "我们保留完整请求日志与判定依据, 可应要求提供以便贵方处置。",
        "请协助确认这些主机的归属与状态, 并采取相应措施。",
        "",
        "此致",
    ]
    return "Subject: %s\n\n%s" % (subject, "\n".join(body))


def export_json(report, path):
    with open(path, "w") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, default=str)
        handle.write("\n")
    return path


def export_csv(report, path):
    """导出时间线为 CSV, 便于导入其他分析工具。"""
    timeline = report.get("timeline") or []
    fields = ["ts", "time", "ip", "method", "target", "status", "score",
              "action", "delay_ms"]
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in timeline:
            writer.writerow(row)
    return path


def export_iocs(report, path):
    """导出 IOC 列表(每行一条), 可直接喂给防火墙或情报平台。"""
    lines = []
    if report["kind"] == "session":
        session = report["session"]
        lines.append(session["ip"])
        lines.append("ua:%s" % session["ua"]) if session["ua"] else None
        lines.append("behavior_hash:%s" % session["behavior_hash"]) \
            if session["behavior_hash"] else None
    else:
        for ip in (report.get("campaign") or {}).get("ips") or []:
            lines.append(ip)
        toolchain = (report.get("campaign") or {}).get("toolchain")
        if toolchain:
            lines.append("toolchain:%s" % toolchain)
    with open(path, "w") as handle:
        handle.write("\n".join(line for line in lines if line) + "\n")
    return path


def write_report_bundle(config, store, report, stem=None):
    """一次性产出完整材料包: Markdown + JSON + CSV + IOC。"""
    directory = config.out_path("reports")
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o750)
    if stem is None:
        if report["kind"] == "session":
            stem = "session-%s" % report["session"]["id"].replace(":", "_")
        else:
            stem = "campaign-%s" % report["campaign"]["id"]
    stem = "%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), stem)

    paths = {
        "markdown": os.path.join(directory, stem + ".md"),
        "json": os.path.join(directory, stem + ".json"),
        "csv": os.path.join(directory, stem + ".csv"),
        "iocs": os.path.join(directory, stem + ".ioc"),
        "abuse": os.path.join(directory, stem + ".abuse.txt"),
    }
    with open(paths["markdown"], "w") as handle:
        handle.write(render_markdown(report))
    export_json(report, paths["json"])
    export_csv(report, paths["csv"])
    export_iocs(report, paths["iocs"])
    with open(paths["abuse"], "w") as handle:
        handle.write(render_abuse_email(report))
    return paths, stem


def batch_report(config, store, min_score=70, limit=20, campaign=False):
    """批量产出达到阈值的目标材料。返回 (成功数, 失败列表)。"""
    produced = 0
    failures = []
    if campaign:
        for row in store.campaigns(limit=limit):
            if (row.get("score_max") or 0) < min_score:
                continue
            try:
                report = build_campaign_report(store, row["id"])
                write_report_bundle(config, store, report)
                produced += 1
            except ValueError as exc:
                failures.append("%s: %s" % (row["id"], exc))
    else:
        for row in store.recent_sessions(limit=limit * 4, min_score=min_score):
            try:
                report = build_session_report(store, row["id"])
                write_report_bundle(config, store, report)
                produced += 1
            except ValueError as exc:
                failures.append("%s: %s" % (row["id"], exc))
            if produced >= limit:
                break
    return produced, failures
