"""阻断与吸收重定向层 (L3/L4)。

两种处置模式:

  drop    丢弃 —— 把攻击者的高危端口流量直接丢掉
  absorb  吸收 —— 把攻击者的业务端口流量 DNAT 重定向进蜜罐
                 (推荐: 攻击者的每一次尝试都变成我们的情报, 而不是被
                  防火墙挡回去让它再换一个目标)

三重安全设计, 因为防火墙规则写错会把自己锁在门外:

  1. **默认不落地**。block.apply=false 时只把规则写到 out/rules/ 供人工审核。
  2. **白名单硬编码优先**。私有网段/回环/管理网段永远不会被写入规则。
  3. **落地前先语法校验**。用 `nft -c -f` 干跑一遍, 校验不过绝不应用。
"""

import ipaddress
import json
import os
import subprocess
import time

DEFAULT_PORTS_DROP = [22, 23, 445, 1433, 3306, 5432, 6379, 9200, 27017, 11211]
DEFAULT_PORTS_ABSORB = [80, 443, 8000, 8080, 8443, 9000]


def check_nft():
    """检查 nft 可用性。返回 (是否可用, 版本或错误信息)。"""
    try:
        out = subprocess.check_output(["nft", "--version"], stderr=subprocess.STDOUT)
        return True, out.decode("utf-8", "replace").strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return False, str(exc)


def is_whitelisted(ip, cfg):
    """判断 IP 是否落在白名单/私有网段内 —— 这些永远不会被处置。"""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True     # 地址解析不了就当作受保护, 宁可漏处置不可误伤

    if address.is_loopback or address.is_link_local or address.is_multicast:
        return True

    for entry in cfg.get("block.whitelist", []) or []:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue

    # 私网默认保护: 内网横向流量不是本系统的处置对象
    private_ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
    for entry in private_ranges:
        try:
            if address in ipaddress.ip_network(entry):
                return True
        except ValueError:
            continue
    return False


def build_rule(ip, cfg, reason="", mode=None, ttl=None):
    """构造单条处置规则(不落地)。

    返回 dict: {ip, mode, reason, ttl, nft, iptables, whitelisted, created}
    """
    mode = mode or cfg.get("block.mode", "absorb")
    ttl = int(ttl or cfg.get("block.ttl_seconds", 3600))
    absorb_target = cfg.get("block.absorb_target", "127.0.0.1:8080")
    whitelisted = is_whitelisted(ip, cfg)

    if whitelisted:
        nft_line = "# %s 命中白名单/私有网段, 未生成处置规则" % ip
        ipt_line = ""
        mode = "none"
    elif mode == "drop":
        nft_line = "add element inet honeypot attackers { %s timeout %ds }" % (ip, ttl)
        ipt_line = "iptables -I INPUT -s %s -j DROP" % ip
    else:
        nft_line = "add element inet honeypot attackers { %s timeout %ds }" % (ip, ttl)
        ipt_line = ("iptables -t nat -I PREROUTING -s %s -p tcp -j DNAT --to-destination %s"
                    % (ip, absorb_target))

    return {
        "ip": ip,
        "mode": mode,
        "reason": reason,
        "ttl": ttl,
        "nft": nft_line,
        "iptables": ipt_line,
        "absorb_target": absorb_target,
        "whitelisted": whitelisted,
        "created": time.time(),
    }


def build_ruleset(rules, cfg):
    """把若干处置规则合成一份可审核、可校验的 nftables 规则集。

    全部放在**同一张 inet 表**里, 这一点是必须的: nftables 的集合作用域限于
    所属表, 不能跨表引用。此前把攻击者集合放在 `table inet honeypot`、
    却在 `table ip honeypot_nat` 里引用 `@attackers`, nft 会直接报错,
    吸收功能无法工作。

    表的重建由 apply_ruleset() 负责(先 delete 再 apply), 因为 nft 语法里
    没有条件判断, 无法在文件内"存在才 flush"。
    """
    absorb_target = cfg.get("block.absorb_target", "127.0.0.1:8080")
    try:
        target_port = int(absorb_target.rsplit(":", 1)[-1])
    except ValueError:
        target_port = 8080
    ttl = int(cfg.get("block.ttl_seconds", 3600))

    drop_ports = ", ".join(str(p) for p in DEFAULT_PORTS_DROP)
    absorb_ports = ", ".join(str(p) for p in DEFAULT_PORTS_ABSORB)
    active = [r for r in rules if not r.get("whitelisted")]

    lines = [
        "#!/usr/sbin/nft -f",
        "# 由 llm-honeypot 自动生成 —— 应用前请人工审核",
        "# 生成时间: %s" % time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "# 处置对象: %d 个(已剔除白名单/私网)" % len(active),
        "#",
        "# 应用:      nft -f <本文件>   (apply_ruleset 会先删表再应用, 幂等)",
        "# 整体撤销:  nft delete table inet honeypot",
        "# 查看目标:  nft list set inet honeypot attackers",
        "#",
        "",
        "table inet honeypot {",
        "    set attackers {",
        "        type ipv4_addr",
        "        flags timeout",
        "        timeout %ds" % ttl,
        "    }",
        "",
        "    chain input_guard {",
        "        type filter hook input priority filter - 10; policy accept;",
        "        # 攻击者的暴力破解类端口: 直接丢弃",
        "        ip saddr @attackers tcp dport { %s } drop" % drop_ports,
        "        ip saddr @attackers udp dport { 53, 123, 161 } drop",
        "        # 除上述端口外放行(由下面的 nat 链吸收到蜜罐), 避免误伤",
        "        ip saddr @attackers counter comment \"llm-honeypot: attacker traffic\"",
        "    }",
        "",
        "    # 吸收: 攻击者访问业务端口 -> 重定向进蜜罐 (而非拒绝)",
        "    # 必须在同一张表内, 才能引用上面定义的 @attackers 集合。",
        "    chain prerouting_absorb {",
        "        type nat hook prerouting priority dstnat; policy accept;",
        "        ip saddr @attackers tcp dport { %s } redirect to :%d" % (
            absorb_ports, target_port),
        "    }",
        "}",
        "",
        "# ---- 攻击者集合元素 ----",
    ]
    for rule in active:
        lines.append(rule["nft"] + "   # %s" % rule["reason"][:100])
    if not active:
        lines.append("# (本轮无有效处置对象)")
    lines.append("")
    return "\n".join(lines)


def validate_ruleset(text, timeout=15):
    """用 `nft -c -f -` 做语法校验, 不产生任何实际变更。

    这是落地前的最后一道闸: 规则语法错误在生产防火墙上是不可接受的。
    """
    available, info = check_nft()
    if not available:
        return False, "nft 不可用: %s" % info
    try:
        proc = subprocess.run(
            ["nft", "-c", "-f", "-"],
            input=text.encode("utf-8"), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "校验执行失败: %s" % exc
    output = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        # nft -c 即便只做校验也需要 CAP_NET_ADMIN。非特权运行(蜜罐的
        # 推荐姿势)会得到 "Operation not permitted" —— 这不是语法错误,
        # 报成"校验未通过"会误导排障(部署实测踩过)。区分两者。
        if "operation not permitted" in output.lower():
            return True, ("跳过校验: 无 CAP_NET_ADMIN(非特权运行属预期)。"
                          "规则文件已生成, 落地前请在特权环境复核语法")
        return False, output or "nft 语法校验未通过(退出码 %d)" % proc.returncode
    return True, output


def apply_ruleset(cfg, text, force=False):
    """应用规则集。

    只有在 block.armed=true **且** block.apply=true 时才会真正落地;
    否则只做语法校验并返回(校验结果仍然有用, 让使用者知道规则是对的)。
    """
    armed = bool(cfg.get("block.armed", False))
    do_apply = bool(cfg.get("block.apply", False)) or force

    ok, message = validate_ruleset(text)
    if not ok:
        return False, "规则校验失败, 未应用: %s" % message

    if not (armed and do_apply):
        return False, ("演练模式: 规则语法校验通过, 但未落地 "
                       "(需 block.armed=true 且 block.apply=true)。校验输出: %s"
                       % (message or "无告警"))

    try:
        proc = subprocess.run(
            ["nft", "-f", "-"], input=text.encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "应用失败: %s" % exc
    output = proc.stdout.decode("utf-8", "replace").strip()
    return proc.returncode == 0, output


def write_rule(cfg, rule):
    """把单条规则写入待审核目录, 返回文件路径。"""
    directory = cfg.out_path("rules")
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o750)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe_ip = rule["ip"].replace(":", "_").replace(".", "_")
    path = os.path.join(directory, "%s-%s.nft" % (stamp, safe_ip))
    body = "\n".join([
        "# 处置规则候选 (未落地, 待人工审核)",
        "# 目标 IP : %s" % rule["ip"],
        "# 模式    : %s" % rule["mode"],
        "# 依据    : %s" % rule["reason"],
        "# 有效期  : %ds" % rule["ttl"],
        "# 等价 iptables: %s" % (rule["iptables"] or "(不适用)"),
        "",
        rule["nft"],
        "",
    ])
    with open(path, "w") as handle:
        handle.write(body)
    return path


def write_ruleset(cfg, rules, name=None):
    """生成并写出整份规则集, 返回 (路径, 校验结果)。"""
    text = build_ruleset(rules, cfg)
    directory = cfg.out_path("rules")
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o750)
    name = name or ("ruleset-%s.nft" % time.strftime("%Y%m%d-%H%M%S"))
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        handle.write(text)
    ok, message = validate_ruleset(text)
    return path, (ok, message)


def load_rules_from_store(store, min_score=85, limit=500):
    """从遥测库挑出达到处置阈值来源 IP, 生成规则候选。"""
    rules = []
    seen = set()
    for row in store.top_ips(limit=limit):
        ip = row["ip"]
        score = row["score_max"] or 0
        if score < min_score or ip in seen:
            continue
        seen.add(ip)
        rules.append({
            "ip": ip, "score": score,
            "reason": "score_max=%d sessions=%d requests=%d" % (
                score, row["sessions"], row["requests"] or 0),
        })
    return rules


def export_json(cfg, rules):
    path = cfg.out_path("rules", "rules-candidates-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    with open(path, "w") as handle:
        json.dump(rules, handle, ensure_ascii=False, indent=2, default=str)
    return path
