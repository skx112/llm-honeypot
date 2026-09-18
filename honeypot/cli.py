#!/usr/bin/env python3
"""CogTrap 命令行入口。

    cogtrap serve                          启动蜜罐(HTTP + SSH 诱饵 + 仪表盘)
    cogtrap generate                       从模板+场景生成一个可运行的蜜罐实例
    cogtrap template list|show|new|validate|lint|render
    cogtrap scenario list|show|new|validate|lint
    cogtrap countermeasures list|stats|show
    cogtrap doctor                         环境自检

设计取舍:
  · 只用标准库。在专门用于诱捕攻击者的主机上引入第三方依赖, 等于自愿扩大
    供应链攻击面, 与项目定位矛盾。
  · 子命令模块惰性导入, 因此缺少某个可选模块(如仪表盘)时其余功能仍可用。
  · 所有"会改变系统状态"的操作(防火墙落地)默认只生成文件, 需显式参数才执行。
"""

import argparse
import json
import os
import shutil
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import config as config_mod
import countermeasures as countermeasures_mod
import inject
import scenarios as scenarios_mod
import templating

VERSION = "0.1.0"
PRODUCT = "CogTrap"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BAD_INPUT = 2
EXIT_NOT_READY = 3


# --------------------------------------------------------------------------
# 输出辅助
# --------------------------------------------------------------------------

def _use_color():
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _c(text, code):
    if not _use_color():
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def ok(message):
    print("%s %s" % (_c("✓", "32"), message))


def warn(message):
    print("%s %s" % (_c("!", "33"), message))


def fail(message):
    print("%s %s" % (_c("✗", "31"), message))


def dim(message):
    print(_c("  %s" % message, "2"))


def heading(title):
    print()
    print(_c(title, "1"))


def table(rows, headers=None):
    """简单等宽表格。中文字符按 2 列宽计算, 否则会错位。"""
    def width(text):
        total = 0
        for char in str(text):
            total += 2 if ord(char) > 0x2E80 else 1
        return total

    def pad(text, target):
        return str(text) + " " * max(0, target - width(text))

    data = ([headers] if headers else []) + rows
    if not data:
        return
    widths = [max(width(row[i]) if i < len(row) else 0 for row in data)
              for i in range(max(len(r) for r in data))]
    for index, row in enumerate(data):
        line = "  ".join(pad(cell, widths[i]) for i, cell in enumerate(row))
        print("  " + line)
        if headers and index == 0:
            print("  " + "  ".join("-" * w for w in widths))


def load_config(args):
    path = getattr(args, "config", None)
    cfg = config_mod.Config.load(path) if path else config_mod.Config.load()
    cfg.ensure_dirs()
    return cfg


# --------------------------------------------------------------------------
# serve
# --------------------------------------------------------------------------

def cmd_serve(args):
    cfg = load_config(args)
    server_mod = __import__("server")

    instance = None
    if args.instance:
        instance = _load_instance_file(args.instance)
    elif args.template:
        instance = _instantiate(args.template, args.scenario, cfg, args.set)

    if args.port:
        cfg["http"]["port"] = int(args.port)
    if args.host:
        cfg["http"]["listen"] = [args.host]

    report = inject.configure(cfg)
    scenario_state = None
    if args.scenario:
        scenario = scenarios_mod.load_scenario(args.scenario, cfg)
        scenario_state = _apply_scenario(scenario, cfg, instance)

    store_mod = __import__("store")
    store = store_mod.Store(cfg.store_path())

    heading("%s %s —— 启动" % (PRODUCT, VERSION))
    dim("实例标识   : %s" % cfg.get("instance"))
    dim("配置来源   : %s" % (args.config or "config.json (默认)"))
    if instance is not None:
        dim("蜜罐模板   : %s (%s)" % (instance.template.id, instance.template.name))
        dim("模板定制   : %s" % (", ".join(sorted(instance.overrides.keys())) or "无"))
    else:
        dim("蜜罐模板   : 未指定, 使用内置默认内容")
    dim("反制方式   : 内置 %d 条, 插件 %d 条%s" % (
        report["builtin"], report["plugins"],
        (" (%d 条插件错误)" % len(report["errors"])) if report["errors"] else ""))
    for error in report["errors"][:5]:
        warn("插件 %s" % error)
    dim("遥测库     : %s" % cfg.store_path())
    if scenario_state:
        thresholds = scenario_state["thresholds"]
        dim("生效阈值   : 观察≥%d 拖滞≥%d 注入≥%d 锁定≥%d" % (
            thresholds["serve_watch"], thresholds["tarpit"],
            thresholds["deceive_inject"], thresholds["lockdown"]))
        dim("权重覆盖   : %s" % (
            ", ".join("%s%+d" % (k, v)
                      for k, v in sorted(scenario_state["weight_overrides"].items()))
            or "无"))
        dim("载荷投放   : %s (最高层级 %s)" % (
            "启用" if scenario_state["payload_enabled"] else "关闭",
            scenario_state["max_tier"]))

    service = server_mod.HoneypotServer(cfg, store=store, instance=instance)

    loop = __import__("asyncio").get_event_loop()
    bound = loop.run_until_complete(service.start())
    if not bound:
        fail("HTTP 监听启动失败")
        return EXIT_ERROR
    wildcard = False
    scheme = "https" if cfg.get("http.tls.enabled") else "http"
    for address in bound:
        host = address[0]
        if host in ("0.0.0.0", "::"):
            wildcard = True
            dim("HTTP 蜜罐  : %s://%s:%s  %s" % (
                scheme, host, address[1], _c("[对所有网卡可达]", "33")))
        else:
            dim("HTTP 蜜罐  : %s://%s:%s" % (scheme, host, address[1]))
    if wildcard:
        warn("正在监听通配地址 —— 本实例对所在网段(乃至公网)全部可达。")
        dim("蜜罐本就该可达, 但请确认: 已在独立诱饵网段、出站已 DROP、")
        dim("且与真实资产之间无双向路由。只想本机试跑请加 --host 127.0.0.1")

    extras = []
    if cfg.get("ssh_decoy.enabled", False):
        try:
            ssh_decoy = __import__("ssh_decoy")
            decoy = ssh_decoy.SSHDecoy(cfg, store=store)
            ssh_bound = loop.run_until_complete(decoy.start())
            extras.append(decoy)
            if ssh_bound:
                dim("SSH 诱饵   : %s:%s" % (ssh_bound[0], ssh_bound[1]))
        except ImportError:
            warn("ssh_decoy 模块缺失, 跳过 SSH 诱饵")

    if cfg.get("dashboard.enabled", True) and not args.no_dashboard:
        try:
            dashboard = __import__("dashboard")
            panel = dashboard.Dashboard(cfg, store=store, server=service)
            loop.run_until_complete(panel.start())
            extras.append(panel)
            dim("仪表盘     : http://%s:%s (仅本机)" % (
                cfg.get("dashboard.host", "127.0.0.1"),
                cfg.get("dashboard.port", 8899)))
        except ImportError:
            warn("dashboard 模块缺失, 跳过仪表盘")

    block = __import__("block")
    path, ruleset_check = block.write_ruleset(cfg, [])
    dim("处置规则集 : %s (未落地, 需 armed+apply)" % os.path.basename(path))
    if not ruleset_check[0]:
        warn("规则集语法校验未通过: %s" % ruleset_check[1])

    print()
    ok("已启动。按 Ctrl-C 停止。")
    dim("告警日志   : %s" % cfg.path(cfg.get("alert.log_path", "logs/alerts.log")))
    print()
    sys.stdout.flush()      # 重定向到文件时不留缓冲, 否则启动信息会"消失"

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print()
        ok("收到中断, 正在停止...")
    finally:
        for extra in extras:
            try:
                loop.run_until_complete(extra.close())
            except Exception:
                pass
        loop.run_until_complete(service.close())
        stats = service.runtime_stats()
        heading("运行统计")
        table([
            ["连接数", stats["connections"]],
            ["请求数", stats["requests"]],
            ["非 HTTP 探测", stats["non_http"]],
            ["拒绝连接", stats["rejected"]],
            ["拖滞累计", "%.1f 秒" % stats["tarpit_seconds"]],
            ["出站字节", stats["bytes_out"]],
            ["告警数", stats["alerts"]],
            ["金丝雀签发", stats["canary"]["issued"]],
        ])
        store.close()
    return EXIT_OK


def _load_instance_file(path):
    """从 generate 产出的 instance.json 载入模板实例。"""
    data = templating._load_json(path)
    template = templating.Template(data["template"], source=path)
    return templating.HoneypotInstance(
        template,
        overrides=data.get("overrides") or {},
        instance_id=data.get("instance_id"),
        host=data.get("host", "localhost"),
        port=int(data.get("port", 8080)),
        canary=data.get("canary", "hpx-instance"),
    )


def _instantiate(template_ref, scenario_ref, cfg, overrides=None):
    template = templating.load_template(template_ref, cfg)
    extra = {}
    if scenario_ref:
        scenario = scenarios_mod.load_scenario(scenario_ref, cfg)
        extra = scenario.overrides
    merged = _merge_overrides(extra, _parse_sets(overrides))
    return templating.HoneypotInstance(
        template, overrides=merged, host="localhost",
        port=int(cfg.get("http.port", 8080)),
        canary="hpx-instantiated",
    )


def _merge_overrides(base, extra):
    result = json.loads(json.dumps(base or {}))
    for key, value in (extra or {}).items():
        parts = key.split(".")
        node = result
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return result


def _parse_sets(items):
    """把 --set a.b=c 解析成嵌套字典, 值做 JSON 推断。"""
    out = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit("--set 需要 key=value 形式: %r" % item)
        key, _, raw = item.partition("=")
        try:
            value = json.loads(raw)
        except ValueError:
            value = raw
        out[key.strip()] = value
    return out


def _apply_scenario(scenario, cfg, instance):
    """把场景包真正生效(而不只是显示)。

    三处都要落到运行时:
      1. config 段(tarpit / inject / block / respond) —— 阈值等
      2. fingerprint 的信号权重覆盖
      3. inject 的反制方式白名单/黑名单/层级
    只做其中一部分会让 `cogtrap scenario show` 显示的数字与实际行为不一致,
    那比不显示更危险。
    """
    merged = scenario.apply_to_config(cfg, instance)
    for section in ("tarpit", "inject", "block", "respond"):
        if section in merged:
            cfg._data[section] = merged[section]

    import fingerprint
    applied = fingerprint.configure(weight_overrides=scenario.weight_overrides(), reset=True)

    payload = scenario.countermeasures
    inject.apply_profile(include=payload.get("include"), exclude=payload.get("exclude"),
                         max_tier=payload.get("max_tier"))
    if not scenario.payload_enabled():
        inject.apply_profile(include=[], exclude=[], max_tier=0)

    return {
        "thresholds": __import__("respond").resolved_thresholds(cfg),
        "weight_overrides": applied,
        "payload_enabled": scenario.payload_enabled(),
        "max_tier": payload.get("max_tier"),
    }


# --------------------------------------------------------------------------
# generate —— 用户生成蜜罐
# --------------------------------------------------------------------------

GENERATE_README = """# %(name)s

由 %(product)s %(version)s 生成的自定义蜜罐实例。

| 项 | 值 |
|---|---|
| 实例标识 | `%(instance_id)s` |
| 蜜罐模板 | `%(template_id)s` (%(template_name)s) |
| 场景包 | %(scenario)s |
| 监听端口 | %(port)s |
| 生成时间 | %(created)s |

## 启动

```bash
./start.sh
```

或指定参数:

```bash
python3 %(cli_path)s --config ./config.json serve --instance ./instance.json --scenario ./scenario.json
```

## 部署前必须确认(重要)

1. **隔离**: 本实例必须部署在独立网段, 与真实资产之间无双向路由。
   %(product)s 的定位是被攻击的诱饵, 不能与生产系统共用网络。
2. **出站拒绝**: 部署后先执行 `sudo bash %(deploy_dir)s/isolate.sh` 确认出站
   流量被丢弃 —— 蜜罐绝不能成为攻击者的跳板。
3. **不落地防火墙**: `config.json` 里 `block.armed` 与 `block.apply` 默认都是
   `false`, 规则只会写到 `out/rules/` 供人工审核。确认无误后再开启。
4. **授权**: 仅在你有明确授权的资产与网段上部署。

## 定制

改 `instance.json` 里的 `overrides` 段即可覆盖模板的任意字段, 例如:

```json
"overrides": {
  "branding": { "site_name": "你的系统名" },
  "network": { "internal_hosts": ["10.1.1.10", "10.1.1.11"] }
}
```

改完用下面命令校验(会检查字段类型、路由冲突、未定义变量等):

```bash
python3 %(cli_path)s template validate ./instance.json
```
"""

START_SH = """#!/usr/bin/env bash
# 由 %(product)s %(version)s 生成
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -u %(cli_path)s --config ./config.json serve \\
    --instance ./instance.json \\
    --scenario ./scenario.json
"""


def cmd_generate(args):
    cfg = load_config(args)
    template = templating.load_template(args.template, cfg)

    scenario = None
    scenario_overrides = {}
    if args.scenario:
        scenario = scenarios_mod.load_scenario(args.scenario, cfg)
        scenario_overrides = scenario.overrides

    overrides = _merge_overrides(scenario_overrides, _parse_sets(args.set))

    import time
    instance_id = args.name or "%s-%s" % (template.id, time.strftime("%Y%m%d%H%M%S"))
    port = int(args.port or cfg.get("http.port", 8080))

    # 实例化即校验: 覆盖项把模板改坏时在这里就报出来
    try:
        instance = templating.HoneypotInstance(
            template, overrides=overrides, instance_id=instance_id,
            host=args.host or "localhost", port=port, canary="hpx-%s" % instance_id[-8:])
    except templating.TemplateError as exc:
        fail("模板实例化失败")
        for line in str(exc).splitlines():
            print("  %s" % line)
        return EXIT_BAD_INPUT

    heading("%s generate" % PRODUCT)
    dim("模板     : %s (%s)" % (template.id, template.name))
    dim("场景     : %s" % (scenario.id if scenario else "未指定"))
    dim("实例标识 : %s" % instance_id)
    dim("监听端口 : %s" % port)

    issues = templating.lint(instance.effective.raw, "instance")
    warnings = [i for i in issues if i["level"] in ("warning", "error")]
    for issue in issues:
        if issue["level"] == "error":
            fail(issue["message"])
        elif issue["level"] == "warning":
            warn(issue["message"])

    output = os.path.abspath(args.output)
    if os.path.exists(output) and not args.force:
        fail("输出目录已存在: %s (加 --force 覆盖)" % output)
        return EXIT_BAD_INPUT
    if not os.path.isdir(output):
        os.makedirs(output, mode=0o750)

    # 1) 合并后的运行配置
    merged_config = scenario.apply_to_config(cfg, instance) if scenario \
        else cfg.as_dict()
    merged_config["instance"] = instance_id
    merged_config["http"]["port"] = port
    if args.host:
        merged_config["http"]["listen"] = [args.host]
    merged_config["honeypot_instance"] = {
        "template": template.id,
        "scenario": scenario.id if scenario else None,
        "branding": instance.effective.branding,
        "network": instance.effective.network,
        "server": instance.effective.server,
    }
    # 生成的实例目录里默认不落地防火墙 —— 使用者必须显式开启
    merged_config.setdefault("block", {})["armed"] = False
    merged_config.setdefault("block", {})["apply"] = False
    merged_config["store"]["path"] = "var/telemetry.db"
    _write_json(os.path.join(output, "config.json"), merged_config)

    # 2) 模板实例(含覆盖项)
    _write_json(os.path.join(output, "instance.json"), {
        "instance_id": instance_id,
        "host": args.host or "localhost",
        "port": port,
        "canary": instance.canary,
        "overrides": overrides,
        "template": instance.effective.to_dict(),
    })

    # 3) 场景副本(便于现场核对当时用的是哪套策略)
    if scenario is not None:
        _write_json(os.path.join(output, "scenario.json"), scenario.to_dict())

    # 4) 启动脚本
    start_path = os.path.join(output, "start.sh")
    with open(start_path, "w") as handle:
        handle.write(START_SH % {"product": PRODUCT, "version": VERSION,
                                 "cli_path": os.path.abspath(__file__)})
    os.chmod(start_path, 0o750)

    # 5) 运行目录
    for sub in ("var", "logs", "out/rules", "out/reports"):
        os.makedirs(os.path.join(output, sub), mode=0o750, exist_ok=True)

    # 6) 部署说明
    with open(os.path.join(output, "README.md"), "w") as handle:
        handle.write(GENERATE_README % {
            "product": PRODUCT, "version": VERSION, "name": instance_id,
            "instance_id": instance_id, "template_id": template.id,
            "template_name": template.name,
            "scenario": scenario.id if scenario else "未指定",
            "port": port, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cli_path": os.path.abspath(__file__),
            "deploy_dir": os.path.join(os.path.dirname(HERE), "deploy"),
        })

    print()
    ok("蜜罐实例已生成: %s" % output)
    print()
    table([
        ["config.json", "运行配置(已合并场景策略)"],
        ["instance.json", "模板实例(含你的定制覆盖项)"],
        ["scenario.json", "场景副本" if scenario else "(未使用场景)"],
        ["start.sh", "一键启动"],
        ["README.md", "部署说明与隔离要求"],
    ], headers=["文件", "说明"])
    print()
    dim("统计: 路由 %d 条, 漏洞面 %d 个, 凭据蜜标 %d 个" % (
        len(instance.effective.routes), len(instance.effective.vulnerabilities),
        len(instance.effective.credentials)))
    if warnings:
        warn("有 %d 条告警未处理, 建议先修再部署" % len(warnings))
    print()
    dim("下一步: cd %s && ./start.sh" % output)
    return EXIT_OK


def _write_json(path, data):
    with open(path, "w") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


# --------------------------------------------------------------------------
# template
# --------------------------------------------------------------------------

def cmd_template_list(args):
    cfg = load_config(args)
    items = templating.list_templates(cfg)
    if not items:
        fail("没有找到任何模板")
        dim("内置模板目录: %s" % templating.BUILTIN_DIR)
        return EXIT_ERROR
    heading("可用蜜罐模板 (%d 个)" % len(items))
    rows = []
    for template in items:
        rows.append([template.id, template.category, template.name,
                     len(template.routes), len(template.vulnerabilities),
                     len(template.credentials)])
    table(rows, headers=["id", "分类", "名称", "路由", "漏洞面", "蜜标"])
    print()
    dim("自定义模板放在 %s, 同 id 会覆盖内置" % cfg.path(templating.CUSTOM_DIR_NAME))
    dim("查看详情: cogtrap template show <id>")
    return EXIT_OK


def cmd_template_show(args):
    cfg = load_config(args)
    try:
        template = templating.load_template(args.id, cfg)
    except templating.TemplateError as exc:
        fail(str(exc))
        return EXIT_BAD_INPUT
    data = template.to_dict()
    heading("模板 %s —— %s" % (template.id, template.name))
    dim("分类      : %s  版本: %s  来源: %s" % (
        template.category, template.version, template.source))
    dim("说明      : %s" % template.description)
    dim("载荷档案  : %s   拖滞档案: %s" % (
        template.payload_profile, template.tarpit_profile))
    if template.tags:
        dim("标签      : %s" % ", ".join(template.tags))

    heading("品牌与服务")
    for key in sorted(template.branding):
        dim("%-14s %s" % (key, template.branding[key]))
    for key in sorted(template.server):
        dim("%-14s %s" % (key, template.server[key]))

    heading("内网拓扑(横向移动诱饵)")
    for key in sorted(template.network):
        dim("%-14s %s" % (key, template.network[key]))

    heading("路由 (%d)" % len(template.routes))
    table([[r.method, r.path, r.kind, r.status,
            ",".join(r.honeytokens) or "-"] for r in template.routes],
          headers=["方法", "路径", "类型", "状态", "蜜标"])

    if template.vulnerabilities:
        heading("假漏洞面 (%d)" % len(template.vulnerabilities))
        table([[v.type, v.method, v.path, v.severity, v.param or "-"]
               for v in template.vulnerabilities],
              headers=["类型", "方法", "路径", "危害", "参数"])
        dim("这些漏洞全部是伪造的: 只回伪造报错, 不存在真实可利用性")

    if template.credentials:
        heading("凭据蜜标 (%d)" % len(template.credentials))
        table([[c.get("id"), c.get("path"), c.get("kind")] for c in template.credentials],
              headers=["id", "投放路径", "类型"])

    if args.json:
        print()
        print(json.dumps(data, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_template_new(args):
    cfg = load_config(args)
    try:
        data = templating.scaffold(args.id)
    except templating.TemplateError as exc:
        fail(str(exc))
        return EXIT_BAD_INPUT
    directory = args.output or cfg.path(templating.CUSTOM_DIR_NAME)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    path = os.path.join(directory, "%s.json" % args.id)
    if os.path.exists(path) and not args.force:
        fail("文件已存在: %s (加 --force 覆盖)" % path)
        return EXIT_BAD_INPUT
    _write_json(path, data)
    ok("已生成模板骨架: %s" % path)
    print()
    dim("骨架里 `_help` 段说明了每个字段该怎么填, 删除它不影响使用。")
    dim("变量语法: {{变量名}}; 内置变量 instance.host / db_host / db_password 等;")
    dim("随机值 {{rand.hex:8}} {{rand.int:1-100}} {{rand.choice:a|b|c}} {{rand.ip}}")
    print()
    dim("改完校验: cogtrap template validate %s" % path)
    return EXIT_OK


def cmd_template_validate(args):
    cfg = load_config(args)
    paths = args.paths or [os.path.join(cfg.path(templating.CUSTOM_DIR_NAME), n)
                           for n in _json_files(cfg.path(templating.CUSTOM_DIR_NAME))]
    if not paths:
        fail("没有指定文件, 且自定义目录下没有 .json")
        return EXIT_BAD_INPUT
    failures = 0
    for path in paths:
        try:
            data = templating._load_json(path)
            templating.validate(data, path)
            ok("%s" % path)
        except templating.TemplateError as exc:
            fail("%s" % path)
            for line in str(exc).splitlines():
                print("    %s" % line)
            failures += 1
    print()
    if failures:
        fail("%d 个文件未通过" % failures)
        return EXIT_BAD_INPUT
    ok("全部通过")
    return EXIT_OK


def cmd_template_lint(args):
    cfg = load_config(args)
    paths = args.paths or [os.path.join(cfg.path(templating.CUSTOM_DIR_NAME), n)
                           for n in _json_files(cfg.path(templating.CUSTOM_DIR_NAME))]
    if not paths:
        fail("没有指定文件, 且自定义目录下没有 .json")
        return EXIT_BAD_INPUT
    total = {"info": 0, "warning": 0, "error": 0}
    for path in paths:
        try:
            data = templating._load_json(path)
        except templating.TemplateError as exc:
            fail("%s" % path)
            print("    %s" % exc)
            total["error"] += 1
            continue
        issues = templating.lint(data, path)
        if not issues:
            ok("%s 无问题" % path)
            continue
        print("%s" % _c(path, "1"))
        for issue in issues:
            total[issue["level"]] = total.get(issue["level"], 0) + 1
            marker = {"error": _c("错误", "31"), "warning": _c("告警", "33"),
                      "info": _c("提示", "36")}.get(issue["level"], issue["level"])
            print("    %s %s" % (marker, issue["message"]))
    print()
    dim("合计: 错误 %d / 告警 %d / 提示 %d" % (
        total["error"], total["warning"], total["info"]))
    return EXIT_BAD_INPUT if total["error"] else EXIT_OK


def cmd_template_render(args):
    """预览模板渲染结果 —— 定制完之后最该做的一步。"""
    cfg = load_config(args)
    try:
        template = templating.load_template(args.id, cfg)
        overrides = _merge_overrides({}, _parse_sets(args.set))
        instance = templating.HoneypotInstance(
            template, overrides=overrides, instance_id=args.name or "preview",
            host=args.host or "preview.example.com", port=args.port or 8080,
            canary="hpx-preview1")
    except templating.TemplateError as exc:
        fail("渲染失败")
        for line in str(exc).splitlines():
            print("  %s" % line)
        return EXIT_BAD_INPUT

    heading("渲染预览 —— %s (%d 条路由)" % (instance.template.name,
                                            len(instance.effective.routes)))
    dim("实例: %s   主机: %s   端口: %s" % (
        instance.instance_id, instance.host, instance.port))
    if overrides:
        dim("覆盖项: %s" % ", ".join(sorted(overrides.keys())))

    selected = instance.effective.routes
    if args.path:
        target = args.path.rstrip("/").lower() or "/"
        selected = [r for r in selected
                    if (r.path.rstrip("/").lower() or "/") == target]
        if not selected:
            fail("模板里没有这个路径: %s" % args.path)
            return EXIT_BAD_INPUT

    for route in selected[:args.limit]:
        status, content_type, body, tokens = instance.page(route)
        print()
        print(_c("─" * 68, "2"))
        print("%s %s  →  %d %s" % (_c(route.method, "1"), _c(route.path, "1"),
                                   status, content_type))
        if tokens:
            dim("蜜标: %s" % ", ".join(tokens))
        print(_c("─" * 68, "2"))
        text = body if isinstance(body, str) else body.decode("utf-8", "replace")
        for line in text.splitlines()[:args.lines]:
            print("  %s" % line)
        if len(text.splitlines()) > args.lines:
            dim("... (%d 行省略)" % (len(text.splitlines()) - args.lines))

    print()
    print(_c("投递面预览(反制载荷如何出现在响应里)", "1"))
    session_like = _PreviewSession("hpx-preview1", instance)
    print()
    print(_c("─ 响应头 ─", "2"))
    for name, value in inject.render_response_headers(session_like.ctx, 95):
        print("  %s: %s" % (name, value))
    print()
    print(_c("─ HTML 注释(埋在每个页面源码里) ─", "2"))
    for line in inject.render_html_comment(session_like.ctx, 95).splitlines()[:args.lines]:
        print("  %s" % line)
    if args.llms:
        print()
        print(_c("─ /llms.txt 全文 ─", "2"))
        for line in inject.render_llms_txt(session_like.ctx, 95).splitlines():
            print("  %s" % line)
    else:
        dim("")
        dim("加 --llms 可看完整的 /llms.txt 投递面(对智能体效果最好的一个面)")
    return EXIT_OK


class _PreviewSession(object):
    def __init__(self, canary, instance):
        self.ctx = inject.PayloadContext(canary, instance.host, instance.instance_id)


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------

def cmd_scenario_list(args):
    cfg = load_config(args)
    items = scenarios_mod.list_scenarios(cfg)
    if not items:
        fail("没有找到任何场景包")
        return EXIT_ERROR
    heading("可用场景包 (%d 个)" % len(items))
    rows = []
    for scenario in items:
        thresholds = scenario.thresholds()
        rows.append([
            scenario.id, scenario.name, scenario.template_ref,
            "开(层%s)" % scenario.countermeasures.get("max_tier", 3)
            if scenario.payload_enabled() else "关",
            scenario.tarpit.get("profile", "standard"),
            scenario.blocking.get("mode", "absorb"),
            "/".join(str(thresholds[a]) for a in scenarios_mod.ACTION_ORDER),
        ])
    table(rows, headers=["id", "名称", "模板", "反制", "拖滞", "处置", "阈值"])
    print()
    dim("阈值顺序: 观察/拖滞/注入/锁定 —— 分数达到该值即启用对应处置档")
    dim("查看详情: cogtrap scenario show <id>")
    return EXIT_OK


def cmd_scenario_show(args):
    cfg = load_config(args)
    try:
        scenario = scenarios_mod.load_scenario(args.id, cfg)
    except scenarios_mod.ScenarioError as exc:
        fail(str(exc))
        return EXIT_BAD_INPUT
    heading("场景 %s —— %s" % (scenario.id, scenario.name))
    dim("说明    : %s" % scenario.description)
    dim("适用    : %s" % scenario.intended_use)
    dim("模板    : %s" % scenario.template_ref)
    dim("来源    : %s" % scenario.source)
    if scenario.tags:
        dim("标签    : %s" % ", ".join(scenario.tags))

    heading("反制策略")
    cm = scenario.countermeasures
    dim("启用    : %s" % ("是" if scenario.payload_enabled() else "否"))
    dim("最低分  : %s" % cm.get("min_score", 50))
    dim("最高层级: %s (0=关闭 1=仅隐蔽 2=+情报/信标 3=全部)" % cm.get("max_tier", 3))
    if cm.get("include"):
        dim("白名单  : %s" % ", ".join(cm["include"]))
    if cm.get("exclude"):
        dim("黑名单  : %s" % ", ".join(cm["exclude"]))

    heading("拖滞强度")
    for key in sorted(scenario.tarpit):
        dim("%-14s %s" % (key, scenario.tarpit[key]))

    heading("检测阈值")
    thresholds = scenario.thresholds()
    table([[action, thresholds[action]] for action in scenarios_mod.ACTION_ORDER],
          headers=["处置档", "触发分数"])
    if scenario.weight_overrides():
        heading("信号权重覆盖")
        for key, value in sorted(scenario.weight_overrides().items()):
            dim("%-26s %+d" % (key, value))

    heading("处置(防火墙)")
    rows = [[k, scenario.blocking[k]] for k in sorted(scenario.blocking)]
    table(rows if rows else [["(未配置)", ""]])

    if scenario.notes:
        heading("设计说明")
        for line in textwrap.wrap(scenario.notes, width=76):
            print("  %s" % line)

    if args.json:
        print()
        print(json.dumps(scenario.to_dict(), ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_scenario_new(args):
    cfg = load_config(args)
    try:
        data = scenarios_mod.scaffold(args.id)
    except scenarios_mod.ScenarioError as exc:
        fail(str(exc))
        return EXIT_BAD_INPUT
    directory = args.output or cfg.path(scenarios_mod.CUSTOM_DIR_NAME)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    path = os.path.join(directory, "%s.json" % args.id)
    if os.path.exists(path) and not args.force:
        fail("文件已存在: %s (加 --force 覆盖)" % path)
        return EXIT_BAD_INPUT
    _write_json(path, data)
    ok("已生成场景骨架: %s" % path)
    dim("改完校验: cogtrap scenario validate %s" % path)
    return EXIT_OK


def cmd_scenario_validate(args):
    cfg = load_config(args)
    paths = args.paths or [os.path.join(cfg.path(scenarios_mod.CUSTOM_DIR_NAME), n)
                           for n in _json_files(cfg.path(scenarios_mod.CUSTOM_DIR_NAME))]
    if not paths:
        fail("没有指定文件, 且自定义目录下没有 .json")
        return EXIT_BAD_INPUT
    failures = 0
    for path in paths:
        try:
            scenarios_mod.validate(scenarios_mod._load_json(path), path)
            ok("%s" % path)
        except scenarios_mod.ScenarioError as exc:
            fail("%s" % path)
            for line in str(exc).splitlines():
                print("    %s" % line)
            failures += 1
    print()
    if failures:
        fail("%d 个文件未通过" % failures)
        return EXIT_BAD_INPUT
    ok("全部通过")
    return EXIT_OK


def cmd_scenario_lint(args):
    cfg = load_config(args)
    paths = args.paths or [os.path.join(cfg.path(scenarios_mod.CUSTOM_DIR_NAME), n)
                           for n in _json_files(cfg.path(scenarios_mod.CUSTOM_DIR_NAME))]
    if not paths:
        fail("没有指定文件, 且自定义目录下没有 .json")
        return EXIT_BAD_INPUT
    total = {"info": 0, "warning": 0, "error": 0}
    for path in paths:
        try:
            data = scenarios_mod._load_json(path)
        except scenarios_mod.ScenarioError as exc:
            fail("%s" % path)
            total["error"] += 1
            continue
        issues = scenarios_mod.lint(data, path)
        if not issues:
            ok("%s 无问题" % path)
            continue
        print("%s" % _c(path, "1"))
        for issue in issues:
            total[issue["level"]] = total.get(issue["level"], 0) + 1
            marker = {"error": _c("错误", "31"), "warning": _c("告警", "33"),
                      "info": _c("提示", "36")}.get(issue["level"], issue["level"])
            print("    %s %s" % (marker, issue["message"]))
    print()
    dim("合计: 错误 %d / 告警 %d / 提示 %d" % (
        total["error"], total["warning"], total["info"]))
    return EXIT_BAD_INPUT if total["error"] else EXIT_OK


# --------------------------------------------------------------------------
# countermeasures
# --------------------------------------------------------------------------

def cmd_countermeasures(args):
    cfg = load_config(args)
    plugin_dir = cfg.path(cfg.get("inject.custom_dir", "payloads/custom"))
    registry, report = countermeasures_mod.build_default_registry(plugin_dir=plugin_dir)

    if args.action == "stats":
        heading("反制方式库统计")
        stats = registry.stats()
        dim("总数      : %d" % stats["total"])
        dim("内置/插件 : %d / %d" % (report["builtin"], report["plugins"]))
        heading("按类别")
        rows = []
        for category in sorted(countermeasures_mod.CATEGORIES):
            count = stats["by_category"].get(category, 0)
            rows.append([category, count, countermeasures_mod.CATEGORIES[category]])
        table(rows, headers=["类别", "条数", "意图"])
        heading("按投放层级")
        for tier in (1, 2, 3):
            label = {1: "隐蔽(不暴露防御存在)", 2: "中等(确证与情报)",
                     3: "激进(含报告投毒)"}[tier]
            dim("层级 %d: %2d 条   %s" % (tier, stats["by_tier"].get(tier, 0), label))
        if report["errors"]:
            heading("插件错误")
            for error in report["errors"]:
                warn(error)
        return EXIT_OK

    if args.action == "show":
        item = registry.get(args.id)
        if item is None:
            fail("找不到反制方式: %s" % args.id)
            dim("用 cogtrap countermeasures list 查看全部")
            return EXIT_BAD_INPUT
        heading("%s —— %s" % (item.id, item.intent))
        dim("类别    : %s (%s)" % (item.category,
                                   countermeasures_mod.CATEGORIES[item.category]))
        dim("层级    : %d" % item.tier)
        dim("权重    : %d    隐蔽度: %.2f" % (item.weight, item.stealth))
        dim("来源    : %s" % item.source)
        dim("最低分  : %d" % item.min_score())
        if item.surfaces:
            dim("适用面  : %s" % ", ".join(item.surfaces))
        if item.tags:
            dim("标签    : %s" % ", ".join(item.tags))
        heading("为什么有效")
        for line in textwrap.wrap(item.rationale, width=76):
            print("  %s" % line)
        heading("载荷正文(中文)")
        for line in item.text_zh.splitlines():
            print("  %s" % line)
        if item.text_en:
            heading("载荷正文(英文)")
            for line in item.text_en.splitlines():
                print("  %s" % line)
        return EXIT_OK

    # list
    heading("反制方式库 (%d 条)" % len(registry.all()))
    rows = []
    for item in sorted(registry.all(),
                       key=lambda i: (i.category, -i.weight)):
        rows.append([item.category, item.id, item.tier, item.weight,
                     "%.1f" % item.stealth])
    table(rows, headers=["类别", "id", "层", "权重", "隐蔽度"])
    print()
    dim("层 1-3 为投放门控: 低分区只投层级 1(隐蔽), 已确证才投层级 3")
    dim("隐蔽度越高越不易被识别为蜜罐, 但中止效果也越弱")
    dim("详情: cogtrap countermeasures show <id>")
    dim("扩充: 把 JSON 放进 %s (可用 cogtrap countermeasures validate 校验)"
        % cfg.path(cfg.get("inject.custom_dir", "payloads/custom")))
    return EXIT_OK


# --------------------------------------------------------------------------
# cert —— 自签证书(TLS 蜜罐面)
# --------------------------------------------------------------------------

def cmd_cert(args):
    """生成自签证书, 供启用 HTTPS 蜜罐面。

    为什么用 openssl CLI 而不是 Python 库: 生成证书需要密码学能力, 标准库
    只有"加载"没有"签发"; openssl 在目标系统(CentOS 8 等)上随基础组件存在,
    比引入 cryptography 依赖更符合"核心零依赖"的部署约束。
    """
    import subprocess
    cfg = load_config(args)
    out_dir = os.path.abspath(args.out or os.path.join(cfg.root, "tls"))
    cn = args.cn or "portal.example.com"
    cert = os.path.join(out_dir, "cert.pem")
    key = os.path.join(out_dir, "key.pem")

    binary = None
    for candidate in ("openssl", "/usr/bin/openssl", "/usr/local/bin/openssl"):
        with open(os.devnull, "w") as devnull:
            try:
                subprocess.check_call([candidate, "version"], stdout=devnull,
                                      stderr=devnull)
                binary = candidate
                break
            except (OSError, subprocess.CalledProcessError):
                continue
    if binary is None:
        fail("未找到 openssl —— 自签证书需要它(目标系统通常自带)")
        return EXIT_ERROR

    if (os.path.exists(cert) or os.path.exists(key)) and not args.force:
        fail("证书已存在: %s (加 --force 覆盖)" % cert)
        return EXIT_BAD_INPUT

    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    subject = "/CN=%s" % cn
    canary = (args.canary or "").strip()
    if canary:
        # 令牌进 SAN 与 O 字段: 部分智能体/扫描器会解析证书字段入上下文,
        # 令牌一旦回显即 TLS 层的上下文复用确证
        subject = "/O=trace %s/CN=%s" % (canary, cn)
        san = "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1,DNS:%s.trace.invalid" % (cn, canary)
    else:
        san = "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1" % cn
    command = [
        binary, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert,
        "-days", str(args.days), "-subj", subject,
        "-addext", san,
    ]
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        output, _ = proc.communicate(timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("openssl 执行失败: %s" % exc)
        return EXIT_ERROR
    if proc.returncode != 0:
        fail("证书生成失败: %s" % output.decode("utf-8", "replace")[:300])
        return EXIT_ERROR
    os.chmod(key, 0o600)

    ok("自签证书已生成")
    dim("证书 : %s" % cert)
    dim("私钥 : %s (权限 600)" % key)
    dim("CN    : %s | 有效期 %d 天" % (cn, args.days))
    print()
    dim("启用 HTTPS 蜜罐面 —— 在 config.json 的 http.tls 段设置:")
    dim('  "tls": {"enabled": true, "cert": "%s", "key": "%s"}' % (cert, key))
    dim("警告: 自签证书会被真浏览器标“不安全”。对蜜罐这通常是优点 ——")
    dim("      攻击者工具默认忽略证书校验, 而真人会先起疑心。")
    return EXIT_OK


# --------------------------------------------------------------------------
# hub / push —— 多节点聚合
# --------------------------------------------------------------------------

def cmd_hub(args):
    """启动聚合节点: 接收各实例推送, 合并统一视图(跨实例战役归因)。"""
    cfg = load_config(args)
    # Config 是只读视图 —— 命令行覆盖经 as_dict 重建(部署实测抓过:
    # 直接对 Config 下标赋值会 TypeError)
    if args.token or args.port or args.host or args.db:
        data = cfg.as_dict()
        hub_cfg = dict(data.get("hub") or {})
        if args.token:
            hub_cfg["token"] = args.token
        if args.port:
            hub_cfg["port"] = args.port
        if args.host:
            hub_cfg["host"] = args.host
        if args.db:
            hub_cfg["db"] = args.db
        data["hub"] = hub_cfg
        cfg = config_mod.Config(data, root=cfg.root)

    token = (cfg.get("hub") or {}).get("token", "")
    if not token:
        warn("未设置 token —— 任何能连到本端口的都可作为推送")
        dim("生成随机 token: python3 -c \"import secrets;print(secrets.token_hex(16)\"")

    import hub as hub_mod
    import store as store_mod
    store = store_mod.Store(cfg.path(cfg.get("hub", {}).get("db", "var/hub.db")))
    node = hub_mod.Hub(cfg, store=store, token=token)

    loop = __import__("asyncio").get_event_loop()
    bound = loop.run_until_complete(node.start())  # store 已注入
    heading("CogTrap hub —— 多节点聚合")
    dim("监听     : %s:%s (仅内网使用)" % bound[:2])
    dim("中心库   : %s" % cfg.path(cfg.get("hub", {}).get("db", "var/hub.db")))
    dim("鉴权     : %s" % ("token 已启用" if token else "未启用(不推荐)"))
    dim("查询     : GET /stats | GET /api/campaigns")
    print()
    ok("已启动。实例侧推送: cogtrap push --hub http://%s:%s --token <token>" % bound[:2])
    print()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print()
        ok("收到中断, 正在停止...")
    finally:
        loop.run_until_complete(node.close())
        print()
        heading("hub 统计")
        table(sorted(node.stats.items()))
        store.close()
    return EXIT_OK


def cmd_push(args):
    """把本实例新遥测推送给聚合节点(幂等, 成功才推进水位线)。"""
    cfg = load_config(args)
    if not args.hub:
        fail("需要 --hub <URL>, 例如 http://10.1.1.10:9443")
        return EXIT_BAD_INPUT
    import hub as hub_mod
    import store as store_mod
    store = store_mod.Store(cfg.store_path())
    try:
        ok_all, message = hub_mod.push_bundle(cfg, args.hub, args.token or "",
                                              store, timeout=args.timeout)
    finally:
        store.close()
    if ok_all:
        ok("推送完成: %s" % message)
        return EXIT_OK
    fail(message)
    return EXIT_ERROR


# --------------------------------------------------------------------------
# report —— 取证与上报
# --------------------------------------------------------------------------

def cmd_report(args):
    cfg = load_config(args)
    try:
        report_mod = __import__("report")
    except ImportError:
        fail("report 模块缺失")
        return EXIT_ERROR

    store_mod = __import__("store")
    store = store_mod.Store(cfg.store_path())

    try:
        if args.session:
            try:
                document = report_mod.build_session_report(store, args.session)
            except ValueError as exc:
                fail(str(exc))
                dim("用 --list 查看可用会话")
                return EXIT_BAD_INPUT
        elif args.campaign:
            try:
                document = report_mod.build_campaign_report(store, args.campaign)
            except ValueError as exc:
                fail(str(exc))
                dim("用 --list 查看可用战役")
                return EXIT_BAD_INPUT
        else:
            fail("需要 --session <id> 或 --campaign <id>, 或 --batch")
            return EXIT_BAD_INPUT

        if args.stdout:
            print(report_mod.render_markdown(document))
            return EXIT_OK

        paths, stem = report_mod.write_report_bundle(cfg, store, document)
        heading("取证材料已生成")
        summary = document.get("summary") or {}
        if document["kind"] == "session":
            dim("目标     : %s" % summary.get("target_ip"))
            dim("判定     : %s (分数 %s)" % (summary.get("label"), summary.get("score")))
        else:
            dim("战役     : %s" % summary.get("campaign_id"))
            dim("源 IP    : %d 个" % summary.get("ip_count", 0))
        dim("请求条数 : %s" % summary.get("request_count"))
        dim("证据摘要 : %s" % document.get("evidence_digest", "-")[:32])
        print()
        table([
            [os.path.basename(paths["markdown"]), "上报材料(人读, 含结论/证据/时间线)"],
            [os.path.basename(paths["json"]), "完整档案(机器读)"],
            [os.path.basename(paths["csv"]), "时间线表格(可导入分析工具)"],
            [os.path.basename(paths["iocs"]), "IOC 清单(可喂给防火墙/情报平台)"],
            [os.path.basename(paths["abuse"]), "向托管方举报的邮件模板"],
        ], headers=["文件", "用途"])
        print()
        dim("目录: %s" % cfg.out_path("reports"))
        if document.get("caveats"):
            print()
            warn("材料含 %d 条证据局限说明 —— 提交前请务必阅读" % len(document["caveats"]))
        return EXIT_OK

    finally:
        store.close()


def cmd_report_list(args):
    cfg = load_config(args)
    store_mod = __import__("store")
    store = store_mod.Store(cfg.store_path())
    try:
        heading("可生成材料的会话(分数 >= %d)" % args.min_score)
        rows = []
        for row in store.recent_sessions(limit=40, min_score=args.min_score):
            rows.append([row["id"][:34], row["ip"], row["score"], row["label"],
                         row["req_count"]])
        table(rows if rows else [["(无)", "", "", "", ""]],
              headers=["会话 id", "源 IP", "分数", "判定", "请求"])
        heading("可生成材料的战役")
        rows = []
        for row in store.campaigns(limit=30):
            if (row["score_max"] or 0) < args.min_score:
                continue
            rows.append([row["id"], row["score_max"], row["session_count"],
                         (row["toolchain"] or "")[:24]])
        table(rows if rows else [["(无)", "", "", ""]],
              headers=["战役 id", "分数上限", "会话数", "工具链"])
    finally:
        store.close()
    return EXIT_OK


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def cmd_block(args):
    """把一个 IP 加入处置(默认只生成规则; --apply 且持有时真实落地)。"""
    import block as block_mod
    cfg = load_config(args)

    if args.list:
        store_mod = __import__("store")
        store = store_mod.Store(cfg.store_path())
        rows = [[row["ip"], (row["reason"] or "")[:34], row["mode"],
                 "已落地" if row["applied"] else "候选", row["score"]]
                for row in store.blocks(limit=30)]
        table(rows, headers=["IP", "依据", "模式", "状态", "分数"])
        store.close()
        return EXIT_OK

    if not args.ip:
        fail("需要 --ip <addr> 或 --list")
        return EXIT_BAD_INPUT

    if block_mod.is_whitelisted(args.ip, cfg):
        warn("%s 在白名单/私网段内 —— 已拒绝处置(保护内网)" % args.ip)
        return EXIT_BAD_INPUT

    rule = block_mod.build_rule(args.ip, cfg, reason=args.reason or "manual")
    path = block_mod.write_rule(cfg, rule)

    store_mod = __import__("store")
    store = store_mod.Store(cfg.store_path())
    store.record_block(args.ip, rule["reason"], args.score or 0,
                       rule["mode"], rule["nft"], applied=False,
                       ttl_seconds=rule.get("ttl", 3600))
    store.close()
    ok("处置规则已生成: %s" % path)
    dim("规则: %s" % rule["nft"])

    if args.apply:
        applied, message = _apply_block_element(args.ip, int(rule.get("ttl", 3600)))
        if applied:
            ok("已真实落地: %s" % message)
        else:
            warn("未落地: %s" % message)
            dim("落地需要: root + cogtrap nft 表已加载(nft -f deploy/nftables-absorb.nft)")
    else:
        dim("默认不落地; 演练窗口加 --apply 真实处置")
    return EXIT_OK


def _apply_block_element(ip, ttl):
    import subprocess
    binary = None
    for candidate in ("/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"):
        if os.path.exists(candidate):
            binary = candidate
            break
    if binary is None:
        return False, "未安装 nft"
    if os.geteuid() != 0:
        return False, "需要 root"
    try:
        proc = subprocess.Popen(
            [binary, "add", "element", "inet", "cogtrap", "offenders",
             "{ %s timeout %ds }" % (ip, ttl)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = proc.communicate(timeout=15)
        if proc.returncode == 0:
            return True, "offenders += %s (TTL %ds)" % (ip, ttl)
        return False, out.decode("utf-8", "replace")[:200]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, repr(exc)


def cmd_effectiveness(args):
    """载荷效果归因: 哪些反制方式真的被服从了(权重调优的数据基础)。"""
    cfg = load_config(args)
    try:
        report_mod = __import__("report")
    except ImportError:
        fail("report 模块缺失")
        return EXIT_ERROR
    store_mod = __import__("store")
    store = store_mod.Store(cfg.store_path())
    try:
        effect = report_mod.payload_effectiveness(store)
        if not effect["payloads"]:
            warn("尚无投放数据 —— 需要有攻击会话命中蜜罐后才会产生")
            return EXIT_OK
        if args.suggest:
            adjustments = report_mod.suggest_weight_adjustments(store)
            md = report_mod.render_adjustments(adjustments)
            print(md)
            return EXIT_OK
        if args.stdout:
            print(report_mod.render_effectiveness(effect))
            return EXIT_OK
        heading("反制载荷效果归因")
        dim("总会话投放: %s | 确证: %s | 总体确证率: %.1f%%" % (
            effect["total_delivered"], effect["total_confirmed"],
            effect["overall_rate"] * 100))
        print()
        table([[r["payload"], r["delivered_sessions"],
                r["confirmed_sessions"],
                "%.1f%%" % (r["confirmation_rate"] * 100)]
               for r in effect["payloads"][:20]],
              headers=["载荷", "投放会话", "确证会话", "确证率"])
        print()
        dim("高确证率=实际被读到并执行; 低确证率+高权重=考虑降权")
        dim("导出 Markdown: cogtrap effectiveness --stdout")
        return EXIT_OK
    finally:
        store.close()


def cmd_doctor(args):
    cfg = load_config(args)
    heading("%s doctor —— 环境自检" % PRODUCT)
    problems = 0
    notes = []

    # Python
    version = sys.version_info
    if version[:2] >= (3, 6):
        ok("Python %d.%d.%d" % (version[0], version[1], version[2]))
    else:
        fail("Python 版本过低: 需要 3.6+")
        problems += 1

    # 模块完整性
    required = ["config", "http_parse", "store", "fingerprint", "inject",
                "deception", "tarpit", "respond", "server", "block",
                "templating", "scenarios", "countermeasures"]
    optional = ["dashboard", "ssh_decoy", "report"]
    missing = []
    for name in required + optional:
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    core_missing = [n for n in missing if n in required]
    if core_missing:
        fail("核心模块缺失: %s" % ", ".join(core_missing))
        problems += 1
    else:
        ok("核心模块完整 (%d 个)" % len(required))
    opt_missing = [n for n in missing if n in optional]
    if opt_missing:
        warn("可选模块缺失(相关功能不可用): %s" % ", ".join(opt_missing))
    else:
        ok("可选模块完整")

    # 模板与场景
    templates = templating.list_templates(cfg)
    scenarios = scenarios_mod.list_scenarios(cfg)
    ok("蜜罐模板 %d 个, 场景包 %d 个" % (len(templates), len(scenarios)))
    if not templates:
        fail("没有模板, 蜜罐将只返回内置默认内容")
        problems += 1

    # 反制方式库
    registry, report = countermeasures_mod.build_default_registry(
        plugin_dir=cfg.path(cfg.get("inject.custom_dir", "payloads/custom")))
    ok("反制方式 %d 条(内置 %d, 插件 %d)" % (
        registry.stats()["total"], report["builtin"], report["plugins"]))
    for error in report["errors"][:5]:
        warn("插件: %s" % error)

    # 目录可写
    for name in ("var", "logs", "out"):
        path = cfg.path(name)
        if os.path.isdir(path) and os.access(path, os.W_OK):
            ok("目录可写: %s" % name)
        else:
            fail("目录不可写: %s" % path)
            problems += 1

    # 防火墙能力(只报告, 不改动)
    try:
        block = __import__("block")
        available, info = block.check_nft()
        if available:
            ok("nft 可用: %s" % info)
        else:
            warn("nft 不可用, 处置功能只能生成规则文件: %s" % info)
    except ImportError:
        warn("block 模块缺失")

    # 安全默认值核查(这几项配错会出事)
    heading("安全配置核查")
    if cfg.get("block.armed", False) and cfg.get("block.apply", False):
        warn("block.armed 与 block.apply 都为 true —— 防火墙规则会真实落地")
        notes.append("确认这是演练环境且已获授权")
    else:
        ok("防火墙默认不落地(演练模式)")
    whitelist = cfg.get("block.whitelist") or []
    if whitelist:
        ok("处置白名单 %d 段: %s" % (len(whitelist), ", ".join(whitelist[:4])))
    else:
        fail("处置白名单为空 —— 有误封内网的风险")
        problems += 1
    limits = cfg.get("limits") or {}
    if limits.get("max_connections") and limits.get("max_tarpit_seconds_per_session"):
        ok("资源上限已设: 连接 %s, 单会话拖滞上限 %s 秒" % (
            limits["max_connections"],
            limits["max_tarpit_seconds_per_session"]))
    else:
        warn("资源上限未完整设置, 拖滞可能反噬自身")

    print()
    if problems:
        fail("发现 %d 个必须解决的问题" % problems)
        return EXIT_NOT_READY
    ok("环境就绪")
    for note in notes:
        dim(note)
    return EXIT_OK


# --------------------------------------------------------------------------
# 参数解析
# --------------------------------------------------------------------------

def _json_files(directory):
    if not os.path.isdir(directory):
        return []
    return sorted(n for n in os.listdir(directory) if n.endswith(".json"))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cogtrap",
        description="%s %s —— 面向大模型驱动攻击的蜜罐防御与反制体系" % (PRODUCT, VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            典型用法:
              首次接触 ---- cogtrap doctor
              看看有什么 -- cogtrap template list / cogtrap scenario list
              造一个蜜罐 -- cogtrap generate --template gov-portal --scenario hw-drill-dmz -o ./my-honeypot
              本地预览 ---- cogtrap template render gov-portal --path /login
              启动 -------- cogtrap serve --scenario hw-drill-dmz
              看战果 ------ cogtrap reports --min-score 70
              出上报材料 -- cogtrap report --session <id>

            合法使用: 仅可部署于你拥有或已获明确书面授权的资产。
            本系统的反制全部发生在己方服务端的响应内容里, 不主动连接攻击方主机。
        """),
    )
    parser.add_argument("--version", action="version",
                        version="%s %s" % (PRODUCT, VERSION))
    parser.add_argument("-c", "--config", help="配置文件路径(默认 config.json)")
    subparsers = parser.add_subparsers(dest="command")

    # serve
    p_serve = subparsers.add_parser("serve", help="启动蜜罐服务")
    p_serve.add_argument("--template", help="使用某个蜜罐模板")
    p_serve.add_argument("--scenario", help="套用某个场景包")
    p_serve.add_argument("--instance", help="从 generate 产出的 instance.json 载入")
    p_serve.add_argument("--host", help="监听地址(默认取配置)")
    p_serve.add_argument("--port", type=int, help="监听端口(默认取配置)")
    p_serve.add_argument("--set", action="append", metavar="KEY=VALUE",
                         help="覆盖模板字段, 可重复, 如 --set branding.site_name=XX")
    p_serve.add_argument("--no-dashboard", action="store_true", help="不启动仪表盘")
    # 全局参数通常写在子命令前, 但使用者常写成 `serve --config x`; 两种都支持,
    # 否则会得到 "unrecognized arguments" 这种让人困惑的报错(真实踩过的坑)。
    # 必须用 SUPPRESS: 子解析器会把自身所有默认值覆盖回主命名空间, 若这里用
    # 普通 default=None, 那么写成 `cogtrap --config x serve` 时, 前置的 --config
    # 会被这个默认值静默覆盖, 导致 **配置文件被忽略并悄悄回落到默认配置**
    # (真实踩过: 蜜罐因此监听了 0.0.0.0 而不是配置里的 127.0.0.1)。
    p_serve.add_argument("-c", "--config", dest="config",
                         default=argparse.SUPPRESS,
                         help="配置文件路径(也可写在子命令前)")
    p_serve.set_defaults(func=cmd_serve)

    # generate
    p_gen = subparsers.add_parser("generate", help="从模板+场景生成一个可运行的蜜罐实例")
    p_gen.add_argument("--template", required=True, help="蜜罐模板 id 或 .json 路径")
    p_gen.add_argument("--scenario", help="场景包 id(提供反制策略与阈值)")
    p_gen.add_argument("-o", "--output", default="honeypot-instance", help="输出目录")
    p_gen.add_argument("--name", help="实例标识(默认 模板id-时间戳)")
    p_gen.add_argument("--host", help="对外主机名(用于渲染页面里的链接)")
    p_gen.add_argument("--port", type=int, help="监听端口")
    p_gen.add_argument("--set", action="append", metavar="KEY=VALUE",
                       help="覆盖模板字段, 如 --set branding.site_name=示例集团")
    p_gen.add_argument("--force", action="store_true", help="输出目录已存在时覆盖")
    p_gen.set_defaults(func=cmd_generate)

    # template
    p_tpl = subparsers.add_parser("template", help="蜜罐模板管理")
    tpl_sub = p_tpl.add_subparsers(dest="action")
    p = tpl_sub.add_parser("list", help="列出可用模板")
    p.set_defaults(func=cmd_template_list)
    p = tpl_sub.add_parser("show", help="查看模板详情")
    p.add_argument("id", help="模板 id")
    p.add_argument("--json", action="store_true", help="同时输出原始 JSON")
    p.set_defaults(func=cmd_template_show)
    p = tpl_sub.add_parser("new", help="生成新模板骨架(用户生成蜜罐的第一步)")
    p.add_argument("id", help="新模板 id(小写字母/数字/连字符)")
    p.add_argument("-o", "--output", help="输出目录(默认 templates/custom)")
    p.add_argument("--force", action="store_true", help="文件已存在时覆盖")
    p.set_defaults(func=cmd_template_new)
    p = tpl_sub.add_parser("validate", help="校验模板")
    p.add_argument("paths", nargs="*", help="文件路径(默认校验 custom 目录)")
    p.set_defaults(func=cmd_template_validate)
    p = tpl_sub.add_parser("lint", help="检查模板的可疑之处")
    p.add_argument("paths", nargs="*", help="文件路径(默认校验 custom 目录)")
    p.set_defaults(func=cmd_template_lint)
    p = tpl_sub.add_parser("render", help="预览渲染结果与反制载荷投递面")
    p.add_argument("id", help="模板 id")
    p.add_argument("--path", help="只看某个路径")
    p.add_argument("--host", help="渲染用的主机名")
    p.add_argument("--port", type=int, help="渲染用的端口")
    p.add_argument("--name", help="预览实例标识")
    p.add_argument("--set", action="append", metavar="KEY=VALUE", help="覆盖字段")
    p.add_argument("--limit", type=int, default=8, help="最多预览几条路由")
    p.add_argument("--lines", type=int, default=24, help="每条路由显示几行")
    p.add_argument("--llms", action="store_true", help="显示完整的 /llms.txt 投递面")
    p.set_defaults(func=cmd_template_render)

    # scenario
    p_scn = subparsers.add_parser("scenario", help="场景包管理")
    scn_sub = p_scn.add_subparsers(dest="action")
    p = scn_sub.add_parser("list", help="列出可用场景")
    p.set_defaults(func=cmd_scenario_list)
    p = scn_sub.add_parser("show", help="查看场景详情")
    p.add_argument("id", help="场景 id")
    p.add_argument("--json", action="store_true", help="同时输出原始 JSON")
    p.set_defaults(func=cmd_scenario_show)
    p = scn_sub.add_parser("new", help="生成场景骨架")
    p.add_argument("id", help="新场景 id")
    p.add_argument("-o", "--output", help="输出目录(默认 scenarios/custom)")
    p.add_argument("--force", action="store_true", help="文件已存在时覆盖")
    p.set_defaults(func=cmd_scenario_new)
    p = scn_sub.add_parser("validate", help="校验场景")
    p.add_argument("paths", nargs="*", help="文件路径(默认校验 custom 目录)")
    p.set_defaults(func=cmd_scenario_validate)
    p = scn_sub.add_parser("lint", help="检查场景的可疑之处")
    p.add_argument("paths", nargs="*", help="文件路径(默认校验 custom 目录)")
    p.set_defaults(func=cmd_scenario_lint)

    # countermeasures
    p_cm = subparsers.add_parser("countermeasures", help="反制方式库")
    p_cm.add_argument("action", nargs="?", default="list",
                      choices=["list", "stats", "show"], help="默认 list")
    p_cm.add_argument("id", nargs="?", help="show 时的反制方式 id")
    p_cm.set_defaults(func=cmd_countermeasures)

    # cert
    p_cert = subparsers.add_parser("cert", help="生成自签证书(启用 HTTPS 蜜罐面)")
    p_cert.add_argument("--cn", help="证书 CN(默认 portal.example.com, 用你的诱饵域名)")
    p_cert.add_argument("--days", type=int, default=825, help="有效期天数(默认 825)")
    p_cert.add_argument("-o", "--out", help="输出目录(默认 ./tls)")
    p_cert.add_argument("--canary", help="把追踪令牌写入证书 SAN/O 字段(TLS 层蜜标)")
    p_cert.add_argument("--force", action="store_true", help="已存在时覆盖")
    p_cert.set_defaults(func=cmd_cert)

    # hub / push
    p_hub = subparsers.add_parser("hub", help="启动多节点聚合节点(内网)")
    p_hub.add_argument("--host", help="监听地址(默认 127.0.0.1, 部署时用内网地址)")
    p_hub.add_argument("--port", type=int, help="端口(默认 9443)")
    p_hub.add_argument("--db", help="中心库路径(默认 var/hub.db)")
    p_hub.add_argument("--token", help="共享鉴权 token(实例侧使用同一串)")
    p_hub.set_defaults(func=cmd_hub)

    p_push = subparsers.add_parser("push", help="把本实例遥测推送给聚合节点")
    p_push.add_argument("--hub", required=True, help="hub 地址, 如 http://10.1.1.10:9443")
    p_push.add_argument("--token", default="", help="与 hub 一致的共享 token")
    p_push.add_argument("--timeout", type=float, default=30.0)
    p_push.set_defaults(func=cmd_push)

    # report
    p_rep = subparsers.add_parser("report", help="生成取证与上报材料")
    p_rep.add_argument("--session", help="按会话 id 生成")
    p_rep.add_argument("--campaign", help="按战役 id 生成")
    p_rep.add_argument("--stdout", action="store_true", help="打印到终端而不写文件")
    p_rep.set_defaults(func=cmd_report)

    p_rep_list = subparsers.add_parser("reports", help="列出可生成材料的会话与战役")
    p_rep_list.add_argument("--min-score", type=int, default=60,
                            help="最低分数(默认 60)")
    p_rep_list.set_defaults(func=cmd_report_list)

    # doctor
    # block
    p_blk = subparsers.add_parser("block", help="一键封禁/吸收处置(演练反制)")
    p_blk.add_argument("--ip", help="处置目标 IP")
    p_blk.add_argument("--reason", help="处置依据(进遥测)")
    p_blk.add_argument("--score", type=int, default=0, help="关联分数(记录用)")
    p_blk.add_argument("--apply", action="store_true",
                       help="真实落地(需 root 且 cogtrap nft 表已加载)")
    p_blk.add_argument("--list", action="store_true", help="列出近期处置记录")
    p_blk.set_defaults(func=cmd_block)

    # effectiveness
    p_eff = subparsers.add_parser("effectiveness",
                                  help="反制载荷效果归因(哪些真的被服从了)")
    p_eff.add_argument("--stdout", action="store_true", help="输出 Markdown")
    p_eff.add_argument("--suggest", action="store_true",
                       help="基于效果给出权重调整建议(不自动应用)")
    p_eff.set_defaults(func=cmd_effectiveness)

    p_doc = subparsers.add_parser("doctor", help="环境自检")
    p_doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        return EXIT_OK
    except (templating.TemplateError, scenarios_mod.ScenarioError) as exc:
        fail(str(exc))
        return EXIT_BAD_INPUT


if __name__ == "__main__":
    sys.exit(main())
