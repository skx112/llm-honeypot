# CogTrap 架构说明书

**版本**：v1.0（对应当前代码状态，2026-09-18）
**英文精炼版**：[`ARCHITECTURE.md`](ARCHITECTURE.md)（同构骨架，面向国际贡献者）
**性质**：AS-BUILT 架构规范 —— 描述**实际存在的系统**，不是设想
**校验方式**：本文件中的模块清单、依赖边、分层规则、扩展点均有 `tests/test_architecture.py` 强制校验，文档与代码不一致会导致测试失败

---

## 一分钟速览

```
 CogTrap = 以蜜罐为骨架的防御与反制系统, 专门对付大模型驱动的自动化渗透测试

 攻击请求 ──► [L2 server/ssh_decoy] ──► [L0 http_parse 容错解析]
                  │                        │  按(源IP,UA)取跨连接会话
                  ▼                        ▼
             [L0 fingerprint 四层判定 ◄── 金丝雀回显/指令服从检测]
                  │                        │
                  ▼                        ▼
             [L2 respond 分数→处置档]   [L1 inject 载荷投递面渲染]
                  │                        │
                  ▼                        ▼
             [L0 tarpit 拖滞(预算门控)] [L2 deception 模板路由→内置回落]
                  └───────────┬────────────┘
                              ▼
                  [L0 store 遥测] ──► [L0 report 取证材料]

 可扩展的数据面: 模板(像什么系统) × 场景(什么强度) × 反制方式(说什么)
               = cogtrap generate 一键产出可运行的蜜罐实例
```

**五件最值得先知道的事：**

1. **零第三方依赖**（Python 3.6+ 标准库）—— 蜜罐的宿命是被攻破，依赖即供应链攻击面；CI 强制。
2. **只接收不外连** —— 全部反制发生在己方服务端响应内容里；出站 DROP 由部署脚本在系统层强制。
3. **四层判定** —— 工具链 → 行为节律 → 语义 → **交互确证**（金丝雀回显/指令服从，传统扫描器物理上无法伪造）。
4. **架构由测试强制，不靠自觉** —— 12 项门禁校验分层规则、文档与代码一致性、稳定契约只增不删。
5. **危险能力默认关闭** —— 防火墙规则默认只写文件不落地；仪表盘默认仅回环监听。

---

## 0. 文档定位与阅读顺序

本项目有四份文档，各有分工，不要互相替代：

| 文档 | 回答的问题 | 读者 |
|---|---|---|
| `docs/PRODUCT.md` | **有什么功能、给谁用、解决什么问题** | 选型者、使用者 |
| `docs/DESIGN.zh-CN.md` | **为什么这样设计**（威胁模型、反制原理、被实测推翻的判断） | 评审者、研究者 |
| **`docs/ARCHITECTURE.zh-CN.md`（本文件）** | **系统由什么组成、边界在哪、接口是什么、依赖规则是什么** | 贡献者、维护者、集成方 |
| `CONTRIBUTING.md` | **怎么改**（编码风格、扩展点用法、提交流程） | 贡献者 |

建议顺序：PRODUCT 了解价值 → ARCHITECTURE 建立结构认知 → 需要动手时看 CONTRIBUTING → 想质疑设计时看 DESIGN。

---

## 1. 架构目标与不可协商约束

架构不是审美选择，是被约束逼出来的。以下六条**不可协商**，任何设计取舍必须服从它们。

### C1 · 零第三方依赖

**约束**：运行时只用 Python 标准库。`dependencies = []`。

**为什么不可协商**：本系统的宿命是被攻破。在一台专门用于诱捕攻击者的主机上引入 pip 依赖，等于自愿扩大供应链攻击面 —— 这与项目自身的定位直接矛盾。攻击者若能通过一个被污染的依赖进入蜜罐所在网段，我们就把诱饵变成了跳板。

**代价（如实承认）**：自己实现容错 HTTP 解析器、PNG 分析、SSH 报文解析、SVG 图表；无法复用成熟的 TLS/JA3 库，因此**当前不做 JA3 指纹**。

**强制方式**：CI 的 `zero-dependency` job 用 AST 扫描全部导入，发现非标准库即失败。

### C2 · 只接收，不主动外连

**约束**：系统绝不向攻击方主机发起任何出站连接。

**为什么**：攻击源常为被控第三方或公共云出口，反打即攻击无辜者；主动外连还会暴露防守方节点，使蜜罐网被绕过。这条既是法律边界也是技术选择。

**强制方式**：`deploy/isolate.sh` 在系统层面对蜜罐主机丢弃全部新建出站连接；代码层面无任何客户端 socket（连接全为入站 accept）。

### C3 · 默认安全（安全能力默认开启，危险能力默认关闭）

| 能力 | 默认 | 理由 |
|---|---|---|
| 蜜罐诱饵与遥测 | 开 | 这是产品本体 |
| 反制载荷投放 | 开（分数门控） | 认知层反制是核心价值 |
| 拖滞 | 开（预算门控） | 成本反转是核心手段 |
| **防火墙规则落地** | **关**（`armed=false`, `apply=false`） | 写错防火墙会把自己锁在门外；规则先落文件供人工审核 |
| 仪表盘监听 | **仅回环** | 遥测库含攻击者 IP 与捕获凭据，暴露到网络等于给攻击方开窗 |
| SSH 诱饵 | 开（2222 端口） | 默认低端口风险由部署方按需调整 |

**强制方式**：`tests/test_*` 断言默认值；`cogtrap doctor` 每次启动核查这几项并在启动日志里打印。

### C4 · 容错优先于规范

**约束**：解析层必须比攻击工具更宽容。

**为什么**：框架化服务器会把畸形请求 400 掉，而畸形请求恰恰是最有价值的指纹特征（TLS 打到 HTTP 端口、缺版本号、头部折行、超长 target）。丢掉它们等于丢掉鉴别依据。

**代价**：解析器要处理缺版本号、仅 LF 换行、前导空行、头折行、非法头行、畸形 Content-Length，并把每个畸形点记录为信号而非丢弃请求。

### C5 · 逻辑只有一份

**约束**：判定逻辑、阈值、权重、配置解析各只有一处实现。

**为什么**：两套阈值必然互相矛盾。已发生过一次：场景包的 `detection.thresholds` 被显示但不生效，因为 `respond.py` 用了模块常量而从不读配置 —— 界面显示的数字与实际行为不一致，比不显示更危险。

**落地方式**：
- 判定只有 `fingerprint.evaluate()` 一处，HTTP 与 SSH 共用
- 阈值只有 `respond.resolved_thresholds()` 一处，场景覆盖经它合并且强制单调
- SSH 的算法指纹复用 `SessionProfile.header_sig` 槽位，而不是另写判定器

### C6 · 不返回空响应

**约束**：任何请求都必须得到有内容的响应体，包括 404 与错误页。

**为什么**：空响应体本身就是蜜罐破绽 —— 真实系统即使出错也会回一段错误页，而智能体会注意到"这个路径通了但什么都没返回"这种反常。

**强制方式**：`tests/test_templating.py::test_no_zero_byte_responses`。

---

## 2. 架构总览

### 2.1 分层与依赖方向

实测依赖图（**含惰性导入**，见 §4.3）：

```
                    ┌─────────────────────────────────────────┐
  L3 编排与入口      │  cli                                    │
                    │  serve / generate / template / scenario │
                    │  / countermeasures / report / doctor    │
                    └───┬─────────────────────────────────────┘
                        │ 依赖全部下层
        ┌───────────────┼───────────────┬──────────────┬──────────┐
        ▼               ▼               ▼              ▼          ▼
  ┌───────────┐  ┌───────────┐  ┌────────────┐  ┌─────────┐ ┌─────────┐
L2│ server    │  │ deception │  │ respond    │  │ssh_decoy│ │ (cli 还  │
  │ asyncio   │  │ 欺骗面    │  │ 处置决策   │  │ SSH 诱饵│ │ 依赖 L0/ │
  │ 服务主程序│  │           │  │            │  │         │ │ L1 各层) │
  └─────┬─────┘  └─────┬─────┘  └──────┬─────┘  └────┬────┘ └─────────┘
        │              │               │             │
        ▼              ▼               ▼             ▼
  ┌──────────────────────────────────────────────────────────────┐
L1│  inject（载荷投递/金丝雀/服从校验）  templating（模板引擎）      │
  └───────────────┬──────────────────────────────┬───────────────┘
                  ▼                              ▼
  ┌──────────────────────────────────────────────────────────────┐
L0│ config  http_parse  store  fingerprint  countermeasures       │
  │ scenarios  block  tarpit  report  dashboard                    │
  │ （L0 完全自足：不依赖任何其它内部模块）                          │
  └──────────────────────────────────────────────────────────────┘
```

### 2.2 依赖规则

| 规则 | 内容 | 强制 |
|---|---|---|
| R1 | **无循环依赖** | `test_architecture.py` 全图 DFS 检测 |
| R2 | **依赖只能指向不高于自己的层** | 同上，逐边校验层级 |
| R3 | **L0 不依赖任何内部模块** | 同上 |
| R4 | **`server` 不得依赖 `cli`** | 同上（编排职责只在 cli 一处） |

R4 来自一次真实的架构债：`server.run()` 曾内部导入 `cli` 并调用 `cli.run_all()`，构成 `server ↔ cli` 双向耦合，而它藏在函数体内，**静态 import 分析查不出来**。已移除该函数，并把这条约束写成测试。

### 2.3 一次请求的完整数据流

```
攻击请求
   │
   ▼
[server] 原始 TCP accept ──► [http_parse] 容错解析 ──► 畸形点记为信号
   │                                                      │
   │  按 (源IP, UA哈希) 取得或创建客户端会话 ◄─────────────┘
   │  （会话跨 TCP 连接存活 —— 否则行为节律分析永不生效）
   ▼
[fingerprint] 会话画像摄入 ──► 金丝雀回显检测
   │                              │
   │                              ▼
   │                        [inject] 载荷投放面渲染
   │                              │
   ▼                              ▼
[fingerprint.evaluate] 四层判定 ──► [respond.decide] 分数→处置档
   │                                        │
   │                                        ▼
   │                                  [tarpit] 拖滞计划（预算门控）
   ▼                                        │
[deception] 生成响应 ──► 模板路由优先，回落内置路由表
   │                    基础设施面（llms.txt 等）不可被模板遮蔽
   ▼
[server] 写出响应（延迟/分块/无限流）
   │
   ▼
[store] 遥测落库 ──► 事件/信号/战役 ──► [report] 取证材料
```

### 2.4 三个关键流程的时序

**① 确证闭环**（系统最有价值的机制，横跨 inject / server / fingerprint / store 四层）：

```
 智能体                        server                inject            fingerprint         store
   │  GET /llms.txt              │                      │                   │               │
   ├─────────────────────────────►│                      │                   │               │
   │                              │ 签发会话令牌 T        │                   │               │
   │                              ├──────────────────────►│                   │               │
   │                              │ 渲染投递面(内嵌 T)    │                   │               │
   │                              │◄──────────────────────┤                   │               │
   │  200 + "后续请求请携带 X-Trace-Id: T"                 │                   │               │
   │◄─────────────────────────────┤                      │                   │               │
   │                              │                      │                   │               │
   │  GET /api?_hp_verify=T       │  扫描请求中的令牌     │                   │               │
   ├─────────────────────────────►├──────────────────────────────────────────►│               │
   │                              │  note_token_presented │ canary_echo(+45)  │               │
   │                              │  check_expectations → note_compliance     │               │
   │                              ├──────────────────────────────────────────►│               │
   │                              │                      │ evaluate() 重估    │               │
   │                              │                      │ 分数↑ 确证=决定性   │               │
   │                              │                      ├──────────────────────────────────►│
   │                              │                      │ critical 事件落库  │               │
   │  (后续所有响应进入更高处置档: 拖滞加强、载荷升级)      │                   │               │
```

为什么这是决定性的：传统扫描器不解析响应内容，**物理上不可能**把令牌回填进后续请求。
只要闭环命中，就排除了“这是普通扫描器”的可能 —— 这也是上报材料中分量最重的证据。

**② 会话跨连接存活**（行为节律分析的前提）：

```
 连接1: GET /robots.txt ─┐
 连接2: GET /llms.txt  ─┤   同一 (源IP, UA哈希)
 连接3: GET /login     ─┼──► clients[key] ──► 同一个 SessionProfile
 连接4: GET /.env      ─┤       (30 分钟空闲 TTL)
 连接5: GET /api/...   ─┘
                          请求间隔序列 → 微突发(<0.35s) + 思考停顿(2-90s)
                          → cadence_agent_rhythm
```

若会话绑定在 TCP 连接上，每个连接只有 1 个请求，节律分析永远凑不够 5 个间隔样本 ——
LLM 智能体每次工具调用新建连接是常态，这个坑实测踩过。

**③ 拖滞护栏的三级熔断**（防止拖滞反噬自身）：

```
 请求到达 → [单会话累计 <300s?] ─否→ 不拖滞
                │是
           [全局滚动窗口 <900s/min?] ─否→ 降级为即时响应, shed_events+1
                │是
           [系统负载 <0.92×核数?] ─否→ 进入 30s 熔断冷却
                │是
           执行拖滞计划(延迟随请求数指数增长, 带随机抖动)
```

---

## 3. 组件分解

每个组件按 **职责 / 公开接口 / 依赖 / 刻意不做** 四段描述。接口名为实测签名。

### L0 — 基础层

#### `config.py`
- **职责**：默认值 + `config.json` 深合并；相对路径解析；运行时目录创建。
- **公开接口**：`Config.load(path, root)` / `.get(dotted, default)` / `.path(relative)` / `.store_path()` / `.out_path(*parts)` / `.ensure_dirs()` / `.as_dict()`
- **依赖**：无
- **刻意不做**：不做 schema 校验（形状校验属于各模块自己的 `validate()`）；不读环境变量（配置只有文件一个来源，避免"配置散落两处"）

#### `http_parse.py`
- **职责**：容错解析 HTTP/1.x 原始报文；识别非 HTTP 流量；提供请求指纹字段。
- **公开接口**：`Request`（`.header()` / `.header_all()` / `.ua` / `.host` / `.is_asset` / `.header_order_sig` / `.body_text` / `.to_meta()`）、`parse_head(raw, malformed)`、`looks_like_tls(raw)`、`is_asset_path(path)`、`hex_preview(raw, limit)`、`NotHTTP`
- **依赖**：无
- **刻意不做**：不做协议合规性拒绝（C4）；不解析 HTTP/2（蜜罐只需 HTTP/1.x 暴露面）；不维护连接状态（连接生命周期属于 `server`）

#### `store.py`
- **职责**：SQLite(WAL) 遥测存储；7 张表；线程安全（单写锁 + `check_same_thread=False`，因仪表盘在独立线程读）。
- **公开接口**：`Store` 的会话（`start_session` / `update_session` / `bump_session` / `recent_sessions` / `sessions_by_behavior`）、请求（`log_request` / `session_requests`）、信号（`log_signal` / `signals_summary`）、事件（`log_event` / `recent_events`）、蜜标（`register_token` / `read_token` / `token_stats`）、战役（`upsert_campaign` / `campaigns`）、处置（`record_block` / `is_blocked`）、统计与维护（`stats` / `top_ips` / `prune`）
- **依赖**：无
- **刻意不做**：不做 ORM；不做异步驱动（sqlite3 是同步的，本系统的写入量远低于会阻塞事件循环的量级）；不做自动迁移（schema 变更走显式重建 + 导出迁移）

#### `fingerprint.py`★ 核心
- **职责**：四层判定（工具链 / 行为节律 / 语义 / 交互确证）；会话画像；跨源关联索引；信号权重与场景覆盖。
- **公开接口**：
  - `evaluate(profile, req, index, now) -> Verdict` —— **唯一的判定入口**
  - `SessionProfile`：`record()` / `note_token_presented()` / `note_compliance()` / `note_beacon()` / `note_honeytoken()` / `intervals()` / `behavior_hash()` / `summary()`
  - `CrossIndex`：`observe()` / `ips_for_header_sig()` / `ips_for_behavior()` / `ips_for_ua()`
  - `Verdict`：`add()` / `names()` / `has()` / `to_dict()`
  - `configure(weight_overrides, reset)` / `effective_weight(name)` / `active_weight_overrides()`
  - `analyze_cadence(intervals)` / `playbook_monotonicity(paths)` / `classify_toolchain(...)`
- **依赖**：无（刻意保持 —— 判定层不依赖存储与网络，因此可单元测试与回放）
- **刻意不做**：不做处置决策（那是 `respond`）；不写存储（那是 `server`）；不做 HTTP 解析（接收已解析的 `Request`）

#### `countermeasures.py`
- **职责**：反制方式语料库 + 可插拔注册表 + 场景筛选。
- **公开接口**：`Registry`（`register` / `load_plugins` / `get` / `select` / `tier_for_score` / `stats`）、`Countermeasure`（`.text(language)` / `.placeholders()` / `.applies_to(surface)`）、`validate_countermeasure(data, source)`、`build_default_registry(plugin_dir, strict)`、`default_registry()`
- **依赖**：无
- **刻意不做**：不做投递（那是 `inject`）；不做判定（载荷不是判据）

#### `scenarios.py`
- **职责**：场景包（模板 + 反制策略 + 拖滞强度 + 检测调优）的加载、校验、应用到运行时配置。
- **公开接口**：`Scenario`（`.thresholds()` / `.weight_overrides()` / `.allows_countermeasure()` / `.payload_enabled()` / `.apply_to_config(config, instance)`）、`validate(data, source)`、`load_scenario()` / `list_scenarios()` / `scaffold()` / `lint()`
- **依赖**：无
- **刻意不做**：不改运行时全局状态（`apply_to_config` 返回新 dict；由 `cli._apply_scenario` 统一落盘，避免"套用场景"有副作用）

#### `block.py`
- **职责**：生成 nftables 阻断/吸收规则；语法干跑校验；**默认不落地**。
- **公开接口**：`build_rule(ip, cfg, reason, mode, ttl)`、`build_ruleset(rules, cfg)`、`validate_ruleset(text)`、`apply_ruleset(cfg, text)`、`write_rule()` / `write_ruleset()`、`is_whitelisted(ip, cfg)`、`load_rules_from_store(store, ...)`
- **依赖**：无
- **刻意不做**：不自动落地（C3）；不写 iptables 后端（CentOS 8 已用 nftables 后端，同时维护两套是负担）

#### `tarpit.py`
- **职责**：拖滞计划计算 + 三重护栏（单会话预算 / 全局滚动窗口 / 负载熔断）。
- **公开接口**：`Tarpit.plan(profile, verdict, action, reply) -> TarpitPlan | None`、`Tarpit.adaptive_delay(profile)`、`TarpitPlan.total_seconds()`、`TarpitBudget.reserve(sid, seconds)` / `.shed()` / `.stats()`
- **依赖**：无
- **刻意不做**：不执行延迟（计划与执行分离：`tarpit` 只算，`server`/`ssh_decoy` 负责 await，因此拖滞逻辑可在无 IO 环境下测试）

#### `report.py`
- **职责**：把遥测整理成可提交的取证材料；确证与推断分离；证据摘要哈希。
- **公开接口**：`build_session_report(store, session_id)`、`build_campaign_report(store, campaign_id)`、`render_markdown(report)`、`render_abuse_email(report)`、`export_json/csv/iocs()`、`write_report_bundle(config, store, report)`、`evidence_digest(requests, events)`
- **依赖**：无（接收 `store` 作为参数而非导入，便于测试与替换）
- **刻意不做**：不判断可信度（那是 `fingerprint`）；不脱敏真实资产（架构上前提是蜜罐内不存在真实资产，因此无脱敏需求）

#### `dashboard.py`
- **职责**：值守界面（仅回环监听）；JSON 接口 + 静态资源服务。
- **公开接口**：`Dashboard(config, store, server)`（`start()` / `close()` 为协程）、`payload_summary()` / `payload_sessions()` / `payload_signals()` / `payload_evidence()` / `payload_campaigns()` / `payload_alerts()`
- **依赖**：无（`server`/`store` 由构造注入，可为 None —— 此时接口仍返回完整键集的零值）
- **刻意不做**：不做认证（绑定回环即边界）；不做前端构建（零构建步骤，静态资源直接服务）

#### `dom_decoys.py`
- **职责**：DOM 级交互诱饵 —— 在页面注入可点击按钮/表单/面包屑/ARIA 导航，让 browser-use / computer-use 型智能体"有事可做"（静态页面会让它们快速离开）。每个交互产生行为信号。
- **公开接口**：`inject_interactive_decoys(html, ctx, score)`、`is_interactive_probe(path)`、`interactive_probe_signal(path)`、`DECOY_ACTIONS`
- **依赖**：无
- **刻意不做**：不做 JS 逻辑执行（交互由服务端路由处理，客户端只产生请求）；不伪装成 SPA（保持静态+表单的朴素外观更像遗留系统）

#### `proto_decoys.py`
- **职责**：多协议处理器注册表 —— 每个协议一个 `@protocol(port, name)` 装饰的 asyncio 协程，做"逼真问候 → 捕获一切 → 合理断开"。
- **公开接口**：`PROTOCOLS`（注册表字典）、`protocol(port, name, banner)`（装饰器）
- **依赖**：无独立依赖（handler 内部使用 asyncio）
- **刻意不做**：不实现完整协议栈；不做协议级反制

#### `proto_server.py`
- **职责**：把 proto_decoys 的处理器变成可运行的 asyncio 服务，共享遥测存储与信号引擎。
- **公开接口**：`MultiProtocolDecoy(config, store)`（`start()` / `close()` 协程、`runtime_stats()`）
- **依赖**：`fingerprint` `inject` `tarpit`（信号引擎共用）
- **捕获目标**：FTP/Telnet 凭据、MySQL 认证哈希、Redis 命令（含 RCE 探测）、ES 查询、SMTP 邮件

#### `proto_counter.py`
- **职责**：协议层反制 —— 让每个协议的文本响应(错误消息/JSON 字段/KEYS 列表)携带 NL 载荷与令牌。跨协议分数共享(同 IP 被 HTTP/SSH 标记后协议层反制拉满)。Redis 深度反制(假未授权+假 KEYS+假 CONFIG dir)。
- **公开接口**：`ftp_response(ctx, score, base)` / `telnet_response(...)` / `redis_error(...)` / `mysql_error(...)` / `es_enhanced(ctx, score)` / `redis_fake_data(...)` / `lookup_ip_score(store, ip)`
- **依赖**：`inject`(载荷渲染)
- **刻意不做**：不做协议级指令执行(只影响对方读到的文本)

#### `alerts.py`
- **职责**：统一告警出口 —— 本地文件(兼容旧格式, dashboard 依赖) + 可选 webhook 异步外发；后台线程 + 有界队列，告警故障绝不影响蜜罐主路径。
- **公开接口**：`Alerter(config)`（`.emit(line, severity)` / `.close()` / `.stats()`）、`get_alerter(config)`（进程单例）、`reset_for_tests()`
- **依赖**：无
- **刻意不做**：不做重试队列/签名（需要时接可选依赖，接口不变）；不做多协议（webhook POST JSON 足够对接主流机器人网关）

#### `hub.py`
- **职责**：多节点聚合 —— 中心节点接收各实例增量遥测并合并；实例侧 `push_bundle()` 水位线推送。战役按 `behavior_hash` 合并，跨实例归因"免费"获得。
- **公开接口**：`Hub(config, store, token)`（`start()` / `close()` 协程、`.ingest(bundle)`、`.summary()`、`.campaigns_payload()`）、`push_bundle(config, hub_url, token, ...)`
- **依赖**：无（store 经参数注入）
- **刻意不做**：不暴露公网（内网设施；出站白名单由 isolate.sh 为 hub 单独放行，不违反"蜜罐不外连"）；不做双向同步（单向推送 + 幂等导入足够）

### L1 — 领域层

#### `inject.py`
- **职责**：反制载荷的**投递机制**（往哪些面发、金丝雀如何签发、服从如何校验）；语料由 `countermeasures` 提供。
- **公开接口**：`CanaryManager`（`issue()` / `scan(haystack)` / `stats()`）、`PayloadContext`（`.render(template)`）、`configure(config)` / `apply_profile(include, exclude, max_tier)`、`select_for_tier(score, ...)`、投递面渲染器（`render_llms_txt` / `render_robots_txt` / `render_security_txt` / `render_html_comment` / `render_response_headers` / `render_json_meta` / `render_error_page` / `render_fake_env`）、确证闭环（`build_expectations()` / `check_expectations()`）、`PAYLOADS`（兼容视图）
- **依赖**：`countermeasures`(L0)
- **刻意不做**：不定义语料（语料在 `countermeasures`，两者拆开是为了让反制方式能独立增长）；不判定分数（接收分数作为参数）

#### `templating.py`
- **职责**：模板 schema 校验、变量渲染、实例化；渲染确定性保证。
- **公开接口**：`Template`（`.routes` / `.vulnerabilities` / `.credentials` / `.route_table()` / `.stats()`）、`HoneypotInstance`（`.render(text, extra)` / `.page(route)` / `.runtime_vars(request)` / `.summary()`）、`validate(data, source)` / `lint(data, source)` / `scaffold(id)` / `list_templates()` / `load_template(id)`、`check_variables()` / `check_placeholder_syntax()`
- **依赖**：`http_parse`(L0)
- **刻意不做**：不生成响应（那是 `deception`）；不做品牌内容撰写（内容属于模板 JSON）

### L2 — 协议与适配层

#### `respond.py`
- **职责**：分数 → 处置档；期望清单校验（指令服从确证）。
- **公开接口**：`decide(verdict, profile, config) -> Decision`、`resolved_thresholds(config)`、`action_for_score(score, thresholds)`、`apply_expectations(request, session, store)`
- **依赖**：`fingerprint`(L0), `inject`(L1)
- **刻意不做**：不做拖滞（`tarpit`）；不做响应内容（`deception`）

#### `deception.py`
- **职责**：路由与内容生成；模板优先、内置回落；凭据蜜标；基础设施面不可遮蔽。
- **公开接口**：`Deception(config, canary, store, instance)`、`.handle(req, session) -> Reply`、`.handle_from_template()`、`.serve_static()`、`Reply`
- **依赖**：`inject`(L1)
- **刻意不做**：不做判定与处置；不自行生成载荷（走 `inject`）

#### `server.py`
- **职责**：asyncio 原始 TCP/HTTP 服务；客户端会话管理（跨连接）；拖滞执行；遥测落库；战役归因。
- **公开接口**：`HoneypotServer(config, store, verbose, instance)`（`start()` / `close()` 协程）、`.runtime_stats()`、`Session`（`.add_expectations()`）
- **依赖**：`block` / `deception` / `fingerprint` / `http_parse` / `inject` / `respond` / `tarpit`
- **刻意不做**：**不依赖 `cli`**（R4）；不做判定与内容（委托给对应层）；不自己解析 HTTP（走 `http_parse`）

#### `ssh_decoy.py`
- **职责**：SSH 协议诱饵 —— banner 交换、未加密 KEXINIT 解析（算法指纹）、客户端识别、拖滞、复用共享判定引擎。
- **公开接口**：`SSHDecoy(config, store, verbose)`（`start()` / `close()` 协程）、`.runtime_stats()`
- **依赖**：`fingerprint` / `http_parse` / `inject` / `respond` / `tarpit`
- **刻意不做**：不做完整 SSH 交互（无密码学库，零依赖约束下不可行）；不采集用户名口令（在 KEX 之后，拿不到）

### L3 — 编排层

#### `cli.py`
- **职责**：**唯一的编排点**；8 个子命令；把配置、场景、模板、服务、仪表盘、SSH 诱饵串起来。
- **公开接口**：`main(argv)`、`build_parser()`、各 `cmd_*`
- **依赖**：全部下层（引入方式：多数用 `__import__()` 惰性导入，使缺少某个可选模块时其余命令仍可用）
- **刻意不做**：不实现业务逻辑（只做参数解析、装配、输出）

---

## 4. 依赖规则与强制方式

### 4.1 分层表

| 层 | 模块 | 允许依赖 |
|---|---|---|
| **L0 基础** | `config` `http_parse` `store` `fingerprint` `countermeasures` `scenarios` `block` `tarpit` `report` `dashboard` `alerts` `hub` `dom_decoys` | **无内部模块** |
| **L1 领域** | `templating` `inject` | L0 |
| **L2 协议与适配** | `respond` `deception` `ssh_decoy` `server` `proto_decoys` `proto_server` `proto_counter` | L0、L1、同层 |
| **L3 编排** | `cli` | 全部 |

### 4.2 四条规则

- **R1 无循环依赖**
- **R2 依赖只能指向不高于自己的层**
- **R3 L0 不依赖任何内部模块**
- **R4 `server` 不得依赖 `cli`**（编排职责只在 cli 一处）

### 4.3 一个容易被忽略的点：惰性导入也要纳入检查

代码里有 `__import__("server")` 这类惰性导入（为了在缺少可选模块时优雅降级）。它们是 `Call` 节点而不是 `Import` 节点，**只扫 Import 的静态分析看不见** —— 而 `server → cli` 的双向耦合正是这样被藏住的。

因此架构检查同时识别 `import x`、`from x import y`、`__import__("x")`、`importlib.import_module("x")` 四种形式。

### 4.4 强制方式

`tests/test_architecture.py` 每次测试都重新解析全部源码构建依赖图并校验 R1–R4；同时校验**本文件列出的模块清单与实际文件一致**、**本文件列出的公开接口确实存在**。文档与代码不一致即测试失败。

---

## 5. 数据架构

### 5.1 存储选型

SQLite + WAL。理由：单文件、零运维、随蜜罐实例目录共存（`var/telemetry.db`）、并发读满足"单写 + 仪表盘读"的模式。写入量远低于需要更强后端的量级（实测一次完整攻击 33 请求 / 91 条确证证据）。

### 5.2 七张表

| 表 | 职责 | 关键字段 |
|---|---|---|
| `sessions` | 会话（跨连接聚合的客户端） | `ip` `ua_hash` `header_sig` `behavior_hash` `label` `score` `action` `tarpit_ms` `campaign_id` `tokens_json` |
| `requests` | 请求级证据 | `target` `status` `delay_ms` `action` `score` `signals_json` `headers_json` `body_text` |
| `signals` | 判定信号 | `name` `weight` `kind` `evidence` |
| `campaigns` | 战役（按行为指纹聚合的多源） | `behavior_hash` `ips_json` `toolchain` `model_guess` `score_max` |
| `honeytokens` | 蜜标登记与读取 | `token` `kind` `path` `first_read_ts` `read_count` `sessions_json` |
| `events` | 确证事件与告警 | `kind` `severity` `detail` |
| `blocks` | 处置记录 | `ip` `reason` `mode` `rule` `applied` `expires` |

### 5.3 三条数据设计决策

**D1 · 请求原文必须留存。** 上报需要证据，而证据需要原文（截断至安全长度）。因此 `requests.headers_json` 与 `body_text` 保存而非只存摘要。

**D2 · 信号独立成表。** 便于统计"哪类特征最有区分度"，这是持续调参的依据；也让场景的权重覆盖效果可回溯。

**D3 · 蜜标读取时自动登记。** 登记与读取发生在不同代码路径上；若读取时因未登记而静默返回，**最高价值的取证事件会凭空消失**。已加此兜底并有测试。

### 5.4 数据保留

`store.prune(retention_days)` 按保留期清理请求/信号/事件/过期会话/过期阻断。默认 180 天（`config.json` 可调）。蜜标与战役不随请求清理，因为它们是长期情报。

### 5.5 证据完整性

`report.evidence_digest()` 对请求序列与关键事件计算 SHA-256，写入上报材料。材料被改动即可被发现 —— 取证材料若无法证明未被篡改，分量会大打折扣。

---

## 6. 部署架构

### 6.1 拓扑

```
                    互联网
                      │
              ┌───────▼────────┐
              │  边界防护/引流  │  ← 把可疑流量导向诱饵网段
              └───────┬────────┘
                      │
        ┌─────────────┴──────────────┐
        │                            │
   ┌────▼─────┐              ┌───────▼────────────────────┐
   │ 真实资产  │              │  诱饵网段 (独立 VLAN)        │
   │  (生产)   │              │  ┌──────────────────────┐  │
   └──────────┘              │  │ CogTrap 实例          │  │
        ▲                    │  │  :8080 HTTP 蜜罐      │  │
        │ 无双向路由          │  │  :2222 SSH 诱饵       │  │
        │ 单向日志外发        │  │  :8899 仪表盘(回环)   │  │
        └────────────────────┼──┤                      │  │
                             │  └──────────┬───────────┘  │
                             │  出站 DROP  │              │
                             └─────────────┘              │
                                                   ← isolate.sh
```

### 6.2 三个监听面

| 面 | 默认 | 职责 |
|---|---|---|
| HTTP 蜜罐 | `0.0.0.0:8080` | 欺骗面 + 载荷投递 + 拖滞 + 遥测 |
| SSH 诱饵 | `0.0.0.0:2222` | banner/KEXINIT 指纹采集 + 拖滞 + 同一遥测 |
| 仪表盘 | `127.0.0.1:8899` | 值守界面（**仅回环**，远程查看走 SSH 隧道） |

### 6.3 隔离要求（硬性）

| 要求 | 实现 |
|---|---|
| 出站默认 DROP | `deploy/isolate.sh --apply`（含回滚与自检） |
| 与真实资产无双向路由 | 部署方保证（脚本在 `--check` 中逐条提示人工确认） |
| 日志单向外发 | 部署方保证（脚本提示，因被攻破后证据仍需完整） |
| 独立凭据域 | 蜜罐内不存在真实凭据；脚本检查常见凭据文件残留 |
| 资源上限 | `limits.*`：最大连接、单 IP 连接、单请求大小、拖滞预算 |
| 权限最小化 | 无需 root 运行蜜罐本体；仅 `block.apply` 需 root |

### 6.4 进程模型

**单进程 asyncio**，非多进程。理由：I/O 密集（等超时、慢响应）而非计算密集；单进程让会话状态、跨源索引、拖滞预算都在内存中共用，避免跨进程一致性开销。48 核机器上单进程足以处理蜜罐量级的并发；如需横向扩展，正确做法是增加诱饵实例（各自的遥测由归因层汇总），而不是把单实例多进程化。

---

## 7. 扩展架构

### 7.1 四个扩展点与稳定性等级

| 扩展点 | 载体 | 稳定性 | 破坏性变更政策 |
|---|---|---|---|
| **蜜罐模板** | `honeypot/templates/*.json` + `templates/custom/` | **稳定** | `schema` 字段版本化；新增字段可选；不改变已有字段语义 |
| **场景包** | `honeypot/scenarios/*.json` + `scenarios/custom/` | **稳定** | 同上 |
| **反制方式** | `payloads/custom/*.json` | **稳定** | `schema` 版本化；占位符白名单只增不减 |
| **配置** | `config.json` | **稳定** | 键只增不删；语义不变 |
| Python 模块接口 | `honeypot/*.py` | 演进中 | 无兼容承诺，但骨架（§3 的公开接口）尽量稳定 |
| SQLite schema | `var/telemetry.db` | 内部 | 无跨版本兼容承诺；变更提供导出迁移路径 |

**为什么把数据格式定为稳定、Python 接口定为演进中**：使用者（蓝队）真正会长期自己维护的是模板、场景、反制方式语料 —— 那是他们环境的私有资产。Python 接口是维护者的事，过度承诺反而会阻碍重构。

### 7.2 扩展点的契约

**模板**（`templating.validate` 强制）
- **严格必填：`id`（小写字母数字点连字符，2–64）/ `name`** —— 其余字段均有默认值
  （`schema`=1、`category`=`generic`、`payload_profile`=`balanced`、`tarpit_profile`=`standard`）。
  这是刻意的：让最简单的模板只需两个字段即可通过校验，降低使用者的起步成本；
  但**显式声明**这些字段更清晰，且仅当字段存在时才校验其取值合法性。
- 若声明则必须合法：`category` / `payload_profile` / `tarpit_profile` 属枚举；`schema` 必须为 1
- `routes[]`：`path` 必须以 `/` 开头；同 `(path, method)` 不可重复；`status` 100–599；`kind` 属枚举
- **正文中所有 `{{变量}}` 必须在 `variables` 定义或属内置/运行时/派生变量**
- **不得出现语法不合法的占位符**（`{{中文名}}`、`{{a-b}}`）—— 它们不会被替换而会静默留在页面上

**场景**（`scenarios.validate` 强制）
- **严格必填：`id` / `template`**；`schema` 默认 1
- `detection.thresholds` 四个阈值**必须严格递增**（否则某档动作永不触发）
- `countermeasures.max_tier` ∈ {0,1,2,3}；`include`/`exclude` 为字符串数组
- `blocking.mode` ∈ {absorb, drop}

**反制方式**（`countermeasures.validate_countermeasure` 强制）
- **严格必填：`id` / `category` / 至少一个 `text_zh` 或 `text_en`**
- 若声明则必须合法：`tier` ∈ {1,2,3}（默认 2）；`stealth` ∈ [0,1]（默认 0.5）
- **占位符必须在 `KNOWN_PLACEHOLDERS` 白名单内**（写错会渲染出字面的 `{canry}`，是明显破绽）

### 7.3 稳定契约的兼容性如何强制

文档写了"键只增不删"，但**声称了政策却不强制，比不声称更糟** —— 使用者会以为自己的模板不会被破坏。因此 `tests/test_architecture.py::test_stable_contracts_are_additive_only` 记录了三个数据契约的**基线快照**：

| 快照项 | 推导方式 |
|---|---|
| 必填字段集 | **经验推导**：拿一份合法文档逐个删除字段，校验失败即该字段必填（不是抄自文档，而是实测） |
| 枚举取值集 | 从模块常量读取（`CATEGORIES` / `ROUTE_KINDS` / `PAYLOAD_PROFILES` / `TARPIT_PROFILES` / 反制类别） |
| 占位符白名单 | `countermeasures.KNOWN_PLACEHOLDERS` |
| 配置顶层键 | `Config.load().as_dict()` 的键 |

**两类契约的兼容性规则不同，这点容易搞错：**

| 契约面 | 规则 | 为什么 |
|---|---|---|
| 枚举取值 / 占位符白名单 / 配置键 | **超集即可** | 新增一个分类、一个占位符、一个配置段都是向后兼容的；只有删除或重命名会破坏使用者资产 |
| **必填字段集** | **必须严格相等** | 除了删除，**新增必填字段同样是破坏性的** —— 使用者现有文档里没有这个字段，会突然校验失败 |

第二条是负向验证发现的：规则最初写成"超集即可"，于是把 `category` 从"有默认值"改成"必填"也没被拦住，而那会让所有未显式声明 `category` 的模板失效。**这个漏洞是靠故意注入违规才暴露的，靠读代码看不出来。**

确实需要变更时，正确做法是：先在本文档记录迁移路径，再**显式更新基线快照**并说明原因 —— 让破坏性变更成为一个被评审的动作，而不是一次疏忽。

### 7.4 用户生成蜜罐的完整闭环

```
cogtrap template new <id>              # 生成带 _help 说明的骨架（JSON 无注释，说明放在 _help 字段）
cogtrap template validate <file>       # 字段类型 / 路由冲突 / 枚举 / 未定义变量 / 非法占位符
cogtrap template lint <file>           # 可疑之处（缺蜜标、真实域名、aggressive 档案等）
cogtrap template render <id> --llms    # 预览渲染结果与载荷投递面
cogtrap generate --template <id> --scenario <id> --set k=v -o <dir>
                                       # 产出：config.json / instance.json / scenario.json
                                       #       start.sh / README.md / 运行目录
cd <dir> && ./start.sh
```

`generate` 的三条硬性保证：
1. **实例自包含** —— 相对路径以**配置文件所在目录**为基准，因此遥测库、日志、规则都落在实例目录内，不写回源码树
2. **防火墙默认关闭** —— 生成的 `config.json` 强制 `block.armed=false` 且 `apply=false`
3. **覆盖项即时校验** —— 覆盖后重新校验，把模板改坏会立刻报出字段路径

---

## 8. 安全架构（系统自身的安全）

蜜罐的宿命是被攻破，因此架构必须假设这一点。

| 威胁 | 缓解 |
|---|---|
| 蜜罐被用作跳板 | 出站 DROP（`isolate.sh`）；代码层无客户端 socket |
| 蜜罐被用作 C2/扫描源 | 同上 |
| 通过第三方依赖植入 | 零依赖（C1）+ CI 强制 |
| 拖滞反噬（自己的资源被耗光） | 三重护栏：单会话预算 / 全局滚动窗口 / 负载熔断 |
| 连接耗尽 | `max_connections` + `max_per_ip`，超限直接拒绝并留事件 |
| 防火墙规则写错锁死自己 | 默认不落地 + `nft -c` 语法干跑 + 白名单 + TTL 自动过期 |
| 仪表盘泄露遥测（含攻击者 IP 与捕获凭据） | 默认仅回环；文档给出 SSH 隧道方式 |
| 点击劫持 / 内容嗅探 | `X-Content-Type-Options: nosniff`、`Cache-Control: no-store` |
| 静态文件路径穿越 | `os.path.normpath` + 前缀校验（有测试） |
| **值守界面被攻击者的数据 XSS** | 前端**只用 `textContent`**，禁用 `innerHTML`（遥测含攻击者可控的 UA/路径/载荷；用 `innerHTML` 等于把攻击者请进我们自己的控制台）。有测试断言 |
| 证据被篡改 | 上报材料附 SHA-256 证据摘要 |

---

## 9. 非功能特性（含实测数字）

### 9.1 性能与容量（默认配置）

| 项 | 值 | 说明 |
|---|---|---|
| 最大连接数 | 2048 | `limits.max_connections` |
| 单 IP 连接上限 | 24 | 超限拒绝并记录 |
| 单请求头上限 | 64 KiB | 超限按畸形处理 |
| 单请求体上限 | 1 MiB | 超限截断并标记 |
| 单会话拖滞上限 | 300 秒 | 防止把资源耗在自己身上 |
| 全局拖滞预算 | 900 秒/分钟 | 滚动窗口 |
| 负载熔断阈值 | 0.92 × CPU 核数 | 超阈值降级为即时响应 |
| 会话空闲回收 | 1800 秒 | 跨连接会话的 TTL |
| 遥测保留 | 180 天 | 可配 |

### 9.2 代码规模（快照：2026-09-18）

| 部分 | 规模 |
|---|---|
| `honeypot/` 模块 | 18 个 |
| 测试模块 | 6 个 |
| 蜜罐模板 | 8 个行业模板 |
| 场景包 | 5 个预设 |
| 反制方式 | 22 条 × 9 类别 |

规模只是背景信息，不作为架构约束 —— 因此它不进测试。

### 9.3 实测性能（本机 48 核 / 92 GB，单进程）

- 无拖滞时单请求响应 **≈1.3 ms**（loopback，curl 实测）
- 拖滞生效时的响应时间序列：`0.001s → 0.86s → 2.07s → 16.6s → 38.6s`，随后因单会话预算耗尽而停止（护栏工作正常）
- 一次完整模拟攻击（33 请求）产生 91 条确证证据、84 KB 级遥测
- 负载比在正常运行时为 `0.003`（远低于熔断阈值）

### 9.4 失效模式（诚实列出）

| 失效 | 表现 | 架构上的应对 |
|---|---|---|
| 全局拖滞预算饱和 | 所有会话停止拖滞 | 这是**设计行为**（保护自身）；`shed_events` 计数可在仪表盘观察 |
| 攻击者识破蜜罐 | 停止交互或换目标 | 分层投放 + 隐蔽度分级（延迟暴露）；但**无法完全避免**，属已知局限 |
| 攻击者伪造官方扫描器 UA | 被反向信号压低分数 | 反向信号同时要求头部集合与静态资源行为，伪造成本高 |
| 短会话样本不足 | 节律与清单顺序特征不触发 | 明确记录为信号未命中；确证类证据（金丝雀/服从）不受样本量影响 |
| 通用 SSH 客户端 | 仅能指纹，无法采集凭据 | 零依赖的必然代价；凭据采集由 HTTP 侧蜜标承担 |

---

## 10. 技术决策记录（ADR）

每条记录**决策 / 理由 / 被否决的替代方案**。被否决的选项同样重要 —— 它们解释了为什么不是别的样子。

| # | 决策 | 理由 | 被否决的替代 |
|---|---|---|---|
| ADR-1 | 全标准库实现 | 蜜罐会被攻破；第三方依赖即供应链攻击面 | FastAPI/uvicorn（性能与生态更好，但引入依赖树） |
| ADR-2 | 自写容错 HTTP 解析器 | 框架会把畸形请求 400 掉，而畸形请求是最有价值的指纹 | http.server / aiohttp（会丢证据） |
| ADR-3 | 单进程 asyncio | I/O 密集；会话状态、跨源索引、拖滞预算需内存共享 | 多进程（跨进程一致性开销）；多线程（GIL + 状态锁复杂度） |
| ADR-4 | SQLite + WAL | 零运维、单文件随实例共存、写量远低于瓶颈 | PostgreSQL（运维负担）；JSONL（查询能力不足）；内存（重启丢失证据） |
| ADR-5 | 会话按 (源 IP, UA 哈希) 跨连接存活 | LLM 智能体每次工具调用新建连接是常态；绑连接会让行为节律分析永远失效 | 按连接（简单，但行为分析形同虚设 —— 已实测踩过） |
| ADR-6 | 判定逻辑只有一份，SSH 复用 | 两套阈值必然矛盾；SSH 算法指纹填入 `header_sig` 槽位即可复用跨源归因 | 为 SSH 另写判定器（重复且易冲突） |
| ADR-7 | 模板/场景/反制方式定义为稳定契约，Python 接口为演进中 | 使用者的私有资产是数据，不是代码 | 全部冻结（阻碍重构）；全部浮动（使用者资产随时被破坏） |
| ADR-8 | 防火墙默认不落地 | 写错规则会把自己锁在门外；规则需人工审核 | 自动落地（危险）；完全不生成（丧失处置能力） |
| ADR-9 | 载荷按分数分层投放 + 按会话轮换 | 一次性全投既不可信又浪费；纯权重排序只用到少数几条并留下稳定特征 | 固定全量投放（不可信）；纯随机（放弃有效性梯度） |
| ADR-10 | 仪表盘零构建步骤、零外部资源 | 诱饵环境常在隔离网络，页面必须能离线打开 | React/Vue（观感上限更高，但引入构建链与离线风险） |
| ADR-11 | 拖滞计划与执行分离 | 计划可在无 IO 环境下单元测试 | 合在一起（拖滞逻辑无法测试，且会反噬自身） |
| ADR-12 | 反制只做被动接收 | 攻击源常为第三方；主动外连暴露蓝队节点且违法 | 主动反制（法律风险 + 暴露自己 + 毁掉证据链） |

---

## 11. 已知架构债与演进路线

### 11.1 架构债（如实列出）

| 债 | 影响 | 计划 |
|---|---|---|
| `store` 写入是同步的，在事件循环内执行 | 高并发下会阻塞事件循环 | 当前写入量下无实测影响；若出现写延迟，改为写队列 + 后台 flush |
| `cli.py` 1365 行，子命令实现与输出格式混在一起 | 贡献者需读较长文件 | 按子命令拆分为 `cli/` 包（纯结构调整，无行为变化） |
| `deception.py` 895 行，内置路由表庞大 | 同上 | 把内置面进一步外化为"默认模板"，让代码只剩路由与渲染 |
| `server` 与 `ssh_decoy` 的会话获取逻辑有两份相似实现 | 修改需同时改两处 | 抽出共享的 `ClientRegistry`（须保持两边的信号语义差异可见） |
| 无 TLS/JA3 指纹 | 无法利用 TLS 层指纹（对智能体工具链识别是有效补充） | 零依赖下需自实现 TLS 解析，成本高；暂列为规划中 |
| 反制方式的效果无度量闭环 | 无法知道哪条载荷真的被服从 | 事件表已有 `injection_compliance` 计数，可据此做载荷有效性排行 |

### 11.2 演进路线（按依赖顺序）

| 阶段 | 内容 | 前置 |
|---|---|---|
| M9 | 载荷有效性度量（用确证事件的命中率反过来调权重） | 已有事件数据 |
| M10 | 多协议诱饵（MySQL / Redis / Elasticsearch） | 复用 `ssh_decoy` 的"半程握手 + 指纹"模式 |
| M11 | 归因汇总层（多实例遥测汇合，跨实例战役关联） | 需先定义实例间数据格式 |
| M12 | 情报导出（STIX 2.1 子集 / MISP 格式） | 已有 `report.export_iocs` 基础 |
| M13 | 反蜜罐识别对抗（针对"先用另一个模型判定这是不是蜜罐"的对手） | 需先有欺骗可信度度量的方法 |

**刻意不排期的**：主动反制能力（ADR-12）、需要第三方依赖的能力（ADR-1）。

---

## 12. 架构如何保持不变形

文档会腐化，除非有东西**强制**它对。本项目用三层保证：

1. **架构测试**（`tests/test_architecture.py`）—— 每次测试重新解析全部源码，校验 R1–R4 四条依赖规则，并校验本文件列出的模块清单与公开接口确实存在。文档漂移即测试失败。
2. **契约测试**（`tests/test_templating.py` / `test_countermeasures.py` / `test_scenarios.py`）—— 扩展点的校验规则有测试覆盖，因此"改坏契约"会立刻被发现。
3. **视觉验收流程**（`tools/render_dashboard.sh` + `CONTRIBUTING.md` 第 8 节）—— 界面改动的验证方法被固化成可复现步骤，而不是依赖个人记忆。

**不做的事**：不追求"架构图与代码自动同步生成"。图是给人看的，测试是给机器看的；用测试守住**结构与契约**这两件真正重要的事，图的手工维护成本就是可接受的。

---

*本文件为 AS-BUILT 架构规范。任何结构性变更（新增模块、改变依赖方向、变更扩展点契约）都必须同步更新本文件与 `tests/test_architecture.py`，否则 CI 会失败。*
