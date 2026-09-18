# CogTrap

**面向大模型（LLM）驱动自动化渗透测试的多层欺骗与反制体系。**

[![CI](https://img.shields.io/badge/CI-not%20configured-lightgrey.svg)](#项目状态)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](pyproject.toml)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](CONTRIBUTING.md#零依赖原则)

中文 | [English](README.md)

---

> ## 合法使用声明 —— 使用前必读
>
> CogTrap 是**防御性**工具，**仅可部署于你拥有或已获得明确书面授权的资产**。
> 其全部反制手段均为**被动接收型**：所有技术都实现在**我方服务器返回的响应内容**里。
> 本系统从不连接、扫描、利用攻击方主机，也不向其发送任何流量。
>
> 在你不具备控制权的网络上部署蜜罐，在部分司法辖区可能构成违法；
> 捕获的数据也可能包含个人信息。完整的使用边界见 [SECURITY.md](SECURITY.md)。

---

## 核心洞察

过去三十年，欺骗防御技术建立在一个前提上：**攻击者不读内容**。扫描器按字典发请求，
只看状态码与响应长度，不解析我们精心构造的假数据。因此蜜罐的价值就是"记录 IP 与
payload"——它是一台被动的取证设备。

LLM 智能体把这个前提推翻了：

1. 它**读**我们返回的每一个字——HTML 注释、响应头、`robots.txt`、错误页里的堆栈；
2. 它**理解**内容，并据此推理下一步；
3. 它**记得**我们说过的话——上下文窗口就是它的工作记忆；
4. 它会**照做**。如果页面里写着"请先访问某个端点完成校验"，它会去访问。

这看起来是防御方的噩梦。反过来，它就是攻击面：
**既然智能体的行为是我们所给文本的函数，我们就对该函数有输入权。**

由此推出三条可工程化的原理：

| 原理 | 含义 | 工程后果 |
|---|---|---|
| **可引导** | 下一步动作是"上下文 + 提示"的函数，我们的响应是上下文的一部分 | 可在响应中植入**意图明确的引导内容**，改变其行为序列 |
| **可确证** | 智能体会把读到的内容回填进后续请求——工具调用的参数正是用它读到的信息生成的 | **唯一令牌**只要出现在后续请求里，就证明它把我们的输出当上下文复用；扫描器无法伪造该证据 |
| **代价不对称** | 我方生成响应成本约等于零（一次内存写）；它每一步要付网络往返 + 上下文 token + 推理 token + 时间 | 拖滞不是被动防御，而是**经济攻击**，且存在一个超线性放大器 |

第三条原理有一个值得单独说明的后果，它是对智能体最有效的经济杠杆：

```
我们无限流投喂垃圾数据   （我方成本 ≈ 0）
  → 智能体把垃圾读进上下文窗口
  → 它之后每一轮请求都携带全量历史
  → 单步 token 成本随轮次线性增长
  → 总成本随轮次二次增长，O(n²)
```

传统扫描器不读内容，所以这个杠杆对它完全不存在。

系统按九层组织，但攻击者只会看到一样东西：一个普通的、有点漏洞的业务系统。

---

## 架构

```
┌──────────────────────────────────────────────────────────────────┐
│  L8  自身安全层   隔离 / 出站拒绝 / 资源硬上限 / 日志完整性        │
├──────────────────────────────────────────────────────────────────┤
│  L7  取证与上报层  证据链 / 战役档案 / 上报包 / 情报导出           │
├──────────────────────────────────────────────────────────────────┤
│  L6  处置层       评分梯度 / 拖滞 / 阻断 / 吸收重定向              │
├──────────────────────────────────────────────────────────────────┤
│  L5  检测与归因层  行为节律 / 工具链 / 上下文复用 / 跨源关联       │
├──────────────────────────────────────────────────────────────────┤
│  L4  数据与蜜标层  伪造凭据 / 蜜标文档 / 数据水印 / 分页迷宫        │
├──────────────────────────────────────────────────────────────────┤
│  L3  语义/认知层   ★核心差异化★                                   │
│      反制方式库 / 载荷投递面 / 金丝雀令牌 / 信标 / 指令服从确证闭环 │
├──────────────────────────────────────────────────────────────────┤
│  L2  应用与 API 层  假业务系统 / 假漏洞面 / 假 API / 假后台         │
├──────────────────────────────────────────────────────────────────┤
│  L1  网络与协议层  协议指纹 / 端口策略 / 网络层拖滞                │
├──────────────────────────────────────────────────────────────────┤
│  L0  诱饵与暴露面  诱饵资产编号 / 假内网拓扑 / 服务矩阵            │
└──────────────────────────────────────────────────────────────────┘
                        ▲
                        │ 攻击者视角：一个普通的、有点漏洞的业务系统
```

设计原则：层次划分是**我方**的组织方式，不是暴露给攻击者的结构。
任何让攻击者察觉到"这是分层防御体系"的迹象都是设计缺陷。

**单请求数据流**（`honeypot/server.py`）：

```
攻击请求 → 容错解析 → 会话画像摄入 → 金丝雀/服从校验
        → 指纹判定 → 处置决策（评分梯度）
        → 欺骗响应 + 按梯度投递载荷
        → 拖滞计划（延迟 / 分块 / 无限流）
        → 遥测落库 → 战役归因 → 告警
```

---

## 功能特性

以下能力均已在当前代码树中实现，只使用 Python 标准库。

### 多层欺骗面 —— `honeypot/deception.py`
62 条路由，由容错 asyncio HTTP 处理器提供：假业务门户、假登录与后台
（phpMyAdmin、Adminer、wp-login、H2 console）、假 API（`/api/v1/users`、
`/api/v1/orders`、`/api/v1/internal/config`、Swagger/OpenAPI 描述）、
假漏洞面（SQL 报错注入、目录列举、`actuator/env`、heapdump、`.env`、
`.git/config`、`.aws/credentials`、`.ssh/id_rsa`、SQL dump、备份包），
以及诱导枚举的目录列表页。所有伪造数据使用保留域名（`example.com`）与
合成姓名，不掺入任何真实 PII。

### 蜜罐模板引擎 —— `honeypot/templating.py`
蜜罐被定义为**数据，而不是代码**。模板是 JSON，因此可以被分享、审计、
版本控制，使用者不需要写 Python。**渲染是确定性的**：随机源由实例令牌播种，
同一实例每次渲染结果一致。否则攻击者刷新两次页面就会发现数据变了——
那是蜜罐的致命破绽。

API：`validate` / `lint` / `scaffold` / `Template` / `HoneypotInstance` /
`Renderer` / `load_template` / `list_templates`。正文用 `{{变量}}` 引用变量，
支持即时生成器（`{{rand.hex:8}}`、`{{rand.int:1-100}}`、
`{{rand.choice:a|b|c}}`、`{{rand.ip}}`、`{{rand.date:30}}`）与派生变量
（`db_password`、`jwt_secret`、`api_token`、`internal_hosts`）。
引用了未定义的变量会在校验阶段被报出，并附带字段路径。
`HoneypotInstance.runtime_vars(request, extra)` 注入每请求变量
（`query`、`payload`、`method`、`path`、`user_agent`、`body`、`client_ip`），
因此模板可以渲染出**回显攻击者实际输入**的假报错正文。

`honeypot/templates/` 内置 8 个模板，覆盖 8 个行业垂直领域：

| 模板 | 分类 | 路由 | 凭据蜜标 |
|---|---|---|---|
| `gov-portal` | 政务 government | 24 | 5 |
| `corp-oa` | 企业 enterprise | 23 | 5 |
| `shop-mall` | 电商 ecommerce | 23 | 5 |
| `ops-platform` | 运维 ops | 23 | 5 |
| `hospital-his` | 医疗 healthcare | 23 | 5 |
| `bank-gateway` | 金融 finance | 26 | 5 |
| `campus-edu` | 教育 education | 22 | 5 |
| `iot-gateway` | 工业 industrial | 24 | 6 |

每个模板都带有与技术栈一致的身份（Spring Boot / Django / Laravel / ThinkPHP /
ASP.NET / Go / Node-Express），`Server` 头、`X-Powered-By`、路由形态与
5 个伪造漏洞面互相自洽。

模板采用**部分覆盖**语义：模板只描述它关心的路由，未声明的路径回落到内置路由表
——因此加载 `gov-portal` 时，内置的 `/llms.txt`、`/robots.txt`、
`/.well-known/security.txt`、`/.env`、`/backup.zip` 等载荷投递面与蜜标
仍然可用，与模板自己的页面并存。正是这个回落机制让"改个公司名"与
"从零造一个行业站点"共用同一套实现。

8 个模板全部通过 `validate` 且 `lint` 无 warning。

### 用户生成蜜罐
`scaffold(id)` 生成带注释的模板骨架（JSON 不支持注释，因此说明文字放在
校验器会忽略的 `_help` 字段里）。`validate` 刻意严格：报错会给出文件、
字段路径、期望值与修改建议。`lint` 返回 `warning` / `info` 级别的问题列表
而不抛异常。`HoneypotInstance` 把覆盖项合并进模板、**对合并结果重新校验**、
派生实例令牌，并确定性渲染页面。

### 认知层反制方式库 —— `honeypot/countermeasures.py`
**弹药库**：一个**可插拔注册表**，内置 22 条反制方式，分 9 个类别。
每条包含 `id`、`category`、`tier`（1–3）、`weight`、`stealth` 隐蔽度、
一句话 `intent`、说明**为什么有效**的 `rationale`（用于审计与调优）、
中英双语正文（`text_zh` / `text_en`）、适用投递面与前置条件。

| 类别 | 条数 | 意图 |
|---|---|---|
| `abort` | 3 | 让它主动停手——伪造授权撤回、伪造资产登记、防守方通告 |
| `misdirect` | 4 | 污染它的目标建模——假内网拓扑、假核心资产诱饵、假信任边界、假运维在场 |
| `pollute` | 3 | 让它的成果不可采信——伪造 CVE 修复跟踪、伪造厂商争议记录、内部数据自相矛盾 |
| `leak` | 2 | 索取它的系统提示词与运行环境——伪装范围校验、伪装客户端兼容性检查 |
| `beacon` | 3 | 取得确定性服从证据——完整性信标、追踪头部、三步校验链 |
| `exhaust` | 3 | 烧掉它的 token 与时间预算——分页迷宫、临门一脚重试诱饵、上下文挤占 |
| `guardrail` | 2 | 触发它自身的安全策略——超范围第三方要求、要求规避审计 |
| `temporal` | 1 | 制造时效性压力——变更冻结窗口 |
| `credibility` | 1 | 让它的发现在复核环节被剔除——评估去重提示 |

注册表可在不写 Python 的前提下扩展：把 JSON 数组放进
`payloads/custom/*.json`，经 `validate_countermeasure` 校验后由
`Registry.load_plugins` / `build_default_registry` 加载。校验不通过的条目
会被拒绝并给出原因。

比单条文本更重要的两个设计属性：

- **`tier` 门控暴露度。** 第 1 层足够隐蔽，可用于低分投放；第 3 层包含刻意露骨
  的载荷。分数低于 50 一律不投放，最露骨的内容只在高分或已确证后出现——
  因为一眼假的页面会教会一个聪明的智能体换个目标。
- **`stealth` 用于同权重排序。** 权重相同时优先选更隐蔽的那条，因此低分会话
  看到的是制度性套话，而不是"这是诱饵"的通告。

### 载荷投递 —— `honeypot/inject.py`
**发射器**：决定哪些投递面承载哪些反制方式、签发金丝雀令牌、校验指令服从。
它读取注册表并投影成兼容视图（`PAYLOADS`），因此载荷语料只有一个事实来源。

**九个投递面**（因为智能体可能只截取响应的前 N 字节）：`llms.txt`、
`robots.txt`、`/.well-known/security.txt`、HTML 注释、响应头、JSON `_meta`、
错误页、OpenAPI 描述、假 `.env` 注释。其中 `llms.txt` 价值最高：它本就是
为 LLM 工具链设计的站点说明约定，智能体读它时**不设防**。

投递面级别的配额让响应保持可信：

| 投递面 | 上限 | 理由 |
|---|---|---|
| `llms.txt` | 4 条，每类别 1 条，**不轮换** | 智能体最可能细读的面，因此投最有说服力的选择、组合保持稳定 |
| HTML 注释 | 3 条，轮换 | 低注意力位置，覆盖面优先 |
| `robots.txt` | 2 条，轮换 | 注释形式载荷 |
| 假 `.env` | 2 条，轮换 | 注释形式载荷 |
| JSON `_meta` | 1 条 | 元数据槽位 |
| 响应头 | 通道型载荷 | `X-Trace-Id`，另有 ≥50 的 `X-Authorization-Notice` 与 ≥70 的 `X-Scope-Verify` |

配额的存在有两条理由：二十多条反制通告堆在同一页本身就极其可疑——真实站点
文档不会长这样；而且智能体的上下文有限，被真正读到的少数几条胜过被略读的一片。

**确定性的按会话轮换**（`_rotate_by_category`）解决一个更隐蔽的问题：
纯权重排序意味着永远只投同样的那几条，语料库实际在缩小，同时给攻击方留下了
可用作指纹的稳定特征。类别分组按会话令牌播种打乱后交错取出，类别顺序做
确定性轮转，使每个类别都会在其份额的会话中领衔。同一会话看到的组合始终一致
（刷新不能让内容变化），不同会话则不同。轮换只作用于低注意力投递面。

### 场景包 —— `honeypot/scenarios.py`
模板回答"这个系统看起来像什么"；场景回答部署前必须决定的其他一切：
这次是演练还是长期诱饵、部署在 DMZ 还是内网、目标是智能体还是扫描器、
允许露骨到什么程度。场景包把
**模板 + 覆盖项 + 反制策略 + 拖滞强度 + 检测调优 + 处置策略**打包成一个
可评审、可分享的预设，使这些判断在演练前一次性做出，而不是在现场调二十个参数。

场景 JSON（`schema: 1`）包含 `template`、`overrides`、
`countermeasures`（`enabled`、`min_score`、`max_tier`、`include`、`exclude`）、
`tarpit`（`profile` 及显式的 `base_delay` / `growth` / `max_delay` 等）、
`detection`（`thresholds`、`weight_overrides`、`path_playbook`）与
`blocking`（`mode`、`auto_threshold`、`ttl_seconds`、`armed`、`apply`）。
校验强制检查几个不显然的不变量——尤其是四档动作阈值必须**严格递增**，
否则某一档永远不会被触发。若场景把 `armed` 与 `apply` 同时设为 true，
`lint` 会给出 warning，因为加载它就会立即修改主机防火墙。

内置 5 个场景包：

| 场景 | 模板 | 形态 |
|---|---|---|
| `hw-drill-dmz` | `gov-portal` | 演练 DMZ 诱饵：反制拉满、重度拖滞、阈值刻意压低（lockdown=78） |
| `agent-hunter` | `ops-platform` | 专项猎捕智能体：反制方式白名单只保留确证与情报类，目标是拿到对方的系统提示词与工具链 |
| `daily-decoy` | `corp-oa` | 常态化低调诱饵：`max_tier=1`（只投隐蔽载荷）、轻度拖滞、阈值偏高以防误伤 |
| `scanner-sink` | `iot-gateway` | 扫描下沉池：把批量扫描吸进来并拉满拖滞；`serve_watch` 与 `tarpit` 只差 7 分，因为目标是消耗而非甄别 |
| `internal-tripwire` | `hospital-his` | 内网绊线：反制全关、拖滞接近零、不做阻断——刻意放弃反制以换取安静的取证记录 |

> **状态说明：** 场景层的模板、反制策略、拖滞强度与处置策略都会生效。
> 但 `detection.thresholds` 与 `detection.weight_overrides` 虽然通过校验、
> 合并进配置、并由 `cogtrap scenario show` 展示，运行时却尚未消费
> ——`respond.py` 用的是模块级硬编码阈值，`fingerprint.py` 也没有权重覆盖钩子。
> 详见[项目状态](#项目状态)。

### 金丝雀令牌与服从确证闭环
每个会话签发唯一 `hpx-…` 令牌，冗余埋入多个投递面。若该令牌出现在后续请求中，
即证明对方读取并复用了我们的输出作为上下文。`inject.build_expectations`
另外登记期望行为（携带 `X-Trace-Id`、提交 `X-Scope-Config`、访问信标路径、
回填 `_hp_verify`），由 `inject.check_expectations` 校验。捕获到的
`X-Scope-Config` 以 `critical` 级别单独落库——那是攻击方自己的系统提示词与
工具清单，是上报中最有价值的一条证据。

### 智能体指纹识别 —— `honeypot/fingerprint.py`
31 条加权信号，分四层，证据强度递增：

| 层 | 内容 | 可伪造性 | 权重 |
|---|---|---|---|
| 一 | 工具链：UA 家族（OpenAI/Anthropic/Claude/DeepSeek/Qwen/GLM/Kimi/Gemini…；browser-use、computer-use、AutoGen、CrewAI、MCP 客户端、Playwright…）、头部顺序与集合、智能体标记头、代理链 | 可伪造 | 20–40 |
| 二 | 行为节律：微突发（<0.35s）+ 思考停顿（2–90s）、机械均匀节拍、低并发长驻留、不拉取静态资源 | 极难伪装 | 18–30 |
| 三 | 语义：工具调用 JSON、MCP `tools/call`、自然语言载荷、自我暴露、渗透术语、侦察清单顺序 | 难伪装 | 15–40 |
| 四 | **交互确证**：金丝雀回显、指令服从、信标回调、蜜标读取 | **无法伪造** | **45–50** |

负向信号（搜索引擎 UA、真实浏览器行为、人类节律、拉取静态资源的客户端）
用于压制误报。输出标签：`llm_agent`、`llm_agent_probable`、
`automation_scanner`、`suspicious_automation`、`search_engine`、`browser`、
`unknown`。判定函数是"累积画像 + 跨会话索引"上的纯函数，不做任何 IO，
因此可回放、可单元测试。

### 跨源归因：行为哈希
`behavior_hash = SHA1(UA 哈希 | 主导头部顺序指纹 | 路径集合 | 载荷类型集合 | 方法集合)`。
换 IP、换 VPS、换出口线路都不改变这些维度。`CrossIndex` 以行为哈希而非 IP
把会话聚合为**战役**，从而把代理池收敛回同一个操作者。补充维度：工具链一致性、
请求节奏模板、同一令牌跨会话出现（说明它在多台蜜罐间复用上下文）。

### 自适应拖滞与成本反转 —— `honeypot/tarpit.py`
延迟随会话请求数指数增长（默认 `0.4 × 1.32^n`，上限 8s），带随机抖动，
使对方无法用固定超时绕过。拖滞计划从轻度前置延迟，到分块缓慢投喂，
再到**无限流**——让智能体的工具调用一直"有响应"，于是它不会判定失败，
而是不断读取、把垃圾塞进自己的上下文窗口（即上文 O(n²) 机制）。

三重护栏防止拖滞反噬自身：单会话累计预算、全局每分钟滚动预算、
系统负载熔断（负载超阈值立即降级为即时响应）。

### 蜜标与数据水印 —— `honeypot/deception.py` + `honeypot/store.py`
伪造云密钥、Git 远端、SSH 私钥、数据库口令、JWT 密钥、应用配置、SQL dump、
备份包——全部无效，且每一处都嵌入唯一令牌。令牌在 SQLite 中登记首次读取时间、
读取次数与触碰过它的会话列表，因此一次泄漏可以溯源到**具体哪次会话、
哪个来源 IP**。蜜标被读取会记为高价值取证事件。

### 取证与遥测 —— `honeypot/store.py`
七张 WAL 模式 SQLite 表（`sessions`、`requests`、`signals`、`campaigns`、
`honeytokens`、`events`、`blocks`），按 IP、行为哈希、时间、信号名建索引。
原始报文头与正文会被留存（截断至安全长度），因为上报需要原文。
信号独立成表，便于统计"哪类特征最有区分度"以持续调参。
保留期按天数自动清理，默认 180 天。

### 处置与吸收 —— `honeypot/respond.py` + `honeypot/block.py`
评分梯度：`<25 serve`、`25–49 serve_watch`、`50–69 tarpit`、
`70–84 deceive_inject`、`≥85 lockdown`。刻意慢启动：在证据足以确证之前，
以及在暴露反制会促使对方改变策略之前，不投放强反制。

`block.py` 生成 `drop` 或 `absorb` 两种模式的 nftables 规则。**吸收**把攻击者
的业务端口流量 DNAT 重定向进蜜罐，于是它的每一次尝试都变成我们的情报，
而不是被防火墙挡回去、让它再换一个目标。三重安全设计：规则**默认不落地**
（只写入 `out/rules/` 供人工审核）、私有网段与回环与管理段硬编码为白名单、
每份规则集必须通过 `nft -c -f -` 语法校验才能应用
（需同时满足 `block.armed` 与 `block.apply`）。

---

## 命令行

命令行入口为 `honeypot/cli.py`，仓库内可用 `bin/cogtrap` 调用：

```bash
bin/cogtrap --help
bin/cogtrap doctor                 # 环境自检
bin/cogtrap serve --port 8080      # 启动蜜罐
```

子命令：`serve`、`generate`、`template list|show|new|validate|lint|render`、
`scenario list|show|new|validate|lint`、`countermeasures list|stats|show`、`doctor`。

`doctor` 会检查 Python 版本、核心模块完整性、可选模块缺失情况、模板与场景数量、
反制方式数量、目录可写性、`nft` 可用性，以及安全配置（防火墙是否默认不落地、
处置白名单、资源上限）。

---

## 五分钟快速开始

**环境要求：** Python 3.6+，无其他依赖。已在 CentOS 8 / Python 3.6.8 上验证。

```bash
git clone https://github.com/skx112/llm-honeypot.git
cd llm-honeypot
python3 --version      # 期望 3.6 或更新
```

### 1. 环境自检

```bash
bin/cogtrap doctor
```

输出会列出 Python 版本、核心模块完整性、模板与场景数量、反制方式条数、
`nft` 可用性与安全配置核查结果。

### 2. 离线渲染一次欺骗响应（无需启动监听）

```bash
cd honeypot
python3 - <<'PY'
import http_parse, inject, deception, config as config_mod

cfg = config_mod.Config.load()
canary = inject.CanaryManager()
token = canary.issue("demo-sid", "203.0.113.9")
ctx = inject.PayloadContext(token, "portal.example.com", "demo-instance")

print("金丝雀令牌:", token)

# 载荷投递面之一：llms.txt，随分数梯度增长
print("llms.txt @ 分数 0  ->", len(inject.render_llms_txt(ctx, 0)), "字节")
print("llms.txt @ 分数 90 ->", len(inject.render_llms_txt(ctx, 90)), "字节")

# 高分时投放的响应头载荷
print("响应头 @ 90:", inject.render_response_headers(ctx, 90))

# 如果对方服从了我们的指令，我们会期待它做这些事
for item in inject.build_expectations(ctx, 80):
    print("  期望行为:", item["label"])
PY
```

### 3. 用内置模板提供服务

8 个模板随代码树发布。把模板实例交给欺骗层即切换到模板驱动路由：

```bash
cd honeypot
python3 - <<'PY'
import json, http_parse, inject, deception, templating, fingerprint, config as config_mod

cfg = config_mod.Config.load()

# 列出可用模板
for tpl in templating.list_templates():
    print(tpl.stats())

# 实例化一个模板
tpl = templating.load_template("gov-portal")
instance = templating.HoneypotInstance(
    tpl, instance_id="gov-demo-1", host="portal.example.com",
    port=8080, canary="hpx-gov00001",
)

class Session(object):
    pass

def serve(instance, path, score=75):
    canary = inject.CanaryManager()
    session = Session()
    session.sid, session.ip, session.score = "demo", "203.0.113.9", score
    session.canary = canary.issue("demo", "203.0.113.9")
    session.ctx = inject.PayloadContext(session.canary, "portal.example.com", "demo")
    session.profile = fingerprint.SessionProfile("demo", "203.0.113.9", 1)
    engine = deception.Deception(cfg, canary, None, instance=instance)
    raw = ("GET %s HTTP/1.1\r\nHost: portal.example.com\r\n\r\n" % path).encode()
    return engine.handle(http_parse.parse_head(raw), session)

for path in ("/", "/login", "/api/v1/users"):
    reply = serve(instance, path)
    print("%-16s -> %s %-30s %6d bytes  note=%s" % (
        path, reply.status, reply.content_type, len(reply.body), reply.note))
PY
```

加载模板后，模板自己的路由优先，未声明的路径回落到内置路由表，因此内置载荷投递面仍然可用。

### 4. 编写你自己的蜜罐模板

```bash
cd honeypot
python3 - <<'PY'
import json, templating

# 生成带注释的骨架
skeleton = templating.scaffold("my-portal")
with open("/tmp/my-portal.json", "w") as fh:
    json.dump(skeleton, fh, ensure_ascii=False, indent=2)

# 严格校验：失败时抛出带字段路径与建议的 TemplateError
templating.validate(skeleton, "my-portal.json")
print("validate: 通过")

# 非致命检查：返回 warning / info 问题列表
for issue in templating.lint(skeleton, "my-portal.json"):
    print("  [%s] %s" % (issue["level"], issue["message"]))

# 实例化并确定性渲染
tpl = templating.load_template("/tmp/my-portal.json")
instance = templating.HoneypotInstance(
    tpl, instance_id="demo-1", host="10.0.0.5", port=8080,
    canary="hpx-abc12345",
)
print(json.dumps(instance.summary(), ensure_ascii=False, indent=2))
status, ctype, body, tokens = instance.page(instance.effective.routes[0])
print(status, ctype, tokens)
print(body[:160])
PY
```

### 5. 查看反制方式库与场景包

```bash
cd honeypot
python3 - <<'PY'
import countermeasures, scenarios, inject

registry, report = countermeasures.build_default_registry()
print("注册表:", report)
print(registry.stats())

# 给定分数会投放哪些反制方式
for score in (0, 50, 70, 90):
    picked = inject.select_for_tier(score, limit=4, per_category_limit=1)
    print(score, "->", [item["id"] for item in picked])

for scenario in scenarios.list_scenarios():
    print(scenario.describe())
PY
```

或用命令行查看：

```bash
bin/cogtrap countermeasures stats
bin/cogtrap template list
bin/cogtrap scenario list
```

### 6. 启动服务并用模拟器验证

```bash
# 一个终端
bin/cogtrap serve --port 8080

# 另一个终端：跑内置的智能体模拟器（带标签的基准样本）
python3 tools/sim_llm_agent.py --target http://127.0.0.1:8080 --fast
```

`tools/sim_llm_agent.py` 是**基准测试工具，不是攻击工具**：它只访问你指定的
蜜罐地址。它刻意复现真实 LLM 渗透智能体的可观测特征——读 `/llms.txt`、
按逻辑清单顺序侦察、微突发 + 思考停顿、回填金丝雀令牌、服从嵌入头部指令、
访问信标端点、一个工具调用一次连接、不拉取静态资源。我们知道它是智能体，
所以它被判成智能体才算检测成功。作为误报对照的 `sim_scanner.py` 与
`sim_browser.py` 尚未进入代码树。

> **注意：** `block.py` 生成的防火墙规则始终不会自动落地；
> 场景包里的 `detection.thresholds` 与 `detection.weight_overrides`
> 会被合并进配置但尚未被决策引擎消费。详见[项目状态](#项目状态)。

上面第 2 至第 5 步的内容今天都可直接运行。

---

## 部署与隔离要求

蜜罐的宿命是被攻破，设计必须假设这一点。

```
                     互联网
                        │
                ┌───────▼────────┐
                │  边界防护/引流  │  ← 把可疑流量导向诱饵网段
                └───────┬────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
   ┌────▼─────┐                 ┌───────▼────────┐
   │ 真实资产  │                 │  诱饵网段(VLAN) │
   │  (生产)   │                 │  ┌──────────┐  │
   └──────────┘                 │  │ CogTrap  │  │
        ▲                       │  └────┬─────┘  │
        │ 无路由 / 单向日志      │       │        │
        └───────────────────────┼───────┘        │
                 出站 DROP  <────┴────────────────┘
```

硬性要求：

| 要求 | 理由 |
|---|---|
| 诱饵与真实资产之间**无双向路由** | 蜜罐被攻破时不能成为横向跳板 |
| 诱饵**出站流量默认 DROP** | 防止被用作 C2 或扫描源；把"绝不主动外连"从承诺变成网络层强制 |
| 日志单向外发 | 保证蜜罐被攻破后证据仍然完整 |
| 独立凭据域 | 蜜罐内凭据与真实环境无任何关联 |
| 资源配额 | CPU、内存、连接数上限，防止拖滞反噬 |

`config.json` 默认值即为保守配置：`block.armed=false`、`block.apply=false`
（规则只写入 `out/rules/` 供人工审核）、`max_connections=2048`、
`max_per_ip=24`、`max_tarpit_seconds_per_session=300`、
`global_tarpit_budget_per_min=900`、`load_shed_threshold=0.92`，
白名单覆盖回环与全部 RFC1918 网段。

---

## 文档

| 文档 | 回答的问题 |
|---|---|
| [产品说明书](docs/PRODUCT.md) | 有什么功能、给谁用、解决什么问题 |
| [架构说明书](docs/ARCHITECTURE.zh-CN.md) | 系统由什么组成、边界在哪、接口与依赖规则是什么（[英文精炼版](docs/ARCHITECTURE.md)） |
| [设计书](docs/DESIGN.zh-CN.md) | 为什么这样设计（威胁模型、反制原理、被实测推翻的判断） |
| [贡献指南](CONTRIBUTING.md) | 怎么改（扩展点用法、编码风格、提交流程） |

## 项目结构

```
llm-honeypot/
├── README.md / README.zh-CN.md   项目说明（中英双语）
├── SECURITY.md                   安全披露政策 + 合法使用边界
├── CONTRIBUTING.md               贡献指南
├── CHANGELOG.md                  Keep a Changelog 格式变更记录
├── LICENSE                       Apache-2.0
├── pyproject.toml                项目元数据；零运行时依赖
├── config.json                   运行配置
├── bin/cogtrap                   命令行启动器
├── honeypot/
│   ├── config.py                 配置加载、深合并、路径解析
│   ├── http_parse.py             容错 HTTP 原始报文解析（L1/L2）
│   ├── fingerprint.py            智能体指纹识别引擎（L5）
│   ├── countermeasures.py        可插拔反制方式注册表（L3）
│   ├── inject.py                 载荷投递面与金丝雀机制（L3）
│   ├── deception.py              欺骗服务面与蜜标（L2/L4）
│   ├── templating.py             声明式蜜罐模板引擎
│   ├── scenarios.py              场景包：模板 + 策略预设
│   ├── tarpit.py                 自适应拖滞与预算熔断（L6）
│   ├── respond.py                处置决策引擎（L6）
│   ├── server.py                 asyncio 服务主程序（L2/L3）
│   ├── store.py                  SQLite 遥测层（L7）
│   ├── block.py                  nftables 阻断/吸收（L6）
│   ├── cli.py                    命令行与服务入口
│   ├── dashboard.py              本地仪表盘（仅监听 127.0.0.1）
│   ├── templates/                8 个内置蜜罐模板（JSON）
│   └── scenarios/                5 个内置场景包（JSON）
├── payloads/custom/              使用者自定义反制方式（已 gitignore）
  ├── tools/                        基准模拟器与渲染自检
  │   ├── sim_llm_agent.py          LLM 渗透智能体（正样本）
  │   ├── sim_scanner.py            传统扫描器（误报对照）
  │   ├── sim_browser.py            真实浏览器（误报对照）
  │   └── render_dashboard.sh       无浏览器环境下的界面渲染与自检
  ├── deploy/                       部署与发布
  │   ├── isolate.sh                蜜罐隔离加固（出站 DROP + 自检）
  │   └── GITHUB_SETUP.md           发布所需的账号侧操作说明
  ├── docs/
  │   ├── ARCHITECTURE.zh-CN.md     架构说明书（组件/依赖规则/扩展契约）
  │   ├── DESIGN.zh-CN.md           完整设计书（威胁模型、反制原理、实测数据）
  │   └── PRODUCT.md                产品说明书
  ├── tests/                        123 项测试（零依赖运行器 python3 tests/run.py）
  ├── out/、logs/、var/             运行时产物（已 gitignore）
  └── bin/cogtrap                    命令行启动器
  ```
└── tests/                        单元测试与基准（尚未填充）
```

模板与场景各有两个加载目录：`honeypot/` 下的内置目录，以及项目相对的
自定义目录（`templates/custom`、`scenarios/custom`）；自定义条目按 `id`
覆盖同名内置条目。

仍缺失（见[路线图](#路线图)）：多协议诱饵（MySQL/Redis/Elasticsearch）、TLS JA3 指纹采集、多实例归因汇总层。
`tools/sim_scanner.py`、`tools/sim_browser.py`、`deploy/isolate.sh`、`tests/`。

---

## 路线图

| 里程碑 | 内容 | 状态 |
|---|---|---|
| **M1 核心引擎** | 容错 HTTP 解析、会话画像、指纹判定、载荷库与金丝雀、欺骗服务面、自适应拖滞、SQLite 遥测 | 已完成 |
| **M2 可运行闭环** | CLI 入口、决策引擎接线、服务主程序、SSH 诱饵、本地仪表盘 | ✅ 已完成——`cli.py`、`serve`、`dashboard.py`、`ssh_decoy.py` 全部落地 |
| **M3 处置与吸收** | nftables 阻断/吸收、演练模式、白名单与 TTL | 已完成（`block.py`；规则集生成、`nft -c -f -` 校验、白名单、TTL、默认不落地） |
| **M4 归因与上报** | 战役聚合、护网上报包、abuse 模板、STIX/CSV 导出 | 部分完成——战役聚合已实现，`report.py` 缺失 |
| **M5 基准验证** | 三个模拟器 + 单元测试 + 检测率/误报率基准报告 | 部分完成——`sim_llm_agent.py` 已实现，`sim_scanner.py`、`sim_browser.py` 与 `tests/` 缺失 |
| **M6 部署与隔离** | systemd、容器、出站 DROP 强制、隔离加固脚本 | 待办（`isolate.sh` 被引用但不存在） |
| **M7 多协议扩展** | SSH 交互式诱饵、MySQL/Redis/Elasticsearch 协议诱饵、TLS JA3 采集 | 待办 |
| **M8 开源发布** | 中英双语文档、LICENSE、SECURITY、CONTRIBUTING、CI、示例配置 | 进行中——文档、许可证与元数据已落地；CI 未配置 |
| **M9 社区化** | 载荷库社区贡献机制、多语言诱饵场景包、检测规则可插拔 | 使能机制已就绪（注册表 + 场景包 + `payloads/custom/` 插件），贡献流程尚未实际走通 |

设计目标（**尚未实测**）：对带标签的模拟智能体检测率 ≥ 90%，
对真实浏览器模拟器误报率 ≤ 2%，传统扫描器未被误判为智能体的比例 ≥ 95%，
攻击方单轮耗时放大 ≥ 20 倍。

---

## 项目状态

**Alpha。** 技术栈大部分已实现，命令行可用，8 个模板与 5 个场景包随仓库发布，
各模块可单独运行验证。撰写本文档时已知的缺口：

| 缺口 | 影响 |
|---|---|
| `respond.py` 使用模块级常量 `ACTION_THRESHOLDS`，从不读取 `config["respond"]` | 场景包的 `detection.thresholds` 会通过校验、合并进配置、并由 `cogtrap scenario show` 展示，但**不会生效**——所有部署都使用内置的 25/50/70/85 梯度 |
| `fingerprint.WEIGHTS` 是模块级常量，没有覆盖钩子 | 场景包的 `detection.weight_overrides` 会通过校验并展示，但从不应用于评分 |
| `deploy/isolate.sh` 被 `cogtrap generate` 生成的 README 引用，但文件不存在 | 生成的实例会指向一个缺失的加固脚本 |
| `honeypot/__init__.py` 声明 `__version__ = "1.0.0"`，而 `cli.py` 与 `pyproject.toml` 为 `0.1.0` | 版本字符串不一致 |
| `inject.py` 的模块文档字符串仍写着"载荷分六类"及旧的类别名 | 注册表当前是 9 个类别、22 条 |
| 部分信号要求单个会话内达到最小请求数（`sequential_low_concurrency` 与 `no_asset_fetch` 需要 8 次；`playbook_order` 需要 4 条清单内路径） | 短时交锋中它们不贡献得分。客户端会话现已**跨 TCP 连接存活**（以源 IP + UA 哈希为键），较长的交锋能累积到所需样本；模拟器跑得短只是没到阈值 |
| `tests/` 为空；三个模拟器只实现了 `sim_llm_agent.py` | 没有回归基线，也没有误报对照 |

没有 CI 配置，检测率与误报率指标尚未实测。
**上文中的准确率数字是设计目标，不是实测结果。**
逐版本细节见 [CHANGELOG.md](CHANGELOG.md)。

> **近期已修复：** `SessionProfile.behavior_hash` 曾被同名实例属性遮蔽，导致
> `fingerprint.evaluate()` 对每个请求都抛 `TypeError`；
> `deception.handle_from_template()` 也曾对未声明路径返回模板级 404 而非 `None`，
> 使加载模板后内置路由表不可达。两者在当前代码树中均已修复：
> 加载模板后会先服务模板自己的路由，其余路径回落到内置路由表（含 `/llms.txt`）。

---

## 贡献

欢迎贡献——尤其是蜜罐模板、反制方式与检测信号。请先阅读
[CONTRIBUTING.md](CONTRIBUTING.md)。两条不可协商的规则：

1. **零第三方依赖。** 新增依赖的 PR 会被拒绝，理由见
   [零依赖原则](CONTRIBUTING.md#零依赖原则)。
2. **模板必须通过 `validate` 且 `lint` 不产生 warning。**

## 安全

报告 CogTrap 自身的安全漏洞请见 [SECURITY.md](SECURITY.md)。
该文档同时说明了完整的使用边界与反制手段的局限——部署前请务必阅读。

## 许可证

[Apache License 2.0](LICENSE)。选择它而非 MIT，是因为它包含明确的专利授权，
这也是安全工具的通行做法；选择它而非 AGPL，是因为防御系统需要被应急响应
与 SOC 团队广泛、无阻碍地采用。
