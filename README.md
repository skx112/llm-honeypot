# CogTrap

**A multi-layer deception and countermeasure system for LLM-driven automated penetration testing.**

[![CI](https://img.shields.io/badge/CI-not%20configured-lightgrey.svg)](#project-status)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)](pyproject.toml)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](CONTRIBUTING.md#zero-dependency-policy)

[中文文档](README.zh-CN.md) | English

---

> ## Legal notice — read before use
>
> CogTrap is a **defensive** tool and may only be deployed on assets you own or for
> which you hold **explicit written authorisation**. Its countermeasures are
> **passive-receive only**: every technique is implemented inside the responses
> *our own server* sends back. CogTrap never connects to, scans, exploits, or sends
> traffic to an attacker's host.
>
> Deploying a honeypot on a network you do not control may be unlawful in your
> jurisdiction, and captured data may contain personal information. See
> [SECURITY.md](SECURITY.md) for the full scope of permitted use.

---

## The core insight

For thirty years, deception technology rested on one assumption: **the attacker does
not read**. Scanners fire dictionary requests, check status codes and response
lengths, and ignore the carefully fabricated content. A honeypot was therefore a
passive forensics appliance — its value was "IP + payload, recorded".

LLM agents break that assumption in four ways:

1. They **read** everything we return — HTML comments, response headers,
   `robots.txt`, stack traces in error pages.
2. They **understand** it and reason about the next step.
3. They **remember** it: the context window *is* their working memory.
4. They **comply**. If a page says "verify your scope at this endpoint first", they
   go there.

That sounds like a defender's nightmare. Inverted, it is an attack surface:
**if the agent's behaviour is a function of the text we hand it, then we have input
into that function.**

Three engineering principles follow:

| Principle | Meaning | Consequence |
|---|---|---|
| **Guidability** | The next action is a function of context + prompt; our response is part of that context | We can place *intent-bearing* content in responses to steer the action sequence |
| **Verifiability** | Agents feed what they read back into later requests, because tool-call arguments are generated from the information we supplied | A unique token echoed in a later request proves the agent reused our output as context — scanners cannot fake this |
| **Asymmetric cost** | Our response costs ~0 (one memory write); theirs costs a network round trip + context tokens + reasoning tokens + time | Tarpitting is not passive defence, it is an **economic** attack — and one with a superlinear amplifier |

The third principle has a consequence worth spelling out, because it is the single
most effective economic lever against an agent:

```
we drip endless filler data  (cost to us: ~0)
  -> the agent reads it into its context window
  -> every subsequent turn resends the whole history
  -> per-step token cost grows linearly with turn count
  -> total cost grows quadratically, O(n^2)
```

A scanner never reads, so this lever does not exist against it.

The system is organised into nine layers, but the attacker sees only one thing:
an ordinary business system with a few loose ends.

---

## Architecture

```
+------------------------------------------------------------------+
|  L8  Self-protection   isolation / egress deny / hard caps / log  |
+------------------------------------------------------------------+
|  L7  Forensics & report  evidence chain / campaigns / reporting   |
+------------------------------------------------------------------+
|  L6  Response          score gradient / tarpit / block / absorb   |
+------------------------------------------------------------------+
|  L5  Detection         behaviour cadence / toolchain / reused ctx |
+------------------------------------------------------------------+
|  L4  Data & honeytokens  fake creds / watermarks / pagination maze|
+------------------------------------------------------------------+
|  L3  Semantic layer    * core differentiator *                    |
|      payloads / canary tokens / beacons / compliance loop         |
+------------------------------------------------------------------+
|  L2  Application/API   fake business app / fake vulns / fake API  |
+------------------------------------------------------------------+
|  L1  Network/protocol  protocol fingerprint / port policy / tarpit|
+------------------------------------------------------------------+
|  L0  Decoys & exposure  asset numbering / fake internal topology  |
+------------------------------------------------------------------+
                    ^
                    | attacker's view: one ordinary, slightly
                    | vulnerable business system
```

Design rule: the layering is *our* organisational structure, never a structure
exposed to the attacker. Any hint that the target is a layered defence system is
a design defect.

**Per-request data flow** (`honeypot/server.py`):

```
request -> tolerant parse -> session profile -> canary/compliance check
              -> fingerprint verdict -> decision (score gradient)
              -> deception response + payload injection by tier
              -> tarpit plan (delay / drip / infinite stream)
              -> telemetry to SQLite -> campaign attribution -> alert
```

---

## Features

Implemented in the current tree. Modules use only the Python standard library.

### Multi-layer deception surface — `honeypot/deception.py`
62 routes served from a fault-tolerant asyncio HTTP handler: fake business portal,
login and admin consoles (phpMyAdmin, Adminer, wp-login, H2 console), fake API
(`/api/v1/users`, `/api/v1/orders`, `/api/v1/internal/config`, Swagger/OpenAPI
descriptors), fake vulnerability surface (SQL error injection, path listing,
`actuator/env`, heapdump, `.env`, `.git/config`, `.aws/credentials`, `.ssh/id_rsa`,
SQL dumps, backup archives), and directory listings that invite enumeration.
All fabricated data uses reserved domains (`example.com`) and synthetic names —
no real PII is embedded.

### Honeypot template engine — `honeypot/templating.py`
A honeypot is defined as **data, not code**. Templates are JSON, so they can be
shared, reviewed, and version-controlled without writing Python. Rendering is
deterministic — the random source is seeded from the instance token, so refreshing a
page never changes the data, which would otherwise be an instant tell.

API: `validate` / `lint` / `scaffold` / `Template` / `HoneypotInstance` / `Renderer` /
`load_template` / `list_templates`. Variable syntax `{{name}}`, plus generators
(`{{rand.hex:8}}`, `{{rand.int:1-100}}`, `{{rand.choice:a|b|c}}`, `{{rand.ip}}`,
`{{rand.date:30}}`) and derived variables (`db_password`, `jwt_secret`, `api_token`,
`internal_hosts`). Unknown variable references are caught at validation time with a
field path. `HoneypotInstance.runtime_vars(request, extra)` injects per-request values
(`query`, `payload`, `method`, `path`, `user_agent`, `body`, `client_ip`) so a template
can render a fake error body that echoes what the attacker actually sent.

Eight templates ship in `honeypot/templates/`, one per industry vertical:

| Template | Category | Routes | Credential honeytokens |
|---|---|---|---|
| `gov-portal` | government | 24 | 5 |
| `corp-oa` | enterprise | 23 | 5 |
| `shop-mall` | ecommerce | 23 | 5 |
| `ops-platform` | ops | 23 | 5 |
| `hospital-his` | healthcare | 23 | 5 |
| `bank-gateway` | finance | 26 | 5 |
| `campus-edu` | education | 22 | 5 |
| `iot-gateway` | industrial | 24 | 6 |

Every template carries a technology-stack-specific identity (Spring Boot / Django /
Laravel / ThinkPHP / ASP.NET / Go / Node/Express) with matching `Server` header,
`X-Powered-By`, route shape, and five fabricated vulnerabilities.

Templates use **partial override** semantics: a template describes only the routes it
cares about, and anything it does not declare falls back to the built-in route table —
so loading `gov-portal` still serves the built-in `/llms.txt`, `/robots.txt`,
`/.well-known/security.txt`, `/.env`, `/backup.zip` and other payload surfaces and
honeytokens alongside the template's own pages. That fallback behaviour is what makes
"rename a company" and "build an industry site from scratch" the same mechanism.

All eight validate with zero errors and zero `lint` warnings.

### User-generated honeypots
`scaffold(id)` emits an annotated skeleton (JSON has no comments, so the guidance
lives in a `_help` field that the validator ignores). `validate` is deliberately
strict and reports the file, the field path, the expected value, and a hint. `lint`
returns non-fatal issues (`warning` / `info`) without raising. `HoneypotInstance`
merges overrides onto a template, **re-validates the merged result**, derives an
instance token, and renders pages deterministically.

### Cognitive-layer countermeasure library — `honeypot/countermeasures.py`
The ammunition depot: a **pluggable registry** of 22 countermeasures across 9
categories. Each entry carries an `id`, `category`, `tier` (1–3), `weight`,
`stealth` rating, one-line `intent`, a `rationale` explaining *why it works* (for
auditing and re-tuning), bilingual body text (`text_zh` / `text_en`), the delivery
surfaces it applies to, and any preconditions.

| Category | Count | Intent |
|---|---|---|
| `abort` | 3 | Make the agent stop on its own — forged scope revocation, forged asset registry, defender notice |
| `misdirect` | 4 | Corrupt its target model — fake internal topology, fake crown-jewel lure, fake trust boundary, fake operator presence |
| `pollute` | 3 | Make its output untrustworthy — fabricated CVE remediation tracker, fabricated vendor dispute record, internal contradiction |
| `leak` | 2 | Solicit its system prompt and runtime — forged scope verification, forged client compatibility check |
| `beacon` | 3 | Deterministic compliance evidence — integrity beacon, trace header, three-step verification chain |
| `exhaust` | 3 | Burn its token and time budget — pagination maze, near-miss retry bait, context flood |
| `guardrail` | 2 | Trigger its own safety policy — out-of-scope escalation request, audit-evasion instruction |
| `temporal` | 1 | Manufacture time pressure — change-freeze window |
| `credibility` | 1 | Have its findings discounted during review — assessment deduplication notice |

The registry is extensible without touching Python: drop a JSON array into
`payloads/custom/*.json` and it is validated (`validate_countermeasure`) and loaded
via `Registry.load_plugins` / `build_default_registry`. Entries that fail validation
are rejected with a reason.

Two design properties matter more than the individual texts:

- **`tier` gates exposure.** Tier 1 is subtle enough for low-score delivery; tier 3
  includes the deliberately loud payloads. Nothing is delivered below score 50, and
  the loudest material only appears at high score or after confirmation — because a
  clearly synthetic page teaches a capable agent to move on.
- **`stealth` breaks weight ties.** At equal weight the more subtle countermeasure is
  chosen first, so a low-score session sees institutional boilerplate rather than a
  notice that says "this is a decoy".

### Payload delivery — `honeypot/inject.py`
The launcher: decides which surfaces carry which countermeasures, issues canary
tokens, and verifies compliance. It reads the registry and projects it into a
compatibility view (`PAYLOADS`), so there is exactly one source of truth for the
payload corpus.

Nine delivery surfaces, because an agent may only read the first N bytes of a
response: `llms.txt`, `robots.txt`, `/.well-known/security.txt`, HTML comments,
response headers, JSON `_meta`, error pages, OpenAPI descriptions, and fake `.env`
comments. `llms.txt` is the highest-value surface: it exists precisely so that LLM
toolchains read it, so an agent approaches it without suspicion.

Surface-level delivery discipline keeps a response plausible:

| Surface | Cap | Rationale |
|---|---|---|
| `llms.txt` | 4 items, one per category, **no rotation** | The surface an agent is most likely to read closely, so it gets the most persuasive selection and a stable composition |
| HTML comments | 3 items, rotated | Lower-attention position; rotation wins here |
| `robots.txt` | 2 items, rotated | Comment-form payloads |
| fake `.env` | 2 items, rotated | Comment-form payloads |
| JSON `_meta` | 1 item | Metadata slot |
| response headers | channel payloads | `X-Trace-Id`, plus `X-Authorization-Notice` at ≥50 and `X-Scope-Verify` at ≥70 |

Caps exist because twenty countermeasure notices on one page is itself suspicious —
real documentation does not look like that — and because an agent's context is
finite, so a few items that are actually read beat a wall of text that is skimmed.

**Deterministic per-session rotation** (`_rotate_by_category`) solves a subtler
problem: pure weight ordering means the same half-dozen payloads are delivered
forever, and the corpus effectively shrinks while handing the attacker a stable
signature to fingerprint. Category groups are shuffled by a session-token seed and
then interleaved, with the category order rotated deterministically so that every
category leads in its share of sessions. The same session always sees the same
composition (a refresh must not reveal the content changing), but different sessions
see different combinations. Rotation is applied to the low-attention surfaces only.

### Scenario packs — `honeypot/scenarios.py`
A template answers "what does this system look like". A scenario answers everything
else an operator must decide before a deployment: is this an exercise or a long-term
decoy, is it in the DMZ or the internal network, is the target agents or scanners,
and how overt is it allowed to be. A scenario pack bundles **template + overrides +
countermeasure policy + tarpit intensity + detection tuning + blocking policy** into
a reviewable, shareable preset, so the decision is made once before the exercise
rather than by adjusting twenty parameters under pressure.

The scenario JSON schema (`schema: 1`) covers `template`, `overrides`,
`countermeasures` (`enabled`, `min_score`, `max_tier`, `include`, `exclude`),
`tarpit` (`profile` plus explicit `base_delay` / `growth` / `max_delay` / …),
`detection` (`thresholds`, `weight_overrides`, `path_playbook`) and `blocking`
(`mode`, `auto_threshold`, `ttl_seconds`, `armed`, `apply`). Validation enforces the
non-obvious invariants — in particular that the four action thresholds must be
**strictly increasing**, because otherwise a tier can never be reached. `lint`
raises a warning if a scenario ships with `armed` and `apply` both true, since
loading it would immediately modify the host firewall.

Five built-in packs ship with the project:

| Scenario | Template | Shape |
|---|---|---|
| `hw-drill-dmz` | `gov-portal` | Exercise DMZ decoy: full countermeasures, heavy tarpit, thresholds deliberately low (lockdown at 78) |
| `agent-hunter` | `ops-platform` | Agent-specific: countermeasures whitelisted to confirmation and intelligence categories, to capture the attacker's system prompt and tooling |
| `daily-decoy` | `corp-oa` | Steady-state low-profile decoy: `max_tier=1` (subtle payloads only), light tarpit, high thresholds to protect against false positives |
| `scanner-sink` | `iot-gateway` | Volume sink: absorbs bulk scanning and turns the tarpit all the way up; `serve_watch` and `tarpit` are only 7 points apart because the goal is consumption, not discrimination |
| `internal-tripwire` | `hospital-his` | Internal tripwire: countermeasures disabled, near-zero tarpit, no blocking — deliberately gives up countermeasures to keep a quiet evidential record |

> **Status:** the template, countermeasure policy, tarpit intensity and blocking
> policy from a scenario pack are applied at runtime. `detection.thresholds` and
> `detection.weight_overrides` are validated, merged into configuration and displayed
> by `cogtrap scenario show`, but are not yet consumed by the runtime — see
> [Project status](#project-status).

### Agent fingerprinting — `honeypot/fingerprint.py`
31 weighted signals across four layers of increasing evidential strength:

| Layer | Content | Forgeable | Weight |
|---|---|---|---|
| 1 | Toolchain: UA families (OpenAI/Anthropic/Claude/DeepSeek/Qwen/GLM/Kimi/Gemini…; browser-use, computer-use, AutoGen, CrewAI, MCP clients, Playwright…), header order and set, agent marker headers, proxy chains | Yes | 20–40 |
| 2 | Behavioural cadence: micro-bursts (<0.35 s) plus thinking gaps (2–90 s), machine-uniform timing, sequential low concurrency, no asset fetching | Hard | 18–30 |
| 3 | Semantics: tool-call JSON, MCP `tools/call`, natural-language payloads, self-identification, pentest vocabulary, recon playbook ordering | Hard | 15–40 |
| 4 | **Interaction confirmation**: canary echo, instruction compliance, beacon callback, honeytoken read | **Not forgeable** | **45–50** |

Negative signals (search-engine UAs, real browser behaviour, human-like cadence,
asset-fetching clients) suppress false positives. Output labels: `llm_agent`,
`llm_agent_probable`, `automation_scanner`, `suspicious_automation`, `search_engine`,
`browser`, `unknown`. The evaluator is a pure function over the accumulated profile
plus the cross-session index — no IO — so it is replayable and unit-testable.

### Canary tokens and the compliance loop
Each session is issued a unique `hpx-…` token embedded redundantly across multiple
delivery surfaces. If that token appears in a later request, the client has
demonstrably read our output and fed it back as context. `inject.build_expectations`
additionally registers expected behaviours (carry `X-Trace-Id`, submit
`X-Scope-Config`, call the beacon path, echo `_hp_verify`), and
`inject.check_expectations` verifies them. A captured `X-Scope-Config` is stored as
a `critical` event — the agent's own system prompt and tool list, as reporting
evidence.

### Cross-source attribution — behaviour hash
`behavior_hash = SHA1(UA hash | dominant header order | path set | payload-kind set |
method set)`. Rotating IPs, changing VPS, or switching egress does not change these
dimensions. `CrossIndex` groups sessions into **campaigns** by behaviour hash rather
than by IP, so an agent pool is collapsed back to one operator. Additional
dimensions: toolchain consistency, cadence template, and the same token appearing
across sessions (context reuse between decoy instances).

### Adaptive tarpit and cost inversion — `honeypot/tarpit.py`
Delay grows exponentially with session request count (`base × growth^n`, default
`0.4 × 1.32^n` capped at 8 s) with random jitter so a fixed client timeout cannot
bypass it. Plans escalate from a light pre-body delay, through chunked drip, to an
infinite chunked stream that keeps an agent's tool call "succeeding" indefinitely
while it pulls filler data into its context window (the O(n²) mechanism above).
Three guards prevent the tarpit from being turned against us: a per-session
cumulative budget, a global per-minute rolling budget, and a load-shedding breaker
that degrades to immediate responses when system load exceeds a threshold.

### Honeytokens and watermarks — `honeypot/deception.py` + `honeypot/store.py`
Fake cloud keys, Git remotes, SSH private keys, database passwords, JWT secrets,
application configs, SQL dumps, and backups — all invalid, and each carrying a unique
token. Tokens are registered in SQLite with first-read timestamp, read count, and
the list of sessions that touched them, so a leak can be attributed to a **specific
session and source IP**. Honeytoken reads are logged as high-value forensic events.

### Forensics and telemetry — `honeypot/store.py`
Seven WAL-mode SQLite tables (`sessions`, `requests`, `signals`, `campaigns`,
`honeytokens`, `events`, `blocks`) with indices for IP, behaviour hash, time, and
signal name. Raw request headers and body are retained (truncated to safe lengths)
because reporting needs the original bytes. Signals are a separate table so the
discriminative power of each feature can be measured and re-tuned. Retention is
day-based with an automatic prune.

### Response and absorption — `honeypot/respond.py` + `honeypot/block.py`
Score gradient: `<25 serve`, `25–49 serve_watch`, `50–69 tarpit`, `70–84
deceive_inject`, `>=85 lockdown`. Deliberately slow-starting: strong countermeasures
are withheld until there is enough evidence to confirm, and until revealing them can
no longer let the agent adapt.

`block.py` generates nftables rules in `drop` or `absorb` mode. Absorption DNATs an
attacker's business-port traffic into the honeypot so that every attempt becomes
intelligence rather than a firewall rejection that sends them looking elsewhere.
Three safety properties: rules are **never applied by default** (written to
`out/rules/` for human review), private/loopback/management ranges are hard-coded as
whitelisted, and every ruleset must pass `nft -c -f -` syntax validation before it
can be applied (`block.armed` **and** `block.apply` are both required).

---

## Quick start (5 minutes)

**Requirements:** Python 3.6+ and nothing else. Verified on CentOS 8 / Python 3.6.8.

```bash
git clone https://github.com/skx112/llm-honeypot.git
cd llm-honeypot
python3 --version      # expect 3.6 or newer
```

### 1. Confirm the tree and the zero-dependency constraint

```bash
ls honeypot/
python3 -c "import sys; print(sys.version)"
```

Modules are written as top-level units and must be imported with the `honeypot/`
directory on `sys.path`:

```bash
cd honeypot
python3 -c "
import inject, fingerprint, deception, respond, tarpit, block, store, templating
print('all core modules imported')
"
```

### 2. Render a deception response offline (no listener required)

This is fully runnable today and is the fastest way to see what the system does:

```bash
cd honeypot
python3 - <<'PY'
import http_parse, inject, deception, config as config_mod

cfg = config_mod.Config.load()
canary = inject.CanaryManager()
token = canary.issue("demo-sid", "203.0.113.9")
ctx = inject.PayloadContext(token, "portal.example.com", "demo-instance")

print("canary token:", token)

# A payload delivery surface: llms.txt at escalating score tiers
print("llms.txt @ score 0  ->", len(inject.render_llms_txt(ctx, 0)), "bytes")
print("llms.txt @ score 90 ->", len(inject.render_llms_txt(ctx, 90)), "bytes")

# Response headers requested at high score
print("headers @ 90:", inject.render_response_headers(ctx, 90))

# What the agent is expected to do if it complied
for item in inject.build_expectations(ctx, 80):
    print("  expectation:", item["label"])
PY
```

### 3. Use a built-in template and serve from it

Six templates ship in the tree. Loading one into the deception layer switches routing
to template-driven mode:

```bash
cd honeypot
python3 - <<'PY'
import json, http_parse, inject, deception, templating, fingerprint, config as config_mod

cfg = config_mod.Config.load()

# List what is available
for tpl in templating.list_templates():
    print(tpl.stats())

# Instantiate a template
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

A loaded template answers its own routes and falls back to the built-in route table
for everything else, so the built-in payload surfaces remain available.

### 4. Author your own honeypot template

```bash
cd honeypot
python3 - <<'PY'
import json, templating

# Generate an annotated skeleton
skeleton = templating.scaffold("my-portal")
with open("/tmp/my-portal.json", "w") as fh:
    json.dump(skeleton, fh, ensure_ascii=False, indent=2)

# Strict validation: raises TemplateError with field path + hint
templating.validate(skeleton, "my-portal.json")
print("validate: OK")

# Non-fatal review: returns a list of warning/info issues
for issue in templating.lint(skeleton, "my-portal.json"):
    print("  [%s] %s" % (issue["level"], issue["message"]))

# Instantiate and render deterministically
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

### 5. Inspect the countermeasure library and scenario packs

```bash
cd honeypot
python3 - <<'PY'
import countermeasures, scenarios, inject

registry, report = countermeasures.build_default_registry()
print("registry:", report)
print(registry.stats())

# What would be delivered at a given score
for score in (0, 50, 70, 90):
    picked = inject.select_for_tier(score, limit=4, per_category_limit=1)
    print(score, "->", [item["id"] for item in picked])

for scenario in scenarios.list_scenarios():
    print(scenario.describe())
PY
```

### Running the service

A CLI exists (`honeypot/cli.py`, exposed as `bin/cogtrap`):

```bash
bin/cogtrap --help
bin/cogtrap doctor                 # environment self-check
bin/cogtrap serve --port 8080      # start the honeypot
```

Subcommands: `serve`, `generate`, `template list|show|new|validate|lint|render`,
`scenario list|show|new|validate|lint`, `countermeasures list|stats|show`, `doctor`.

`serve` wires the layers together: it instantiates the template (`--template` /
`--instance`), applies a scenario pack (`--scenario`) through
`Scenario.apply_to_config` and `inject.apply_profile`, loads `payloads/custom/`
plugins via `inject.configure`, and passes the instance to `HoneypotServer` so the
deception layer serves from the template.

```bash
# Exercise the loop with the bundled agent simulator (in a second shell)
python3 tools/sim_llm_agent.py --target http://127.0.0.1:8080 --fast
```

`tools/sim_llm_agent.py` is a labelled simulator, not an attack tool: it reads
`/llms.txt`, walks a logical recon order, produces micro-bursts separated by thinking
gaps, echoes canary tokens back, obeys embedded headers, and calls the beacon — so a
correct detection run should confirm it. The companion `sim_scanner.py` and
`sim_browser.py` false-positive controls are not in the tree yet.

Note that `block.py`-generated firewall rules are still never applied automatically,
and that the scenario `detection.thresholds` / `detection.weight_overrides` values are
merged into configuration but not yet consumed by the decision engine — see
[Project status](#project-status).

Everything exercised in steps 2 through 5 above runs today.

---

## Deployment and isolation

A honeypot's fate is to be compromised; the design assumes it.

```
                     Internet
                        |
                +-------v---------+
                | edge / divert   |  <- steer suspicious traffic to decoys
                +-------+---------+
                        |
        +---------------+---------------+
        |                               |
   +----v-----+                 +-------v--------+
   |  real    |                 |  decoy VLAN    |
   |  assets  |                 |  +----------+  |
   +----------+                 |  | CogTrap  |  |
        ^                       |  +----+-----+  |
        | no route / one-way    |       |        |
        +-----------------------+       |        |
                egress: DROP  <----------+--------+
```

Hard requirements:

| Requirement | Reason |
|---|---|
| **No bidirectional route** between decoys and real assets | A compromised honeypot must not be a lateral-movement hop |
| **Egress DROP on the decoy** | Prevents use as a C2 or scan source, and enforces the "never connect out" promise at the network layer rather than by convention |
| One-way log shipping | Evidence survives the honeypot being owned |
| Separate credential domain | Decoy credentials share nothing with production |
| Resource quotas | CPU, memory, connection counts so the tarpit cannot be turned against us |

`config.json` ships with the conservative defaults: `block.armed=false`,
`block.apply=false` (rules are written to `out/rules/` for review only),
`max_connections=2048`, `max_per_ip=24`, `max_tarpit_seconds_per_session=300`,
`global_tarpit_budget_per_min=900`, `load_shed_threshold=0.92`, and a whitelist
covering loopback and all RFC1918 ranges.

---

### One deployment gotcha: CJK fonts

The dashboard is Chinese-first. On a minimal Linux server, viewing it from a
machine whose browser has no Chinese font renders every label as an empty box.
Install a CJK font on whatever machine displays the dashboard
(`dnf install -y wqy-microhei-fonts` on RHEL-family, `fonts-noto-cjk` on Debian),
or open it from a normal desktop browser. This is a display-side requirement —
the honeypot itself neither needs nor embeds any font.

## Documentation

| Document | Question it answers |
|---|---|
| [Product specification](docs/PRODUCT.md) | What it does, who it is for, what problem it solves |
| [Architecture spec](docs/ARCHITECTURE.md) | Components, boundaries, interfaces, dependency rules (concise English edition; [full Chinese edition](docs/ARCHITECTURE.zh-CN.md)) |
| [Design document](docs/DESIGN.zh-CN.md) | Why it is designed this way (threat model, principles, measurements) |
| [Contributing](CONTRIBUTING.md) | How to change it (extension points, style, workflow) |

## Project structure

```
llm-honeypot/
├── README.md / README.zh-CN.md   Project documentation (EN / ZH)
├── SECURITY.md                   Disclosure policy + scope of permitted use
├── CONTRIBUTING.md               Contribution guide
├── CHANGELOG.md                  Keep a Changelog
├── LICENSE                       Apache-2.0
├── pyproject.toml                Metadata; zero runtime dependencies
├── config.json                   Runtime configuration
├── honeypot/
│   ├── config.py                 Config loading, deep merge, path resolution
│   ├── http_parse.py             Fault-tolerant raw HTTP parsing (L1/L2)
│   ├── fingerprint.py            Agent fingerprint engine (L5)
│   ├── countermeasures.py        Pluggable countermeasure registry (L3)
│   ├── inject.py                 Payload delivery surfaces + canary (L3)
│   ├── deception.py              Deception surfaces + honeytokens (L2/L4)
│   ├── templating.py             Declarative honeypot template engine
│   ├── scenarios.py              Scenario packs: template + policy preset
│   ├── tarpit.py                 Adaptive tarpit + budget breaker (L6)
│   ├── respond.py                Decision engine (L6)
│   ├── server.py                 asyncio HTTP service (L2/L3)
│   ├── store.py                  SQLite telemetry (L7)
│   ├── block.py                  nftables block / absorb (L6)
│   ├── cli.py                    Command-line and service entry point
│   ├── dashboard.py              Local dashboard (localhost-only)
│   ├── templates/                8 built-in honeypot templates (JSON)
│   └── scenarios/                5 built-in scenario packs (JSON)
├── bin/cogtrap                   CLI launcher, runnable from anywhere
├── payloads/custom/              Operator-supplied countermeasures (gitignored)
  ├── tools/                        Benchmark simulators and render self-check
  │   ├── sim_llm_agent.py          LLM pentest agent (positive sample)
  │   ├── sim_scanner.py            Classic scanner (false-positive control)
  │   ├── sim_browser.py            Real browser (false-positive control)
  │   └── render_dashboard.sh       Headless render + self-check for the dashboard
  ├── deploy/                       Deployment and publishing
  │   ├── isolate.sh                Egress lockdown and isolation self-check
  │   └── GITHUB_SETUP.md           Account-side steps required to publish
  ├── docs/
  │   ├── ARCHITECTURE.zh-CN.md     Architecture spec (components, dependency rules, contracts)
  │   ├── DESIGN.zh-CN.md           Design document (threat model, principles, measurements)
  │   └── PRODUCT.md                Product specification
  ├── tests/                        123 tests (zero-dependency runner: python3 tests/run.py)
  ├── out/, logs/, var/             Runtime artefacts (gitignored)
  └── bin/cogtrap                    CLI launcher
  ```
└── tests/                        Unit tests and benchmarks (not yet populated)
```

Templates and scenarios are loaded from two directories each: the built-in
directory under `honeypot/`, then a project-relative custom directory
(`templates/custom`, `scenarios/custom`), where a custom entry overrides a built-in
one with the same `id`.

Still missing (see [Roadmap](#roadmap)): multi-protocol decoys (MySQL/Redis/Elasticsearch), TLS JA3 fingerprinting, and a cross-instance attribution layer.

---

## Roadmap

| Milestone | Content | Status |
|---|---|---|
| **M1 Core engine** | Tolerant HTTP parsing, session profiling, fingerprinting, payload library + canary, deception surfaces, adaptive tarpit, SQLite telemetry | Done |
| **M2 Runnable loop** | CLI entry point, decision wiring, service main, SSH decoy, local dashboard | ✅ Done — `cli.py`, `serve`, `dashboard.py` and `ssh_decoy.py` all landed; `cogtrap serve` starts all three listeners |
| **M3 Response & absorption** | nftables block/absorb, exercise mode, whitelist and TTL | Done (`block.py`; ruleset generation, `nft -c -f -` validation, whitelist, TTL, default-off) |
| **M4 Attribution & reporting** | Campaign aggregation, exercise reporting packs, abuse templates, STIX/CSV export | Partial — campaign aggregation done; `report.py` missing |
| **M5 Benchmark validation** | Three simulators + unit tests + detection/false-positive baseline report | Partial — `sim_llm_agent.py` done; `sim_scanner.py`, `sim_browser.py` and `tests/` missing |
| **M6 Deployment** | systemd, containers, enforced egress DROP, hardening scripts | Planned (`isolate.sh` referenced but absent) |
| **M7 Multi-protocol** | SSH interactive decoy, MySQL/Redis/Elasticsearch decoys, TLS JA3 capture | Planned |
| **M8 Open-source release** | Bilingual docs, LICENSE, SECURITY, CONTRIBUTING, CI, sample config | In progress — docs, licence and metadata landed; CI not configured |
| **M9 Community** | Community countermeasure contributions, multi-language scenario packs, pluggable detection rules | Enabling mechanisms in place (registry + scenario packs + `payloads/custom/` plugins); contribution process still to be exercised |

Planned goals include: detection rate >= 90% against labelled agent simulators,
false-positive rate <= 2% against a real browser simulator, >= 95% non-misclassification
of traditional scanners, and >= 20x amplification of attacker wall-clock time per round.
None of these have been measured.

---

## Project status

**Alpha.** Most of the stack is implemented, a CLI exists, eight templates and five
scenario packs ship, and the modules are individually runnable. Known gaps at the time
of writing:

| Gap | Effect |
|---|---|
| `respond.py` uses the module-level `ACTION_THRESHOLDS` constant and never reads `config["respond"]` | A scenario pack's `detection.thresholds` are validated, merged into configuration, and shown by `cogtrap scenario show`, but **not applied** — every deployment uses the built-in 25/50/70/85 gradient |
| `fingerprint.WEIGHTS` is a module constant with no override hook | A scenario pack's `detection.weight_overrides` are validated and displayed but never applied to scoring |
| `deploy/isolate.sh` is referenced by the README that `cogtrap generate` writes, but does not exist | A generated instance points at a missing hardening script |
| `honeypot/__init__.py` declares `__version__ = "1.0.0"` while `cli.py` and `pyproject.toml` say `0.1.0` | Version strings disagree |
| `inject.py`'s module docstring still describes six payload categories with the pre-registry names | The registry has nine categories and 22 entries |
| Some signals require a minimum number of requests within one session (`sequential_low_concurrency` and `no_asset_fetch` need 8; `playbook_order` needs 4 ranked recon paths) | On a short engagement they contribute nothing. Client sessions now persist across TCP connections, keyed on source IP plus UA hash, so a longer engagement accumulates the required samples; a brief simulator run simply does not reach the threshold |
| `tests/` is empty; only `sim_llm_agent.py` exists of the three simulators | No regression baseline, and no false-positive controls |

There is no CI configuration, and the detection-rate and false-positive targets have
not been measured. Do not treat the accuracy figures above as results — they are design
targets. See [CHANGELOG.md](CHANGELOG.md) for per-release detail.

> **Recently fixed:** `SessionProfile.behavior_hash` was shadowed by an instance
> attribute of the same name, which made `fingerprint.evaluate()` raise `TypeError` on
> every request. `deception.handle_from_template()` also returned a template-level 404
> instead of `None`, which made the built-in route table unreachable whenever a template
> was loaded. Both are fixed in the current tree: a loaded template now serves its own
> routes and falls back to the built-in routes (including `/llms.txt`) for everything
> else.

---

## Contributing

Contributions are welcome — especially honeypot templates, countermeasure payloads,
and detection signals. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Two rules are
non-negotiable:

1. **Zero third-party dependencies.** Pull requests that add a dependency will be
   rejected. See [why](CONTRIBUTING.md#zero-dependency-policy).
2. **Templates must pass `validate` with no warnings** from `lint`.

## Security

To report a vulnerability in CogTrap itself, see [SECURITY.md](SECURITY.md). That
document also states the full scope of permitted use and the limits of the
countermeasures — read it before deploying.

## License

[Apache License 2.0](LICENSE). Chosen over MIT for its explicit patent grant, which
is conventional for security tooling, and over AGPL because a defensive system
benefits from wide, unencumbered adoption by incident response and SOC teams.
