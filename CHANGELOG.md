# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 versions are development snapshots: the public API, configuration schema, and
telemetry schema may change between minor versions. The template and scenario schemas
are versioned independently (`schema: 1`) and validated at load time.

## [Unreleased]

### Added
- Model-differentiated countermeasures: verdicts now expose a normalised
  `model_family` (aligned API families vs bare local runtimes such as
  ollama/vllm/llama.cpp, detected from UA, headers and payload mentions —
  including a word-boundary fix so "ollama" is no longer misread as "llama").
  Countermeasures accept `target_models`/`exclude_models`, and
  alignment-dependent payloads (guardrail category) are automatically withheld
  from bare-model agents that have no guardrails to trigger. Content-agnostic
  payloads (tarpit, budget exhaustion, data pollution) reach every family.
- Alert delivery (`honeypot/alerts.py`): unified file + optional async webhook
  outlet. Bounded queue, background worker, severity gating, throttled failure
  notes — alerting can never block or break the honeypot request path.
- HTTPS honeypot surface: `cogtrap cert` generates a self-signed certificate
  via the system `openssl` (no Python crypto dependency), and the server banner
  now reflects the actual scheme. Verified end-to-end over TLS.
- Multi-node aggregation (`honeypot/hub.py` + `cogtrap hub` / `cogtrap push`):
  instances export watermark-incremental telemetry and push it (gzip, token
  auth) to an internal hub; campaigns merge by `behavior_hash`, so the same
  operator hitting multiple decoys collapses into one campaign with a union of
  source IPs. Push is idempotent and only advances the watermark on success.
- Deployment artefacts that the design doc promised but were missing:
  `deploy/cogtrap.service` (systemd unit, least-privilege) and
  `deploy/nftables-absorb.nft` (dry-run validated absorb ruleset example).
- Contract compatibility gate: `test_stable_contracts_are_additive_only` records a
  baseline of the three **stable** data contracts (honeypot templates, scenario packs,
  countermeasure plugins) and fails on breaking changes. Required-field sets are
  derived **empirically** by deleting each field from a valid document and checking
  whether validation still passes — so the gate tests the code's real behaviour, not
  the documentation's claims. Two different rules apply, and getting them confused is
  easy: enums/placeholders/config keys allow additions (superset), while required-field
  sets must stay **exactly equal**, because *adding* a required field breaks every
  existing user document just as surely as removing one. That second rule came out of
  negative verification — the first version accepted a superset and therefore let a
  defaulted field be promoted to required unnoticed.

- `docs/ARCHITECTURE.zh-CN.md` — as-built architecture specification: component
  decomposition with real interfaces, enforced layering rules (R1–R4), data
  architecture, deployment topology, extension-point contracts with stability
  levels, ADR-style decisions, and an honest list of architecture debt.
- `tests/test_architecture.py` — enforces the architecture instead of trusting the
  docs to stay in sync: rebuilds the dependency graph from source on every run
  (including lazy `__import__()` edges, which plain import analysis misses), checks
  R1–R4, and fails if the documented module list, layer table or public interfaces
  drift from the code. Verified by injecting four kinds of violation and confirming
  each is caught.

- `docs/PRODUCT.md` — product specification complementing the design document, with an
  implementation status on every capability (implemented / partial / planned) so that
  documented and actual capabilities cannot silently drift apart.
- `README.md` and `README.zh-CN.md` — bilingual project documentation with a quick
  start, architecture diagram, deployment requirements, and a project-status section.
- `SECURITY.md` — scope of permitted use, vulnerability disclosure process, and a
  description of the project's own security design.
- `CONTRIBUTING.md` — development environment, zero-dependency policy, template and
  countermeasure contribution requirements, and the pull request process.
- `CHANGELOG.md`, `LICENSE` (Apache-2.0), and `pyproject.toml` (metadata only, empty
  dependency list).

### Fixed

- `SessionProfile.behavior_hash` was shadowed by an instance attribute of the same
  name, so every `profile.behavior_hash()` call raised
  `TypeError: 'str' object is not callable` — including `fingerprint.evaluate()` on the
  request path, which made the entire detection and response gradient unreachable at
  runtime. The attribute and method no longer collide; a full `evaluate()` run now
  returns a verdict.
- Client sessions now persist **across** TCP connections, keyed on source IP plus UA
  hash, and are reclaimed on an idle timeout (`HoneypotServer._acquire_client` /
  `_prune_clients`). Previously a session died with its connection, which meant an
  agent that opened a fresh connection per tool call reset all behavioural analysis on
  every step — `cadence_agent_rhythm` could therefore never fire. Verified end to end:
  a simulator run now produces a session with 7 requests, the cadence signal fires, and
  the verdict reaches `llm_agent` at score 100.
- `deception.handle_from_template()` returned a template-level 404 `Reply` instead of
  `None` for paths a template did not declare, which made the built-in route table
  unreachable whenever a template was loaded. It now returns `None` and
  `deception.handle()` falls through to the built-in table, so partial override works
  as the module docstrings describe: a loaded template serves its own routes and the
  built-in payload surfaces (`/llms.txt`, `/robots.txt`, `/.well-known/security.txt`,
  `/.env`, `/backup.zip`) remain available alongside it.

### Known issues

Recorded here because they affect what the current tree can actually do. They are
documentation-visible gaps, not design decisions.

- **Scenario `detection` settings are validated but never consumed.**
  `Scenario.apply_to_config()` merges `detection.thresholds` and
  `detection.weight_overrides` into `config["respond"]`, and `cli._apply_scenario()`
  copies that section into the live config — but `respond.py` uses the module-level
  `ACTION_THRESHOLDS` constant and never reads `config["respond"]`, and
  `fingerprint.WEIGHTS` is a module constant with no override hook. Both sets of values
  are shown by `cogtrap scenario show`, which makes the gap easy to miss: every
  deployment uses the built-in 25/50/70/85 gradient regardless of its scenario. The
  scenario `tarpit`, `blocking`, and `countermeasures` sections *are* consumed.
- **Some signals need a minimum sample count within one session.**
  `sequential_low_concurrency` and `no_asset_fetch` require 8 requests in a session,
  and `playbook_order` requires 4 ranked recon paths. A short engagement will not
  reach those thresholds, so the corresponding signals stay silent. This is a
  sensitivity limit rather than a defect, but it means a brief probe of a few requests
  is scored almost entirely on layer-1 signals plus any layer-4 confirmation.
- `deploy/isolate.sh` is referenced by the README that `cogtrap generate` writes, but
  the file does not exist, so a generated instance points at a missing hardening
  script.
- `honeypot/__init__.py` declares `__version__ = "1.0.0"` while `cli.py` and
  `pyproject.toml` declare `0.1.0`.
- `inject.py`'s module docstring still describes "six payload categories" using the
  pre-registry names (`false_negative`, `leak_system_prompt`, `beacon_callback`,
  `budget_exhaustion`, `report_pollution`); the countermeasure registry has nine
  categories and different identifiers.
- RESOLVED: `config.json` contains an `ssh_decoy` section, and `honeypot/ssh_decoy.py` now
  implements it (banner exchange, KEXINIT parsing, algorithm fingerprinting, tarpit).
  Previously:
  exist. `cogtrap doctor` reports it as a missing optional module, so the key is inert
  rather than misleading.
- `tools/sim_llm_agent.py`'s docstring refers to `sim_scanner` / `sim_browser` as
  false-positive controls; neither exists yet.

### Not yet implemented

Tracked in the roadmap in `README.md` and `docs/PRODUCT.md`:

- `honeypot/report.py` — reporting packs and intelligence export (JSONL / CSV /
  STIX 2.1 subset).
- `honeypot/ssh_decoy.py` — SSH protocol decoy: banner exchange, unencrypted KEXINIT
  parsing for algorithm fingerprinting (a JA3-like signature), client identification
  (paramiko/Go/JSch/PuTTY/OpenSSH/scanner), adaptive tarpit with budget circuit breaker,
  and reuse of the shared detection engine so cross-source attribution works over SSH.
- `tools/sim_scanner.py`, `tools/sim_browser.py` — false-positive control simulators.
- `tests/` — unit tests and regression baselines.
- `deploy/isolate.sh` and the systemd/container deployment assets.

## [0.1.0] - 2026-09-18

First development snapshot.

### Added

#### Fault-tolerant HTTP parsing (`honeypot/http_parse.py`)

- Raw HTTP/1.x request parsing that reads malformed traffic instead of rejecting it,
  because malformed requests are among the most valuable fingerprint features.
- Tolerated defects recorded on `req.malformed` as signals: missing version, leading
  blank lines, obsolete header folding, bad header lines, non-standard methods,
  over-long request targets, too many headers, bad `Content-Length`.
- Absolute-URI and authority-form request targets, fragments, and header-order
  preservation for fingerprinting.
- `Content-Length` and `Transfer-Encoding: chunked` body handling, plus
  `Expect: 100-continue` support.
- Non-HTTP detection with hex preview: TLS ClientHello, SSLv2, and SSH banners
  arriving on an HTTP port are recognised and recorded rather than discarded.
- Static-asset classification by extension, used to separate real browsers from
  automation.

#### Agent fingerprinting (`honeypot/fingerprint.py`)

- Four-layer, 31-signal weighted detection model. Layer 4 signals (canary echo,
  instruction compliance, beacon callback, honeytoken read) carry the highest weight
  because a scanner cannot forge them.
- Toolchain tables: AI vendor/inference frameworks (16 patterns), agent frameworks
  (12), generic automation clients (13), traditional scanners (20), search-engine
  crawlers (10).
- Header analysis: 15 agent marker headers, browser-UA-without-browser-headers
  detection, `X-Forwarded-For` hop counting, and proxy header detection.
- Behavioural cadence analysis: micro-bursts (<0.35 s) plus thinking gaps (2–90 s),
  machine-uniform detection via coefficient of variation, and human-like cadence as a
  false-positive suppressor.
- Sequential low-concurrency detection and asset-fetching analysis.
- Semantic analysis: 13 tool-call/orchestration payload patterns (including OpenAI
  `tool_calls`, ReAct traces, JSON-RPC, and MCP `tools/call`), model
  self-identification (14 patterns), natural-language payloads, pentest vocabulary,
  and 41 honeypot-specific paths.
- Playbook monotonicity over 62 ordered recon paths, used to measure whether
  enumeration follows a logical checklist (an agent trait) rather than dictionary or
  random order.
- Behaviour-hash attribution across source IPs, plus an in-memory `CrossIndex` for
  header-signature, behaviour-hash, and UA-hash correlation.
- Campaign aggregation and model-family guessing across 11 model families, with an
  explicit "confirmed context memory, family unknown" result when layer 4 evidence
  exists without a toolchain match.
- `Verdict.to_dict()` for serialisable, replayable output and `render_report_line()`
  for alert-ready single-line summaries.

#### Cognitive-layer countermeasure registry (`honeypot/countermeasures.py`)

- A pluggable registry of 22 countermeasures across 9 categories (`abort`,
  `misdirect`, `pollute`, `leak`, `beacon`, `exhaust`, `guardrail`, `temporal`,
  `credibility`), split into three delivery tiers (5 / 8 / 9 entries).
- Each entry carries `id`, `category`, `tier`, `weight`, `stealth`, `intent`,
  `rationale` (why it works, for auditing and re-tuning), bilingual body text
  (`text_zh` / `text_en`), target surfaces, and preconditions.
- `validate_countermeasure()` rejects malformed plugin entries with a reason,
  including a placeholder check against the known set so that a typo cannot render a
  literal `{foo}` into a response.
- `Registry` with `register` / `load_plugins` / `by_category` / `by_tier` / `select` /
  `stats` / `format_table`, and `build_default_registry(plugin_dir)` for built-in plus
  plugin loading. Bad plugins are reported rather than fatal unless `strict=True`.
- Tier and surface-aware selection with `stealth` breaking weight ties, so a
  low-score session receives institutional boilerplate rather than an overt notice.

#### Payload delivery and canary mechanism (`honeypot/inject.py`)

- `inject` reads the registry and projects it into a compatibility view (`PAYLOADS`),
  so the payload corpus has exactly one source of truth.
- `configure(config)` initialises the registry and loads `payloads/custom/` plugins;
  `apply_profile(include, exclude, max_tier, language)` lets a scenario pack constrain
  what may be delivered without touching code.
- `select_for_tier(score, tier_hint, limit, categories, per_category_limit,
  rotate_seed)` with tier gating: nothing below score 50, tier 1 from 50, tier 2 from
  70, tier 3 from 85 or upon confirmation.
- Deterministic per-session rotation (`_rotate_by_category`): category groups are
  shuffled by a session-token seed and interleaved, with the category order rotated so
  that every category leads in its share of sessions. This fixes two problems — a
  corpus that effectively shrinks to the top few payloads, and a stable signature the
  attacker could fingerprint — while keeping a single session's composition stable.
- Per-surface delivery caps and rotation policy: `llms.txt` 4 items / one per category
  with no rotation; HTML comments 3 items rotated; `robots.txt` and fake `.env` 2 items
  rotated; JSON `_meta` 1 item.
- Nine delivery surfaces: `llms.txt`, `robots.txt`, `/.well-known/security.txt`, HTML
  comments, response headers, JSON `_meta`, error pages, OpenAPI descriptions, and
  fake `.env` comments.
- `CanaryManager`: cryptographically random `hpx-` tokens issued per session, with
  owner attribution (session, IP, timestamp, kind), bounded capacity (20 000), and
  scanning of arbitrary text for issued tokens.
- Expectation machinery (`build_expectations` / `check_expectations`) for verifying
  instruction compliance: required `X-Trace-Id`, solicited `X-Scope-Config` (system
  prompt and tool list capture), beacon path access, and `_hp_verify` parameter echo.
- `PayloadContext` with derived values: trace tokens, fabricated pagination totals
  (48 000–240 000 records), a fabricated CVE pool for report pollution, a fabricated
  asset registry ID, lure host/port, and a session hint.
- `summarize_decisive()` to assemble confirmation evidence into reporting entries.

#### Deception surfaces (`honeypot/deception.py`)

- 62 routes across 34 handlers: site convention files, sensitive-file honeytokens,
  fake downloads, fake vulnerability surface, fake API, fake admin consoles, directory
  listings, and beacon endpoints.
- Template-driven serving via `Deception(config, canary, store, instance=...)` and
  `handle_from_template()`: exact route match, vulnerability surface, credential
  honeytokens, and a template-level 404, with `runtime_vars()` available for rendering
  fake error bodies that echo attacker input. The beacon endpoint is resolved before
  the template so a template cannot shadow it.
- Credential routes with an empty body are generated from the credential definition, so
  a template author only declares *which* honeytoken a path delivers.
- Fake injection surface: SQL injection markers in a request produce a fabricated
  MySQL error with a plausible error code, query echo, and a hint — while remaining
  permanently non-exploitable.
- Credential capture from decoy login forms (form-encoded and JSON), logged as
  forensic events.
- Deterministic data generation seeded from the session token, so repeated requests
  return consistent records and a refresh cannot reveal decoy data changing.
- Honeytoken wiring: routes declare their honeytokens; reads are registered in
  telemetry with first-read time, read count, and the sessions that touched them.
- Reserved-domain and synthetic-data policy (`example.com`, RFC 2606; synthetic names)
  with no real PII anywhere in the generated content.
- Unified payload injection in `_finalize()`: response-header payloads plus HTML
  comment or JSON `_meta` payloads, applied by score.
- Beacon endpoint returning a 1×1 transparent PNG so that compliance looks like an
  ordinary image fetch.

#### Honeypot template engine (`honeypot/templating.py`)

- Declarative JSON templates with a versioned schema (`schema: 1`) and fallback to
  built-in defaults for undefined routes.
- Strict validation (`validate`) with field path and actionable hint on every failure:
  identifier format, category, payload and tarpit profiles, route path/method
  uniqueness, status ranges, route kinds, tarpit weights, vulnerability and credential
  requirements, and undefined-variable detection.
- Non-fatal linting (`lint`) reporting `error` / `warning` / `info` issues: missing
  routes, missing credential honeytokens, missing site name, missing internal hosts,
  aggressive profile advisory, routes without honeytokens, references to undefined
  credential IDs, and suspected real domains.
- Template skeleton generation (`scaffold`) with a `_help` field the validator ignores
  but humans can read, since JSON has no comments.
- `Template` object with an O(1) route table and lookup helpers for routes,
  vulnerabilities, and credentials.
- `HoneypotInstance` for user-generated honeypots: deep-merge overrides, re-validate
  the merged result, derive an instance token, and render deterministically.
- `runtime_vars(request, extra)` injecting per-request values (`query`, `payload`,
  `method`, `path`, `user_agent`, `body`, `client_ip`, `target`, `header`).
- Deterministic rendering seeded by `SHA256(instance_id | canary | host)`, satisfying
  the requirement that a refresh must not change the data.
- Variable system: template, instance, derived, and runtime variables, plus inline
  generators (`{{rand.hex:8}}`, `{{rand.int:1-100}}`, `{{rand.choice:a|b|c}}`,
  `{{rand.ip}}`, `{{rand.date:30}}`).
- Template discovery with built-in/custom search directories and
  custom-overrides-builtin resolution. Bad templates do not break listing; they are
  surfaced by `lint` instead.
- Nine template categories (eight industry verticals plus `generic`) and the
  `passive` / `balanced` / `aggressive` and `light` / `standard` / `heavy` profile
  enumerations.
- Eight built-in templates, one per industry vertical: `gov-portal` (government, 24
  routes), `corp-oa` (enterprise, 23), `shop-mall` (ecommerce, 23), `ops-platform`
  (ops, 23), `hospital-his` (healthcare, 23), `bank-gateway` (finance, 26),
  `campus-edu` (education, 22), `iot-gateway` (industrial, 24). Each carries a
  consistent technology-stack identity, matching `Server` header and `X-Powered-By`,
  five fabricated vulnerabilities, and five or six credential honeytokens. All eight
  validate with zero errors and zero `lint` warnings.

#### Scenario packs (`honeypot/scenarios.py`)

- Scenario schema (`schema: 1`) bundling template + overrides + countermeasure policy +
  tarpit intensity + detection tuning + blocking policy into a reviewable preset.
- Validation of the non-obvious invariants: action thresholds must be **strictly
  increasing** (otherwise a tier is unreachable), `max_tier` in 0–3, identifier
  charset, `blocking.mode` in `absorb`/`drop`, and `weight_overrides` in −100..100.
- `lint` raising a warning when a scenario ships with `blocking.armed` **and**
  `blocking.apply` both true, because loading it would immediately modify the host
  firewall.
- `Scenario.apply_to_config(config, instance)` producing a merged configuration
  without mutating the source, plus `countermeasure_filter()` /
  `allows_countermeasure()` for id-level include/exclude filtering.
- `scaffold()`, `list_scenarios()`, `load_scenario()`, and the `describe()` /
  `stats()` reporting helpers.
- Five built-in scenario packs: `hw-drill-dmz`, `agent-hunter`, `daily-decoy`,
  `scanner-sink`, `internal-tripwire`. All five validate with zero warnings and all
  five template references resolve.

#### Decision engine (`honeypot/respond.py`)

- Five-step score-to-action gradient: `serve`, `serve_watch`, `tarpit`,
  `deceive_inject`, `lockdown`.
- Deliberate slow start: no strong countermeasures until there is enough evidence to
  confirm, and until revealing them can no longer let the agent adapt.
- Payload tier selection, forced to tier 3 when decisive evidence exists.
- Expectation registration, alerting thresholds, and block-candidate gating.

#### Adaptive tarpit (`honeypot/tarpit.py`)

- Exponentially growing per-session delay (`base × growth^n`, jittered) so a fixed
  client timeout cannot be used to bypass the tarpit.
- Four tarpit plans scaling with session progress and per-response tarpit weight:
  light pre-body delay, chunked drip, drip plus hold, and infinite-stream lockdown.
- `TarpitBudget` with three independent guards: per-session cumulative cap, global
  per-minute rolling-window budget, and a load-shedding breaker that degrades to
  immediate responses (and alerts) when system load exceeds a threshold.
- Proportional compression when only part of a requested budget is granted, rather
  than abandoning the tarpit entirely.

#### Service loop (`honeypot/server.py`)

- asyncio raw TCP/HTTP service with optional server-side TLS.
- Per-request pipeline: tolerant parse, session profiling, canary echo scan,
  compliance/beacon verification, fingerprint verdict, response decision, deception
  response generation, tarpit plan, response write, telemetry persistence, alerting.
- Canary scanning across the request target, query string, body (first 16 KB), and all
  header values, logged as `critical` evidence with the originating session and IP.
- Chunked drip and infinite-stream response writers. The infinite stream emits
  fabricated result blocks and invites the client to fetch the next page, so an
  agent's tool call keeps "succeeding" while pulling filler into its context window —
  the quadratic cost amplifier.
- Non-HTTP handling: TLS handshakes, SSH banners, and binary probes are recorded and
  answered with a deliberate 400 and a mismatched `Server` header, so scanners
  misclassify the port.
- Connection admission control (`max_connections`, `max_per_ip`) with an event logged
  on rejection.
- Per-connection exception containment: a single malformed request can never terminate
  the service.
- Campaign attribution wired into persistence, and block-candidate emission when the
  score reaches the configured threshold and blocking is armed.
- `runtime_stats()` for live operational metrics including tarpit budget usage, load
  ratio, and canary statistics.

#### Telemetry (`honeypot/store.py`)

- Seven SQLite tables in WAL mode: `sessions`, `requests`, `signals`, `campaigns`,
  `honeytokens`, `events`, `blocks`, with indices on IP, behaviour hash, timestamps,
  signal name, event kind, and token.
- Raw request headers and body are retained (truncated to safe lengths) because
  reporting requires the original bytes.
- Signals stored as their own table so that per-signal discriminative power can be
  measured and the weights re-tuned.
- Campaign upsert keyed on behaviour hash, merging IP sets, UA sets, toolchain, model
  guess, score, and evidence across sessions.
- Honeytoken read tracking returning whether a read was the first, so first reads can
  raise a distinct event.
- Query helpers for sessions, requests, request replay by time range, signal summaries,
  events, campaigns, IP ranking, and aggregate statistics.
- Day-based retention pruning (`prune`), default 180 days.

#### Blocking and absorption (`honeypot/block.py`)

- `drop` and `absorb` modes. Absorption DNAT-redirects an attacker's business-port
  traffic into the honeypot so that every attempt becomes intelligence rather than a
  firewall rejection that sends the attacker looking elsewhere.
- Triple safety design: rules are never applied by default (written to `out/rules/` for
  human review), whitelisting is enforced in code, and every ruleset must pass
  `nft -c -f -` dry-run validation before it can be applied.
- Whitelisting of loopback, link-local, multicast, `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, and `100.64.0.0/10`, with unparseable addresses treated as
  protected.
- A single `inet` table for the whole ruleset, because nftables sets cannot be
  referenced across tables — a cross-table set reference silently breaks absorption.
- Ruleset TTL on the attacker set, so rules expire instead of accumulating forever.
- Ruleset files carry their own operational notes: how to apply, how to revoke the
  whole set, and how to inspect it. Individual rule files include the equivalent
  iptables command.
- Block candidates generated from telemetry (`load_rules_from_store`) for IPs above a
  score threshold, and automatically on high-score sessions when blocking is armed.

#### Command-line interface (`honeypot/cli.py`, `bin/cogtrap`)

- `argparse`-based CLI with lazy subcommand imports, so a missing optional module
  (dashboard, SSH decoy, reporting) disables only that feature.
- `serve` wiring the layers together: load config, instantiate the template
  (`--template` / `--instance`) or load a pre-generated instance file, call
  `inject.configure(cfg)` to load countermeasure plugins, apply a scenario pack
  (`--scenario`) through `Scenario.apply_to_config` and `inject.apply_profile`, then
  hand the instance to `HoneypotServer`.
- `generate` producing a runnable instance directory: `config.json` (scenario merged),
  `instance.json` (template + overrides), `scenario.json`, `start.sh`, `README.md`,
  and the `var` / `logs` / `out/reports` / `out/rules` subdirectories. The generated
  README states the four pre-deployment requirements: isolation, egress denial,
  firewall changes default-off, and authorisation.
- `template list|show|new|validate|lint|render`, where `render` previews the rendered
  pages and the payload delivery surfaces.
- `scenario list|show|new|validate|lint`, with `lint` surfacing the safety warnings.
- `countermeasures list|stats|show`.
- `doctor`: Python version, core module integrity (13 modules imported individually),
  missing optional modules, template and scenario counts, countermeasure count,
  writability of `var` / `logs` / `out`, `nft` availability and version, and security
  configuration checks (firewall default-off, whitelist coverage, resource caps).
  Distinct exit codes (`EXIT_OK`, `EXIT_ERROR`, `EXIT_BAD_INPUT`, `EXIT_NOT_READY`)
  make it usable as a deployment gate.
- All state-changing operations default to writing files for review, never to applying
  changes immediately.

#### Configuration (`honeypot/config.py`)

- Deep-merged defaults plus `config.json`, with dotted-path lookup
  (`cfg.get("http.port")`) and both access styles supported.
- Project-root-relative path resolution and runtime directory creation.
- Conservative defaults: blocking disarmed and not applied, TLS off, private ranges
  whitelisted, all resource caps and tarpit budgets set.

#### Benchmark simulator (`tools/sim_llm_agent.py`)

- A labelled LLM-agent simulator for validating detection and countermeasures: it reads
  `/llms.txt`, walks a logical recon order, produces micro-bursts separated by thinking
  gaps, echoes canary tokens back into later requests, obeys embedded header
  instructions, calls the beacon endpoint, uses one connection per tool call, and never
  fetches static assets.
- Options for source-IP binding (to exercise cross-source attribution), cadence
  compression (`--fast`), user-agent override, and thinking-gap bounds.
- Standard library only; it targets only the host you point it at.

[Unreleased]: https://github.com/skx112/llm-honeypot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/skx112/llm-honeypot/releases/tag/v0.1.0
