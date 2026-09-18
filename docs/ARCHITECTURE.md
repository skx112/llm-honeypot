# CogTrap Architecture

**Version**: v1.0 (matches the current code, 2026-09-18)
**Nature**: AS-BUILT specification — it describes the system that **exists**, not a proposal
**Enforcement**: the module list, dependency rules and public interfaces in this file are verified by `tests/test_architecture.py`. If the documentation and the code disagree, the test fails.

> This is the concise English edition. The full edition ([`ARCHITECTURE.zh-CN.md`](ARCHITECTURE.zh-CN.md), Chinese) carries the same structure plus extended narrative, sequence diagrams for the three key flows, and the complete ADR reasoning.

---

## 0. Document map

| Document | Answers | Audience |
|---|---|---|
| `docs/PRODUCT.md` | What it does, for whom | Evaluators, users |
| **This file** | What the system is made of, boundaries, interfaces, dependency rules | Contributors, maintainers, integrators |
| `docs/DESIGN.zh-CN.md` | Why it is designed this way | Reviewers, researchers |
| `CONTRIBUTING.md` | How to change it | Contributors |

## 1. One-minute overview

```
 CogTrap = a honeypot-based defence and countermeasure system aimed at
           LLM-driven automated penetration testing

 request ──► [L2 server / ssh_decoy] ──► [L0 http_parse tolerant parsing]
                  │                        │  client session keyed by (IP, UA-hash)
                  ▼                        ▼   (survives across TCP connections)
             [L0 fingerprint 4-layer verdict ◄── canary echo / compliance checks]
                  │                        │
                  ▼                        ▼
             [L2 respond score→action]  [L1 inject payload surfaces]
                  │                        │
                  ▼                        ▼
             [L0 tarpit (budgeted)]     [L2 deception template→built-in fallback]
                  └───────────┬────────────┘
                              ▼
                  [L0 store telemetry] ──► [L0 report forensic bundles]

 extensible data plane: templates (what it looks like) × scenarios (how aggressive)
                      × countermeasures (what they say)
                      = `cogtrap generate` produces a runnable honeypot instance
```

**Five things worth knowing first:**

1. **Zero third-party dependencies** (Python 3.6+ stdlib). A honeypot's fate is to be compromised; dependencies are supply-chain attack surface. Enforced by CI.
2. **Receive-only, never dial out.** All countermeasures happen inside our own server responses. Egress is dropped at the OS level by the deployment script.
3. **Four-layer detection** — toolchain → behavioural cadence → semantics → **interactive confirmation** (canary echo / instruction compliance), which classical scanners physically cannot forge because they do not parse response content.
4. **The architecture is enforced by tests, not convention** — 12 gates check layering rules, doc/code consistency, and that the stable data contracts only ever grow.
5. **Dangerous capabilities default off** — firewall rules are written to files but not applied by default; the dashboard binds to loopback only.

## 2. Non-negotiable constraints

Each constraint lists the reason, the acknowledged cost, and how it is enforced.

| # | Constraint | Why | Enforced by |
|---|---|---|---|
| C1 | Stdlib only | A compromised honeypot must not become a supply-chain victim | CI `zero-dependency` job (AST scan) |
| C2 | No outbound connections to attackers | Attack sources are often hijacked third parties; dialling out also exposes blue-team nodes | `deploy/isolate.sh` egress DROP; no client sockets in code |
| C3 | Safe defaults (dangerous off) | A misapplied firewall rule locks *you* out; telemetry exposure leaks captured credentials | `test_documented_defaults_match_configuration` |
| C4 | Tolerance over strictness in parsing | Malformed requests are the most valuable fingerprints; a framework would 400 them away | `test_core.py` malformed-input cases |
| C5 | Exactly one implementation per concern | Two threshold tables inevitably contradict each other (this happened once) | single `evaluate()`, single `resolved_thresholds()` |
| C6 | Never return an empty body | An empty response is itself a honeypot tell | `test_no_zero_byte_responses` |

## 3. Layering and dependency rules

```
 L3  cli                     orchestration, the only entry point
 L2  server ssh_decoy deception respond        protocol & adaptation
 L1  inject templating                          domain
 L0  config http_parse store fingerprint countermeasures
     scenarios block tarpit report dashboard
     alerts hub                                 foundation (self-sufficient)
```

| Rule | Meaning | Rationale |
|---|---|---|
| R1 | No circular dependencies | Cycles defeat independent reasoning and testing |
| R2 | Dependencies point to the same or lower layer only | Upstream changes must not ripple downward into detection |
| R3 | L0 imports no internal module | The foundation is where detection correctness lives |
| R4 | `server` must not depend on `cli` | Orchestration lives in exactly one place; a hidden `server ↔ cli` cycle once escaped static analysis via `__import__()` |

All four are checked on every test run. **Lazy imports count as dependencies**: `__import__("x")` and `importlib.import_module("x")` are tracked exactly like `import x`, because a lazy import still creates a real edge — that is precisely how a cycle once hid.

**Adding a module takes three coordinated edits** (create the file; register it in `LAYERS` in `tests/test_architecture.py`; document it in §4 of this file and in the Chinese full edition). Forgetting any of them turns CI red — there is no way to add a module that escapes the layering rules.

## 4. Component summary

Each module documents: responsibility / public interface / dependencies / **deliberately not done**. Full detail in the Chinese edition §3; the authoritative interface list is the code itself (verified against this documentation by test).

| Module (layer) | Responsibility | Depends on | Deliberately not done |
|---|---|---|---|
| `config` (L0) | Defaults + JSON deep-merge, path resolution | — | Schema validation (owned by each module's `validate()`) |
| `http_parse` (L0) | Tolerant HTTP/1.x parsing, non-HTTP detection | — | Protocol rejection; HTTP/2 |
| `store` (L0) | SQLite(WAL) telemetry, 7 tables | — | ORM, async driver, auto-migration |
| `fingerprint` (L0) ★ | 4-layer verdict, session profile, cross-source index | — | Disposal decisions, storage, parsing (kept dependency-free so verdicts are unit-testable and replayable) |
| `countermeasures` (L0) | Payload corpus, plugin registry | — | Delivery (that is `inject`), scoring |
| `scenarios` (L0) | Policy packs: thresholds/weights/whitelists | — | Global side effects (`apply_to_config` returns a new dict) |
| `block` (L0) | nftables rule generation, dry-run validation | — | Auto-application (C3) |
| `tarpit` (L0) | Delay planning, three-tier budget guardrails | — | Execution (plan and execution are separated so tarpit logic is testable without IO) |
| `report` (L0) | Forensic bundles, evidence digests | — | Credibility judgement; redaction (no real assets exist inside a honeypot by construction) |
| `dashboard` (L0) | Loopback-only operator UI | — | Authentication (loopback *is* the boundary); frontend build step |
| `dom_decoys` (L0) | DOM-level interactive decoys for browser agents | — | JS logic execution (server routes handle the interaction) |
| `alerts` (L0) | File + optional async webhook alerting | — | Retry queues/signing (optional-dep territory); multi-protocol gateways |
| `hub` (L0) | Multi-node aggregation: ingest, merge, watermarked push | — (store injected) | Public exposure (internal facility only); bidirectional sync |
| `inject` (L1) | Delivery surfaces, canary manager, compliance checks | countermeasures | Corpus definition; scoring |
| `templating` (L1) | Template schema, deterministic rendering, instantiation | http_parse | Response generation |
| `respond` (L2) | Score→action mapping, expectation checks | fingerprint, inject | Tarpit, response content |
| `deception` (L2) | Routing & content: template-first, built-in fallback | inject | Detection, disposal |
| `server` (L2) | asyncio HTTP honeypot, cross-connection sessions | many (see test) | Depends on `cli` (R4) |
| `ssh_decoy` (L2) | SSH banner + unencrypted-KEXINIT fingerprinting | fingerprint, http_parse, inject, respond, tarpit | Full SSH session (no crypto library); credential capture (post-KEX, unreachable) |
| `cli` (L3) | The only orchestration point, 8 subcommands | all lower layers | Business logic |

## 5. Data architecture

SQLite + WAL. Seven tables: `sessions`, `requests`, `signals`, `campaigns`, `honeytokens`, `events`, `blocks`.

Three deliberate decisions: request originals are retained (evidence needs the original bytes — full headers/body, truncated to safe lengths); signals live in their own table (tuning requires knowing which features discriminate); honeytokens self-register on first read (registration and reading happen on different code paths — a silent miss would erase the highest-value forensic events).

Evidence integrity: `report.evidence_digest()` computes a SHA-256 over the request sequence and key events; tampered bundles are detectable.

## 6. Deployment architecture

Three listeners: HTTP honeypot (`:8080`), SSH decoy (`:2222`), dashboard (`127.0.0.1:8899` — loopback only; remote viewing via SSH tunnel). Egress dropped by `deploy/isolate.sh`. Hard requirements (isolated VLAN, no bidirectional routing to production, one-way log shipping, zero real credentials) are listed by `isolate.sh --check` for human confirmation.

Single-process asyncio by design: the workload is IO-bound, and sessions, the cross-source index and the tarpit budget must share memory. Scaling out means more decoy instances, not multiprocessing within one.

## 7. Extension contracts and their stability

| Extension point | Carrier | Stability | Breaking-change policy |
|---|---|---|---|
| Honeypot templates | `templates/*.json` + `custom/` | **stable** | fields/enum values/placeholders only ever added |
| Scenario packs | `scenarios/*.json` + `custom/` | **stable** | same |
| Countermeasure plugins | `payloads/custom/*.json` | **stable** | same; placeholder whitelist only grows |
| `config.json` keys | — | **stable** | keys only added |
| Python module interfaces | — | evolving | no compatibility promise; the skeleton (§4) kept stable where practical |
| SQLite schema | — | internal | export/migration path on change |

Data formats are the stable surface because they are the users' long-lived private assets; Python interfaces are the maintainers' concern, and over-promising there would block refactoring.

**How "additive only" is enforced** (`test_stable_contracts_are_additive_only`): a baseline snapshot records the contract surface — required fields derived **empirically** (delete each field from a valid document; validation failure ⇒ required), enum sets, the placeholder whitelist, config keys. Two different rules apply, and confusing them is easy:

- enums / placeholders / config keys → **superset allowed** (additions are backward compatible)
- **required-field sets → must stay exactly equal** (adding a required field breaks every existing user document just as surely as removing one — found by negative verification, not by reading code)

## 8. Security of the system itself

A honeypot's fate is to be compromised; the architecture assumes it. Full threat→mitigation table in the Chinese edition §8. Highlights: egress DROP; budget circuit breakers so tarpit cannot exhaust ourselves; firewall rules dry-run validated and never applied by default; dashboard loopback-only with `nosniff`/`no-store`; path-traversal checks on static serving; and the operator UI renders telemetry **only via `textContent`** — telemetry contains attacker-controlled text (User-Agent, paths, payloads), and `innerHTML` would invite the attacker into our own console (enforced by test).

## 9. Known debt and roadmap

Honestly listed (Chinese edition §11): synchronous store writes inside the event loop; `cli.py` and `deception.py` are large; duplicated client-session acquisition between `server` and `ssh_decoy`; no TLS/JA3 fingerprinting (costly without a crypto dependency); no closed-loop measurement of countermeasure effectiveness yet. Deliberately unscheduled: active counter-strikes and anything requiring third-party dependencies.

---

*Any structural change — new module, changed dependency direction, contract change — must update this file, the Chinese full edition, and `tests/test_architecture.py` together, or CI fails. That friction is the point.*
