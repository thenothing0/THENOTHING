# PHASE_ATTACK_AUDIT_REPORT — Attack Section

> Independent audit of `hydra/attack/` + `hydra/attack_runtime/` · 2026-06-16 · all numbers verified
> live. Branch `bug-bounty-exploitation`. This report is deliberately honest about gaps; several
> integrations described in commit messages are **partial** and are flagged here.

## 1. Current MCP count
- **180 MCP tools total.**
- **~24 offensive attack-section tools** — 16 `attack_*` (access_control, chain_execute, execute,
  graphql, jwt, login, plan, privesc, queue, race, recon_scan, report, save_findings, scan,
  scan_crawled, web_probe) + 3 OOB (`oob_payload`, `oob_confirm`, `interactsh_register`) + 3
  authorization (`register_bounty_program`, `authorize_target`, `load_bounty_scope`) + 2 payload/bypass
  (`generate_payloads`, `waf_bypass`).
- The other 7 `attack_*` tools (`attack_tactics/techniques/gaps/profiles/skills/capabilities/health`)
  are **Phase-T ATT&CK *intelligence*** (advisory, NON-executing) — not offensive tools.

## 2. Attack package inventory
| Package | Modules | LOC |
|---------|---------|-----|
| `hydra/attack/` (pure, network-free) | **19** — chain_exec, chain_templates, crawl_seed, detection, evidence, graphql, injection_points, jwt_attacks, knowledge_loop, oob, payloads, queue, rbac, report_builder, two_signal, util, waf_bypass, web_probes, workflow | 2136 |
| `hydra/attack_runtime/` (network/I-O boundary) | **6** — confirm, interactsh, login, oob_client, race, session | 711 |
| **Tests** | `tests/attack/` + `tests/attack_runtime/` | **78** (+ MCP behavior/contract tests) |

## 3. Two-signal confirmation matrix
The two-signal rule lives in `scan()` (`DifferentialDetector.signals()` → `TwoSignalConfirmer`).
**Only the signal-based classes route through it; the rest confirm via a separate mechanism.**

| Class | Two-signal in `scan()` | Mechanism |
|-------|------------------------|-----------|
| **XSS** | ✅ Yes | reflection (content-type aware) **+** DOM execution (`BrowserConfirmer`/Playwright) |
| **SQLi** | ✅ Yes | error signature **+** timing (independent families); boolean-pair available but *not* auto-wired into scan |
| **Redirect** | ✅ Yes | off-host `Location` **+** status differential (302) |
| **SSRF** | ⚠️ No (blind) | OOB only; the OOB confirmer is **not wired into the scan loop** → confirmed via the *manual* `oob_confirm` tool |
| **XXE** | ⚠️ No (blind) | same as SSRF — OOB + manual |
| **JWT** | ➖ N/A | separate crypto: forge (`attack_jwt`) → **manual replay** → observe auth bypass (not signal-based) |
| **CORS** | ➖ N/A | single-probe (`attack_web_probe`): reflected Origin + credentials (one mechanism) |
| **Race** | ➖ N/A | concurrency outcome distribution → `candidate` verdict |

**Honest gap:** of the 8 classes, only **3 (XSS, SQLi, Redirect)** are genuinely two-signal-confirmed
inside `scan()`. SSRF/XXE depend on OOB that the scan loop does not currently invoke; JWT/CORS/Race
confirm through separate, single-mechanism flows.

## 4. Knowledge-graph integration
**Flow:** `scan()` (verdict=`confirmed`) → `FindingPublisher.publish()` (skips suspected/single-signal)
→ `save_fn` = `save_finding(title, severity, target, description, finding_type)` → SQLite INSERT into
`LEARNING_DB.findings`; **and** `record_outcome()` → `attack_memory.jsonl`.

- **Fields persisted** (`findings` table): `id` (autoincrement), `title`, `severity`, `target`,
  `description`, `evidence`, `finding_type`, `created_at`.
- **Deduplication:** only at the *report* layer (`AttackReporter.dedup()` by `(vuln_class, point,
  verdict)`). **No DB-level dedup** — every `save_finding` call appends a row.
- **Confidence handling:** **none persisted** — there is no confidence column. "Confidence" is implicit
  in the two-signal gate (only `confirmed` findings are written).
- **⚠️ Material gap:** `save_finding` writes to the **v7 `LEARNING_DB` findings table**, which is *not*
  the Phase-A canonical wiki, and is **not consumed by** Phase-D source learning or the Phase-S/T/U
  derived analytics (those read `tool_health.db` / `verification_learning.db` / the catalog / the wiki).
  The loop-back therefore **terminates at `findings.db` + `attack_memory.jsonl`**; the "feeds the
  intelligence layers" claim is **aspirational / not yet wired** (see §9).

## 5. Attack coverage matrix
| Tier | Classes |
|------|---------|
| **Fully supported** (active + confirmable) | XSS, SQLi (error/time), Open Redirect, LFI / Path Traversal (file marker), 403/WAF bypass, CORS, GraphQL (introspection/field-suggestion), JWT (forge+replay), IDOR (dual-session), RBAC/priv-esc, injection-point discovery, crawl-seeded scan |
| **Partially supported** (capability exists, detection weak / OOB / manual) | SSRF, XXE (payloads + OOB infra, not wired into scan), SSTI (marker only), CRLF, CMDI (payloads but **no detection signal**), cache poisoning (detection-only/benign), host-header, race conditions (candidate-only), blind-SQLi-OOB, authenticated multi-step (CSRF yes; OAuth/MFA no) |
| **Advisory / plan-only** | HTTP request smuggling (plan-only, never sent), chain execution (validates stages, **no auto-pivot**) |
| **Unsupported** (not built) | NoSQL injection, LDAP injection, insecure deserialization, prototype pollution, mass-assignment, **BOLA/BFLA** (API top-10), OAuth/OIDC/SAML protocol attacks, web cache deception, GraphQL mutations/authz, business-logic |

## 6. Safety controls
- **Authorization gate flow:** every target-naming tool → `BugBountyAuthorizationGate.authorize(target,
  action)` → **deny-by-default**. Host extracted → matched against registered programs (wildcard covers
  subdomains, bare host is exact); explicit out-of-scope wins; **absolute prohibitions** (DoS /
  destructive / data-exfil / social) denied even in-scope; exploitation/data-access forced **PoC-only**.
  `HttpExecutor` **re-verifies authorization on every request** (defense-in-depth).
- **Scope verification:** `register_bounty_program` (operator-declared) or `load_bounty_scope` (live
  HackerOne/Bugcrowd via `ScopePolicyEngine`) → persisted `data/authorized_programs.json` →
  `covering_program()` / `_excluded()` conservative matching.
- **Rate limiting:** `HttpExecutor` min-interval (MCP-clamped 0.1–5 req/s) + exponential **WAF back-off**
  on 429/503 (bounded ≤5 s); `RaceTester` hard-capped at 30 concurrent.
- **Audit logging:** gate audit log (every allow/deny + `audit_id`), executor audit log (every send +
  block), `attack_memory.jsonl`.
- **OOB controls:** talks only to the operator-supplied collaborator; full interactsh crypto (RSA
  register + AES-CFB/RSA-OAEP decrypt); cache-poison/host use benign markers; smuggling never auto-sent.

## 7. Benchmark (verified live, localhost)
| Path | Time |
|------|------|
| Cold start (import + gate + first scan) | **116–163 ms** |
| Warm scan (1 endpoint) | **57–79 ms** |
| Crawl scan (5 distinct seeds) | **305–339 ms** |
| Authenticated scan (session) | **57–60 ms** |
| Graph publication (`save_finding`) | **~3.8 ms / finding** |

**Caveat:** these measure compute + localhost I/O. On a **real target** the wall-clock is dominated by
**rate-limiting** — a 6-payload × 8-point scan ≈ 48 requests ≈ **~48 s at the default 1 req/s**.
Sequential scanning is the performance bottleneck at scale (see §8).

## 8. Remaining architectural gaps
**Top 10 weaknesses**
1. Loop-back does **not** feed Phase-D/S/T/U — it writes only `findings.db` + `attack_memory.jsonl`.
2. SSRF/XXE **active OOB testers not wired into `scan()`** (manual `oob_confirm` only).
3. **Sequential scanning** — no concurrency; slow at real scale.
4. No **scan state / resume / cross-run dedup**.
5. No **campaign orchestration** — ~24 tools are manually chained.
6. **CMDI/SSTI detection signals weak/absent** (payloads exist, confirmation does not).
7. No **response normalization** (gzip / charset / SPA-rendered DOM).
8. `save_finding` → v7 findings table, **not** the canonical wiki; **no confidence / no DB dedup**.
9. No **API top-10** (BOLA/BFLA/mass-assignment) despite having session/access-control primitives.
10. No NoSQL / deserialization / prototype-pollution / auth-protocol coverage.

**Top 10 highest-value future improvements**
1. **Campaign orchestration** (recon → prioritize → scan → confirm → chain → report → graph), one gated flow.
2. **Active OOB SSRF/XXE/deserialization** testers (infra already exists).
3. **Wire the loop-back** into Phase-D learning + make Phase-S/T/U consume confirmed findings (close §9).
4. **Bounded scan concurrency** + state/resume + cross-run dedup (the perf + repeat-work fix).
5. **API top-10** (BOLA/BFLA/mass-assignment) on the existing session model.
6. **Response normalization** + multi-baseline noise reduction (detection accuracy).
7. Remaining injection variants (NoSQL / deserialization / prototype pollution).
8. **Auth-protocol attacks** (OAuth/OIDC/SAML).
9. **Confidence scoring** on findings + DB-level dedup + canonical-wiki write path.
10. Proxy/Burp interop + a scan results dashboard.

## 9. Dependency diagram (current reality vs intended)
```
                       ┌─────────────────────────── CURRENT (wired) ───────────────────────────┐
  Attack section ──► save_finding ──► LEARNING_DB.findings ──► get_findings (read-back only)
       │                └─► record_outcome ──► attack_memory.jsonl
       │
       └──► Authorization Gate ──► hydra/scope + hydra/guardrails   (consumed: YES)

  ┌──────────────────────────── INTENDED (NOT yet wired) ────────────────────────────┐
  Attack confirmed findings  ✗─►  Phase-D source learning (reads tool_health.db / verification_learning.db)
                             ✗─►  Phase-S Opportunity Intelligence  (reads catalog + tool-health)
                             ✗─►  Phase-T Threat Intelligence       (reads Phase-P/Q/R/S, ATT&CK map)
                             ✗─►  Phase-Q Campaign Intelligence      (reads Phase-P)
                             ✗─►  Phase-R Skill Intelligence         (reads capability graph)
```
**Reality:** the attack section **consumes** the authorization/scope/guardrail layers (✓) but its
output (`findings.db`) is **not read** by the Phase-D/S/T/U derived intelligence — those layers read
the catalog + derived learning logs + the wiki. The arrows to Opportunity/Threat/Campaign/Skill
intelligence are currently **broken** (✗). Closing this is improvement #3.

## 10. Readiness assessment
| Use case | Rating | Notes |
|----------|--------|-------|
| **Research tool** | **HIGH** | Comprehensive, well-tested (78 attack tests), deterministic, safe-by-construction. Excellent for studying technique modelling + gated exploitation. |
| **Bug-bounty tool** | **MEDIUM-HIGH** | Gated, PoC-only, strong web coverage + evidence/CVSS reporting. Held back by SSRF/XXE-automation, API-top-10 gaps, and sequential-scan latency. |
| **Internal security assessment** | **MEDIUM** | Usable for web app testing; needs auth-protocol attacks, more classes, concurrency, and richer reporting/ticketing before unattended engagements. |
| **Production maturity** | **Level 3 / 5** (functional + tested, not yet hardened for unattended scale) | Solid, well-factored, safety-first core; gaps in orchestration, robustness, and the intelligence loop-back. |
| **Estimated engineering debt** | **Moderate (~2–4 focused weeks)** | Dominated by: loop-back wiring (#3), scan concurrency + state (#4), campaign orchestration (#1), active OOB testers (#2), and the findings-store ↔ canonical-wiki split. Test/lint/safety scaffolding is healthy → debt is *feature/integration* debt, not *quality* debt. |

---
**Verdict:** a genuinely capable, safety-first authorized-exploitation pipeline with excellent
engineering hygiene, whose next value is in **orchestration, robustness, and closing the
intelligence loop-back** rather than more vuln-class breadth. The most important correction this audit
surfaces: the knowledge-graph loop-back is **partial** — it persists findings but does not yet feed the
Phase-D/S/T/U intelligence it was intended to enrich.
