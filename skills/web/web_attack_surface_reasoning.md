# Skill: Web Attack Surface Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `web_attack_surface_reasoning` |
| **version** | `1.0.0` |
| **category** | Web |
| **correlates_with** | XSS, SQLi, SSTI, LFI, open redirect, CSRF, CORS, cache poisoning |

## Objective
Establish the generic web attack surface for a target and drive the gated injection scanners
efficiently: fingerprint the stack, mine hidden parameters, then run **fingerprint-prioritized**,
two-signal differential scans across discovered injection points.

## Scope Rules
- Deny-by-default gate on every target; PoC-only payloads; rate-limited.
- Respect WAF/edge backoff signals.

## Trigger Conditions
- `html_response`, `forms`, `cookies`; any in-scope web origin.

## Technology Fingerprints
- Generic: server/header banners, CMS markers, framework cookies, JS bundles.

## Recon Methodology
1. `whatweb_detect` + `wafw00f_detect` → stack + WAF.
2. `attack_tech_plan` on the fingerprint → which vuln classes are worth testing.
3. Crawl + param-mine to expand injectable surface.

## MCP Tool Orchestration Logic
- `whatweb_detect` / `wafw00f_detect` — fingerprint + WAF.
- `attack_tech_plan` — recommend classes; pass the same `fingerprint` to scans.
- `attack_recon_scan` / `attack_scan_crawled` — crawl-seeded, deduped, concurrent differential scans.
- `attack_scan fingerprint=...` — float stack-relevant payloads first; `confirm_dom` for XSS.
- `attack_param_mine` / `attack_js_extract` — discover hidden params/endpoints.
- `attack_web_probe` — cors / cache_poison / host_header / smuggle (plan-only).

## Reasoning Heuristics
- Reflective sink + DOM execution = confirmed XSS; reflection alone = suspected.
- A WAF 403 ≠ a backend block — document both (run `waf_bypass`).
- Honeypot/static "vulnerable" pages confirm benign input → demote (handled by the scan guard).

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Reflected/stored XSS on a discovered param |
| H2 | SQLi (error/time/boolean) on a query param |
| H3 | Open redirect / SSRF on a URL param |
| H4 | Hidden param unlocks an unguarded action |

## Validation Workflow
1. Two independent signals; `attack_reverify` before reporting.
2. Correlate duplicates (`attack_correlate`); triage with `attack_triage`.

## False-Positive Reduction
- Baseline-sample dynamic pages; ignore length deltas within jitter.
- SPA shells reflecting input client-side are flagged, not trusted as server reflection.

## Stealth + OPSEC Guidance
- Start passive; rate-limit; bounded concurrency; back off on `429/503`.

## Replay Procedures
- Persist confirmed findings + PoC bundles (`attack_reverify bundle=true`).

## Evidence Requirements
- curl repro, differential indicators, screenshot per platform rules.

## Confidence Scoring Logic
- Two-signal confirmed: high; single-signal: suspected (manual review).

## Adaptive Branching Logic
- API/JSON responses → branch to `skills/api/*`; GraphQL → `skills/graphql/*`; SSTI markers → `skills/ssti/*`.

## Related Exploit Chains
- `skills/xss/advanced_xss_hunting.md`, `skills/ssrf/chained_ssrf.md`

## Safety Boundaries
No data exfiltration/destruction/DoS; smuggling stays plan-only.

## Output Artifact Requirements
`output/<target_slug>/web/` — `fingerprint.json`, `scan_findings.json`, `poc/`
