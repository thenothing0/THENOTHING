# Skill: Responsible Passive-First Operations

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `passive_first_operations` |
| **version** | `1.0.0` |
| **category** | Stealth / OPSEC |
| **correlates_with** | Rate limiting, WAF handling, human emulation, scope discipline |

## Objective
Sequence engagements passive-first and pace active testing responsibly: rate-limit, back off on WAF/edge
signals, and keep traffic non-disruptive — so authorized testing never degrades the target.

## Scope Rules
- Passive sources first; escalate to active only when needed and in-scope.
- Never generate DoS-shaped traffic; honor program intensity rules.

## Trigger Conditions
- `rate_limit_sensitive`, `waf_detected`; `429/503` responses, WAF challenge pages.

## Technology Fingerprints
- Cloudflare, Akamai, AWS WAF, rate-limit headers (`Retry-After`, `X-RateLimit-*`).

## Recon Methodology
1. Detect WAF/edge and rate-limit posture before active scans.
2. Set per-host concurrency + request rate within safe bounds.

## MCP Tool Orchestration Logic
- `wafw00f_detect` — identify the WAF.
- `check_tools` — verify toolchain without touching the target.
- (scanners) — use bounded `concurrency` + `rate_per_sec`; the executor auto-backs-off on `429/503`.
- `waf_bypass` — document WAF-vs-backend responses for 403s (methodically, not floods).

## Reasoning Heuristics
- A 403/406/429 from the edge ≠ a backend block — distinguish and slow down.
- Escalating backoff on repeated `429/503` prevents accidental DoS.
- Distinguish WAF challenge pages from real app responses to avoid false signals.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | WAF gap reachable via origin/alternate path (document, don't flood) |
| H2 | Rate limit too low for the planned scan → reduce intensity |

## Validation Workflow
1. Confirm pacing keeps error rates low; abort on instability.
2. Re-run confirmations at low rate rather than bursting.

## False-Positive Reduction
- WAF block pages reflecting input are not vulnerabilities — see the honeypot/trap guard.

## Stealth + OPSEC Guidance
- This *is* the pacing skill — apply its limits to every active skill.
- Realistic UA + spacing; no rapid-fire; bounded retries.

## Replay Procedures
- Log rate/backoff decisions alongside scan runs.

## Evidence Requirements
- WAF identification + the documented WAF-vs-backend response table when relevant.

## Confidence Scoring Logic
- N/A (operational control).

## Adaptive Branching Logic
- Persistent blocks → origin-discovery branch in `skills/recon/*` (within scope).

## Related Exploit Chains
- N/A (pacing control for all skills).

## Safety Boundaries
No DoS-shaped traffic; honor `Retry-After` and program intensity limits.

## Output Artifact Requirements
`output/<target_slug>/stealth/` — `waf.json`, `pacing_log.csv`
