# Skill: False-Positive Reduction (Validation-First)

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `false_positive_reduction` |
| **version** | `1.0.0` |
| **category** | Validation |
| **correlates_with** | Two-signal confirmation, honeypot guard, reverify, reporting |

## Objective
Turn scanner hypotheses into trustworthy verdicts: require **two independent signals**, suppress
trap/honeypot and dynamic-page noise, and **re-verify** every candidate before it reaches a report.

## Scope Rules
- A scanner hit is a hypothesis until independently replayed.
- Never elevate severity on a single signal.

## Trigger Conditions
- `scanner_hit`, `heuristic_alert`; any `suspected`/`single_signal` finding.

## Technology Fingerprints
- WAF/edge challenge pages, SPA shells, static "vulnerable-looking" templates, canary/honeypot pages.

## Recon Methodology
1. Re-baseline the endpoint with stability sampling (jitter + status stability).
2. Send a benign non-payload probe and ask whether class-confirming signals still fire (trap test).

## MCP Tool Orchestration Logic
- `attack_reverify` — replay the stored request vs a fresh baseline → reproduces true/false.
- `attack_scan baseline_samples=3` — stability-aware differentials (kills length/status FPs).
- `nuclei_scan` / `httpx_probe` — corroborate independently of the original sink.
- (scan-internal) honeypot guard + two-signal confirmer — demote canned "confirmations".

## Reasoning Heuristics
- Benign input that triggers a SQL error / `/etc/passwd` marker / 7*7 → **trap**, demote to suspected.
- Length/status delta within baseline jitter is noise, not signal.
- Reflection into a JSON/SPA context is not XSS.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Candidate is a real two-signal finding (keep) |
| H2 | Candidate is a WAF/honeypot artifact (demote) |
| H3 | Candidate is dynamic-page jitter (refute) |

## Validation Workflow
1. Independent second signal from a different family (execution/timing/oob/error).
2. `attack_reverify` reproduces against a fresh baseline.
3. Only then mark `confirmed` and pass to reporting.

## False-Positive Reduction
- This *is* the FP-reduction skill — apply it to every other skill's output.

## Stealth + OPSEC Guidance
- Re-verification adds requests; keep rate limits and bounded retries.

## Replay Procedures
- Store the reproduce result + fresh evidence alongside the original.

## Evidence Requirements
- The two independent signals, the reverify result, and the baseline comparison.

## Confidence Scoring Logic
- Reproduced + two signals: high; reproduced single-signal: medium/suspected; not reproduced: drop.

## Adaptive Branching Logic
- Not reproduced → re-triage or discard; reproduced → branch to `skills/reporting/validation_first_reporting.md`.

## Related Exploit Chains
- N/A (cross-cutting quality gate).

## Safety Boundaries
Never submit unverified findings; honor scope on every replay.

## Output Artifact Requirements
`output/<target_slug>/validation/` — `reverify_log.json`, `demoted.csv`
