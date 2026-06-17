# Skill: Validation-First Reporting

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `validation_first_reporting` |
| **version** | `1.0.0` |
| **category** | Reporting |
| **correlates_with** | Triage, correlation, reverify, evidence, CVSS/VRT |

## Objective
Produce submission-ready reports that pass triage on the first read: confirmed-vs-suspected split,
reproducible PoC + screenshot, program-rubric severity, chaining-based elevation, and an honest
assessment — with duplicates merged and readiness gated.

## Scope Rules
- Report only in-scope findings; attach reproducible proof to **every** report.
- Separate confirmed from suspected; never overstate severity.

## Trigger Conditions
- `finding_candidate`, `triage_complete`; a set of two-signal-confirmed findings.

## Technology Fingerprints
- N/A (output stage).

## Recon Methodology
1. Collect confirmed findings + executed chains.
2. Merge duplicates by root cause; map each to program severity + bounty band.

## MCP Tool Orchestration Logic
- `attack_correlate` — merge findings sharing a root cause (one bug → one report).
- `attack_triage` — CVSS → P-scale/VRT + bounty band + submission-readiness gate.
- `attack_reverify bundle=true` — attach a replayable PoC bundle.
- `attack_report` — build exec summary + confirmed/suspected + PoC + remediation + CVSS (+ markdown for
  hackerone/bugcrowd).
- `attack_save_findings` — write two-signal-confirmed findings back into the knowledge loop.

## Reasoning Heuristics
- A chained P4 can land P2 — show the chain and its realized severity.
- Comparison tables and clear business impact raise acceptance/bounty.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Finding is ready (confirmed + proof + in-scope + unique) |
| H2 | Finding needs more proof before submission |

## Validation Workflow
1. Readiness gate must pass: confirmed, two signals, proof attached, in-scope, not duplicate.
2. Re-verify reproduction immediately before submitting.

## False-Positive Reduction
- Suspected findings go in a separate section, never as confirmed.

## Stealth + OPSEC Guidance
- Redact secrets/PII in evidence; store artifacts locally, not in third-party services.

## Replay Procedures
- Ship the curl + request/response bundle so the triager reproduces in seconds.

## Evidence Requirements
- Screenshot/video on EVERY report (platform rule), curl, differential indicators, CVSS vector.

## Confidence Scoring Logic
- Map readiness_score → submit / hold; only `ready` findings are submitted.

## Adaptive Branching Logic
- Not ready → loop back to `skills/validation/false_positive_reduction.md`.

## Related Exploit Chains
- `skills/exploit_chains/exploit_chain_composition.md`

## Safety Boundaries
No exaggerated impact; honest assessment section mandatory.

## Output Artifact Requirements
`output/<target_slug>/reports/` — `report.md`, `poc/`, `severity_matrix.csv`
