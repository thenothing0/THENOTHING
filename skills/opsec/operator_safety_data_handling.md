# Skill: Operator Safety & Data Handling

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `operator_safety_data_handling` |
| **version** | `1.0.0` |
| **category** | OPSEC |
| **correlates_with** | Scope enforcement, guardrails, evidence redaction, stealth |

## Objective
Keep engagements legal and safe: enforce written authorization, minimize and redact sensitive data,
store artifacts locally, and prevent the platform from crossing absolute prohibitions (DoS, destruction,
exfiltration, social engineering).

## Scope Rules
- Active testing only against assets covered by a registered program scope (deny-by-default gate).
- Absolute prohibitions are never allowed, even in-scope; exploitation is PoC-only.

## Trigger Conditions
- `pii_risk`, `credential_artifacts`; any handling of secrets, tokens, or personal data.

## Technology Fingerprints
- N/A (cross-cutting governance).

## Recon Methodology
1. Confirm scope/authorization before any active action (`authorize_target`).
2. Classify artifacts: which contain secrets/PII and must be redacted.

## MCP Tool Orchestration Logic
- `authorize_target` — deny-by-default gate check immediately before any active action.
- `check_tools` — verify the toolchain without touching targets.
- (every active tool) — already gated + PoC-only by construction.

## Reasoning Heuristics
- If scope is unclear → stop and ask; do not "collateral-test" suppliers/users.
- A minimal proof beats a full dump — never exfiltrate beyond PoC.
- Secrets in chat/logs are burned — rotate after exposure.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | An action would touch an out-of-scope host → block |
| H2 | Evidence contains PII/secrets → redact before storing/reporting |

## Validation Workflow
1. Pre-action gate check; post-capture redaction pass.
2. Confirm no prohibited action class is invoked.

## False-Positive Reduction
- N/A (policy, not detection) — bias toward stopping when uncertain.

## Stealth + OPSEC Guidance
- Store evidence under `output/` locally; never paste secrets/PII into third-party services.
- Redact tokens/credentials in curl and request/response captures.

## Replay Procedures
- Keep an immutable audit trail of authorization decisions and actions.

## Evidence Requirements
- Redacted artifacts only; authorization reference for each engagement.

## Confidence Scoring Logic
- N/A — binary allow/deny via the gate.

## Adaptive Branching Logic
- WAF/rate-limit detected → branch to `skills/stealth/passive_first_operations.md`.

## Related Exploit Chains
- N/A (governance gate for all skills).

## Safety Boundaries
No DoS, destruction, exfiltration, or social engineering — ever.

## Output Artifact Requirements
`output/<target_slug>/opsec/` — `authorization.md`, `redaction_log.csv`, `audit_trail.jsonl`
