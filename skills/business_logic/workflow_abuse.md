# Skill: Multi-Step Workflow & State Machine Abuse

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `workflow_abuse` |
| **version** | `1.0.0` |
| **category** | Business logic / Process |
| **correlates_with** | KYC, onboarding, refunds, admin approvals |

## Objective
Find **skippable steps**, **reordered steps**, and **stale state** in multi-step flows (checkout, onboarding, dispute). Prove **business impact** with minimal state mutation on **test** accounts.

## Scope Rules
- Do not bypass **legal/KYC** controls in production without explicit legal approval.
- Document every **state token** manipulation (CSRF, predictable IDs).

## Trigger Conditions
- `step=`, `stage=`, JWT-like state blobs in hidden fields, session flags.

## Technology Fingerprints
- BPM engines, Stripe Checkout-style sessions, custom `flowId`.

## Recon Methodology
1. Draw **state diagram** from UI + network traffic.
2. Test **jump** to later step with earlier cookies only.
3. Replay **completion** call without prerequisites.

## MCP Tool Orchestration Logic
- `katana_crawl` — discover step URLs.
- `httpx_probe` — replay sequences with saved cookies (manual cookie jar notes).

## Reasoning Heuristics
- **Server-side** step index vs **client-only** progress bars—prioritize server gaps.
- **Parallel** flows (two tabs) may desync expected order.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Skip payment step |
| H2 | Re-enter discount after total locked |
| H3 | Approve own request |

## Validation Workflow
1. Minimal path deviation with clean session.
2. Second repro with different browser profile.

## False-Positive Reduction
- **A/B tests** changing UI order ≠ security flaw unless integrity breaks.

## Stealth + OPSEC Guidance
- Avoid leaving accounts in broken states—revert via UI if possible.

## Replay Procedures
- HAR sequence with annotated step numbers.

## Evidence Requirements
- Diagram + requests proving skipped guard.

## Reporting Methodology
- Enforce server-side state machine, signed step tokens, idempotent transitions.

## Confidence Scoring Logic
- Provable free good or privilege: **0.9**; cosmetic step skip: low unless impact exists.

## Adaptive Branching Logic
- **Admin vs user** flows → compare endpoint parity.

## Related Exploit Chains
- `skills/business_logic/race_condition.md`

## Safety Boundaries
No fraud; coordinated disclosure for billing systems.

## Output Artifact Requirements
`output/<target_slug>/workflow/` — `state_machine.mmd`, `evidence.har`
