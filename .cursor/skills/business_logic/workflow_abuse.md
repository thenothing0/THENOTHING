# Skill: Workflow Abuse

## Metadata
| **id** | `bl_workflow_abuse` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/workflow/` |

## Objective
Find skippable/reorderable steps in multi-step flows (onboarding, checkout, approvals) with state token analysis.

## Trigger Conditions
`step`, `stage`, signed state blobs, multi-tab flows.

## Technology Fingerprints
BPM engines, Stripe-like sessions, internal “flowId”.

## Reasoning Heuristics
Server-enforced vs client-only progress; parallel tabs desync; JWT state tampering (pair with JWT skill).

## Exploit Hypotheses
Skip payment; approve self-request; re-enter discount after lock.

## MCP Orchestration Logic
`katana_crawl` + HAR-driven replay notes; `httpx_probe` for transitions.

## Stealth Guidance
Revert broken test accounts after runs.

## Validation Workflow
Minimal path deviation + second-browser repro.

## Evidence Requirements
HAR with step annotations; state diagram.

## Adaptive Branching
Race windows → `race_conditions.md`.

## Confidence Scoring
0.85 provable free-good or privilege; cosmetic-only = low.

## Replay Logic
Ordered request list in `replay/ordered.md`.

## Reporting Guidance
Server-side state machine, signed step tokens, idempotent transitions.
