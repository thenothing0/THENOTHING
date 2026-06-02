# Skill: Race Conditions

## Metadata
| **id** | `bl_race_conditions` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/race/` |

## Objective
Detect TOCTOU and parallel win windows (coupons, transfers, inventory) with **bounded** concurrency and program permission.

## Trigger Conditions
Balance updates, coupon apply, ticket sales, one-time tokens, MFA steps.

## Technology Fingerprints
Optimistic locking, Redis counters, Stripe idempotency keys.

## Reasoning Heuristics
Design paired parallel requests; measure statistical wins vs baseline; avoid conflating 500 storms with wins.

## Exploit Hypotheses
Double spend; double redeem; counter bypass; OAuth code race.

## MCP Orchestration Logic
`httpx_probe` latency baselines; parallel replay often **outside** MCP—log timings in `logs/` per output rule.

## Stealth Guidance
Short bursts; backoff; cap N; business-hours coordination if needed.

## Validation Workflow
Statistical significance + clean replay on test account.

## Evidence Requirements
Timeline CSV; script version; account IDs synthetic.

## Adaptive Branching
Payment flows → `payment_abuse.md`.

## Confidence Scoring
0.9 deterministic duplicate business outcome; one-off flake = low.

## Replay Logic
Concurrency parameter + seed timestamps.

## Reporting Guidance
Transactions, locks, idempotency keys, compare-and-set, queue serialization.
