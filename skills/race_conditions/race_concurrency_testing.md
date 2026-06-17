# Skill: Race & Concurrency Testing

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `race_concurrency_testing` |
| **version** | `1.0.0` |
| **category** | Web / Concurrency |
| **correlates_with** | Payments, coupons, inventory, MFA/OTP, "use-once" tokens, TOCTOU |

## Objective
Prove **TOCTOU** / check-then-act gaps with **bounded controlled parallelism** — a deterministic win of
an unsafe interleaving (double-spend, coupon reuse, limit overrun) without harming production stability.

## Scope Rules
- Confirm the program **allows** race testing (some forbid it).
- Cap concurrency; stop on `503/429` storms or DB-stress signals; test merchants only.

## Trigger Conditions
- `balance_transfer`, `coupon_redeem`, `seat_booking`; signup bonuses, MFA steps, single-use tokens.

## Technology Fingerprints
- Optimistic-locking apps, Redis counters, Stripe idempotency keys (respect them).

## Recon Methodology
1. Map the feature state machine (create → pay → capture).
2. Identify non-atomic check/use pairs from responses/errors.
3. Design N-way parallel requests (same vs distinct idempotency keys, hypothesis-driven).

## MCP Tool Orchestration Logic
- `attack_race` — bounded concurrent identical requests → limit-overrun / TOCTOU candidate (never amplifies).
- `httpx_probe` — baseline latency distribution.
- `attack_login` — authenticated session for the state-changing action.

## Reasoning Heuristics
- "Already used" coupon errors that flip under load → strong signal.
- Last-write-wins PATCH is a common race surface.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Coupon/credit redeemed N times via parallel submit |
| H2 | Balance/inventory overrun on concurrent capture |
| H3 | OTP/limit check bypass under concurrency |

## Validation Workflow
1. Reproduce the unsafe interleaving deterministically (≥2 successful overruns).
2. Quantify impact within agreed limits; reverify.

## False-Positive Reduction
- One anomalous response under load is not a confirmed race — require repeatable overrun.
- Respect idempotency keys: a blocked duplicate is correct behavior.

## Stealth + OPSEC Guidance
- Bound concurrency (`attack_race` caps ≤30); abort on instability; never run a real financial drain.

## Replay Procedures
- Log per-request timings + outcomes; capture the winning interleaving.

## Evidence Requirements
- Timing log, the N successful outcomes that should have been 1, remediation (atomic ops / locks / idempotency).

## Confidence Scoring Logic
- Deterministic repeatable overrun: **0.9+**; single flaky success: suspected.

## Adaptive Branching Logic
- HTTP/2 multiplexing blocked → try HTTP/1.1 many-connections (within scope).

## Related Exploit Chains
- `skills/business_logic/payment_logic_flaws.md`, `skills/business_logic/coupon_abuse.md`

## Safety Boundaries
No real financial theft; bounded parallelism only; honor "no race testing" rules.

## Output Artifact Requirements
`output/<target_slug>/race/` — `timings.csv`, `overrun_poc.md`
