# Skill: Race Conditions & Concurrency Flaws

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `race_condition` |
| **version** | `1.0.0` |
| **category** | Business logic / Concurrency |
| **correlates_with** | Payments, coupons, inventory, double-spend, TOCTOU |

## Objective
Identify **TOCTOU** and **check-then-act** gaps using **controlled parallelism**—prove **deterministic** win of an unsafe interleaving without harming production stability beyond agreed limits.

## Scope Rules
- Confirm program allows **parallel** requests; some ban “race condition testing.”
- Cap concurrency; stop on **503/429** storms or DB outage signals.
- No financial theft on real users—use **test merchants** only.

## Trigger Conditions
- Balance transfers, coupon redemption, ticket booking, signup bonuses, MFA steps, “use once” tokens.

## Technology Fingerprints
- Single-threaded app servers + optimistic locking; **Redis** counters; **Stripe** idempotency keys (respect them).

## Recon Methodology
1. Map **state machine** of the feature (create → pay → capture).
2. Identify **non-atomic** check/use pairs in API responses/errors.
3. Design **N-way** parallel requests with identical idempotency keys vs distinct (hypothesis-driven).

## MCP Tool Orchestration Logic
- `httpx_probe` — baseline latency distribution.
- Custom parallel client often outside MCP—**log** timings in `output/`; use `ffuf` **-threads`** cautiously if MCP exposes threading flags.

**Branching:** If HTTP/2 multiplexing blocked → try HTTP/1.1 pipelining vs many connections per program.

## Reasoning Heuristics
- **Last-write-wins** on PATCH is a common race surface.
- **Coupon** “already used” errors that flip under load → strong signal.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Double redemption |
| H2 | Double withdrawal |
| H3 | Bypass limit counters |
| H4 | OAuth/code reuse race |

## Validation Workflow
1. Statistical evidence: success rate > baseline under parallel burst.
2. **Account-level** proof on test user; capture server logs if provided by program.

## False-Positive Reduction
- Random 500s under load ≠ race win; need **consistent** state violation.

## Stealth + OPSEC Guidance
- Short bursts; exponential backoff; business-hours coordination.

## Replay Procedures
- Script with concurrency N; seed timestamps.

## Evidence Requirements
- Timeline table; successful duplicate state; IDs of conflicting operations.

## Reporting Methodology
- DB transactions, row locks, idempotency keys, compare-and-set, queue serialization.

## Confidence Scoring Logic
- Deterministic duplicate **business** outcome: **0.9**; flaky once-off: low.

## Adaptive Branching Logic
- **Microservices** split → race across services branch (distributed tracing if in scope).

## Related Exploit Chains
- `skills/business_logic/payment_logic_flaws.md`

## Safety Boundaries
No DoS; no draining real inventory.

## Output Artifact Requirements
`output/<target_slug>/race/` — `timeline.csv`, `script.py`, `summary.md`
