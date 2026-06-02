# Skill: Payment & Checkout Logic Flaws

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `payment_logic_flaws` |
| **version** | `1.0.0` |
| **category** | Business logic / Payments |
| **correlates_with** | Race conditions, currency rounding, negative qty, webhooks |

## Objective
Test **pricing integrity**, **currency**, **refund**, **partial capture**, and **webhook** ordering assumptions using **sandbox** payment providers and **test cards** only.

## Scope Rules
- **No** real money movement without merchant authorization.
- Follow PSP **ToS** (Stripe, Adyen, etc.) for testing patterns.

## Trigger Conditions
- Cart APIs, `amount`, `currency`, `discount`, `tax`, `shipping`, `capture` flags.
- Webhook endpoints without signature or replay protection.

## Technology Fingerprints
- Stripe, PayPal, Braintree, native “wallet” ledgers.

## Recon Methodology
1. Map **client-calculated** vs **server-calculated** totals.
2. Test **negative** quantities, **overflow** amounts, **currency swap** at capture.
3. Webhook: **replay**, **reorder**, **duplicate** `event_id`.

## MCP Tool Orchestration Logic
- `httpx_probe` — capture API sequences.
- `katana_crawl` — find alternate checkout endpoints (mobile vs web).

## Reasoning Heuristics
- **Rounding** to smallest currency unit; **tax** after discount changes.
- **Gift cards** + **coupons** stacking rules.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Pay less than cart total |
| H2 | Refund more than paid |
| H3 | Webhook replay grants double credit |
| H4 | Currency confusion |

## Validation Workflow
1. All tests in **sandbox** with documented PSP mode.
2. Save **ledger** IDs and server responses.

## False-Positive Reduction
- UI glitch with server-correct charge ≠ vuln.

## Stealth + OPSEC Guidance
- Low frequency; do not trigger fraud alerts—use test mode.

## Replay Procedures
- API JSON bodies with timestamps.

## Evidence Requirements
- Sandbox proof; cannot submit? disclose limitation clearly.

## Reporting Methodology
- Server-side price authority, idempotent webhooks, signature + timestamp tolerance.

## Confidence Scoring Logic
- Server accepts wrong paid amount in sandbox mirroring prod logic: **high** pending PM review.

## Adaptive Branching Logic
- **Marketplace** split payouts → multi-party abuse branch.

## Related Exploit Chains
- `skills/business_logic/race_condition.md`
- `skills/business_logic/coupon_abuse.md`

## Safety Boundaries
No fraud; legal review for payment findings.

## Output Artifact Requirements
`output/<target_slug>/payments/` — `sandbox_logs/`, `math.md`
