# Skill: Coupon, Discount & Promotional Abuse

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `coupon_abuse` |
| **version** | `1.0.0` |
| **category** | Business logic / Promotions |
| **correlates_with** | Race conditions, multi-currency, referral loops |

## Objective
Evaluate **stacking**, **reuse**, **scope**, and **negative** discount handling without **draining** marketing budgets on production. Prefer **sandbox** or **single-use** test coupons.

## Scope Rules
- Programs may consider **financial loss** out of scope—read brief.
- Stop at first **material** price impact signal if disallowed.

## Trigger Conditions
- `coupon`, `promo`, `voucher`, `referral`, `credit` parameters.
- Client-side price display vs server total mismatch.

## Technology Fingerprints
- E-commerce platforms (Shopify apps, custom carts).

## Recon Methodology
1. Enumerate **coupon application** endpoints (cart vs checkout vs account).
2. Test **stacking** matrix (A+B), **case sensitivity**, **UUID** coupon leaks in JS.
3. Pair with **race** skill for “double apply” windows.

## MCP Tool Orchestration Logic
- `katana_crawl`, `httpx_probe`, controlled `ffuf_fuzz` on coupon codes **you generated**.

## Reasoning Heuristics
- **Server total** JSON field is source of truth—diff vs UI.
- **Referral** loops: self-referral, org self-referral.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Unlimited reuse |
| H2 | Stack incompatible promos |
| H3 | Negative final total |
| H4 | Coupon valid for wrong SKU tier |

## Validation Workflow
1. Server response shows **incorrect** final amount vs business rules.
2. Replay with clean cart baseline.

## False-Positive Reduction
- **Intentional** employee coupons in dev builds.

## Stealth + OPSEC Guidance
- Avoid brute forcing public coupon codes—ethical + ToS issue.

## Replay Procedures
- JSON cart state before/after apply.

## Evidence Requirements
- Policy violation of stated promo rules with screenshots.

## Reporting Methodology
- Single-use enforcement, server-side rules engine, audit logs.

## Confidence Scoring Logic
- Clear monetary arbitrage: **0.85+** if in scope.

## Adaptive Branching Logic
- **Gift card** + coupon interaction branch.

## Related Exploit Chains
- `skills/business_logic/race_condition.md`

## Safety Boundaries
No marketplace manipulation harming sellers.

## Output Artifact Requirements
`output/<target_slug>/coupons/` — `stack_matrix.md`, `responses/`
