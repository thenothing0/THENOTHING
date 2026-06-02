# Skill: Coupon & Promotion Abuse

## Metadata
| **id** | `bl_coupon_abuse` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/coupons/` |

## Objective
Test stacking, reuse, scope errors, and negative totals using **issuer-provided** or **sandbox** coupons—no brute force of public codes.

## Trigger Conditions
`coupon`, `promo`, `referral`, `credit` fields; client/server total mismatch.

## Technology Fingerprints
Custom carts, Shopify apps, marketplace checkouts.

## Reasoning Heuristics
Trust server JSON totals; pair with race windows; avoid ethical ToS violations on code guessing.

## Exploit Hypotheses
Unlimited reuse; incompatible stack; negative final totals.

## MCP Orchestration Logic
`katana_crawl` + `httpx_probe`; throttled `ffuf` only on codes you generated.

## Stealth Guidance
Low volume; sandbox; document merchant impact.

## Validation Workflow
Server response shows incorrect total vs stated promo rules.

## Evidence Requirements
Before/after JSON; policy text reference.

## Adaptive Branching
Race on apply → `race_conditions.md`.

## Confidence Scoring
0.85 clear monetary arbitrage in scope.

## Replay Logic
Cart state snapshots.

## Reporting Guidance
Server rules engine, single-use enforcement, audit logs.
