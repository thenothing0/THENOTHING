# Skill: Payment Abuse

## Metadata
| **id** | `bl_payment_abuse` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/payments/` |

## Objective
Evaluate pricing, currency, capture/refund, and webhook ordering in **sandbox** PSP modes only.

## Trigger Conditions
Cart APIs, `amount`, `currency`, webhooks without replay protection.

## Technology Fingerprints
Stripe, PayPal, Adyen, native wallets.

## Reasoning Heuristics
Server totals vs client UI; rounding; webhook replay; race with `race_conditions.md`.

## Exploit Hypotheses
Underpay; over-refund; double credit via webhook replay.

## MCP Orchestration Logic
`httpx_probe` sequence capture; no destructive prod financial calls.

## Stealth Guidance
PSP test mode; low frequency; avoid fraud triggers.

## Validation Workflow
Sandbox ledger IDs; math proof of incorrect server total.

## Evidence Requirements
Sandbox-only artifacts; legal/compliance note if prod-like.

## Adaptive Branching
Coupons stacking → extend workflow tests carefully.

## Confidence Scoring
0.85 if sandbox mirrors prod logic and shows wrong totals.

## Replay Logic
JSON bodies + timestamps in `replay/`.

## Reporting Guidance
Server-side authority, idempotent webhooks, signatures, reconciliation jobs.
