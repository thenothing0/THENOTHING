---
type: pattern
aliases: ["rate limit bypass via mass targeting", "per-target rate limit"]
tags: [rate-limit, captcha, sms, api-abuse, mass-targeting]
created: 2026-06-01
updated: 2026-06-01
---
# Per-Target Rate Limit ≠ Mass-Target Protection

## Pattern
Rate limiting and CAPTCHA gates often bind to (target_resource, source_IP). This blocks repeated abuse of a **single** target but allows unlimited abuse across **different** targets from the same IP. An attacker who targets N unique resources gets N × (free-tier quota) total actions.

## Typical implementation
- SMS send: CAPTCHA after 2 requests to same phone from same IP
- Password reset: lockout after 5 attempts on same account
- API query: rate limit per endpoint per user

## Exploitation
- SMS bombing: 2 free SMS × 1M unique phone numbers = 2M SMS, zero CAPTCHAs
- Credential stuffing: 5 attempts × 100K accounts = 500K guesses
- Enumeration: rate limit per query target, not per session

## Validation method
1. Send N requests to **same** target → observe when rate limit/CAPTCHA triggers
2. Send 1 request each to **N different** targets → observe if any limit triggers
3. If step 2 shows no limit, the mass-targeting vector is open

## Observed instances
- [[vk-r6-sms-abuse-live]]: CAPTCHA after ~2 req/phone/IP, but no limit on unique phones

## Severity argument
Per-target limits reduce single-victim harassment but do NOT prevent:
- Financial abuse (cost per action × unlimited targets)
- Mass enumeration
- Distributed harassment across many victims
- Account takeover at scale (low-rate distributed brute force)

## Cross-target applicability
Any API that rate-limits per resource rather than per session/IP globally. Extremely common. Check every SMS send, password reset, OTP, and verification endpoint.
