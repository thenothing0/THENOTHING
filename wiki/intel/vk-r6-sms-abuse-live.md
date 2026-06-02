---
type: intel
aliases: ["VK SMS abuse", "auth.validatePhone"]
tags: [vk, sms, api-abuse, rate-limit, captcha]
target: "[[vk]]"
created: 2026-06-01
updated: 2026-06-01
sources: ["own testing 2026-05-29 and 2026-06-01"]
---
# VK auth.validatePhone — Unauthenticated SMS Send (Live)

## Summary
`api.vk.com/method/auth.validatePhone` sends SMS verification codes to any phone number without authentication. Still live as of 2026-06-01. In vendor review on Standoff 365.

## Vulnerability class
CWE-770 (Allocation of Resources Without Limits) / API abuse / SMS flooding

## Root cause
Legacy auth method exposed publicly without authentication gate. Designed for app registration flow but callable by anyone.

## Attack path
1. `GET api.vk.com/method/auth.validatePhone?v=5.199&phone=<target>` → SMS sent
2. No auth token, no session, no CAPTCHA on first request
3. Response: `{"response":{"validation_type":"sms","code_length":6,"delay":60}}`

## Rate limiting behavior (tested 2026-06-01)
| Request | Same phone, same IP | Different phones, same IP |
|---------|--------------------|-----------------------------|
| 1-2 | SMS sent | SMS sent |
| 3+ | **CAPTCHA required** (error 14) | SMS sent (no CAPTCHA) |
| Sustained | Flood control (error 9) | Unknown ceiling |

**Critical insight**: CAPTCHA is per-phone-per-IP. Mass-targeting unique numbers = 2 free SMS each, no CAPTCHA.

## International scope
- Russian numbers: work
- Egyptian +201286439183: **worked** (SMS delivered)
- Egyptian +201117690085: rejected (carrier/format, not country block)
- Claim "any phone worldwide" is mostly true but some numbers rejected

## Impact
- Financial: VK pays per SMS × unlimited unique targets
- Harassment: VK verification SMS to any number, attacker-controlled
- Chain: combine with `auth.restore` (phone enumeration) → target confirmed VK users → `auth.confirm` (code brute force, rate-limited per IP but distributable)

## Lessons learned
- Always test CAPTCHA/rate-limit behavior before claiming "no rate limit"
- Per-phone-per-IP rate limits don't prevent mass-targeting — document the distinction
- Test international numbers, not just local format — the scope matters for severity

## Technique links
- [[unauthenticated-sms-send]] (new — to create)

## Chain links
- [[vk-auth-chain]] (validatePhone → restore → confirm)
