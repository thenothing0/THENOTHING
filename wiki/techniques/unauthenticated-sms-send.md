---
type: technique
aliases: ["SMS send abuse", "unauth SMS", "phone validation abuse"]
tags: [sms, api-abuse, enumeration, financial-abuse]
created: 2026-06-01
updated: 2026-06-01
---
# Unauthenticated SMS Send via Phone Validation Endpoints

## Prerequisites
- Target has a phone validation / signup / password-reset endpoint
- Endpoint accepts phone number and triggers SMS without authentication
- No CAPTCHA on first request (or CAPTCHA is per-target, not global)

## Workflow
1. Identify phone validation endpoints: `auth.validatePhone`, `auth.sendCode`, `users.sendVerification`, `/api/v1/sms/send`, etc.
2. Test with your own number — confirm SMS delivery
3. Test rate limiting: same phone repeated vs different phones
4. Document: auth required? CAPTCHA? per-phone cooldown? per-IP limit? global limit?
5. Test international numbers (severity multiplier if global reach)

## Indicators of vulnerability
- `validation_type: "sms"` in response (or equivalent confirmation)
- No `401`/`403` on unauthenticated request
- No CAPTCHA challenge on first request to new phone
- Different phones from same IP all succeed

## Validation methods
- Send to own phone, confirm SMS received
- Test 3+ unique phones from same IP — if all succeed, mass-targeting is viable
- Check if response differs for registered vs unregistered phones (enumeration bonus)

## Impact arguments
| Angle | Argument |
|-------|----------|
| Financial | Each SMS costs the target company. Volume × cost = unbounded expense |
| Harassment | Attacker weaponizes target's verified sender ID for SMS bombing |
| Regulatory | Unsolicited SMS may violate telecom laws (TCPA, GDPR, local equiv.) |
| Chain | Combine with phone enumeration → target only real users → brute force OTP |

## Limitations
- Per-phone cooldown reduces single-target harassment (but not mass-targeting)
- CAPTCHA after N requests per phone/IP (document the threshold)
- OTP brute force is usually rate-limited at the verification step

## Common false positives
- SMS appears to send but response is cached/mocked (verify actual delivery)
- Rate limit kicks in after 1 request (effectively mitigated)

## Observed instances
- [[vk-r6-sms-abuse-live]]: 2 free SMS per phone per IP, CAPTCHA after that, no limit on unique phones

## Cross-target applicability
**High.** Any platform with phone-based registration or 2FA has a send-SMS endpoint. Test: social networks, banking apps, e-commerce, SaaS platforms. Especially valuable on targets that support international SMS (higher per-message cost).
