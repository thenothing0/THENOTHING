---
type: pattern
aliases: ["public API key", "client-side key", "public key pitfall"]
tags: [anti-pattern, severity, rejection-lesson]
created: 2026-05-30
updated: 2026-05-30
---
# Public API Key Pitfall (anti-pattern)

> **A client-side/public API key is NEVER itself a finding.** It's meant to be in the client
> (like a Google Maps browser key, Algolia search key, or Stripe publishable key). Do not
> frame it as "broken access control," "authorization bypass," or "leaked credential."

## The pattern
Mobile apps and web clients embed public keys by design. Finding and using one is not a
vulnerability. The doc portal, quota numbers, and rate limits being visible are by-design too.

## The ONLY valid finding here
**Sensitive data or privileged functionality exposed *through* the key** that a public
consumer should not reach — e.g. a public key returning customer PII, payment data, or admin
actions, or a *billable* service with confirmed unrestricted quota and quantified abuse cost.
Confirm the sensitive exposure with evidence before writing; never report the key itself.

## Examples — rejection lessons
- [[tripadvisor]] `adf6d1b8-0aca-4b0c-a492-50530aadd7aa` — public partner key. A report framing
  it as an embedded credential granting broken access control **collapsed and was retracted**.
- [[tripadvisor]] REPORT_19 (GCP Translation API key in APK) → **N/A**: public-by-design, no
  real financial impact demonstrated.
- [[tripadvisor]] REPORT_03 (gwapi reviews via the public key) → **N/A**: review data is
  public-facing content, not private PII.

## Severity impact
Reframe entirely: the value rests on **data exposure / lack of rate limiting / billable abuse
cost**, NOT on the key being secret. Before calling key exposure a vuln, ask: *"is this key
intended to be client-side?"* If yes, pivot to what the API exposes. See [[severity-calibration]].

## Related
- Targets: [[tripadvisor]] · Pattern: [[severity-calibration]]
