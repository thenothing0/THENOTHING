---
type: technique
aliases: ["progressive auth", "auth error enumeration"]
tags: [api, auth, info-disclosure]
created: 2026-05-30
updated: 2026-05-30
---
# Progressive Authentication Probing

> Escalate auth correctness step-by-step. Each step leaks more about the auth mechanism;
> **the differing error messages themselves are the finding** (they enable enumeration).

## When to use
Any authenticated API endpoint (REST, GraphQL, SigV4-signed).

## Procedure (4-step escalation, log every distinct error)
1. **No auth header** → reveals "auth required" message / format hint.
2. `Authorization: Bearer test` → reveals format requirements.
3. Correct **format**, wrong **value** → reveals validation behavior (and "missing" vs "invalid" difference).
4. Vary `Accept: application/json` etc. → reveals API versioning.

## What "a hit" looks like
Distinct error messages for *missing* vs *invalid* credentials, or errors that disclose the
auth scheme / header names / signing requirements.

## Severity & framing
Verbose auth errors alone are P4; the enumeration capability + chaining raises it. See [[severity-calibration]].

## Evidence it works (real hits)
- [[tripadvisor]] — GraphQL AWS SigV4 disclosure (REPORT_06), Viator `exp-api-key` (REPORT_12);
  api.viator.com leaked the auth header *name* via a missing `Accept` header.

## Applies to
- [[tripadvisor]] APIs; **[[vk]]** — apply to `auth.restore` / `auth.validatePhone` and the
  1000+ dev.vk.com methods for 2FA-bypass and phone-enum signals.

## Pitfalls / false positives
- A generic 401 with no detail is not a finding — you need *informative* error divergence.

## Related
- Techniques: [[response-header-forensics]] · Patterns: [[severity-calibration]]
