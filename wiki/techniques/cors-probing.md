---
type: technique
aliases: ["CORS testing", "cross-origin"]
tags: [web, cors, headers]
created: 2026-05-30
updated: 2026-05-30
---
# CORS Probing

> Always send three probes per endpoint. The critical finding is a **reflected origin with
> `Access-Control-Allow-Credentials: true`** (wildcard `*` + credentials is browser-rejected).

## When to use
Every endpoint — including WAF-blocked 403 pages (their CORS often differs from app 200 pages).

## Procedure
Send and compare:
1. `Origin: https://evil.com` — arbitrary domain reflection.
2. `Origin: null` — null origin (exploitable from sandboxed iframes / `data:` URIs).
3. Inspect **both** `Access-Control-Allow-Origin` **and** `Access-Control-Allow-Credentials`.
   Also read `access-control-expose-headers` (which custom headers are cross-origin readable).

## What "a hit" looks like
The endpoint reflects your arbitrary/null `Origin` *and* sets `Allow-Credentials: true`.

## Severity & framing
Standalone P4; becomes a P3 [[waf-gap-chain]]-style chain when combined with sequential IDs +
no rate limiting + a ~10-line browser PoC. See [[severity-calibration]].

## Evidence it works (real hits)
- [[tripadvisor]] — CORS issues in 4 reports. **DataDome reflects any origin with credentials
  on its 403 pages** — a vendor-level bug affecting all DataDome customers.

## Pitfalls / false positives
- Wildcard `*` + `credentials:true` is rejected by browsers — not the finding. Reflected origin is.

## Related
- Techniques: [[response-header-forensics]] · Patterns: [[waf-gap-chain]]
