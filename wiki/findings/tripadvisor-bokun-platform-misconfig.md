---
type: finding
aliases:
- Bókun mega-report
- REPORT_09
- Bokun platform misconfig
tags:
- bokun
- waf-gap
- api-abuse
- clickjacking
- info-disclosure
- subsidiary
target: '[[tripadvisor]]'
host: '*.bokun.io'
scope_status: in-scope
status: submitted
severity: P2
created: 2026-05-30
updated: '2026-06-26'
report: ../output/tripadvisor/REPORT_9_BOKUN_PLATFORM_MISCONFIG.md
reward: ''
---

# Bókun Platform — Systemic Security Misconfiguration (12 findings)

> P2 mega-report against the Bókun booking platform (Tripadvisor subsidiary). 12 distinct
> misconfigs sharing one root cause: **inconsistent security controls across the `bokun.io`
> subdomain hierarchy** — main domain has Cloudflare WAF, 7+ payment/booking/CDN subdomains
> have none. Full report: `../output/tripadvisor/REPORT_9_BOKUN_PLATFORM_MISCONFIG.md`.
> Demonstrates the [[waf-gap-chain]] pattern and the mega-report tactic from [[severity-calibration]].

## Summary
Hosts: `*.bookingarea.bokun.io`, `payments.bokun.io`, `static.bokun.io`, `imgcdn.bokun.tools`,
`bokun-cdn-origin.bokun.io`. CWEs: 441, 1021, 200, 693, 1104.

| # | Sub-finding | Severity driver |
|---|-------------|-----------------|
| 1 | **Unauthenticated Google Places API proxy** (`/google/autocomplete`, `/google/place-details`) on every tenant subdomain, using Bókun's key | **$147K/month** abuse → financial elevator |
| 2 | **Payment-page clickjacking** (`payments.bokun.io`) — no XFO/CSP frame-ancestors/frame-busting on a Stripe flow | payment integrity |
| 3 | Unrestricted HTTP methods (PUT/DELETE/PATCH = 200) on payment endpoint (Express) | latent risk |
| 4 | **250KB `/jsroutes`** exposing 150+ internal endpoints (admin, Chargebee billing, customer export, S3 sig) | full attack-surface map |
| 5 | **CDN origin bypass** — `bokun-cdn-origin.bokun.io` leaked in jsroutes (nginx/1.30.0) | bypasses CloudFront rate-limit |
| 6 | S3 bucket exposure (`static.bokun.io`) — raw XML, AWS RequestId/HostId | infra disclosure |
| 7 | OEmbed proxy = **limited SSRF** (YouTube-only whitelist; internal IPs rejected) | limited |
| 8 | jQuery 1.9.1 (40+ CVEs, no SRI) + Bootstrap 3.3.6 on error pages | client-side |
| 9 | Avo analytics debug mode (`?avo_debug=1`, localStorage-persisted) | info leak |
| 10 | Gumlet CDN `imgcdn.bokun.tools` CORS `*` — cross-origin reads of vendor images | [[cors-probing]] |
| 11 | New Relic creds exposed (`licenseKey d93e1d23c8`, appID 15663599) → telemetry injection | cred leak |
| 12 | `BokunInternalErrorId` + `__env=dublin-prod` disclosure on 500s | infra disclosure |

## Evidence / PoC (confirmed, re-verified at write time)
**Finding 1 — Google proxy, zero auth:**
```bash
curl -sk "https://115586-beacon.bookingarea.bokun.io/google/autocomplete?input=New+York&types=geocode"
# → {"predictions":[{"description":"New York, NY, USA",...}],"status":"OK"}
```
Works across all `*.bookingarea.bokun.io` tenants. Pricing: autocomplete $2.83/1k, place-details $17/1k; ~100 req/s across tenants ≈ **$147K/month**.

**Finding 2 — frameable Stripe page:** `payments.bokun.io` returns only `x-powered-by: Express`; no XFO/CSP/HSTS; no frame-busting in `BokunPaymentWidget.*.js`. Transparent-iframe clickjacking PoC in report.

## Impact (maximized but honest)
Direct financial abuse ($147K/mo, zero auth), payment-flow clickjacking, complete internal API
inventory of a multi-tenant booking platform, CloudFront bypass, and AWS/New-Relic infra
disclosure — a systemic security-control failure across an acquired subsidiary. Compliance: the
payment-page gaps touch PCI DSS handling expectations.

## Honest assessment — what limits the impact
- jsroutes admin/billing/customer endpoints all require auth (303 → login).
- Clickjacking needs a valid, short-lived, server-created Stripe `paymentIntentId`.
- OEmbed SSRF is YouTube-only (internal IPs/localhost rejected).
- NR key is a browser RUM key (limited server-side API).
- S3 listing blocked by CloudFront; booking-area IDs sequential but no cross-tenant access.

## Techniques used
[[dns-first-recon]] (subdomain discovery) → [[response-header-forensics]] (header/version/cred
leaks) → [[cors-probing]] (Finding 10) → route-map discovery (`/jsroutes`).

## Chaining
End-to-end narrative built in [[bokun-platform-compromise]]. Instance of [[waf-gap-chain]];
realizes the mega-report tactic in [[severity-calibration]].

## Status / triage
- Submitted as REPORT_09. Response: pending. (Distinct from the **N/A** Tripadvisor reports —
  REPORT_19/03 — which failed on the [[public-api-key-pitfall]]; this one rests on data/abuse, not key secrecy.)

## Patterns (discovered)
- [[ssrf-pattern]]

## Chains (discovered)
- [[tripadvisor-estate-waf-gap]]
