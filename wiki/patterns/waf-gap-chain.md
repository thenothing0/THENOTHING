---
type: pattern
aliases: ["WAF gap", "WAF coverage gap"]
tags: [waf, chaining, severity, subsidiary]
created: 2026-05-30
updated: 2026-05-30
---
# WAF-Gap Chain

> **Main domain has WAF → subsidiary/API/origin lacks it → direct access to unprotected
> backend.** The strongest *systemic* finding pattern; repeated across an entire estate it
> climbs from P4 to P2.

## The pattern
Organizations deploy WAF on the most visible endpoint and forget APIs, payment pages, CDN
subdomains, internal services, and acquisitions. Acquisitions especially inherit a different
security posture than the parent.

## How to detect / exploit
1. [[dns-first-recon]] to enumerate subsidiaries/APIs/origins.
2. `wafw00f_detect` on the main domain **and** ≥5 subdomains/APIs of each service.
3. Build a coverage table: `domain | WAF? | WAF type | server behind`. **The table is the finding.**
4. Where the gap exists, confirm backend reachability → [[403-waf-bypass]] if a path 403s.
5. Test `api.* payments.* static.* cdn.* staging.* internal.*` of every WAF'd service.

## Examples (≥2)
- [[tripadvisor]] — DataDome on www but **not** api.viator.com; Cloudflare on bokun.io but not
  payments.bokun.io; AWS WAF on `api.production.cde` root path only.
- [[tripadvisor]] — pattern across 7 bokun.io subdomains → [[tripadvisor-bokun-platform-misconfig]] (mega-report) and the [[bokun-platform-compromise]] chain.
- [[tripadvisor-cde-waf-bypass]] — AWS WAF enforces only `GET/POST /` on a PCI CDE payment API.
- **Estate-wide:** the same gap recurs across 3 subsidiaries/clouds → [[tripadvisor-estate-waf-gap]] (the systemic-posture chain).

## Severity impact
- One unprotected subdomain = P3/P4.
- Same gap across 7 subdomains of a subsidiary = **P2** (systemic).
- On a CDE/payment host → add **PCI DSS 6.4/6.6/11.4** → P2 regardless of count. See [[severity-calibration]].

## Related
- Techniques: [[dns-first-recon]], [[403-waf-bypass]], [[cors-probing]] · Targets: [[tripadvisor]]
