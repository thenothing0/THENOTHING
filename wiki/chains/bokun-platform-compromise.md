---
type: chain
aliases: ["Bókun attack chain", "Bokun platform compromise"]
tags: [bokun, waf-gap, chaining, subsidiary]
target: "[[tripadvisor]]"
severity: P2
nodes: ["[[tripadvisor-bokun-platform-misconfig]]"]
created: 2026-05-30
updated: 2026-05-30
---
# Bókun Platform Compromise Chain

> How the 12 sub-findings of [[tripadvisor-bokun-platform-misconfig]] combine into one coherent
> P2 narrative against the Bókun booking platform. The chain *is* the severity argument: a
> dozen isolated P3/P4s become one systemic-failure mega-report (see [[severity-calibration]]).

## Chain
**Map → Abuse → Target payments → Bypass infra → Client-side → Manipulate monitoring**

1. **Discovery & mapping** (sub-findings 4, 6, 10, 11, 12) — `/jsroutes` (150+ endpoints) + S3
   exposure + New Relic config (`dublin-prod`) + Avo debug give a complete architecture picture.
2. **Financial abuse** (1) — unauthenticated Google Places proxy → ~**$147K/month**, zero
   exploitation complexity, distributable across hundreds of tenant subdomains.
3. **Payment targeting** (2, 3) — knowing the `paymentIntentId` flow from jsroutes, the frameable
   Stripe page enables clickjacking; unrestricted methods open future API-route abuse.
4. **Infrastructure bypass** (5, 6, 10) — leaked CDN origin (`bokun-cdn-origin.bokun.io`) bypasses
   CloudFront rate-limiting; S3 bucket name enables direct AWS attempts; Gumlet CORS `*` allows
   cross-origin image reads.
5. **Client-side exploitation** (8) — jQuery 1.9.1 (CVE-2020-11022, no SRI) on error pages, if an
   attacker can trigger error pages with controlled content. *(Hypothesis — needs a reflected
   sink to be confirmed; falsified if error pages never reflect attacker input.)*
6. **Monitoring manipulation** (11) — New Relic browser creds allow injecting fake telemetry →
   mask attacks / trigger alert fatigue.

## Why the chain > sum of parts
Each item alone triages low (config disclosure, missing header). The **WAF-gap root cause across
7 subdomains** (table below) turns them into evidence of systemic security neglect on an acquired
platform — the framing that justifies **P2** rather than a dozen dismissed informationals.

| Subdomain | WAF | Sec headers | Auth | Server |
|-----------|-----|-------------|------|--------|
| `bokun.io` | Cloudflare ✓ | full ✓ | yes | — |
| `payments.bokun.io` | none (CloudFront) | **none** | partial | Express |
| `*.bookingarea.bokun.io` | none | **none** | no (proxies) | nginx/1.30.0 |
| `bokun-cdn-origin.bokun.io` | none | — | yes | nginx/1.30.0 (origin) |
| `static.bokun.io` | none | `server: AmazonS3` | no | S3 direct |
| `imgcdn.bokun.tools` | none | `ACAO: *` | no | Gumlet |

## Related
- Finding: [[tripadvisor-bokun-platform-misconfig]] · Pattern: [[waf-gap-chain]], [[severity-calibration]] · Target: [[tripadvisor]]
