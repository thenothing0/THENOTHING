---
type: target
aliases: ["Tripadvisor", "TA"]
tags: [travel, waf-gap, subsidiary, api]
platform: bugcrowd
scope_status: in-scope
created: 2026-05-30
updated: 2026-05-30
---
# Tripadvisor

> Travel platform with multiple acquired subsidiaries (Viator, Bókun) and cloud infra
> (tamg.cloud, tapayments). Main domain is hardened (DataDome WAF); **the money is in the
> subsidiaries and APIs where WAF/headers/controls are inconsistent.**

## Program facts
- **Platform / URL:** Bugcrowd — `bugcrowd.com/engagements/tripadvisor-bb-og`
- **Scope reference:** `../scope.txt` (Tier 1 payment APIs $250–$5,000; Tier 2 web+APIs $150–$3,000). Verify before every action.
- **Public API key:** `adf6d1b8-0aca-4b0c-a492-50530aadd7aa` — **public by design**, never a finding on its own → [[public-api-key-pitfall]].
- **Status:** APK + recon complete; 14 reports written. 2 confirmed N/A (see below).

## Attack surface
### Assets / subdomains (notable)
| Host | Type | Tech / WAF | Notes | Status |
|------|------|-----------|-------|--------|
| www.tripadvisor.com | Main web | DataDome WAF, HSTS, CSP | Hardened — injection/XSS blocked | in-scope |
| api.production.cde.tamg.cloud | Payment CDE API | AWS WAF on root only | **WAF gap** → P2 (REPORT_01). PCI DSS angle | in-scope |
| partnerapi*.tapayments.com, walletproxy*.tapayments.com | Payment APIs | | Tier 1 | in-scope |
| api.viator.com | Subsidiary API | **No DataDome** | exp-api-key disclosure, internal IPs | in-scope |
| *.bokun.io / bookingarea.bokun.io | Subsidiary platform | Cloudflare (gaps) | 250KB jsroutes, 12-finding mega-report (REPORT_09) | in-scope |
| fbauth.viator.com | Firebase hosting | | Full Firebase config exposed (REPORT_13) | in-scope |
| operatorresources.viator.com | WordPress | | wp-json user enum (REPORT_14) | in-scope |
| rentals.tripadvisor.com | Decommissioned | | Shut down Nov 2025, still running, stale tokens | in-scope |
| gwapi.tripadvisor.com | Internal API gateway | | reviews PII endpoint — N/A (public data) | in-scope |

### Tech stack & infra map
- **WAF/CDN:** DataDome (main), Cloudflare (bokun.io), AWS WAF (CDE root only). Coverage is uneven → [[waf-gap-chain]].
- **Servers seen:** Jetty 9.4.26, Tomcat 7.0.90, nginx 1.27.2/1.30.0, Apache httpd, Envoy.
- **Internal IPs:** 10.40.14.179, 10.40.8.150, 10.40.7.152, 10.40.7.132 (Viator, via `x-unique-id`); `ip-10-75-128-89.eu-west-1` (HTML comment). → [[response-header-forensics]].
- **Cloud:** S3 (`vi-prod-k8s-json-schemas` public listing, REPORT_13), Firebase (fbauth.viator.com), K8s CRD schemas.

## Credential / token inventory
| Credential | Source | Type | Public-by-design? | Notes |
|-----------|--------|------|-------------------|-------|
| `adf6d1b8-...` | web/APK | Partner API key | **Yes** | Not a finding. Pivot to data exposed *through* it. |
| New Relic `d93e1d23c8`, `5df886ae17` | rentals/decommissioned | NR license keys | No | 2 distinct → multiple NR accounts |
| `AIzaSyC2ZT6...` | fbauth.viator.com `/__/firebase/init.js` | Firebase API key | client-side | Project config exposed; RTDB/Storage rules held |

## Findings (14 reports in `../output/tripadvisor/`)
| Severity | Finding | Status |
|----------|---------|--------|
| P2 | [[tripadvisor-cde-waf-bypass]] — CDE WAF bypass (REPORT_01), PCI DSS; anchors [[tripadvisor-estate-waf-gap]] | submitted |
| P2 | [[tripadvisor-bokun-platform-misconfig]] — Bókun mega-report (REPORT_09), $147K/mo API abuse, chain → [[bokun-platform-compromise]] | submitted |
| P3×10 | CORS reflection, cookie flags, info disclosure, user enum, infra exposure | submitted |
| P2 → **N/A** | GCP Translation API key in APK (REPORT_19) | rejected — public key |
| MEDIUM → **N/A** | gwapi reviews PII (REPORT_03) | rejected — public data |
| P4 (unsubmitted) | Jetty 9.4.26 version disclosure | not submitted |

## Techniques that work / don't here
- **Works:** [[dns-first-recon]], [[response-header-forensics]], [[cors-probing]], [[waf-gap-chain]], [[progressive-auth-probing]], S3/Firebase/wp-json enum.
- **Doesn't (DataDome + CSP on main):** SQLi, XSS, SSRF (OEmbed whitelist), subdomain takeover, open redirect, authed IDOR (no authed testing done).

## Lessons learned (rejections)
- Public/client-side keys ≠ vuln → [[public-api-key-pitfall]]. Public review data ≠ PII.
- For mobile findings, focus on real exploitation (code exec, deep-link hijack), not config disclosure.

## Open threads / next actions
- [x] Promote REPORT_09 to a `finding` page ([[tripadvisor-bokun-platform-misconfig]]) + chain ([[bokun-platform-compromise]]).
- [x] Promote REPORT_01 to a `finding` page ([[tripadvisor-cde-waf-bypass]]) + built estate chain ([[tripadvisor-estate-waf-gap]]).
- [ ] Promote REPORT_12 (Viator API WAF gap) to [[tripadvisor-viator-api-wafgap]] — 3rd node of the estate chain (currently cited inline).
- [ ] Audit adjacent CDE hosts (internalapi/vault-ext/walletproxy.production.cde.tamg.cloud) for the same root-only WAF rule.
- [ ] Revisit Tier 1 payment APIs (tapayments) — least-tested, highest reward.
