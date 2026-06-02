---
type: finding
aliases: ["CDE WAF bypass", "REPORT_01", "tamg.cloud WAF bypass"]
tags: [tamg-cloud, cde, waf-gap, waf-bypass, pci-dss, payment]
target: "[[tripadvisor]]"
host: api.production.cde.tamg.cloud
scope_status: in-scope
status: submitted
severity: P2
report: "../output/tripadvisor/REPORT_1_CDE_WAF_BYPASS.md"
reward: ""
created: 2026-05-30
updated: 2026-05-30
---
# CDE Payment API — Root-Only WAF Enforcement Bypassed (path + method)

> P2 (CWE-693). The WAF on the **Tier-1 CDE payment API** `api.production.cde.tamg.cloud`
> enforces rules **only on `GET /` and `POST /`**. Every other path and several methods reach
> the backend Jetty server directly, unfiltered. On a PCI DSS-scoped CDE host this is a control
> *failure*, not partial protection. Full report: `../output/tripadvisor/REPORT_1_CDE_WAF_BYPASS.md`.

## Summary
- **WAF (AWS ELB)** returns `403` only on `GET /` and `POST /`.
- **All non-root paths** return `404` from the **Jetty** application server — i.e. the WAF never
  sees them. Distinct components confirmed by content-type: WAF 403 = `iso-8859-1`, app 404 = `utf-8`.
- **Methods on root** also bypass: `OPTIONS / → 200` (`Allow: GET,HEAD,POST,OPTIONS`),
  `PUT/DELETE → 405`, `PATCH → 501` — all from the application, proving backend reachability.
- Backend fingerprinted as **Jetty 9.4.26** via `//` → `Bad Message 400: Ambiguous URI empty segment`.

## Evidence / PoC (re-verified at write time)
```bash
curl -sk -o /dev/null -w "%{http_code}" https://api.production.cde.tamg.cloud/        # 403 (WAF)
curl -sk -o /dev/null -w "%{http_code}" https://api.production.cde.tamg.cloud/health  # 404 (Jetty)
curl -sk -X OPTIONS -D- https://api.production.cde.tamg.cloud/                         # 200, Allow: GET,HEAD,POST,OPTIONS
curl -sk https://api.production.cde.tamg.cloud//                                       # Jetty "Bad Message 400"
```
Tested 30+ payment/infra/doc paths (`/api/v1/payments`, `/actuator/env`, `/v3/api-docs`, …) — all
404 from the app (consistent 301-byte body), none filtered by the WAF.

## Impact (maximized but honest)
A WAF deployed as the compensating control for a CardHolder Data Environment inspects only one
path on a multi-path system. **The next researcher who discovers a valid 200 endpoint (e.g. by
intercepting payment flows on www.tripadvisor.com, as scope notes invite) reaches the live CDE
backend with zero WAF inspection.** Compounded by the backend running Jetty 9.4.26 (known CVEs,
REPORT_05) — the WAF was likely deployed *because* of that, and it isn't working.

### PCI DSS (the severity driver — see [[severity-calibration]])
| Req | Relevance |
|-----|-----------|
| 6.4(.2) | Public-facing CDE web apps must be WAF-protected for *all* traffic — root-only ≠ partial, it's a control failure a QSA flags. |
| 6.6 | WAF must address threats across the application; root-only coverage fails this. |
| 11.4 | Monitoring/IDS effectiveness reduced when the WAF can't inspect most traffic. |

## Honest assessment — what limits the impact
- **No valid 200 endpoint discovered** — all non-root paths 404. No sensitive data accessed.
- The actual payment-API attack surface is unknown without intercepting real payment flows.
- The case rests on the *bypass being reproducible* + the *PCI control-failure framing*, not on a
  demonstrated data breach. (This is exactly why it's P2 on compliance grounds, not P1.)

## Techniques used
[[403-waf-bypass]] (path + method families; WAF-vs-backend differentiation), [[dns-first-recon]]
(host discovered among 5,286 tamg.cloud subs / 549 CDE hosts, REPORT_02), [[response-header-forensics]]
(content-type split + Jetty error fingerprint).

## Chaining
Anchor node of the [[tripadvisor-estate-waf-gap]] chain. Instance of [[waf-gap-chain]].
Adjacent CDE hosts to audit for the same rule: `internalapi.production.cde.tamg.cloud`,
`vault-ext.production.cde.tamg.cloud`, `walletproxy.production.cde.tamg.cloud`.

## Status / triage
- Submitted as REPORT_01. Response: pending.
