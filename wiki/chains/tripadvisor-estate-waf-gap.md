---
type: chain
aliases:
- estate-wide WAF gap
- Tripadvisor group WAF gap
- systemic WAF coverage gap
tags:
- waf-gap
- chaining
- subsidiary
- systemic
- pci-dss
target: '[[tripadvisor]]'
severity: P2
created: 2026-05-30
updated: '2026-06-26'
nodes:
- '[[tripadvisor-cde-waf-bypass]]'
- '[[tripadvisor-bokun-platform-misconfig]]'
- tripadvisor-bokun-platform-misconfig
- tripadvisor-cde-waf-bypass
---

# Tripadvisor Estate-Wide WAF-Gap Chain

> Not a single-host exploit chain but a **systemic-posture chain**: the same WAF-coverage failure
> recurs independently across **three separate Tripadvisor subsidiaries/clouds**, on
> revenue-critical and PCI-scoped surfaces. Individually the nodes triage P2/P3; together they
> demonstrate a *group-level* security-control failure — the framing that justifies the top
> severity and resists per-host dismissal. Instance of [[waf-gap-chain]]; tactic per [[severity-calibration]].

## The recurring failure
`www.*` brand domains enforce DataDome/Cloudflare; the **APIs, payment hosts, and acquired
platforms behind them do not.** Each was discovered via [[dns-first-recon]] and confirmed with
[[403-waf-bypass]] / [[response-header-forensics]].

| Node | Host | Brand control | Gap | Severity driver | Source |
|------|------|---------------|-----|-----------------|--------|
| **1. CDE / tamg.cloud** | `api.production.cde.tamg.cloud` | AWS WAF (root only) | All non-root paths + OPTIONS/PUT/DELETE/PATCH reach Jetty unfiltered | **PCI DSS 6.4/6.6/11.4** on a CardHolder Data Environment | [[tripadvisor-cde-waf-bypass]] (REPORT_01, P2) |
| **2. Bókun** | `payments/bookingarea/static/imgcdn.bokun.io` (7 subdomains) | Cloudflare on `bokun.io` | No WAF/headers on payments, booking, CDN origin, S3, image CDN | $147K/mo API abuse + payment-page clickjacking | [[tripadvisor-bokun-platform-misconfig]] (REPORT_09, P2) |
| **3. Viator** | `api.viator.com` | DataDome on `www.viator.com` | No DataDome on the booking API — no rate-limit/bot-detect; accepts `User-Agent: sqlmap/1.7` | unauth probing + `exp-api-key` progressive disclosure on the revenue API | `../output/tripadvisor/REPORT_12_VIATOR_API.md` (P3) — promote to [[tripadvisor-viator-api-wafgap]] |

## Why the chain > sum of parts
- **Independence proves it's structural, not a one-off.** Three different teams, three different
  clouds (AWS ELB / Cloudflare+CloudFront / DataDome), same mistake → it's a *process* failure
  (no org-wide standard that "an API/subdomain inherits its brand's WAF"), not a misconfigured box.
- **It lands on the worst surfaces.** A PCI CDE payment API (node 1), a Stripe payment platform +
  $147K/mo abusable proxy (node 2), and the revenue-critical booking API (node 3) — the gap
  consistently exposes money/payment flows, not marketing pages.
- **Acquisitions inherit weaker posture.** Bókun and Viator are acquired; both show the gap the
  parent brand domain doesn't — the classic subsidiary pattern in [[waf-gap-chain]].
- **Remediation is one decision, not three tickets:** mandate that every internet-facing
  subdomain/API inherit (≥) its brand domain's WAF + security-header baseline, enforced in the
  deploy pipeline. Framing it as one systemic finding makes that the obvious fix.

## Severity
**P2 group-level.** Don't double-count the nodes' standalone severities; the elevation is the
*pattern across the estate* + the PCI/payment surface concentration. See [[severity-calibration]].

## Honest assessment — what limits it
- No node demonstrated a data breach *through* the gap: node 1 found no 200 endpoint, node 3's
  `exp-api-key` is likely a provisioned UUID (brute-force infeasible), node 2's authed endpoints
  still 303→login. The chain's strength is **systemic control failure on sensitive surfaces**,
  not a single proven exfiltration. State that plainly.

## Related
- Pattern: [[waf-gap-chain]], [[severity-calibration]] · Findings: [[tripadvisor-cde-waf-bypass]],
  [[tripadvisor-bokun-platform-misconfig]] · Techniques: [[dns-first-recon]], [[403-waf-bypass]],
  [[response-header-forensics]] · Target: [[tripadvisor]]
