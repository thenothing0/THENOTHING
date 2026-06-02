---
type: pattern
aliases: ["severity", "P4 to P2", "VRT calibration"]
tags: [severity, reporting, chaining]
created: 2026-05-30
updated: 2026-05-30
---
# Severity Calibration

> What turns a low-severity scanner hit into a high-severity, well-paid report. Calibrated
> from 14 Tripadvisor reports (2× P2, 10× P3, 2× P4).

## The four elevators (P4 → P2)
1. **Financial impact** — quantify: `API calls × price/call × abuse rate × 30 days`. (Bókun
   Google Places proxy = $2.83–$17 / 1000 calls × millions = **$147K/month** → P2.)
2. **Compliance implications** — name the standard: **PCI DSS 6.4/6.6/11.4** (WAF gap on CDE),
   **GDPR** (bulk PII export), **SOC 2** (access-control failure).
3. **Pattern multiplier** — 1 misconfigured cookie = P4; 10 cookies missing the same flag on
   the session API = P3; the same pattern across 7 subsidiary subdomains = **P2**.
4. **Chain completion** — CORS wildcard alone = P4; CORS + sequential IDs + no rate limiting +
   browser PoC = P3 chain; add API-proxy abuse + payment-page clickjacking = P2 platform report.

## Reporting moves that realize the severity
- **Honest Assessment** section ("what limits the impact") — pre-empts triager counterarguments, builds credibility.
- **Comparison tables** for systematic findings (cookies, CORS, WAF coverage, server versions).
- **Cross-report chaining** — reference 2-3 other findings by number; show systemic posture.
- **Mega-reports** — cluster many findings on one subsidiary into one P2 instead of a dozen P4s.
- **Maximize impact honestly** — worst realistic scenario, users affected, $ + compliance, chain escalation.

## What does NOT elevate (don't waste effort)
- The mere existence of a **public/client-side key** → [[public-api-key-pitfall]].
- Speculative chains ("if XSS existed...") with no confirmed component.
- Double-counting a standalone P3's severity into "the chain also makes it P3."

## Examples
- [[tripadvisor]] — both P2s came from elevators #1 (financial) and #2 (PCI DSS); the P3s from
  #3 (pattern multiplier) and PII exposure.

## Related
- Patterns: [[waf-gap-chain]], [[public-api-key-pitfall]] · Techniques: all
