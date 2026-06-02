---
type: technique
aliases: ["403 bypass", "WAF bypass"]
tags: [waf, access-control, bypass]
created: 2026-05-30
updated: 2026-05-30
---
# 403 / WAF Bypass

> On any 403, systematically attempt bypass families and **document WAF response vs Backend
> response for every attempt** (per CLAUDE.md methodology). Don't overstate — a `200` on
> robots.txt is not a bypass.

## When to use
Any 403 Forbidden, especially on protected paths of a host with a WAF (see [[waf-gap-chain]]).

## Procedure (try in order, document each)
1. **Path-based:** `/%2e/path`, `/path/..;/`, `/path;/`, `//path`, `/./path`
2. **Method-based:** OPTIONS, PUT, DELETE, PATCH, TRACE, HEAD, CONNECT
3. **Header-based:** `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`
4. **Host header:** `Host: localhost`, `Host: 127.0.0.1`
5. **Encoding:** URL encoding, double encoding, Unicode normalization
6. **Root-only protection:** test `/` vs `/*` vs `/specific-path` (WAF often on root only)

## What "a hit" looks like
A request reaching the **backend** (distinct response body/headers/version) where the WAF
returned 403. Confirm it's the app responding, not another WAF page.

## Severity & framing
On a payment/CDE path → cite **PCI DSS 6.4 / 6.6 / 11.4** → P2. See [[severity-calibration]].

## Evidence it works (real hits)
- [[tripadvisor]] — AWS WAF protected `api.production.cde.tamg.cloud` root only; other paths
  reachable → **P2** (REPORT_01), PCI DSS angle.

## Pitfalls / false positives
- A 200 on an already-public path (robots.txt, health) is not a bypass — be honest.
- Distinguish "WAF 403" from "backend 403/401" — they mean different things.

## Related
- Patterns: [[waf-gap-chain]], [[severity-calibration]] · Techniques: [[dns-first-recon]] (find the gap)
