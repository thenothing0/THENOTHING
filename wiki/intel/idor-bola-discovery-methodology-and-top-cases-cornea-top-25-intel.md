---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[methodology]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://corneacristian.medium.com/top-25-idor-bug-bounty-reports-ba8cd59ad331
learning_score: 9
---

# IDOR BOLA Discovery Methodology and Top Cases (Cornea Top 25) — actionable intelligence

> Distilled from report [[idor-bola-discovery-methodology-and-top-cases-cornea-top-25]]. What to *reuse*, not an archive copy.

- **Vuln class:** idor
- **Target / asset type:** api / api
- **Root cause to look for:** unknown
- **Trust boundary to probe:** unknown
- **Learning score:** 9/10

## Reusable exploitation sequence
1. Proxy and capture ALL browser->server requests (Burp).
2. Inspect URL params, header values, and cookies for object identifiers.
3. Decode/crack encoded or hashed IDs (e.g. MD5-hashed ids are crackable).
4. Heavily enumerate API requests — APIs are the most common IDOR location.

## Provenance
- Source: https://corneacristian.medium.com/top-25-idor-bug-bounty-reports-ba8cd59ad331
- Report page: [[idor-bola-discovery-methodology-and-top-cases-cornea-top-25]]
- Target: [[methodology]]

## Patterns (discovered)
- [[idor-pattern]]
