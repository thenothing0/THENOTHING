---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[nextcloud]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://hackerone.com/reports/3382343
learning_score: 9
---

# Nextcloud Out-of-Office API BOLA Reads Any User Absence (HackerOne 3382343) — actionable intelligence

> Distilled from report [[nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343]]. What to *reuse*, not an archive copy.

- **Vuln class:** idor
- **Target / asset type:** api / api
- **Root cause to look for:** missing per-object authorization — the handler trusts the client-supplied userId instead of binding the query to the session identity.
- **Trust boundary to probe:** unknown
- **Learning score:** 9/10

## Reusable exploitation sequence
1. The Out-of-Office API endpoints take a userId path parameter identifying whose absence record to read.
2. Any authenticated user could substitute another user's userId and retrieve that user's out-of-office / absence data with no ownership check.
3. Pure object-reference tampering — no privilege required beyond a normal authenticated session.

## Provenance
- Source: https://hackerone.com/reports/3382343
- Report page: [[nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343]]
- Target: [[nextcloud]]

## Patterns (discovered)
- [[idor-pattern]]
