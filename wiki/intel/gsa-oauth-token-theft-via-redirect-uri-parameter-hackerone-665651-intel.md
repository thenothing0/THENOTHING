---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[gsa-bounty]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://hackerone.com/reports/665651
learning_score: 5
---

# GSA OAuth Token Theft via redirect_uri Parameter (HackerOne 665651) — actionable intelligence

> Distilled from report [[gsa-oauth-token-theft-via-redirect-uri-parameter-hackerone-665651]]. What to *reuse*, not an archive copy.

- **Vuln class:** open_redirect
- **Target / asset type:** api / api
- **Root cause to look for:** insufficient redirect_uri allowlisting (origin-only or partial matching, or an exploitable open redirect on a trusted host) lets the authorization grant be exfiltrated.
- **Trust boundary to probe:** unknown
- **Learning score:** 5/10

## Reusable exploitation sequence
1. The OAuth authorization endpoint accepted an attacker-influenced redirect_uri that was not strictly validated against the registered allowlist.
2. By pointing redirect_uri at an attacker-controlled destination (or an open redirect on an allowed host), the authorization response (code/token) was delivered to the attacker after the victim authenticated.
3. The attacker replays the stolen code/token to log in as the victim.

## Provenance
- Source: https://hackerone.com/reports/665651
- Report page: [[gsa-oauth-token-theft-via-redirect-uri-parameter-hackerone-665651]]
- Target: [[gsa-bounty]]
