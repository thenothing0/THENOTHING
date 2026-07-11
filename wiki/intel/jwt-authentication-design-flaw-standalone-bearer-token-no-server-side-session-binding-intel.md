---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[generic]]'
created: '2026-07-06'
updated: '2026-07-06'
sources:
- https://wadgamaraldeen.medium.com/how-i-found-a-critical-jwt-authentication-design-flaw-and-earned-a-1-450-bug-bounty-4ea6bbd90bb5
learning_score: 9
---

# JWT Authentication Design Flaw — Standalone Bearer Token, No Server-Side Session Binding — actionable intelligence

> Distilled from report [[jwt-authentication-design-flaw-standalone-bearer-token-no-server-side-session-binding]]. What to *reuse*, not an archive copy.

- **Vuln class:** auth_bypass
- **Target / asset type:** web / web
- **Root cause to look for:** unknown
- **Trust boundary to probe:** unknown
- **Learning score:** 9/10

## Reusable exploitation sequence
1. Login issued multiple cookies (refresh token, session cookie, platform cookies).
2. The author removed ALL cookies except the refresh token.
3. The app still treated the session as authenticated — protected pages stayed accessible, no re-auth.

## Provenance
- Source: https://wadgamaraldeen.medium.com/how-i-found-a-critical-jwt-authentication-design-flaw-and-earned-a-1-450-bug-bounty-4ea6bbd90bb5
- Report page: [[jwt-authentication-design-flaw-standalone-bearer-token-no-server-side-session-binding]]
- Target: [[generic]]
