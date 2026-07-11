---
type: report
tags:
- report
- auto
target: '[[generic]]'
severity: critical
created: '2026-07-06'
updated: '2026-07-06'
source: https://wadgamaraldeen.medium.com/how-i-found-a-critical-jwt-authentication-design-flaw-and-earned-a-1-450-bug-bounty-4ea6bbd90bb5
vuln_class: auth_bypass
asset_type: web
learning_score: 9
learning_score_rationale: base 6 (high-value class 'auth_bypass') · +2 chain · +1
  escalation
unresolved_references:
- auth-bypass
---

# JWT Authentication Design Flaw — Standalone Bearer Token, No Server-Side Session Binding

> Reusable lesson distilled from a disclosed report — see the intel page [[jwt-authentication-design-flaw-standalone-bearer-token-no-server-side-session-binding-intel]].

## Distilled intelligence
- **Root cause:** unknown  
  <sub>provenance: not found</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** Login issued multiple cookies (refresh token, session cookie, platform cookies)., The author removed ALL cookies except the refresh token., The app still treated the session as authenticated — protected pages stayed accessible, no re-auth.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** unknown  
  <sub>provenance: not found</sub>
- **Severity reasoning:** Severity here rests on a conditional premise; the strip-cookies observation alone is a hardening finding, exploitable only when chained with a token-acquisition primitive (issuance flaw / leak / weak alg).  
  <sub>provenance: severity/CVSS line</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **9/10** — base 6 (high-value class 'auth_bypass') · +2 chain · +1 escalation
- signals: chain, escalation

## Unresolved references (recorded, not created)
- `auth-bypass` — no page exists (Phase C may create it)

## Related
- Intel: [[jwt-authentication-design-flaw-standalone-bearer-token-no-server-side-session-binding-intel]] · Target: [[generic]]
