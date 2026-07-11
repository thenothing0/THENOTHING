---
type: report
tags:
- report
- auto
target: '[[gsa-bounty]]'
severity: high
created: '2026-06-26'
updated: '2026-06-26'
source: https://hackerone.com/reports/665651
vuln_class: oauth
asset_type: api
learning_score: 5
learning_score_rationale: base 2 (low-signal class 'open_redirect') · +2 chain · +1
  escalation
unresolved_references:
- open-redirect
---

# GSA OAuth Token Theft via redirect_uri Parameter (HackerOne 665651)

> Reusable lesson distilled from a disclosed report — see the intel page [[gsa-oauth-token-theft-via-redirect-uri-parameter-hackerone-665651-intel]].

## Distilled intelligence
- **Root cause:** insufficient redirect_uri allowlisting (origin-only or partial matching, or an exploitable open redirect on a trusted host) lets the authorization grant be exfiltrated.  
  <sub>provenance: line 9 ('Root cause:')</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** The OAuth authorization endpoint accepted an attacker-influenced redirect_uri that was not strictly validated against the registered allowlist., By pointing redirect_uri at an attacker-controlled destination (or an open redirect on an allowed host), the authorization response (code/token) was delivered to the attacker after the victim authenticated., The attacker replays the stolen code/token to log in as the victim.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** account takeover of any user who initiates the flow via the attacker's crafted link.  
  <sub>provenance: line 11 ('Impact:')</sub>
- **Severity reasoning:** unknown  
  <sub>provenance: no explicit severity statement</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **5/10** — base 2 (low-signal class 'open_redirect') · +2 chain · +1 escalation
- signals: chain, escalation

## Unresolved references (recorded, not created)
- `open-redirect` — no page exists (Phase C may create it)

## Related
- Intel: [[gsa-oauth-token-theft-via-redirect-uri-parameter-hackerone-665651-intel]] · Target: [[gsa-bounty]]
