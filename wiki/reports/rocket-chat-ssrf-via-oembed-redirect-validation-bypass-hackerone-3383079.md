---
type: report
tags:
- report
- auto
target: '[[rocketchat]]'
severity: medium
created: '2026-06-26'
updated: '2026-06-26'
source: https://hackerone.com/reports/3383079
vuln_class: ssrf
asset_type: api
learning_score: 8
learning_score_rationale: base 6 (high-value class 'ssrf') · +2 chain
unresolved_references:
- ssrf
---

# Rocket.Chat SSRF via oEmbed Redirect Validation Bypass (HackerOne 3383079)

> Reusable lesson distilled from a disclosed report — see the intel page [[rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079-intel]].

## Distilled intelligence
- **Root cause:** allowlist/SSRF guard applied only to the initial URL, not to redirect targets ("time-of-check vs time-of-fetch"). Redirect following defeats first-hop validation.  
  <sub>provenance: line 9 ('Root cause:')</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** Rocket.Chat's oEmbed/link-preview fetches posted URLs server-side to render a preview., Direct internal URLs may be blocked, but the destination of an HTTP redirect was NOT re-validated. The attacker posts a public shortener / attacker-controlled URL that 30x-redirects to an internal host., The server follows the redirect and fetches the internal address, rendering the response — confirming SSRF. The reporter noted the same primitive reaches cloud metadata (e.g. AWS IMDS 169.254.169.254) and internal services.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** read internal services / cloud metadata via a public, unauthenticated message-preview feature; potential credential theft if redirected to IMDS.  
  <sub>provenance: line 11 ('Impact:')</sub>
- **Severity reasoning:** unknown  
  <sub>provenance: no explicit severity statement</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **8/10** — base 6 (high-value class 'ssrf') · +2 chain
- signals: chain

## Unresolved references (recorded, not created)
- `ssrf` — no page exists (Phase C may create it)

## Related
- Intel: [[rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079-intel]] · Target: [[rocketchat]]
