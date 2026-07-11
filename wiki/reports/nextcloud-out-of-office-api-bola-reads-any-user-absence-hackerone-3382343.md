---
type: report
tags:
- report
- auto
target: '[[nextcloud]]'
severity: medium
created: '2026-06-26'
updated: '2026-06-26'
source: https://hackerone.com/reports/3382343
vuln_class: idor
asset_type: api
learning_score: 9
learning_score_rationale: base 6 (high-value class 'idor') · +2 chain · +1 escalation
unresolved_references:
- idor
---

# Nextcloud Out-of-Office API BOLA Reads Any User Absence (HackerOne 3382343)

> Reusable lesson distilled from a disclosed report — see the intel page [[nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343-intel]].

## Distilled intelligence
- **Root cause:** missing per-object authorization — the handler trusts the client-supplied userId instead of binding the query to the session identity.  
  <sub>provenance: line 9 ('Root cause:')</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** The Out-of-Office API endpoints take a userId path parameter identifying whose absence record to read., Any authenticated user could substitute another user's userId and retrieve that user's out-of-office / absence data with no ownership check., Pure object-reference tampering — no privilege required beyond a normal authenticated session.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** cross-user disclosure of absence data (who is away, when, replacement contact) — useful for social-engineering/targeting. Triage outcome (dispute lesson): Nextcloud closed it as Informative, treating cross-user OOO visibility as an intended collaboration feature (like mail autoresponders). Records BOTH the technical bug and the severity-calibration reality: "is it a vuln or a feature?" depends on the data's intended visibility.  
  <sub>provenance: line 11 ('Impact:')</sub>
- **Severity reasoning:** severity-calibration reality: "is it a vuln or a feature?" depends on the data's intended visibility.  
  <sub>provenance: severity/CVSS line</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **9/10** — base 6 (high-value class 'idor') · +2 chain · +1 escalation
- signals: chain, escalation

## Unresolved references (recorded, not created)
- `idor` — no page exists (Phase C may create it)

## Related
- Intel: [[nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343-intel]] · Target: [[nextcloud]]
