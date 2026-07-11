---
type: report
tags:
- report
- auto
target: '[[methodology]]'
severity: high
created: '2026-06-26'
updated: '2026-06-26'
source: https://corneacristian.medium.com/top-25-idor-bug-bounty-reports-ba8cd59ad331
vuln_class: idor
asset_type: api
learning_score: 9
learning_score_rationale: base 6 (high-value class 'idor') · +2 chain · +1 escalation
unresolved_references:
- idor
---

# IDOR BOLA Discovery Methodology and Top Cases (Cornea Top 25)

> Reusable lesson distilled from a disclosed report — see the intel page [[idor-bola-discovery-methodology-and-top-cases-cornea-top-25-intel]].

## Distilled intelligence
- **Root cause:** unknown  
  <sub>provenance: not found</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** Proxy and capture ALL browser->server requests (Burp)., Inspect URL params, header values, and cookies for object identifiers., Decode/crack encoded or hashed IDs (e.g. MD5-hashed ids are crackable)., Heavily enumerate API requests — APIs are the most common IDOR location.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** unknown  
  <sub>provenance: not found</sub>
- **Severity reasoning:** unknown  
  <sub>provenance: no explicit severity statement</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **9/10** — base 6 (high-value class 'idor') · +2 chain · +1 escalation
- signals: chain, escalation

## Unresolved references (recorded, not created)
- `idor` — no page exists (Phase C may create it)

## Related
- Intel: [[idor-bola-discovery-methodology-and-top-cases-cornea-top-25-intel]] · Target: [[methodology]]
