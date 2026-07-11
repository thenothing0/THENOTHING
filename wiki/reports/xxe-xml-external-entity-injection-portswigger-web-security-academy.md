---
type: report
tags:
- report
- auto
target: '[[methodology]]'
severity: critical
created: '2026-06-26'
updated: '2026-06-26'
source: https://portswigger.net/web-security/xxe
vuln_class: ssrf
asset_type: api
learning_score: 8
learning_score_rationale: base 6 (high-value class 'ssrf') · +2 chain
unresolved_references:
- ssrf
---

# XXE (XML External Entity) Injection — PortSwigger Web Security Academy

> Reusable lesson distilled from a disclosed report — see the intel page [[xxe-xml-external-entity-injection-portswigger-web-security-academy-intel]].

## Distilled intelligence
- **Root cause:** XML parsers support dangerous features by default. The XML specification contains potentially dangerous features (external entity declarations, parameter entities, XInclude), and standard parsers support these even when not needed by the application. Vulnerability arises when: 1. The application accepts and parses untrusted XML. 2. The XML parser is not hardened against entity expansion. 3. The application echoes parsed data or performs server-side actions based on entity content.  
  <sub>provenance: section '## Root Cause' (line 3)</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** The application accepts and parses untrusted XML., The XML parser is not hardened against entity expansion., The application echoes parsed data or performs server-side actions based on entity content., **Confidentiality** – Read `/etc/passwd`, config files, private keys, database credentials., **SSRF** – Probe internal network, access cloud metadata (AWS/GCP), bypass firewalls., **Denial of Service** – Billion Laughs, XML bomb (if external entity expansion not blocked)., **Remote Code Execution** – Indirect, via SSRF to deployment pipeline or infrastructure., **Data Exfiltration** – Out-of-band via blind XXE callback., **Burp Scanner** – Automatic XXE detection via payload injection + response analysis., **Manual testing** – Inject entity in each XML node; monitor for:  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** 1. **Confidentiality** – Read `/etc/passwd`, config files, private keys, database credentials. 2. **SSRF** – Probe internal network, access cloud metadata (AWS/GCP), bypass firewalls. 3. **Denial of Service** – Billion Laughs, XML bomb (if external entity expansion not blocked). 4. **Remote Code Execution** – Indirect, via SSRF to deployment pipeline or infrastructure. 5. **Data Exfiltration** – Out-of-band via blind XXE callback.  
  <sub>provenance: section '## Impact' (line 67)</sub>
- **Severity reasoning:** severity** (CWE-611) when exploited for file disclosure or SSRF.  
  <sub>provenance: severity/CVSS line</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **8/10** — base 6 (high-value class 'ssrf') · +2 chain
- signals: chain

## Unresolved references (recorded, not created)
- `ssrf` — no page exists (Phase C may create it)

## Related
- Intel: [[xxe-xml-external-entity-injection-portswigger-web-security-academy-intel]] · Target: [[methodology]]
