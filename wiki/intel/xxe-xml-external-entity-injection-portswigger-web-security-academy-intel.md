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
- https://portswigger.net/web-security/xxe
learning_score: 8
---

# XXE (XML External Entity) Injection — PortSwigger Web Security Academy — actionable intelligence

> Distilled from report [[xxe-xml-external-entity-injection-portswigger-web-security-academy]]. What to *reuse*, not an archive copy.

- **Vuln class:** ssrf
- **Target / asset type:** api / api
- **Root cause to look for:** XML parsers support dangerous features by default. The XML specification contains potentially dangerous features (external entity declarations, parameter entities, XInclude), and standard parsers support these even when not needed by the application. Vulnerability arises when: 1. The application accepts and parses untrusted XML. 2. The XML parser is not hardened against entity expansion. 3. The application echoes parsed data or performs server-side actions based on entity content.
- **Trust boundary to probe:** unknown
- **Learning score:** 8/10

## Reusable exploitation sequence
1. The application accepts and parses untrusted XML.
2. The XML parser is not hardened against entity expansion.
3. The application echoes parsed data or performs server-side actions based on entity content.
4. **Confidentiality** – Read `/etc/passwd`, config files, private keys, database credentials.
5. **SSRF** – Probe internal network, access cloud metadata (AWS/GCP), bypass firewalls.
6. **Denial of Service** – Billion Laughs, XML bomb (if external entity expansion not blocked).
7. **Remote Code Execution** – Indirect, via SSRF to deployment pipeline or infrastructure.
8. **Data Exfiltration** – Out-of-band via blind XXE callback.
9. **Burp Scanner** – Automatic XXE detection via payload injection + response analysis.
10. **Manual testing** – Inject entity in each XML node; monitor for:

## Provenance
- Source: https://portswigger.net/web-security/xxe
- Report page: [[xxe-xml-external-entity-injection-portswigger-web-security-academy]]
- Target: [[methodology]]

## Patterns (discovered)
- [[rce-pattern]]
