---
type: report
tags:
- report
- auto
target: '[[us-dod-vdp]]'
severity: medium
created: '2026-06-26'
updated: '2026-06-26'
source: https://hackerone.com/reports/1624140
vuln_class: ssrf
asset_type: api
learning_score: 8
learning_score_rationale: base 6 (high-value class 'ssrf') · +2 chain
unresolved_references:
- ssrf
---

# US DoD SSRF to AWS Metadata via download-url (HackerOne 1624140)

> Reusable lesson distilled from a disclosed report — see the intel page [[us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140-intel]].

## Distilled intelligence
- **Root cause:** unvalidated user-supplied URL passed to a server-side HTTP client with no allowlist and no metadata-IP block; instance on IMDSv1 (no session-token requirement).  
  <sub>provenance: line 9 ('Root cause:')</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** An endpoint accepted a fully attacker-controlled URL parameter: /api/v1/download-url?url=  — a server-side fetch sink., Supplying url=http://169.254.169.254/latest/meta-data/ caused the server to fetch the AWS EC2 Instance Metadata Service (IMDSv1, no token required) and return the response., Walking the metadata tree (…/iam/security-credentials/<role>) yields temporary IAM role credentials (AccessKeyId, SecretAccessKey, Token).  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** theft of IAM role credentials → access to whatever the role permits (S3, etc.); same primitive as the 2019 Capital One breach.  
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
- Intel: [[us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140-intel]] · Target: [[us-dod-vdp]]
