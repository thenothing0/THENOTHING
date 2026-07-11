---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[us-dod-vdp]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://hackerone.com/reports/1624140
learning_score: 8
---

# US DoD SSRF to AWS Metadata via download-url (HackerOne 1624140) — actionable intelligence

> Distilled from report [[us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140]]. What to *reuse*, not an archive copy.

- **Vuln class:** ssrf
- **Target / asset type:** api / api
- **Root cause to look for:** unvalidated user-supplied URL passed to a server-side HTTP client with no allowlist and no metadata-IP block; instance on IMDSv1 (no session-token requirement).
- **Trust boundary to probe:** unknown
- **Learning score:** 8/10

## Reusable exploitation sequence
1. An endpoint accepted a fully attacker-controlled URL parameter: /api/v1/download-url?url=  — a server-side fetch sink.
2. Supplying url=http://169.254.169.254/latest/meta-data/ caused the server to fetch the AWS EC2 Instance Metadata Service (IMDSv1, no token required) and return the response.
3. Walking the metadata tree (…/iam/security-credentials/<role>) yields temporary IAM role credentials (AccessKeyId, SecretAccessKey, Token).

## Provenance
- Source: https://hackerone.com/reports/1624140
- Report page: [[us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140]]
- Target: [[us-dod-vdp]]

## Patterns (discovered)
- [[ssrf-pattern]]
