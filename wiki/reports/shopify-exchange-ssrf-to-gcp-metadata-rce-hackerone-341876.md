---
type: report
tags:
- report
- auto
target: '[[shopify]]'
severity: critical
created: '2026-06-26'
updated: '2026-06-26'
source: https://hackerone.com/reports/341876
vuln_class: ssrf
asset_type: api
learning_score: 9
learning_score_rationale: base 6 (high-value class 'ssrf') · +2 chain · +1 escalation
unresolved_references:
- ssrf
---

# Shopify Exchange SSRF to GCP Metadata RCE (HackerOne 341876)

> Reusable lesson distilled from a disclosed report — see the intel page [[shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876-intel]].

## Distilled intelligence
- **Root cause:** server-side URL fetcher with no allowlist / no egress restriction to link-local metadata IP, combined with GCP's legacy v1beta1 metadata path not enforcing the anti-SSRF header.  
  <sub>provenance: line 10 ('Root cause:')</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** The Exchange store-screenshot feature fetched attacker-supplied URLs server-side (classic URL-fetch SSRF sink)., GCP instance metadata normally requires the request header "Metadata-Flavor: Google", which a basic SSRF cannot set. Reading GCP docs, the researcher found the legacy endpoint http://metadata.google.internal/computeMetadata/v1beta1/ still served metadata WITHOUT the Metadata-Flavor header — a built-in header-requirement bypass., Via v1beta1 the SSRF retrieved the instance service-account token and project metadata, then escalated to remote code execution on the instance., Researcher stopped at confirmed RCE; Shopify disabled the vulnerable service the same night.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** full instance compromise (RCE) and theft of GCP service-account credentials → potential lateral movement across the project.  
  <sub>provenance: line 12 ('Impact:')</sub>
- **Severity reasoning:** unknown  
  <sub>provenance: no explicit severity statement</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **9/10** — base 6 (high-value class 'ssrf') · +2 chain · +1 escalation
- signals: chain, escalation

## Unresolved references (recorded, not created)
- `ssrf` — no page exists (Phase C may create it)

## Related
- Intel: [[shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876-intel]] · Target: [[shopify]]
