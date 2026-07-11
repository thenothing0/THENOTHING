---
type: report
tags:
- report
- auto
target: '[[gitlab]]'
severity: medium
created: '2026-06-26'
updated: '2026-06-26'
source: https://hackerone.com/reports/369451
vuln_class: ssrf
asset_type: api
learning_score: 9
learning_score_rationale: base 6 (high-value class 'ssrf') · +2 chain · +1 escalation
unresolved_references:
- ssrf
---

# GitLab CI Runner SSRF to GCP Metadata Service Token (HackerOne 369451)

> Reusable lesson distilled from a disclosed report — see the intel page [[gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451-intel]].

## Distilled intelligence
- **Root cause:** CI/CD execution environment shares the host's metadata reachability; untrusted job code runs with the runner instance's cloud identity. No network policy isolating workloads from link-local metadata.  
  <sub>provenance: line 9 ('Root cause:')</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** GitLab CI runners did not restrict the CI job's network access to the GCP instance metadata API., A malicious CI job (attacker controls .gitlab-ci.yml) issued requests to http://metadata.google.internal/computeMetadata/v1/ from inside the runner., This allowed creation/retrieval of a service-account token and access to internal Google Cloud Storage buckets containing private keys and logfiles. Noted to work "after first run".  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** service-account token theft → internal bucket read (private keys, logs) → broad cloud compromise. Demonstrates that SSRF need not be an HTTP parameter — arbitrary code execution surfaces (CI, serverless, build steps) are SSRF-equivalent against metadata.  
  <sub>provenance: line 11 ('Impact:')</sub>
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
- Intel: [[gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451-intel]] · Target: [[gitlab]]
