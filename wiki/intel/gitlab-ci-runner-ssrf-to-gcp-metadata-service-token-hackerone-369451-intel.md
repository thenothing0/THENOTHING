---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[gitlab]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://hackerone.com/reports/369451
learning_score: 9
---

# GitLab CI Runner SSRF to GCP Metadata Service Token (HackerOne 369451) — actionable intelligence

> Distilled from report [[gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451]]. What to *reuse*, not an archive copy.

- **Vuln class:** ssrf
- **Target / asset type:** api / api
- **Root cause to look for:** CI/CD execution environment shares the host's metadata reachability; untrusted job code runs with the runner instance's cloud identity. No network policy isolating workloads from link-local metadata.
- **Trust boundary to probe:** unknown
- **Learning score:** 9/10

## Reusable exploitation sequence
1. GitLab CI runners did not restrict the CI job's network access to the GCP instance metadata API.
2. A malicious CI job (attacker controls .gitlab-ci.yml) issued requests to http://metadata.google.internal/computeMetadata/v1/ from inside the runner.
3. This allowed creation/retrieval of a service-account token and access to internal Google Cloud Storage buckets containing private keys and logfiles. Noted to work "after first run".

## Provenance
- Source: https://hackerone.com/reports/369451
- Report page: [[gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451]]
- Target: [[gitlab]]

## Patterns (discovered)
- [[ssrf-pattern]]
