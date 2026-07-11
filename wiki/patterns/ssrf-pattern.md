---
type: pattern
tags:
- pattern
- discovered
- ssrf
status: candidate
confidence: high
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-6eeca837f1eb
source_refs:
- blind-ssrf-to-internal-services-in-matrix-preview-link-api-reddit-intel
- dropbox-full-response-ssrf-via-google-drive-integration-17-576-intel
- exposed-proxy-allows-access-to-internal-reddit-domains-intel
- gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451-intel
- gitlab-repositorypipeline-allows-importing-of-local-git-repos-22-300-intel
- gitlab-ssrf-via-remote-attachment-url-on-note-10-000-intel
- hackerone-confluence-ssrf-12-500-intel
- rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079-intel
- ssrf-exploitation-methodology-and-payload-catalog-2025-squidhacker-intel
- tripadvisor-bokun-platform-misconfig
- us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T14:40:14Z'
vuln_class: ssrf
---

# ssrf-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `ssrf`, confidence **high**. new pattern: signature 'ssrf' seen across 5 independent sources ({'report_intel': 4, 'validated_finding': 1}); signals=['auto', 'chain', 'intel', 'report-derived', 'ssrf', 'trust_boundary']; confidence=high

## Examples (≥2)
- [[exposed-proxy-allows-access-to-internal-reddit-domains-intel]]
- [[blind-ssrf-to-internal-services-in-matrix-preview-link-api-reddit-intel]]
- [[gitlab-ssrf-via-remote-attachment-url-on-note-10-000-intel]]
- [[hackerone-confluence-ssrf-12-500-intel]]
- [[dropbox-full-response-ssrf-via-google-drive-integration-17-576-intel]]
- [[gitlab-repositorypipeline-allows-importing-of-local-git-repos-22-300-intel]]
- [[gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451-intel]]
- [[rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079-intel]]
- [[ssrf-exploitation-methodology-and-payload-catalog-2025-squidhacker-intel]]
- [[tripadvisor-bokun-platform-misconfig]]
- [[us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140-intel]]
