---
type: pattern
tags:
- pattern
- discovered
- path_traversal
status: candidate
confidence: medium
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-00ef16c53854
source_refs:
- arbitrary-file-reading-on-uber-ssl-vpn-intel
- gitlab-arbitrary-file-read-during-project-import-16-000-intel
- gitlab-arbitrary-file-read-via-bulk-imports-uploadspipeline-29-000-intel
- gitlab-arbitrary-file-read-via-uploadsrewriter-20-000-intel
- gitlab-path-traversal-in-nuget-package-registry-12-000-intel
- gitlab-path-traversal-to-rce-12-000-intel
- gitlab-workhorse-bypass-allowing-file-read-10-000-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T15:49:32Z'
vuln_class: path_traversal
---

# path-traversal-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `path_traversal`, confidence **medium**. new pattern: signature 'path_traversal' seen across 2 independent sources ({'report_intel': 2}); signals=['auto', 'intel', 'path_traversal', 'report-derived', 'trust_boundary']; confidence=medium

## Examples (≥2)
- [[arbitrary-file-reading-on-uber-ssl-vpn-intel]]
- [[gitlab-workhorse-bypass-allowing-file-read-10-000-intel]]
- [[gitlab-path-traversal-to-rce-12-000-intel]]
- [[gitlab-path-traversal-in-nuget-package-registry-12-000-intel]]
- [[gitlab-arbitrary-file-read-during-project-import-16-000-intel]]
- [[gitlab-arbitrary-file-read-via-bulk-imports-uploadspipeline-29-000-intel]]
- [[gitlab-arbitrary-file-read-via-uploadsrewriter-20-000-intel]]
