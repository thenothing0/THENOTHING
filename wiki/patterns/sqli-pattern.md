---
type: pattern
tags:
- pattern
- discovered
- sqli
status: candidate
confidence: medium
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-4a5999f42a09
source_refs:
- mail-ru-sql-injection-at-fleet-city-mobil-ru-10-000-intel
- mail-ru-time-based-blind-sql-injection-15-000-intel
- sql-like-clauses-wildcard-injection-mail-ru-intel
- unauthenticated-sql-injection-with-direct-output-at-news-mail-ru-mail-ru-intel
- valve-sql-injection-in-report-xml-php-via-countryfilter-25-000-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T15:59:58Z'
vuln_class: sqli
---

# sqli-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `sqli`, confidence **medium**. new pattern: signature 'sqli' seen across 2 independent sources ({'report_intel': 2}); signals=['auto', 'intel', 'report-derived', 'sqli', 'trust_boundary']; confidence=medium

## Examples (≥2)
- [[unauthenticated-sql-injection-with-direct-output-at-news-mail-ru-mail-ru-intel]]
- [[sql-like-clauses-wildcard-injection-mail-ru-intel]]
- [[mail-ru-sql-injection-at-fleet-city-mobil-ru-10-000-intel]]
- [[mail-ru-time-based-blind-sql-injection-15-000-intel]]
- [[valve-sql-injection-in-report-xml-php-via-countryfilter-25-000-intel]]
