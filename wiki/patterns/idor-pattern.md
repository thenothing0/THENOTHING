---
type: pattern
tags:
- pattern
- discovered
- idor
status: candidate
confidence: medium
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-2dca87532363
source_refs:
- cross-organization-data-access-in-city-mobil-ru-mail-ru-intel
- customer-private-program-discloses-email-of-any-user-via-invited-username-hackerone-intel
- github-arbitrary-read-of-another-user-s-private-repository-without-authorization-idor-intel
- gitlab-private-objects-exposed-through-project-import-idor-20-000-intel
- gitlab-steal-private-objects-of-other-projects-via-project-import-20-000-intel
- hackerone-graphql-idor-exposing-private-program-policypageassetgroup-25-000-intel
- hackerone-idor-to-view-email-from-any-report-12-500-intel
- hackerone-idor-to-view-license-key-12-500-intel
- idor-bola-discovery-methodology-and-top-cases-cornea-top-25-intel
- mail-ru-observer-privesc-to-admin-15-000-intel
- mail-ru-read-new-emails-from-any-inbox-via-ios-app-notification-center-idor-intel
- nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343-intel
- paypal-idor-to-add-secondary-users-10-500-intel
- snapchat-idor-user-disclosure-15-000-intel
- valve-getting-all-cd-keys-of-any-game-via-idor-20-000-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T14:40:22Z'
vuln_class: idor
---

# idor-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `idor`, confidence **medium**. new pattern: signature 'idor' seen across 2 independent sources ({'report_intel': 2}); signals=['auto', 'escalation', 'idor', 'intel', 'report-derived', 'trust_boundary']; confidence=medium

## Examples (≥2)
- [[customer-private-program-discloses-email-of-any-user-via-invited-username-hackerone-intel]]
- [[cross-organization-data-access-in-city-mobil-ru-mail-ru-intel]]
- [[mail-ru-read-new-emails-from-any-inbox-via-ios-app-notification-center-idor-intel]]
- [[github-arbitrary-read-of-another-user-s-private-repository-without-authorization-idor-intel]]
- [[paypal-idor-to-add-secondary-users-10-500-intel]]
- [[snapchat-idor-user-disclosure-15-000-intel]]
- [[mail-ru-observer-privesc-to-admin-15-000-intel]]
- [[hackerone-idor-to-view-license-key-12-500-intel]]
- [[hackerone-idor-to-view-email-from-any-report-12-500-intel]]
- [[valve-getting-all-cd-keys-of-any-game-via-idor-20-000-intel]]
- [[hackerone-graphql-idor-exposing-private-program-policypageassetgroup-25-000-intel]]
- [[gitlab-steal-private-objects-of-other-projects-via-project-import-20-000-intel]]
- [[gitlab-private-objects-exposed-through-project-import-idor-20-000-intel]]
- [[idor-bola-discovery-methodology-and-top-cases-cornea-top-25-intel]]
- [[nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343-intel]]
