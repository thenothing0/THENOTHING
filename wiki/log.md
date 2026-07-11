# Wiki Log

> Append-only chronological record. One entry per ingest / query / lint.
> Prefix format: `## [YYYY-MM-DD] <op> | <summary>` so `grep "^## \[" log.md | tail` works.

## [2026-05-30] init | Wiki bootstrapped
Adapted the LLM Wiki pattern (`../CLAUDE1.md`) to bug-bounty research. Created `SCHEMA.md`,
`index.md`, `log.md`, and `_templates/` (target, technique, asset, pattern, finding, intel,
chain). Seeded from operator memory + `output/` + `scope.txt`:
- Targets: [[tripadvisor]], [[vk]]
- Techniques: [[dns-first-recon]], [[response-header-forensics]], [[cors-probing]],
  [[403-waf-bypass]], [[progressive-auth-probing]]
- Patterns: [[waf-gap-chain]], [[public-api-key-pitfall]], [[severity-calibration]]
- Intel: [[vk-disclosed-reports]]

Next suggested actions: promote individual Tripadvisor reports (REPORT_01 CDE WAF bypass,
REPORT_09 Bókun mega-report) into `finding` pages and build a [[waf-gap-chain]] chain page;
ingest the VK recon dump from `../output/vk_scan/` to populate [[vk]] assets.

## [2026-05-30] ingest | REPORT_9_BOKUN_PLATFORM_MISCONFIG.md → 5 pages
Source: `../output/tripadvisor/REPORT_9_BOKUN_PLATFORM_MISCONFIG.md` (P2, 12 sub-findings).
Created [[tripadvisor-bokun-platform-misconfig]] (finding) and [[bokun-platform-compromise]]
(chain, 6-step). Cross-linked into [[tripadvisor]] (findings table + next-actions),
[[waf-gap-chain]] (examples), and [[index]]. Confirmed it is *not* a [[public-api-key-pitfall]]
case — value rests on the $147K/mo abuse + systemic WAF gap, not key secrecy.

## [2026-05-30] ingest | REPORT_1_CDE_WAF_BYPASS.md + estate-wide chain → 6 pages
Source: `../output/tripadvisor/REPORT_1_CDE_WAF_BYPASS.md` (P2, CWE-693). Created
[[tripadvisor-cde-waf-bypass]] (finding). Built [[tripadvisor-estate-waf-gap]] — the systemic
WAF-gap chain across **3 subsidiaries/clouds**: CDE/tamg.cloud (REPORT_01), Bókun (REPORT_09),
Viator api.viator.com (REPORT_12, cited inline pending promotion to [[tripadvisor-viator-api-wafgap]]).
Cross-linked into [[tripadvisor]], [[waf-gap-chain]], [[index]]. Read REPORT_12 as supporting
evidence for the 3rd node. Open: promote REPORT_12; audit adjacent CDE hosts.

## [2026-05-30] schema | Added Reader Contract
Per operator: agents that read the wiki must *store and understand* it, not skim. Added the
"Reader contract" section to [[SCHEMA]].

## [2026-06-01] ingest | VK triage outcomes → 6 new wiki pages
VK reports triaged by Solimonka. Re-validated R1, R2, R6 with live testing.

**Intel pages created:**
- [[vk-r2-oauth-redirect-fix]]: OAuth redirect_uri reflection fixed by VK. Key lesson: two-endpoint OAuth split (UI vs code issuer).
- [[vk-r6-sms-abuse-live]]: auth.validatePhone still live. Mapped CAPTCHA behavior (2 free per phone/IP, then CAPTCHA; no limit on unique phones).

**Pattern pages created:**
- [[two-endpoint-oauth-split]]: OAuth UI reflecting redirect_uri ≠ exploitable if code issuer validates separately. High false-positive risk.
- [[per-target-vs-mass-rate-limit]]: Per-phone CAPTCHA/rate-limit doesn't prevent mass-targeting unique resources. Applies broadly.

**Technique page created:**
- [[unauthenticated-sms-send]]: Reusable playbook for testing phone validation endpoints. Workflow, impact arguments, cross-target applicability.

**Chain page created:**
- [[vk-auth-chain]]: auth.restore (enum) → auth.validatePhone (SMS) → auth.confirm (brute). Entry+pivot confirmed, escalation theoretical.

Updated [[index]] with all 6 new pages. Updated [[vk]] target status in index.

## [2026-06-01] schema | Added `hypothesis` node type
Closed the gap against the Report Intelligence System spec (hypothesis generation). Created
`hypotheses/` dir + `_templates/hypothesis.md` (falsifiable claim, supporting evidence,
confidence, validation plan, what-would-falsify). Registered `hypothesis` in [[SCHEMA]]
(page-types table, frontmatter keys `confidence`/`status`, new **Hypothesize** operation) and
added a Hypotheses section to [[index]]. No reports processed yet — scaffolding only. Next:
seed hypotheses from [[vk-disclosed-reports]] and the existing patterns via the Hypothesize op.

## [2026-06-05] fuse | materialized 46 asset(s): admin-awards.donationalerts.com, admin-bookkeeper.donationalerts.com, admin-market.donationalerts.com, admins-studio.donationalerts.com, api-awards.donationalerts.com, api-bookkeeper.donationalerts.com, api-bot.donationalerts.com, api-chat.donationalerts.com…

## [2026-06-05] fuse | materialized 61 asset(s): af-02.prod.ptcloud.ru, af-02.ptcloud.ru, af-migration.ptcloud.ru, af-migration.sre.ptcloud.ru, af.ptcloud.ru, afbusrep-old-internal.ptcloud.ru, afbusrep.ptcloud.ru, afbusrep.sre.ptcloud.ru…

## [2026-06-26] report-intel | ingested 'Shopify Exchange SSRF to GCP Metadata RCE (HackerOne 341876)' → report/shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876 + intel/shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876-intel (learning_score=9)

## [2026-06-26] report-intel | ingested 'US DoD SSRF to AWS Metadata via download-url (HackerOne 1624140)' → report/us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140 + intel/us-dod-ssrf-to-aws-metadata-via-download-url-hackerone-1624140-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'GitLab CI Runner SSRF to GCP Metadata Service Token (HackerOne 369451)' → report/gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451 + intel/gitlab-ci-runner-ssrf-to-gcp-metadata-service-token-hackerone-369451-intel (learning_score=9)

## [2026-06-26] report-intel | ingested 'Rocket.Chat SSRF via oEmbed Redirect Validation Bypass (HackerOne 3383079)' → report/rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079 + intel/rocket-chat-ssrf-via-oembed-redirect-validation-bypass-hackerone-3383079-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'Nextcloud Out-of-Office API BOLA Reads Any User Absence (HackerOne 3382343)' → report/nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343 + intel/nextcloud-out-of-office-api-bola-reads-any-user-absence-hackerone-3382343-intel (learning_score=9)

## [2026-06-26] report-intel | ingested 'SSRF Exploitation Methodology and Payload Catalog 2025 (SquidHacker)' → report/ssrf-exploitation-methodology-and-payload-catalog-2025-squidhacker + intel/ssrf-exploitation-methodology-and-payload-catalog-2025-squidhacker-intel (learning_score=9)

## [2026-06-26] report-intel | ingested 'OAuth 2.0 Common Vulnerabilities Catalog (Doyensec 2025)' → report/oauth-2-0-common-vulnerabilities-catalog-doyensec-2025 + intel/oauth-2-0-common-vulnerabilities-catalog-doyensec-2025-intel (learning_score=7)

## [2026-06-26] report-intel | ingested 'Authentik CVE-2024-52289 redirect_uri Regex Bypass Account Takeover (Omegapoint)' → report/authentik-cve-2024-52289-redirect-uri-regex-bypass-account-takeover-omegapoint + intel/authentik-cve-2024-52289-redirect-uri-regex-bypass-account-takeover-omegapoint-intel (learning_score=5)

## [2026-06-26] report-intel | ingested 'GSA OAuth Token Theft via redirect_uri Parameter (HackerOne 665651)' → report/gsa-oauth-token-theft-via-redirect-uri-parameter-hackerone-665651 + intel/gsa-oauth-token-theft-via-redirect-uri-parameter-hackerone-665651-intel (learning_score=5)

## [2026-06-26] report-intel | ingested 'IDOR BOLA Discovery Methodology and Top Cases (Cornea Top 25)' → report/idor-bola-discovery-methodology-and-top-cases-cornea-top-25 + intel/idor-bola-discovery-methodology-and-top-cases-cornea-top-25-intel (learning_score=9)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (create_new, conf=high)

## [2026-06-26] discover | materialized pattern/idor-pattern (create_new, conf=medium)

## [2026-06-26] report-intel | ingested 'OAuth 2.0 Common Vulnerabilities Catalog — Doyensec 2025' → report/oauth-2-0-common-vulnerabilities-catalog-doyensec-2025 + intel/oauth-2-0-common-vulnerabilities-catalog-doyensec-2025-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'Subdomain Takeover: Basics (Patrik Hudak) — CNAME/NS/MX/A Dangling DNS Methodology' → report/subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology + intel/subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Authentik CVE-2024-52289: Redirect URI Regex Bypass to Account Takeover' → report/authentik-cve-2024-52289-redirect-uri-regex-bypass-to-account-takeover + intel/authentik-cve-2024-52289-redirect-uri-regex-bypass-to-account-takeover-intel (learning_score=5)

## [2026-06-26] report-intel | ingested 'XXE (XML External Entity) Injection — PortSwigger Web Security Academy' → report/xxe-xml-external-entity-injection-portswigger-web-security-academy + intel/xxe-xml-external-entity-injection-portswigger-web-security-academy-intel (learning_score=8)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/rce-pattern (create_new, conf=medium)

## [2026-06-26] discover | materialized chain/tripadvisor-estate-waf-gap (strengthen_existing)

## [2026-06-26] report-intel | ingested 'Shopify — Github access token exposure ($50,000)' → report/shopify-github-access-token-exposure-50-000 + intel/shopify-github-access-token-exposure-50-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Uber — API access to Phabricator via leaked certificate ($40,000)' → report/uber-api-access-to-phabricator-via-leaked-certificate-40-000 + intel/uber-api-access-to-phabricator-via-leaked-certificate-40-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'GitLab — Account Takeover via Password Reset without user interaction ($35,000)' → report/gitlab-account-takeover-via-password-reset-without-user-interaction-35-000 + intel/gitlab-account-takeover-via-password-reset-without-user-interaction-35-000-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'Mail.ru — Unprotected Zeppelin instance ($35,000)' → report/mail-ru-unprotected-zeppelin-instance-35-000 + intel/mail-ru-unprotected-zeppelin-instance-35-000-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'GitLab — Remote Command Execution via Github import ($33,510)' → report/gitlab-remote-command-execution-via-github-import-33-510 + intel/gitlab-remote-command-execution-via-github-import-33-510-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'GitLab — RCE via DecompressedArchiveSizeValidator and Project BulkImports ($33,510)' → report/gitlab-rce-via-decompressedarchivesizevalidator-and-project-bulkimports-33-510 + intel/gitlab-rce-via-decompressedarchivesizevalidator-and-project-bulkimports-33-510-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PayPal — RCE via npm misconfig / dependency confusion ($30,000)' → report/paypal-rce-via-npm-misconfig-dependency-confusion-30-000 + intel/paypal-rce-via-npm-misconfig-dependency-confusion-30-000-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'GitLab — Arbitrary file read via bulk imports UploadsPipeline ($29,000)' → report/gitlab-arbitrary-file-read-via-bulk-imports-uploadspipeline-29-000 + intel/gitlab-arbitrary-file-read-via-bulk-imports-uploadspipeline-29-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Snapchat — Exposed Kubernetes API / RCE / Exposed Creds ($25,000)' → report/snapchat-exposed-kubernetes-api-rce-exposed-creds-25-000 + intel/snapchat-exposed-kubernetes-api-rce-exposed-creds-25-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Valve — SQL Injection in report_xml.php via countryFilter[] ($25,000)' → report/valve-sql-injection-in-report-xml-php-via-countryfilter-25-000 + intel/valve-sql-injection-in-report-xml-php-via-countryfilter-25-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'HackerOne — GraphQL IDOR exposing Private Program PolicyPageAssetGroup ($25,000)' → report/hackerone-graphql-idor-exposing-private-program-policypageassetgroup-25-000 + intel/hackerone-graphql-idor-exposing-private-program-policypageassetgroup-25-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — RepositoryPipeline allows importing of local git repos ($22,300)' → report/gitlab-repositorypipeline-allows-importing-of-local-git-repos-22-300 + intel/gitlab-repositorypipeline-allows-importing-of-local-git-repos-22-300-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Teleport — Access list owner privilege escalation to highest roles ($21,000)' → report/teleport-access-list-owner-privilege-escalation-to-highest-roles-21-000 + intel/teleport-access-list-owner-privilege-escalation-to-highest-roles-21-000-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'Twitter/X — Pre-auth RCE on Twitter VPN ($20,160)' → report/twitter-x-pre-auth-rce-on-twitter-vpn-20-160 + intel/twitter-x-pre-auth-rce-on-twitter-vpn-20-160-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PayPal — Stored XSS via HTTP Request Smuggling bypass ($20,000)' → report/paypal-stored-xss-via-http-request-smuggling-bypass-20-000 + intel/paypal-stored-xss-via-http-request-smuggling-bypass-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'HackerOne — Account takeover via leaked session cookie ($20,000)' → report/hackerone-account-takeover-via-leaked-session-cookie-20-000 + intel/hackerone-account-takeover-via-leaked-session-cookie-20-000-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'GitLab — Arbitrary file read via UploadsRewriter ($20,000)' → report/gitlab-arbitrary-file-read-via-uploadsrewriter-20-000 + intel/gitlab-arbitrary-file-read-via-uploadsrewriter-20-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Valve — Getting all CD keys of any game via IDOR ($20,000)' → report/valve-getting-all-cd-keys-of-any-game-via-idor-20-000 + intel/valve-getting-all-cd-keys-of-any-game-via-idor-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Pornhub — RCE via PHP object injection in cookie ($20,000)' → report/pornhub-rce-via-php-object-injection-in-cookie-20-000 + intel/pornhub-rce-via-php-object-injection-in-cookie-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — RCE when removing metadata with ExifTool ($20,000)' → report/gitlab-rce-when-removing-metadata-with-exiftool-20-000 + intel/gitlab-rce-when-removing-metadata-with-exiftool-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — RCE via unsafe inline Kramdown options in Wiki pages ($20,000)' → report/gitlab-rce-via-unsafe-inline-kramdown-options-in-wiki-pages-20-000 + intel/gitlab-rce-via-unsafe-inline-kramdown-options-in-wiki-pages-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PlayStation — BD-J exploit chain / privilege escalation ($20,000)' → report/playstation-bd-j-exploit-chain-privilege-escalation-20-000 + intel/playstation-bd-j-exploit-chain-privilege-escalation-20-000-intel (learning_score=5)

## [2026-06-26] report-intel | ingested 'GitLab — Steal private objects of other projects via project import ($20,000)' → report/gitlab-steal-private-objects-of-other-projects-via-project-import-20-000 + intel/gitlab-steal-private-objects-of-other-projects-via-project-import-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — Private objects exposed through project import IDOR ($20,000)' → report/gitlab-private-objects-exposed-through-project-import-idor-20-000 + intel/gitlab-private-objects-exposed-through-project-import-idor-20-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PayPal — Stored XSS on paypal.com/signin via cache poisoning ($18,900)' → report/paypal-stored-xss-on-paypal-com-signin-via-cache-poisoning-18-900 + intel/paypal-stored-xss-on-paypal-com-signin-via-cache-poisoning-18-900-intel (learning_score=6)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/xss-pattern (create_new, conf=high)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/rce-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/path-traversal-pattern (create_new, conf=medium)

## [2026-06-26] report-intel | ingested 'LocalTapiola — Oracle WebCenter Sites admin access ($18,000)' → report/localtapiola-oracle-webcenter-sites-admin-access-18-000 + intel/localtapiola-oracle-webcenter-sites-admin-access-18-000-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'Shopify Scripts — Struct type confusion RCE ($18,000)' → report/shopify-scripts-struct-type-confusion-rce-18-000 + intel/shopify-scripts-struct-type-confusion-rce-18-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Dropbox — Full Response SSRF via Google Drive integration ($17,576)' → report/dropbox-full-response-ssrf-via-google-drive-integration-17-576 + intel/dropbox-full-response-ssrf-via-google-drive-integration-17-576-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — Stored XSS in markdown via DesignReferenceFilter ($16,000)' → report/gitlab-stored-xss-in-markdown-via-designreferencefilter-16-000 + intel/gitlab-stored-xss-in-markdown-via-designreferencefilter-16-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'GitLab — Arbitrary file read during project import ($16,000)' → report/gitlab-arbitrary-file-read-during-project-import-16-000 + intel/gitlab-arbitrary-file-read-during-project-import-16-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'PayPal — Token leak via rewrite module ($15,300)' → report/paypal-token-leak-via-rewrite-module-15-300 + intel/paypal-token-leak-via-rewrite-module-15-300-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify — TOCTOU race condition in Cart ($15,250)' → report/shopify-toctou-race-condition-in-cart-15-250 + intel/shopify-toctou-race-condition-in-cart-15-250-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'Snapchat — IDOR user disclosure ($15,000)' → report/snapchat-idor-user-disclosure-15-000 + intel/snapchat-idor-user-disclosure-15-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PlayStation — RCE via buffer overflow ($15,000)' → report/playstation-rce-via-buffer-overflow-15-000 + intel/playstation-rce-via-buffer-overflow-15-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Mail.ru — Time-based blind SQL injection ($15,000)' → report/mail-ru-time-based-blind-sql-injection-15-000 + intel/mail-ru-time-based-blind-sql-injection-15-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Snapchat — Jenkins unauthenticated access ($15,000)' → report/snapchat-jenkins-unauthenticated-access-15-000 + intel/snapchat-jenkins-unauthenticated-access-15-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Mail.ru — QCOW2 file read via support attachment ($15,000)' → report/mail-ru-qcow2-file-read-via-support-attachment-15-000 + intel/mail-ru-qcow2-file-read-via-support-attachment-15-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'TikTok — Authentication bypass ($15,000)' → report/tiktok-authentication-bypass-15-000 + intel/tiktok-authentication-bypass-15-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Mail.ru — Observer privesc to admin ($15,000)' → report/mail-ru-observer-privesc-to-admin-15-000 + intel/mail-ru-observer-privesc-to-admin-15-000-intel (learning_score=7)

## [2026-06-26] report-intel | ingested 'Snapchat — JFrog instance with leaked credentials ($15,000)' → report/snapchat-jfrog-instance-with-leaked-credentials-15-000 + intel/snapchat-jfrog-instance-with-leaked-credentials-15-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Cosmos — Chain halt via invalid evidence ($15,000)' → report/cosmos-chain-halt-via-invalid-evidence-15-000 + intel/cosmos-chain-halt-via-invalid-evidence-15-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'GitLab — Stored XSS in wiki via Mermaid ($13,950)' → report/gitlab-stored-xss-in-wiki-via-mermaid-13-950 + intel/gitlab-stored-xss-in-wiki-via-mermaid-13-950-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'GitLab — Stored XSS in Jira integration ($13,950)' → report/gitlab-stored-xss-in-jira-integration-13-950 + intel/gitlab-stored-xss-in-jira-integration-13-950-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Stripe — Mass ATO via CSRF ($13,000)' → report/stripe-mass-ato-via-csrf-13-000 + intel/stripe-mass-ato-via-csrf-13-000-intel (learning_score=5)

## [2026-06-26] report-intel | ingested 'HackerOne — IDOR to view email from any report ($12,500)' → report/hackerone-idor-to-view-email-from-any-report-12-500 + intel/hackerone-idor-to-view-email-from-any-report-12-500-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'HackerOne — IDOR to view license key ($12,500)' → report/hackerone-idor-to-view-license-key-12-500 + intel/hackerone-idor-to-view-license-key-12-500-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'HackerOne — Disclosed report attachments access ($12,500)' → report/hackerone-disclosed-report-attachments-access-12-500 + intel/hackerone-disclosed-report-attachments-access-12-500-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'LY Corp — Spring Actuator RCE ($12,500)' → report/ly-corp-spring-actuator-rce-12-500 + intel/ly-corp-spring-actuator-rce-12-500-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'HackerOne — Confluence SSRF ($12,500)' → report/hackerone-confluence-ssrf-12-500 + intel/hackerone-confluence-ssrf-12-500-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PlayStation — Buffer overflow RCE in firmware ($12,500)' → report/playstation-buffer-overflow-rce-in-firmware-12-500 + intel/playstation-buffer-overflow-rce-in-firmware-12-500-intel (learning_score=6)

## [2026-06-26] discover | materialized pattern/xss-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/rce-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/path-traversal-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/csrf-pattern (create_new, conf=medium)

## [2026-06-26] discover | materialized pattern/sqli-pattern (create_new, conf=medium)

## [2026-06-26] discover | materialized chain/tripadvisor-estate-waf-gap (strengthen_existing)

## [2026-06-26] report-intel | ingested 'HackerOne — DOS via GraphQL mutation aliasing in account recovery ($12,500)' → report/hackerone-dos-via-graphql-mutation-aliasing-in-account-recovery-12-500 + intel/hackerone-dos-via-graphql-mutation-aliasing-in-account-recovery-12-500-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'GitLab — Git flag injection to RCE ($12,000)' → report/gitlab-git-flag-injection-to-rce-12-000 + intel/gitlab-git-flag-injection-to-rce-12-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — Local file overwrite to RCE ($12,000)' → report/gitlab-local-file-overwrite-to-rce-12-000 + intel/gitlab-local-file-overwrite-to-rce-12-000-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'GitLab — Project template privesc to copy private data ($12,000)' → report/gitlab-project-template-privesc-to-copy-private-data-12-000 + intel/gitlab-project-template-privesc-to-copy-private-data-12-000-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'GitLab — Runner tokens exposed via JSON serialization ($12,000)' → report/gitlab-runner-tokens-exposed-via-json-serialization-12-000 + intel/gitlab-runner-tokens-exposed-via-json-serialization-12-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'GitLab — Run pipeline jobs as arbitrary user ($12,000)' → report/gitlab-run-pipeline-jobs-as-arbitrary-user-12-000 + intel/gitlab-run-pipeline-jobs-as-arbitrary-user-12-000-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'TikTok — Account takeover via auth bypass in recovery ($12,000)' → report/tiktok-account-takeover-via-auth-bypass-in-recovery-12-000 + intel/tiktok-account-takeover-via-auth-bypass-in-recovery-12-000-intel (learning_score=7)

## [2026-06-26] report-intel | ingested 'GitLab — Path traversal to RCE ($12,000)' → report/gitlab-path-traversal-to-rce-12-000 + intel/gitlab-path-traversal-to-rce-12-000-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'GitLab — Path traversal in Nuget Package Registry ($12,000)' → report/gitlab-path-traversal-in-nuget-package-registry-12-000 + intel/gitlab-path-traversal-in-nuget-package-registry-12-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'LY Corp — Arbitrary code execution via npm dependency confusion ($11,500)' → report/ly-corp-arbitrary-code-execution-via-npm-dependency-confusion-11-500 + intel/ly-corp-arbitrary-code-execution-via-npm-dependency-confusion-11-500-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'GitLab — Exfiltrate data via injected templated service ($11,000)' → report/gitlab-exfiltrate-data-via-injected-templated-service-11-000 + intel/gitlab-exfiltrate-data-via-injected-templated-service-11-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PayPal — IDOR to add secondary users ($10,500)' → report/paypal-idor-to-add-secondary-users-10-500 + intel/paypal-idor-to-add-secondary-users-10-500-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Grammarly — DOS SSO + account takeover ($10,500)' → report/grammarly-dos-sso-account-takeover-10-500 + intel/grammarly-dos-sso-account-takeover-10-500-intel (learning_score=7)

## [2026-06-26] report-intel | ingested 'PlayStation — Use-after-free in IPV6 leading to kernel R/W ($10,000)' → report/playstation-use-after-free-in-ipv6-leading-to-kernel-r-w-10-000 + intel/playstation-use-after-free-in-ipv6-leading-to-kernel-r-w-10-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Snapchat — Access to production Grafana dashboards ($10,000)' → report/snapchat-access-to-production-grafana-dashboards-10-000 + intel/snapchat-access-to-production-grafana-dashboards-10-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'GitLab — Workhorse bypass allowing file read ($10,000)' → report/gitlab-workhorse-bypass-allowing-file-read-10-000 + intel/gitlab-workhorse-bypass-allowing-file-read-10-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Mail.ru — Memory content disclosure ($10,000)' → report/mail-ru-memory-content-disclosure-10-000 + intel/mail-ru-memory-content-disclosure-10-000-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Mail.ru — SQL injection at fleet.city-mobil.ru ($10,000)' → report/mail-ru-sql-injection-at-fleet-city-mobil-ru-10-000 + intel/mail-ru-sql-injection-at-fleet-city-mobil-ru-10-000-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Mail.ru — RCE on shared.mail.ru via widget plugin ($10,000)' → report/mail-ru-rce-on-shared-mail-ru-via-widget-plugin-10-000 + intel/mail-ru-rce-on-shared-mail-ru-via-widget-plugin-10-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitLab — SSRF via remote_attachment_url on Note ($10,000)' → report/gitlab-ssrf-via-remote-attachment-url-on-note-10-000 + intel/gitlab-ssrf-via-remote-attachment-url-on-note-10-000-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Partial disclosure of report activity through new "Export as .zip" feature' → report/partial-disclosure-of-report-activity-through-new-export-as-zip-feature + intel/partial-disclosure-of-report-activity-through-new-export-as-zip-feature-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Double Payout via PayPal' → report/double-payout-via-paypal + intel/double-payout-via-paypal-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK' → report/sock-raw-sockets-reachable-from-webkit-process-allows-triggering-double-free-in-ip6-exthdr-check + intel/sock-raw-sockets-reachable-from-webkit-process-allows-triggering-double-free-in-ip6-exthdr-check-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Information Disclosure in /skills call' → report/information-disclosure-in-skills-call + intel/information-disclosure-in-skills-call-intel (learning_score=2)

## [2026-06-26] discover | materialized pattern/auth-bypass-pattern (create_new, conf=high)

## [2026-06-26] discover | materialized pattern/xss-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/rce-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/path-traversal-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/sqli-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/csrf-pattern (strengthen_existing, conf=medium)

## [2026-06-26] report-intel | ingested 'Deserialization of untrusted data at redtube.com media/hls endpoint' → report/deserialization-of-untrusted-data-at-redtube-com-media-hls-endpoint + intel/deserialization-of-untrusted-data-at-redtube-com-media-hls-endpoint-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Valve Left4Dead2 buffer overflow RCE via malformed NAV file' → report/valve-left4dead2-buffer-overflow-rce-via-malformed-nav-file + intel/valve-left4dead2-buffer-overflow-rce-via-malformed-nav-file-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitHub arbitrary read of another user's private repository without authorization IDOR' → report/github-arbitrary-read-of-another-user-s-private-repository-without-authorization-idor + intel/github-arbitrary-read-of-another-user-s-private-repository-without-authorization-idor-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'PlayStation sys_fsc2h_ctrl kernel stack use-after-free' → report/playstation-sys-fsc2h-ctrl-kernel-stack-use-after-free + intel/playstation-sys-fsc2h-ctrl-kernel-stack-use-after-free-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'PlayStation double fdrop on socket through sys_netcontrol' → report/playstation-double-fdrop-on-socket-through-sys-netcontrol + intel/playstation-double-fdrop-on-socket-through-sys-netcontrol-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Pornhub publicly exposed SVN repository at ht.pornhub.com' → report/pornhub-publicly-exposed-svn-repository-at-ht-pornhub-com + intel/pornhub-publicly-exposed-svn-repository-at-ht-pornhub-com-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'HackerOne 2FA bypass and reporter blacklist bypass through embedded submission form' → report/hackerone-2fa-bypass-and-reporter-blacklist-bypass-through-embedded-submission-form + intel/hackerone-2fa-bypass-and-reporter-blacklist-bypass-through-embedded-submission-form-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Mail.ru read new emails from any inbox via iOS app notification center IDOR' → report/mail-ru-read-new-emails-from-any-inbox-via-ios-app-notification-center-idor + intel/mail-ru-read-new-emails-from-any-inbox-via-ios-app-notification-center-idor-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitHub authentication bypass on gist.github.com through SSH Certificates' → report/github-authentication-bypass-on-gist-github-com-through-ssh-certificates + intel/github-authentication-bypass-on-gist-github-com-through-ssh-certificates-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'GitHub Enterprise CSRF protection bypass in management console' → report/github-enterprise-csrf-protection-bypass-in-management-console + intel/github-enterprise-csrf-protection-bypass-in-management-console-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'PlayStation use-after-free in setsockopt IPV6_2292PKTOPTIONS CVE-2020-7457' → report/playstation-use-after-free-in-setsockopt-ipv6-2292pktoptions-cve-2020-7457 + intel/playstation-use-after-free-in-setsockopt-ipv6-2292pktoptions-cve-2020-7457-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Uber RCE via Flask Jinja2 template injection SSTI' → report/uber-rce-via-flask-jinja2-template-injection-ssti + intel/uber-rce-via-flask-jinja2-template-injection-ssti-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Zilliqa using gossip protocol to drain miner wallets' → report/zilliqa-using-gossip-protocol-to-drain-miner-wallets + intel/zilliqa-using-gossip-protocol-to-drain-miner-wallets-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Uber password reset token leaking allowed for account takeover' → report/uber-password-reset-token-leaking-allowed-for-account-takeover + intel/uber-password-reset-token-leaking-allowed-for-account-takeover-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'Uber OneLogin authentication bypass on WordPress sites' → report/uber-onelogin-authentication-bypass-on-wordpress-sites + intel/uber-onelogin-authentication-bypass-on-wordpress-sites-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Elastic Kibana RCE hazard in reporting via Chromium' → report/elastic-kibana-rce-hazard-in-reporting-via-chromium + intel/elastic-kibana-rce-hazard-in-reporting-via-chromium-intel (learning_score=7)

## [2026-06-26] report-intel | ingested 'Shopify Scripts infinite loop via zero-length heredoc identifiers' → report/shopify-scripts-infinite-loop-via-zero-length-heredoc-identifiers + intel/shopify-scripts-infinite-loop-via-zero-length-heredoc-identifiers-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts memory corruption via NoMethodError overwrite crash' → report/shopify-scripts-memory-corruption-via-nomethoderror-overwrite-crash + intel/shopify-scripts-memory-corruption-via-nomethoderror-overwrite-crash-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts segfault via break and ||= inside a loop' → report/shopify-scripts-segfault-via-break-and-inside-a-loop + intel/shopify-scripts-segfault-via-break-and-inside-a-loop-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts buffer overflow in mrb_time_asctime' → report/shopify-scripts-buffer-overflow-in-mrb-time-asctime + intel/shopify-scripts-buffer-overflow-in-mrb-time-asctime-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts stack overflow via tight C-level recursion' → report/shopify-scripts-stack-overflow-via-tight-c-level-recursion + intel/shopify-scripts-stack-overflow-via-tight-c-level-recursion-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts segfault via maximum method call arguments' → report/shopify-scripts-segfault-via-maximum-method-call-arguments + intel/shopify-scripts-segfault-via-maximum-method-call-arguments-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts assertion crash via Decimal self-initialization' → report/shopify-scripts-assertion-crash-via-decimal-self-initialization + intel/shopify-scripts-assertion-crash-via-decimal-self-initialization-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts null pointer dereference in codegen with negation' → report/shopify-scripts-null-pointer-dereference-in-codegen-with-negation + intel/shopify-scripts-null-pointer-dereference-in-codegen-with-negation-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Shopify Scripts Range#initialize_copy null pointer dereference' → report/shopify-scripts-range-initialize-copy-null-pointer-dereference + intel/shopify-scripts-range-initialize-copy-null-pointer-dereference-intel (learning_score=2)

## [2026-06-26] discover | materialized pattern/auth-bypass-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/rce-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/csrf-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/xss-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/path-traversal-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/sqli-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized chain/tripadvisor-estate-waf-gap (strengthen_existing)

## [2026-06-26] report-intel | ingested 'Range constructor type confusion DoS — Shopify Scripts' → report/range-constructor-type-confusion-dos-shopify-scripts + intel/range-constructor-type-confusion-dos-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Segfault in mruby/mruby_engine null pointer dereference — Shopify Scripts' → report/segfault-in-mruby-mruby-engine-null-pointer-dereference-shopify-scripts + intel/segfault-in-mruby-mruby-engine-null-pointer-dereference-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'DoS on PayPal via web cache poisoning' → report/dos-on-paypal-via-web-cache-poisoning + intel/dos-on-paypal-via-web-cache-poisoning-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'XSS at jamfpro.shopifycloud.com — Shopify' → report/xss-at-jamfpro-shopifycloud-com-shopify + intel/xss-at-jamfpro-shopifycloud-com-shopify-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'RCE via npm misconfig — installing internal libraries from public registry — Uber' → report/rce-via-npm-misconfig-installing-internal-libraries-from-public-registry-uber + intel/rce-via-npm-misconfig-installing-internal-libraries-from-public-registry-uber-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'RCE on CS:GO client using unsanitized entity ID in EntityMsg — Valve' → report/rce-on-cs-go-client-using-unsanitized-entity-id-in-entitymsg-valve + intel/rce-on-cs-go-client-using-unsanitized-entity-id-in-entitymsg-valve-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'AWS keys and user cookie leakage via uninitialized memory leak in librsvg — Basecamp' → report/aws-keys-and-user-cookie-leakage-via-uninitialized-memory-leak-in-librsvg-basecamp + intel/aws-keys-and-user-cookie-leakage-via-uninitialized-memory-leak-in-librsvg-basecamp-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'SAML Authentication Bypass on uchat.uberinternal.com — Uber' → report/saml-authentication-bypass-on-uchat-uberinternal-com-uber + intel/saml-authentication-bypass-on-uchat-uberinternal-com-uber-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Cross-organization data access in city-mobil.ru — Mail.ru' → report/cross-organization-data-access-in-city-mobil-ru-mail-ru + intel/cross-organization-data-access-in-city-mobil-ru-mail-ru-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'SQL LIKE clauses wildcard injection — Mail.ru' → report/sql-like-clauses-wildcard-injection-mail-ru + intel/sql-like-clauses-wildcard-injection-mail-ru-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'CVE-2022-40604: Apache Airflow Format String Vulnerability — Internet Bug Bounty' → report/cve-2022-40604-apache-airflow-format-string-vulnerability-internet-bug-bounty + intel/cve-2022-40604-apache-airflow-format-string-vulnerability-internet-bug-bounty-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Complete Account Takeover — Uber' → report/complete-account-takeover-uber + intel/complete-account-takeover-uber-intel (learning_score=7)

## [2026-06-26] report-intel | ingested 'RCE and secret token exfiltration by poisoning Mozilla FxA CI build cache' → report/rce-and-secret-token-exfiltration-by-poisoning-mozilla-fxa-ci-build-cache + intel/rce-and-secret-token-exfiltration-by-poisoning-mozilla-fxa-ci-build-cache-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'Account Takeover via billing — Chaturbate' → report/account-takeover-via-billing-chaturbate + intel/account-takeover-via-billing-chaturbate-intel (learning_score=3)

## [2026-06-26] report-intel | ingested 'Segfault via Object#send Ruby method invoked by C — Shopify Scripts' → report/segfault-via-object-send-ruby-method-invoked-by-c-shopify-scripts + intel/segfault-via-object-send-ruby-method-invoked-by-c-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Null target_class DoS — Shopify Scripts' → report/null-target-class-dos-shopify-scripts + intel/null-target-class-dos-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'DoS due to invalid memory access in mrb_ary_concat — Shopify Scripts' → report/dos-due-to-invalid-memory-access-in-mrb-ary-concat-shopify-scripts + intel/dos-due-to-invalid-memory-access-in-mrb-ary-concat-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'DoS in mruby null pointer dereference — Shopify Scripts' → report/dos-in-mruby-null-pointer-dereference-shopify-scripts + intel/dos-in-mruby-null-pointer-dereference-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Undefined method_missing null pointer dereference — Shopify Scripts' → report/undefined-method-missing-null-pointer-dereference-shopify-scripts + intel/undefined-method-missing-null-pointer-dereference-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Ruby DoS mruby.science — Shopify Scripts' → report/ruby-dos-mruby-science-shopify-scripts + intel/ruby-dos-mruby-science-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Segfault in kh_get_mt bad memory access — Shopify Scripts' → report/segfault-in-kh-get-mt-bad-memory-access-shopify-scripts + intel/segfault-in-kh-get-mt-bad-memory-access-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Crash mrb_any_to_s NilClass/Symbol/Fixnum — Shopify Scripts' → report/crash-mrb-any-to-s-nilclass-symbol-fixnum-shopify-scripts + intel/crash-mrb-any-to-s-nilclass-symbol-fixnum-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Crash Proc::initialize_copy with uninitialized Proc — Shopify Scripts' → report/crash-proc-initialize-copy-with-uninitialized-proc-shopify-scripts + intel/crash-proc-initialize-copy-with-uninitialized-proc-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Crash host with uninitialized Time obj mruby-time — Shopify Scripts' → report/crash-host-with-uninitialized-time-obj-mruby-time-shopify-scripts + intel/crash-host-with-uninitialized-time-obj-mruby-time-shopify-scripts-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'DOS via issue preview — GitLab' → report/dos-via-issue-preview-gitlab + intel/dos-via-issue-preview-gitlab-intel (learning_score=2)

## [2026-06-26] discover | materialized pattern/sqli-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/csrf-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/rce-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/auth-bypass-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/xss-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/path-traversal-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized chain/tripadvisor-estate-waf-gap (strengthen_existing)

## [2026-06-26] report-intel | ingested 'Customer private program discloses email of any user via invited username — HackerOne' → report/customer-private-program-discloses-email-of-any-user-via-invited-username-hackerone + intel/customer-private-program-discloses-email-of-any-user-via-invited-username-hackerone-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Stored XSS in Steam React chat client — Valve' → report/stored-xss-in-steam-react-chat-client-valve + intel/stored-xss-in-steam-react-chat-client-valve-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Modify in-flight data to payment provider Smart2Pay — Valve' → report/modify-in-flight-data-to-payment-provider-smart2pay-valve + intel/modify-in-flight-data-to-payment-provider-smart2pay-valve-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'HTTP Request Smuggling via HTTP/2 — Basecamp' → report/http-request-smuggling-via-http-2-basecamp + intel/http-request-smuggling-via-http-2-basecamp-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Exposed proxy allows access to internal Reddit domains' → report/exposed-proxy-allows-access-to-internal-reddit-domains + intel/exposed-proxy-allows-access-to-internal-reddit-domains-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Stealing SSO Login Tokens on snappublisher.snapchat.com — Snapchat' → report/stealing-sso-login-tokens-on-snappublisher-snapchat-com-snapchat + intel/stealing-sso-login-tokens-on-snappublisher-snapchat-com-snapchat-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Stored XSS in developer.uber.com — Uber' → report/stored-xss-in-developer-uber-com-uber + intel/stored-xss-in-developer-uber-com-uber-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'OOB reads in network message handlers leads to RCE — Valve' → report/oob-reads-in-network-message-handlers-leads-to-rce-valve + intel/oob-reads-in-network-message-handlers-leads-to-rce-valve-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Buffer overrun in Steam SILK voice decoder — Valve' → report/buffer-overrun-in-steam-silk-voice-decoder-valve + intel/buffer-overrun-in-steam-silk-voice-decoder-valve-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Unauthenticated SQL Injection with direct output at news.mail.ru — Mail.ru' → report/unauthenticated-sql-injection-with-direct-output-at-news-mail-ru-mail-ru + intel/unauthenticated-sql-injection-with-direct-output-at-news-mail-ru-mail-ru-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'RCE via crafted closed captions file in CS:GO Source engine — Valve' → report/rce-via-crafted-closed-captions-file-in-cs-go-source-engine-valve + intel/rce-via-crafted-closed-captions-file-in-cs-go-source-engine-valve-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'IPv4-mapped IPv6 addresses bypass local IP ban — Cloudflare' → report/ipv4-mapped-ipv6-addresses-bypass-local-ip-ban-cloudflare + intel/ipv4-mapped-ipv6-addresses-bypass-local-ip-ban-cloudflare-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'CS:GO Server to Client RCE through OOB access in CSVCMsg_SplitScreen — Valve' → report/cs-go-server-to-client-rce-through-oob-access-in-csvcmsg-splitscreen-valve + intel/cs-go-server-to-client-rce-through-oob-access-in-csvcmsg-splitscreen-valve-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'Signedness issue in ClassInfo handler leads to RCE on CS:GO client — Valve' → report/signedness-issue-in-classinfo-handler-leads-to-rce-on-cs-go-client-valve + intel/signedness-issue-in-classinfo-handler-leads-to-rce-on-cs-go-client-valve-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Adobe Flash Player FileReference Use-after-Free — Internet Bug Bounty' → report/adobe-flash-player-filereference-use-after-free-internet-bug-bounty + intel/adobe-flash-player-filereference-use-after-free-internet-bug-bounty-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Git flag injection in Search API with scope blobs — GitLab' → report/git-flag-injection-in-search-api-with-scope-blobs-gitlab + intel/git-flag-injection-in-search-api-with-scope-blobs-gitlab-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Authenticated Elasticsearch Painless script execution via GraphQL — HackerOne' → report/authenticated-elasticsearch-painless-script-execution-via-graphql-hackerone + intel/authenticated-elasticsearch-painless-script-execution-via-graphql-hackerone-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'OneLogin authentication bypass on WordPress via XMLRPC — Uber' → report/onelogin-authentication-bypass-on-wordpress-via-xmlrpc-uber + intel/onelogin-authentication-bypass-on-wordpress-via-xmlrpc-uber-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Slack workspace metadata accessible to unauthorized parties' → report/slack-workspace-metadata-accessible-to-unauthorized-parties + intel/slack-workspace-metadata-accessible-to-unauthorized-parties-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Cookie-modification and expired CSP domain replacing Dropbox login page' → report/cookie-modification-and-expired-csp-domain-replacing-dropbox-login-page + intel/cookie-modification-and-expired-csp-domain-replacing-dropbox-login-page-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Arbitrary File Reading on Uber SSL VPN' → report/arbitrary-file-reading-on-uber-ssl-vpn + intel/arbitrary-file-reading-on-uber-ssl-vpn-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Steal bearer token from deep link — Basecamp' → report/steal-bearer-token-from-deep-link-basecamp + intel/steal-bearer-token-from-deep-link-basecamp-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Exposed Cortex API at cortex-ingest.shopifycloud.com — Shopify' → report/exposed-cortex-api-at-cortex-ingest-shopifycloud-com-shopify + intel/exposed-cortex-api-at-cortex-ingest-shopifycloud-com-shopify-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Blind SSRF to internal services in matrix preview_link API — Reddit' → report/blind-ssrf-to-internal-services-in-matrix-preview-link-api-reddit + intel/blind-ssrf-to-internal-services-in-matrix-preview-link-api-reddit-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'XXE on pulse.mail.ru — Mail.ru' → report/xxe-on-pulse-mail-ru-mail-ru + intel/xxe-on-pulse-mail-ru-mail-ru-intel (learning_score=6)

## [2026-06-26] discover | materialized pattern/sqli-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/csrf-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/xss-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/auth-bypass-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/path-traversal-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/idor-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized pattern/ssrf-pattern (strengthen_existing, conf=high)

## [2026-06-26] discover | materialized pattern/rce-pattern (strengthen_existing, conf=medium)

## [2026-06-26] discover | materialized chain/tripadvisor-estate-waf-gap (strengthen_existing)

## [2026-06-26] report-intel | ingested 'Mozilla VPN Clients: RCE via file write and path traversal' → report/mozilla-vpn-clients-rce-via-file-write-and-path-traversal + intel/mozilla-vpn-clients-rce-via-file-write-and-path-traversal-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'Apache Flink RCE via GET jar/plan API Endpoint' → report/apache-flink-rce-via-get-jar-plan-api-endpoint + intel/apache-flink-rce-via-get-jar-plan-api-endpoint-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'HTTP Request Smuggling in Cloudflare Transform Rules using hexadecimal escape sequences in concat()' → report/http-request-smuggling-in-cloudflare-transform-rules-using-hexadecimal-escape-sequences-in-concat + intel/http-request-smuggling-in-cloudflare-transform-rules-using-hexadecimal-escape-sequences-in-concat-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Stored XSS on any page in most Uber domains' → report/stored-xss-on-any-page-in-most-uber-domains + intel/stored-xss-on-any-page-in-most-uber-domains-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Open Selenoid instance at Mail.ru leads to LFR/SSRF' → report/open-selenoid-instance-at-mail-ru-leads-to-lfr-ssrf + intel/open-selenoid-instance-at-mail-ru-leads-to-lfr-ssrf-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Hijack all emails sent to any domain that uses Cloudflare Email Forwarding' → report/hijack-all-emails-sent-to-any-domain-that-uses-cloudflare-email-forwarding + intel/hijack-all-emails-sent-to-any-domain-that-uses-cloudflare-email-forwarding-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Stored XSS via malicious JavaScript injection in tags.tiqcdn.com affecting most Uber domains' → report/stored-xss-via-malicious-javascript-injection-in-tags-tiqcdn-com-affecting-most-uber-domains + intel/stored-xss-via-malicious-javascript-injection-in-tags-tiqcdn-com-affecting-most-uber-domains-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'LRF on shared.mail.ru due to markdown plugin path traversal' → report/lrf-on-shared-mail-ru-due-to-markdown-plugin-path-traversal + intel/lrf-on-shared-mail-ru-due-to-markdown-plugin-path-traversal-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Chain of vulnerabilities in Uber for Business Vouchers allows arbitrary charges via IDOR' → report/chain-of-vulnerabilities-in-uber-for-business-vouchers-allows-arbitrary-charges-via-idor + intel/chain-of-vulnerabilities-in-uber-for-business-vouchers-allows-arbitrary-charges-via-idor-intel (learning_score=8)

## [2026-06-26] report-intel | ingested 'Mint OAuth2 access token for targeted user in GitLab' → report/mint-oauth2-access-token-for-targeted-user-in-gitlab + intel/mint-oauth2-access-token-for-targeted-user-in-gitlab-intel (learning_score=6)

## [2026-06-26] report-intel | ingested 'Possible DoS Vulnerability with Range Header in Rack' → report/possible-dos-vulnerability-with-range-header-in-rack + intel/possible-dos-vulnerability-with-range-header-in-rack-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Stored XSS in SVG file as data: url on Shopify' → report/stored-xss-in-svg-file-as-data-url-on-shopify + intel/stored-xss-in-svg-file-as-data-url-on-shopify-intel (learning_score=4)

## [2026-06-26] report-intel | ingested 'Stored XSS in Shopify /admin/product and /admin/collections' → report/stored-xss-in-shopify-admin-product-and-admin-collections + intel/stored-xss-in-shopify-admin-product-and-admin-collections-intel (learning_score=5)

## [2026-06-26] report-intel | ingested 'Discoverability by phone number/email restriction bypass on Twitter/X' → report/discoverability-by-phone-number-email-restriction-bypass-on-twitter-x + intel/discoverability-by-phone-number-email-restriction-bypass-on-twitter-x-intel (learning_score=2)

## [2026-06-26] report-intel | ingested 'Remote code execution on Basecamp.com' → report/remote-code-execution-on-basecamp-com + intel/remote-code-execution-on-basecamp-com-intel (learning_score=6)

## [2026-07-06] report-intel | ingested 'Authentication Bypass + File Upload + Arbitrary File Overwrite (JWT realm + drop-Bearer + S3 destination overwrite)' → report/authentication-bypass-file-upload-arbitrary-file-overwrite-jwt-realm-drop-bearer-s3-destination-overwrite + intel/authentication-bypass-file-upload-arbitrary-file-overwrite-jwt-realm-drop-bearer-s3-destination-overwrite-intel (learning_score=7)

## [2026-07-06] report-intel | ingested 'JWT Authentication Design Flaw — Standalone Bearer Token, No Server-Side Session Binding' → report/jwt-authentication-design-flaw-standalone-bearer-token-no-server-side-session-binding + intel/jwt-authentication-design-flaw-standalone-bearer-token-no-server-side-session-binding-intel (learning_score=9)

## [2026-07-06] report-intel | ingested 'Blind XSS to Admin Panel via Un-WAF'd Mobile App Comment Field' → report/blind-xss-to-admin-panel-via-un-waf-d-mobile-app-comment-field + intel/blind-xss-to-admin-panel-via-un-waf-d-mobile-app-comment-field-intel (learning_score=5)

## [2026-07-06] report-intel | ingested 'Blind Password-Hash Extraction via Unauthenticated GraphQL Count Oracle (LIKE on credential fields)' → report/blind-password-hash-extraction-via-unauthenticated-graphql-count-oracle-like-on-credential-fields + intel/blind-password-hash-extraction-via-unauthenticated-graphql-count-oracle-like-on-credential-fields-intel (learning_score=2)

## [2026-07-06] report-intel | ingested 'GraphQL Exposed IDE + Introspection — Schema Visibility Is Not Exploitability' → report/graphql-exposed-ide-introspection-schema-visibility-is-not-exploitability + intel/graphql-exposed-ide-introspection-schema-visibility-is-not-exploitability-intel (learning_score=2)

## [2026-07-06] report-intel | ingested 'GraphQL Nested-Resolver BOLA — Field-Level Auth Bypass Exposes Medical Records' → report/graphql-nested-resolver-bola-field-level-auth-bypass-exposes-medical-records + intel/graphql-nested-resolver-bola-field-level-auth-bypass-exposes-medical-records-intel (learning_score=6)

## [2026-07-06] report-intel | ingested 'Error-Based SQLi in GraphQL WebSocket (quiet keep-alive) Chained IDOR to PII Leak' → report/error-based-sqli-in-graphql-websocket-quiet-keep-alive-chained-idor-to-pii-leak + intel/error-based-sqli-in-graphql-websocket-quiet-keep-alive-chained-idor-to-pii-leak-intel (learning_score=5)
