---
type: pattern
tags:
- pattern
- discovered
- rce
status: candidate
confidence: medium
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-fe7d6305202e
source_refs:
- buffer-overrun-in-steam-silk-voice-decoder-valve-intel
- cs-go-server-to-client-rce-through-oob-access-in-csvcmsg-splitscreen-valve-intel
- elastic-kibana-rce-hazard-in-reporting-via-chromium-intel
- git-flag-injection-in-search-api-with-scope-blobs-gitlab-intel
- gitlab-git-flag-injection-to-rce-12-000-intel
- gitlab-local-file-overwrite-to-rce-12-000-intel
- gitlab-rce-via-decompressedarchivesizevalidator-and-project-bulkimports-33-510-intel
- gitlab-rce-via-unsafe-inline-kramdown-options-in-wiki-pages-20-000-intel
- gitlab-rce-when-removing-metadata-with-exiftool-20-000-intel
- gitlab-remote-command-execution-via-github-import-33-510-intel
- ly-corp-spring-actuator-rce-12-500-intel
- mail-ru-rce-on-shared-mail-ru-via-widget-plugin-10-000-intel
- mail-ru-unprotected-zeppelin-instance-35-000-intel
- oob-reads-in-network-message-handlers-leads-to-rce-valve-intel
- paypal-rce-via-npm-misconfig-dependency-confusion-30-000-intel
- playstation-buffer-overflow-rce-in-firmware-12-500-intel
- playstation-rce-via-buffer-overflow-15-000-intel
- pornhub-rce-via-php-object-injection-in-cookie-20-000-intel
- rce-and-secret-token-exfiltration-by-poisoning-mozilla-fxa-ci-build-cache-intel
- rce-on-cs-go-client-using-unsanitized-entity-id-in-entitymsg-valve-intel
- rce-via-crafted-closed-captions-file-in-cs-go-source-engine-valve-intel
- rce-via-npm-misconfig-installing-internal-libraries-from-public-registry-uber-intel
- shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876-intel
- shopify-scripts-struct-type-confusion-rce-18-000-intel
- signedness-issue-in-classinfo-handler-leads-to-rce-on-cs-go-client-valve-intel
- snapchat-exposed-kubernetes-api-rce-exposed-creds-25-000-intel
- twitter-x-pre-auth-rce-on-twitter-vpn-20-160-intel
- uber-rce-via-flask-jinja2-template-injection-ssti-intel
- valve-left4dead2-buffer-overflow-rce-via-malformed-nav-file-intel
- xxe-xml-external-entity-injection-portswigger-web-security-academy-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T15:03:42Z'
vuln_class: rce
---

# rce-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `rce`, confidence **medium**. new pattern: signature 'rce' seen across 2 independent sources ({'report_intel': 2}); signals=['auto', 'chain', 'escalation', 'intel', 'rce', 'report-derived', 'trust_boundary']; confidence=medium

## Examples (≥2)
- [[signedness-issue-in-classinfo-handler-leads-to-rce-on-cs-go-client-valve-intel]]
- [[rce-via-crafted-closed-captions-file-in-cs-go-source-engine-valve-intel]]
- [[oob-reads-in-network-message-handlers-leads-to-rce-valve-intel]]
- [[git-flag-injection-in-search-api-with-scope-blobs-gitlab-intel]]
- [[cs-go-server-to-client-rce-through-oob-access-in-csvcmsg-splitscreen-valve-intel]]
- [[buffer-overrun-in-steam-silk-voice-decoder-valve-intel]]
- [[rce-via-npm-misconfig-installing-internal-libraries-from-public-registry-uber-intel]]
- [[rce-on-cs-go-client-using-unsanitized-entity-id-in-entitymsg-valve-intel]]
- [[rce-and-secret-token-exfiltration-by-poisoning-mozilla-fxa-ci-build-cache-intel]]
- [[valve-left4dead2-buffer-overflow-rce-via-malformed-nav-file-intel]]
- [[uber-rce-via-flask-jinja2-template-injection-ssti-intel]]
- [[elastic-kibana-rce-hazard-in-reporting-via-chromium-intel]]
- [[mail-ru-rce-on-shared-mail-ru-via-widget-plugin-10-000-intel]]
- [[gitlab-local-file-overwrite-to-rce-12-000-intel]]
- [[gitlab-git-flag-injection-to-rce-12-000-intel]]
- [[shopify-scripts-struct-type-confusion-rce-18-000-intel]]
- [[playstation-rce-via-buffer-overflow-15-000-intel]]
- [[playstation-buffer-overflow-rce-in-firmware-12-500-intel]]
- [[ly-corp-spring-actuator-rce-12-500-intel]]
- [[twitter-x-pre-auth-rce-on-twitter-vpn-20-160-intel]]
- [[snapchat-exposed-kubernetes-api-rce-exposed-creds-25-000-intel]]
- [[pornhub-rce-via-php-object-injection-in-cookie-20-000-intel]]
- [[paypal-rce-via-npm-misconfig-dependency-confusion-30-000-intel]]
- [[mail-ru-unprotected-zeppelin-instance-35-000-intel]]
- [[gitlab-remote-command-execution-via-github-import-33-510-intel]]
- [[gitlab-rce-when-removing-metadata-with-exiftool-20-000-intel]]
- [[gitlab-rce-via-unsafe-inline-kramdown-options-in-wiki-pages-20-000-intel]]
- [[gitlab-rce-via-decompressedarchivesizevalidator-and-project-bulkimports-33-510-intel]]
- [[shopify-exchange-ssrf-to-gcp-metadata-rce-hackerone-341876-intel]]
- [[xxe-xml-external-entity-injection-portswigger-web-security-academy-intel]]
