---
type: pattern
tags:
- pattern
- discovered
- xss
status: candidate
confidence: high
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-3bf3aaccbf16
source_refs:
- gitlab-stored-xss-in-jira-integration-13-950-intel
- gitlab-stored-xss-in-markdown-via-designreferencefilter-16-000-intel
- gitlab-stored-xss-in-wiki-via-mermaid-13-950-intel
- paypal-stored-xss-on-paypal-com-signin-via-cache-poisoning-18-900-intel
- paypal-stored-xss-via-http-request-smuggling-bypass-20-000-intel
- stored-xss-in-developer-uber-com-uber-intel
- stored-xss-in-steam-react-chat-client-valve-intel
- subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology-intel
- xss-at-jamfpro-shopifycloud-com-shopify-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T15:49:12Z'
vuln_class: xss
---

# xss-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `xss`, confidence **high**. new pattern: signature 'xss' seen across 3 independent sources ({'report_intel': 3}); signals=['auto', 'intel', 'report-derived', 'trust_boundary', 'xss']; confidence=high

## Examples (≥2)
- [[stored-xss-in-steam-react-chat-client-valve-intel]]
- [[stored-xss-in-developer-uber-com-uber-intel]]
- [[xss-at-jamfpro-shopifycloud-com-shopify-intel]]
- [[gitlab-stored-xss-in-wiki-via-mermaid-13-950-intel]]
- [[gitlab-stored-xss-in-markdown-via-designreferencefilter-16-000-intel]]
- [[gitlab-stored-xss-in-jira-integration-13-950-intel]]
- [[paypal-stored-xss-on-paypal-com-signin-via-cache-poisoning-18-900-intel]]
- [[paypal-stored-xss-via-http-request-smuggling-bypass-20-000-intel]]
- [[subdomain-takeover-basics-patrik-hudak-cname-ns-mx-a-dangling-dns-methodology-intel]]
