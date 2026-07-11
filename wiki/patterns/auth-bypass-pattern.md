---
type: pattern
tags:
- pattern
- discovered
- auth_bypass
status: candidate
confidence: high
created: '2026-06-26'
updated: '2026-06-26'
discovered_by: phase_c
candidate_id: patt-275b67b17701
source_refs:
- complete-account-takeover-uber-intel
- github-authentication-bypass-on-gist-github-com-through-ssh-certificates-intel
- grammarly-dos-sso-account-takeover-10-500-intel
- hackerone-2fa-bypass-and-reporter-blacklist-bypass-through-embedded-submission-form-intel
- onelogin-authentication-bypass-on-wordpress-via-xmlrpc-uber-intel
- saml-authentication-bypass-on-uchat-uberinternal-com-uber-intel
- stealing-sso-login-tokens-on-snappublisher-snapchat-com-snapchat-intel
- tiktok-account-takeover-via-auth-bypass-in-recovery-12-000-intel
- tiktok-authentication-bypass-15-000-intel
- uber-onelogin-authentication-bypass-on-wordpress-sites-intel
signature_provider: tag_technique_vocab/v1
confirmed_at: '2026-06-26T16:07:21Z'
vuln_class: auth_bypass
---

# auth-bypass-pattern

> Discovered pattern (machine-proposed, `status: candidate`). Signature `auth_bypass`, confidence **high**. new pattern: signature 'auth_bypass' seen across 3 independent sources ({'report_intel': 3}); signals=['auth_bypass', 'auto', 'escalation', 'intel', 'report-derived', 'trust_boundary']; confidence=high

## Examples (≥2)
- [[stealing-sso-login-tokens-on-snappublisher-snapchat-com-snapchat-intel]]
- [[onelogin-authentication-bypass-on-wordpress-via-xmlrpc-uber-intel]]
- [[saml-authentication-bypass-on-uchat-uberinternal-com-uber-intel]]
- [[complete-account-takeover-uber-intel]]
- [[uber-onelogin-authentication-bypass-on-wordpress-sites-intel]]
- [[hackerone-2fa-bypass-and-reporter-blacklist-bypass-through-embedded-submission-form-intel]]
- [[github-authentication-bypass-on-gist-github-com-through-ssh-certificates-intel]]
- [[grammarly-dos-sso-account-takeover-10-500-intel]]
- [[tiktok-account-takeover-via-auth-bypass-in-recovery-12-000-intel]]
- [[tiktok-authentication-bypass-15-000-intel]]
