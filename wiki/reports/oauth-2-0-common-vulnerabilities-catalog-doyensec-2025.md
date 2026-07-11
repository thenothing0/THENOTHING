---
type: report
tags:
- report
- auto
target: '[[oauth-security-methodology]]'
severity: high
created: '2026-06-26'
updated: '2026-06-26'
source: https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
vuln_class: csrf
asset_type: api
learning_score: 8
learning_score_rationale: base 4 (mid class 'csrf') · +2 chain · +1 escalation · +1
  pivot
unresolved_references:
- csrf
---

# OAuth 2.0 Common Vulnerabilities Catalog (Doyensec 2025)

> Reusable lesson distilled from a disclosed report — see the intel page [[oauth-2-0-common-vulnerabilities-catalog-doyensec-2025-intel]].

## Distilled intelligence
- **Root cause:** unknown  
  <sub>provenance: not found</sub>
- **Trust-boundary failure:** unknown  
  <sub>provenance: not found</sub>
- **Exploitation sequence:** CSRF on the callback: no binding between the browser that starts the flow and the one that consumes the code. Attacker forces victim to redeem the attacker's code, linking victim into attacker's context. Mitigate with a session-bound state nonce. Detect: callbacks missing/reusing static state., redirect_uri validation flaws: absent or weak per-client allowlisting. Manipulate redirect target to leak the auth code to an untrusted origin (often via open redirect or referer leak). Mitigate: exact-match redirect_uri including scheme+host+port+path; NEVER origin-only/subdomain/subpath/wildcard/regex. Detect: redirect_uri outside allowlist; wildcard/regex configs; codes in referer logs., Authorization code interception (mobile scheme hijacking): custom URI schemes can be registered by multiple apps; a malicious app steals the code. Mitigate: PKCE + Android App Links (assetlinks.json) / iOS Associated Domains, not custom schemes., Implicit-flow token leakage: access token returned in URL fragment, exposed via XSS/referer/redirect. Deprecated in OAuth 2.1. Mitigate: Authorization Code + PKCE; if needed response_mode=form_post. Detect: access tokens in URLs/logs., Client confusion: client fails to verify the token was issued for its own client_id; attacker reuses a token minted for a different client_id (Salt Security "millions of accounts" research). Mitigate: validate token audience/client_id; never accept access tokens from user-controlled params., Scope upgrade abuse: AS trusts a scope param at the token-exchange step; malicious client requests higher scope. Mitigate: ignore token-request scope or verify it equals the original authorization-request scope., Mutable-claims account takeover: client identifies users by mutable email/handle instead of immutable sub; attacker sets an unverified email (self-managed org) to impersonate (Descope "noauth"). Mitigate: key identity on sub, never unverified email.  
  <sub>provenance: research_ingestion methodology steps</sub>
- **Escalation / impact:** unknown  
  <sub>provenance: not found</sub>
- **Impact:** unknown  
  <sub>provenance: not found</sub>
- **Severity reasoning:** unknown  
  <sub>provenance: no explicit severity statement</sub>
- **Attacker assumptions:** unknown  
  <sub>provenance: not found</sub>

## Why the learning_score
- **7/10** — base 4 (mid class 'xss') · +2 chain · +1 escalation
- signals: chain, escalation

## Unresolved references (recorded, not created)
- `xss` — no page exists (Phase C may create it)

## Related
- Intel: [[oauth-2-0-common-vulnerabilities-catalog-doyensec-2025-intel]] · Target: [[methodology]]
