---
type: intel
tags:
- intel
- auto
- report-derived
target: '[[oauth-security-methodology]]'
created: '2026-06-26'
updated: '2026-06-26'
sources:
- https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
learning_score: 8
---

# OAuth 2.0 Common Vulnerabilities Catalog (Doyensec 2025) — actionable intelligence

> Distilled from report [[oauth-2-0-common-vulnerabilities-catalog-doyensec-2025]]. What to *reuse*, not an archive copy.

- **Vuln class:** xss
- **Target / asset type:** mobile / mobile
- **Root cause to look for:** unknown
- **Trust boundary to probe:** unknown
- **Learning score:** 7/10

## Reusable exploitation sequence
1. CSRF on the callback: no binding between the browser that starts the flow and the one that consumes the code. Attacker forces victim to redeem the attacker's code, linking victim into attacker's context. Mitigate with a session-bound state nonce. Detect: callbacks missing/reusing static state.
2. redirect_uri validation flaws: absent or weak per-client allowlisting. Manipulate redirect target to leak the auth code to an untrusted origin (often via open redirect or referer leak). Mitigate: exact-match redirect_uri including scheme+host+port+path; NEVER origin-only/subdomain/subpath/wildcard/regex. Detect: redirect_uri outside allowlist; wildcard/regex configs; codes in referer logs.
3. Authorization code interception (mobile scheme hijacking): custom URI schemes can be registered by multiple apps; a malicious app steals the code. Mitigate: PKCE + Android App Links (assetlinks.json) / iOS Associated Domains, not custom schemes.
4. Implicit-flow token leakage: access token returned in URL fragment, exposed via XSS/referer/redirect. Deprecated in OAuth 2.1. Mitigate: Authorization Code + PKCE; if needed response_mode=form_post. Detect: access tokens in URLs/logs.
5. Client confusion: client fails to verify the token was issued for its own client_id; attacker reuses a token minted for a different client_id (Salt Security "millions of accounts" research). Mitigate: validate token audience/client_id; never accept access tokens from user-controlled params.
6. Scope upgrade abuse: AS trusts a scope param at the token-exchange step; malicious client requests higher scope. Mitigate: ignore token-request scope or verify it equals the original authorization-request scope.
7. Mutable-claims account takeover: client identifies users by mutable email/handle instead of immutable sub; attacker sets an unverified email (self-managed org) to impersonate (Descope "noauth"). Mitigate: key identity on sub, never unverified email.

## Provenance
- Source: https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- Report page: [[oauth-2-0-common-vulnerabilities-catalog-doyensec-2025]]
- Target: [[methodology]]

## Patterns (discovered)
- [[csrf-pattern]]
