# Skill: OAuth / OIDC Abuse Patterns

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `oauth_oidc_abuse_patterns` |
| **version** | `1.0.0` |
| **category** | Auth / Identity |
| **correlates_with** | Open redirect, JWT, CSRF, SSRF, mobile deep links |

## Objective
Attack the authorization-code / implicit / hybrid / device flows for **redirect_uri** validation
bypasses, **missing `state`** (login CSRF), **missing PKCE** (code interception), implicit-flow token
leakage, over-broad scope, and code/token reuse.

## Scope Rules
- Use **test** OAuth clients registered in-program; never hijack another vendor's `client_id`.
- No phishing real users' consent screens.

## Trigger Conditions
- `oauth_callback`, `authorization_code_flow`; params `response_type`, `client_id`, `redirect_uri`,
  `state`, `code_challenge`.

## Technology Fingerprints
- Auth0, Okta, Keycloak, Cognito, Azure AD, Clerk, Firebase, Ory.

## Recon Methodology
1. Map `redirect_uri` matching mode (exact vs prefix vs regex vs open-redirect-concatenation).
2. Confirm `state` and PKCE requirements across all `response_type`s.
3. Inspect SPA `postMessage` relay on the callback page.

## MCP Tool Orchestration Logic
- `attack_oauth` — static weakness flags (missing state/PKCE, implicit, broad scope) **and** active
  `redirect_uri` tamper test (full-replace / subdomain / `@`-trick / path-append / open-redirect param).
- `katana_crawl` — discover callback paths.
- `attack_jwt` — analyze/forge the resulting ID/access tokens.

## Reasoning Heuristics
- A same-site open redirect can bypass a sloppy `redirect_uri` allowlist.
- Public client without PKCE → code-interception class.
- ID token accepted as an access token at the resource server → confusion bug.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | redirect_uri abuse → code/token theft → ATO |
| H2 | Missing `state` → login CSRF |
| H3 | Authorization-code reuse |
| H4 | nonce not enforced in hybrid flow |

## Validation Workflow
1. End-to-end replay in the test app; confirm the server **honors** the attacker destination.
2. Chain to `oauth_redirect_ato` template; reverify with `attack_reverify`.

## False-Positive Reduction
- An error page reflecting `redirect_uri` ≠ a honored redirect — require a 3xx `Location` to the attacker host.
- `localhost` allowed only in dev — confirm the environment.

## Stealth + OPSEC Guidance
- Do not spam `/authorize`; back off on lockouts.

## Replay Procedures
- Save the full authorize→callback URL chain (redact secrets).

## Evidence Requirements
- Sequence diagram + minimal PoC + remediation (strict redirect URIs, PKCE, state).

## Confidence Scoring Logic
- Clear token-theft path: **0.95**; weak error detail only: low/suspected.

## Adaptive Branching Logic
- Mobile custom-scheme callback → branch to `skills/mobile/mobile_client_trust_boundaries.md`.

## Related Exploit Chains
- `skills/api/jwt_weaknesses.md`, `skills/auth/authentication_session_testing.md`

## Safety Boundaries
No real-user account-linking attacks; test clients only.

## Output Artifact Requirements
`output/<target_slug>/oauth/` — `flow_notes.md`, `redirect_matrix.csv`
