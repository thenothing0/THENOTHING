# Skill: OAuth 2.0 & OIDC Abuse Methodology

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `oauth_oidc_abuse` |
| **version** | `1.0.0` |
| **category** | API / Identity |
| **correlates_with** | Open redirect, SSRF, JWT, PKCE, mobile deep links |

## Objective
Stress **authorization code**, **implicit (legacy)**, **device code**, and **hybrid** flows for **state/ nonce** issues, **redirect_uri** allowlist bypasses, **code reuse**, **PKCE** downgrades, and **token** leakage via referrers/logs.

## Scope Rules
- Use **test** OAuth apps registered in program; do not hijack real client_ids of other vendors without permission.
- No phishing of real users’ consent screens.

## Trigger Conditions
- `/authorize`, `/token`, `response_type`, `client_id`, `redirect_uri`, `code_challenge`.
- Mobile `intent://` or custom scheme callbacks.

## Technology Fingerprints
- Auth0, Okta, Keycloak, Cognito, Azure AD, Clerk, Firebase.

## Recon Methodology
1. Map **redirect_uri** validation (exact vs prefix vs regex).
2. Inspect **state** requirement on all modes.
3. Check **web message** / **postMessage** relay in SPA callback pages.
4. Compare **desktop** vs **web** redirect behavior.

## MCP Tool Orchestration Logic
- `katana_crawl` — callback paths.
- `httpx_probe` — parameter reflection on errors.
- `ffuf_fuzz` — `redirect_uri` mutations **slowly** with allowlist awareness.

## Reasoning Heuristics
- **Open redirect** on same site may **bypass** `redirect_uri` if concatenated poorly.
- **Missing PKCE** on public clients → code interception class.
- **Device code** user interaction gaps.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | redirect_uri open redirect chain |
| H2 | Missing `state` → CSRF login |
| H3 | Authorization code reuse |
| H4 | ID token accepted as access token at resource server |
| H5 | nonce not enforced in hybrid |

## Validation Workflow
1. End-to-end replay in **test** app with captured traffic.
2. Demonstrate **account linking** or **session fixation** impact if in scope.

## False-Positive Reduction
- Error pages reflecting `redirect_uri` ≠ bypass.
- **localhost** allowed only on dev—confirm environment.

## Stealth + OPSEC Guidance
- Do not spam authorization endpoints; backoff on lockouts.

## Replay Procedures
- Save full authorize URL chain (redact secrets).

## Evidence Requirements
- Sequence diagram; minimal PoC; remediation: strict redirect URIs, PKCE, state, rotate secrets.

## Confidence Scoring Logic
- Clear token theft path: **0.95**; weak error detail only: low.

## Adaptive Branching Logic
- **Mobile** schemes → intent hijack branch if in Android scope.

## Related Exploit Chains
- `skills/api/jwt_weaknesses.md`
- `skills/ssrf/chained_ssrf.md`

## Safety Boundaries
No real-user account linking attacks.

## Output Artifact Requirements
`output/<target_slug>/oauth/` — `flow_notes.md`, `redirect_matrix.csv`
