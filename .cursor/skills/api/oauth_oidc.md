# Skill: OAuth / OIDC Abuse

## Metadata
| **id** | `api_oauth_oidc` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/oauth/` |

## Objective
Test redirect URI validation, `state`/`nonce`, PKCE, code reuse, and token audience mixups using **program-registered** test clients only.

## Trigger Conditions
`/authorize`, `/token`, mobile custom schemes, SPA callback pages.

## Technology Fingerprints
Auth0, Okta, Azure AD, Cognito, Clerk, Keycloak.

## Reasoning Heuristics
Open redirect chains into `redirect_uri`; missing PKCE on public clients; `postMessage` relay bugs.

## Exploit Hypotheses
Redirect theft; CSRF login; code reuse; ID token misuse at resource server.

## MCP Orchestration Logic
`katana_crawl` (callbacks) → `httpx_probe` (error reflections) → controlled `ffuf_fuzz` on redirect params (slow).

## Stealth Guidance
Avoid consent spam; backoff on lockout signals.

## Validation Workflow
End-to-end replay on test app; capture redirect chain hashes (secrets redacted).

## Evidence Requirements
Redirect matrix CSV; sequence diagram; minimal PoC outline.

## Adaptive Branching
JWT at resource API → `jwt_attacks.md`.

## Confidence Scoring
0.95 token theft path on test; weak errors alone = low.

## Replay Logic
Save authorize URLs with line-referenced components.

## Reporting Guidance
Strict redirect URIs, PKCE, state, rotate secrets, audience binding.
