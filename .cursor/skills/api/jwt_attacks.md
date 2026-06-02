# Skill: JWT Attacks

## Metadata
| **id** | `api_jwt_attacks` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/jwt/` |

## Objective
Analyze JWT/JWE/JWS handling for alg confusion, weak secrets, `kid`/`jku` abuse, and claim violations—without leaking live tokens in artifacts.

## Trigger Conditions
Bearer JWT in APIs; JWKS endpoints; libraries exposing `alg` header.

## Technology Fingerprints
Auth0, Okta, Keycloak, Cognito, `jsonwebtoken`, PyJWT, jjwt.

## Reasoning Heuristics
Separate parser acceptance from **session establishment**; test claim enforcement (`aud`, `iss`, `exp`).

## Exploit Hypotheses
`none` alg; RS256→HS256; weak HMAC; `kid` path tricks; `jku` SSRF to internal JWKS.

## MCP Orchestration Logic
`httpx_probe` (collect auth flows) → `nuclei_scan` (JWT exposures) → lab token crafting documented in `replay/` (redacted).

## Stealth Guidance
No public posting of tokens; brute-force only lab keys when explicitly allowed.

## Validation Workflow
Matrix of token variants vs endpoint behavior; session impact confirmation on test user.

## Evidence Requirements
Redacted header/payload structure + response code matrix.

## Adaptive Branching
OAuth adjacent → `api/oauth_oidc.md`.

## Confidence Scoring
0.95 clear ATO path on test tenant; 0.5 parser-only quirks.

## Replay Logic
Offline decode + server behavior table (no secrets in repo).

## Reporting Guidance
Correct algorithms, JWKS rotation, claims, key injection defenses, permission boundaries.
