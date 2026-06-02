# Skill: REST API Authentication & Session Logic Flaws

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `rest_api_auth_flaws` |
| **version** | `1.0.0` |
| **category** | API / AuthZ-AuthN |
| **correlates_with** | JWT, OAuth, mobile clients, gateway misconfigs |

## Objective
Find **broken authentication** and **broken function/object authorization** on REST/JSON APIs: weak token binding, **verb/path** ACL gaps, **version** drift (`/v1` vs `/v2`), and **state-changing** endpoints without proper session integrity.

## Scope Rules
- Two-account testing only on **program-approved** test users.
- No credential stuffing or password spraying against production unless explicitly allowed.

## Trigger Conditions
- Bearer tokens in `Authorization`, custom headers, cookies on API subdomain.
- Mixed **public** and **private** routes behind same gateway.
- Admin routes under predictable paths (`/admin`, `/internal`).

## Technology Fingerprints
- Kong, Apigee, AWS API Gateway, Azure APIM, NGINX ingress annotations.

## Recon Methodology
1. OpenAPI/Swagger discovery + `katana` JS-driven routes.
2. Map **auth middleware** coverage per route (401 vs 403 semantics).
3. Test **HTTP method** matrix on sensitive resources.
4. Compare **mobile** vs **web** client headers (user-agent gates).

## MCP Tool Orchestration Logic
- `katana_crawl`, `httpx_probe`, `ffuf_fuzz` (method + path), `nuclei_scan` (exposures, default panels).

**Branching:** If **403** on browser but **200** with API client headers → ACL differential branch.

## Reasoning Heuristics
- **401 vs 403** misuse often hides IDOR (200 with wrong object).
- **JWT in localStorage** increases XSS impact—chain consciously.
- **Pagination** cursors may leak other users’ records.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Missing auth on alternate verb |
| H2 | IDOR on `/resource/{id}` |
| H3 | Host-header / routing bypass to internal upstream |
| H4 | Weak API keys in mobile bundles |

## Validation Workflow
1. Same request with/without token.
2. Cross-account object access attempts (in-scope IDs only).
3. Replay with minimal diff.

## False-Positive Reduction
- **Public** marketing JSON ≠ auth flaw.
- Cached 401 from CDN—vary `Cache-Control` tests.

## Stealth + OPSEC Guidance
- Throttle ID enumeration; derive IDs from public references when possible.

## Replay Procedures
- Store token type; redact secrets in artifacts.

## Evidence Requirements
- Two-account diff; route + method; gateway behavior.

## Reporting Methodology
- Centralized authZ, resource-level checks, consistent 404/403, key rotation.

## Confidence Scoring Logic
- Clear cross-account data: **0.95**; ambiguous 200 with empty body: investigate more.

## Adaptive Branching Logic
- **GraphQL** adjacent → import GraphQL skill.
- **Webhooks** → signature bypass branch.

## Related Exploit Chains
- `skills/api/jwt_weaknesses.md`
- `skills/api/oauth_oidc_abuse.md`

## Safety Boundaries
No access to real user PII beyond proof rows.

## Output Artifact Requirements
`output/<target_slug>/api_auth/` — `matrix.csv`, `replay.sh`, `accounts_used.txt`
