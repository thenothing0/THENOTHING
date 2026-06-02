# Skill: JWT & JWE Weakness Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `jwt_weaknesses` |
| **version** | `1.0.0` |
| **category** | API / Token cryptography |
| **correlates_with** | OAuth, session fixation, kid/jku abuse, algorithm confusion |

## Objective
Analyze JWT/JWS/JWE handling: **alg none**, **HS/RS confusion**, **weak secrets**, **kid** injection, **jku/x5u** fetching, **claims** (`iss`, `aud`, `exp`, `nbf`). Produce **cryptographically sound** repros without dumping live user tokens in public artifacts.

## Scope Rules
- Do not publish **live** JWTs; redact signatures and PII claims.
- Brute-force only **explicitly allowed** capture-the-flag keys or lab tokens.

## Trigger Conditions
- `Authorization: Bearer eyJ...`
- Libraries: `jsonwebtoken`, `PyJWT`, `jjwt`, Auth0/Okta custom rules.

## Technology Fingerprints
- HS256 vs RS256 stacks; JWKS endpoints; opaque tokens vs JWT.

## Recon Methodology
1. Decode **header/payload** (offline) to inspect `alg`, `kid`, `jku`.
2. Test **algorithm** acceptance matrix in **lab** or minimal prod probe per ROE.
3. Validate **claim** enforcement (`aud`, `iss`).

## MCP Tool Orchestration Logic
- `httpx_probe` — collect auth headers on routes.
- `nuclei_scan` — JWT exposure templates (signals).
- Manual `jwt_tool` style work—record commands in private notes if allowed.

## Reasoning Heuristics
- **`kid` path traversal** patterns (`../../../dev/null`)—high risk if file-based keys hinted.
- **`jku`** SSRF to internal JWKS—pair with SSRF skill if in scope.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | alg `none` accepted |
| H2 | RS256→HS256 confusion with public key as HMAC secret |
| H3 | Weak HMAC secret |
| H4 | Missing `aud`/`iss` validation |
| H5 | Key injection via `kid` |

## Validation Workflow
1. Craft token variants; observe **401/403** vs **200** consistently.
2. Replay with clock skew tests for `exp`.
3. Confirm **session establishment** impact, not only parser acceptance.

## False-Positive Reduction
- Parser accepts token but **Redis session** rejects → down-rank.

## Stealth + OPSEC Guidance
- Do not log tokens in shared CI; use local vault.

## Replay Procedures
- Redacted JWT structure + server response codes only in shared artifacts.

## Reporting Methodology
- Use RS256 with JWKS, enforce claims, rotate keys, disallow `none`, harden `kid`.

## Confidence Scoring Logic
- Account takeover path: **1.0**; theoretical alg confusion without session: **0.55**.

## Adaptive Branching Logic
- **Opaque tokens** → pivot OAuth introspection skill.

## Related Exploit Chains
- `skills/api/oauth_oidc_abuse.md`

## Safety Boundaries
No ATO on real users; lab proofs only unless authorized.

## Output Artifact Requirements
`output/<target_slug>/jwt/` — `header_payload_redacted.txt`, `matrix.md`
