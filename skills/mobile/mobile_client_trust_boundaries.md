# Skill: Mobile Client Trust Boundaries

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `mobile_client_trust_boundaries` |
| **version** | `1.0.0` |
| **category** | Mobile |
| **correlates_with** | API BOLA/BFLA, JWT, OAuth deep links, hardcoded secrets, cert pinning |

## Objective
Treat the mobile app as a thin client over an API: extract endpoints/secrets from the package, then
attack the **backend** for object/function-level authz, token weaknesses, and deep-link/OAuth abuse —
where the real bugs live.

## Scope Rules
- Test the in-scope **API** the app talks to; reverse-engineering the app is fine if the package is in-scope.
- Operator's own test accounts; no real-user data.

## Trigger Conditions
- `mobile_api`, `deeplink`; `intent://`/custom-scheme callbacks, mobile-only API hosts.

## Technology Fingerprints
- Android (APK), iOS (IPA), Firebase, AWS Amplify, GraphQL/REST backends.

## Recon Methodology
1. Pull strings/config from the package: API base URLs, keys, feature flags.
2. Capture app↔API traffic (proxy) to enumerate endpoints and auth material.
3. Map deep links / custom schemes used as OAuth callbacks.

## MCP Tool Orchestration Logic
- `attack_js_extract` — for hybrid/RN bundles: endpoints/params/secrets.
- `httpx_probe` — probe mobile API hosts.
- `attack_api check=bola|bfla|mass_assignment|excessive_data_exposure` — the core mobile-backend tests.
- `attack_jwt` — analyze/forge mobile session tokens; `attack_oauth` for deep-link callbacks.

## Reasoning Heuristics
- Mobile APIs often skip the web's authz checks → BOLA/BFLA hotspots.
- Hardcoded keys are common; confirm what they unlock (not mere presence).
- Custom-scheme OAuth callbacks enable code interception on a shared device.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Backend BOLA via predictable object ids |
| H2 | Hardcoded secret grants API access |
| H3 | Deep-link OAuth code interception |
| H4 | Excessive data exposure in mobile API responses |

## Validation Workflow
1. Confirm authz gap with two identities; reverify against fresh baseline.
2. Validate any secret read-only.

## False-Positive Reduction
- A public/publishable key by design is not a finding — only the data/actions it unlocks.
- Client-side-only checks bypassed via direct API calls = real; UI-only "lock" is not.

## Stealth + OPSEC Guidance
- Rate-limit the API; do not exfiltrate real user data.

## Replay Procedures
- Save the API requests (not the app binary) and the authz diff.

## Evidence Requirements
- Cross-account API response, secret-unlock proof (redacted), remediation.

## Confidence Scoring Logic
- Cross-account data via API: high; string-only secret w/o validated access: low.

## Adaptive Branching Logic
- JWT → `skills/api/jwt_weaknesses.md`; deep-link OAuth → `skills/oauth/oauth_oidc_abuse_patterns.md`.

## Related Exploit Chains
- `skills/api/bola_idor.md`, `skills/api/rest_api_auth_flaws.md`

## Safety Boundaries
No real-user data exfiltration; API-side PoC only.

## Output Artifact Requirements
`output/<target_slug>/mobile/` — `endpoints.txt`, `api_authz_matrix.csv`, `secrets_redacted.json`
