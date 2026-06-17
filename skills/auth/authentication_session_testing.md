# Skill: Authentication & Session Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `authentication_session_testing` |
| **version** | `1.0.0` |
| **category** | Auth / Session |
| **correlates_with** | JWT, OAuth/OIDC, CSRF, cookies, password reset, IDOR/BOLA |

## Objective
Probe the full authenticated lifecycle — login, session issuance, rotation, MFA, logout, and password
reset — for **broken authentication** and **broken session management**: fixation, missing rotation,
weak/forgeable tokens, CSRF on state-changing actions, insecure cookies, and host-header reset poisoning.

## Scope Rules
- Operator's **own** test accounts only — never brute or stuff real credentials.
- Two registered identities (low-priv + admin/owner) for access-control diffs.
- No lockout storms; back off on `429`/lockout signals.

## Trigger Conditions
- `jwt_cookie`, `session_rotation`, `mfa_flow`; presence of `/login`, `/logout`, `/reset`, `Set-Cookie`.

## Technology Fingerprints
- Session frameworks (Express-session, Devise, Spring Security), Bearer/JWT APIs, SSO redirectors.

## Recon Methodology
1. Capture a clean login with `attack_login` → reusable `SessionContext` (cookies + bearer).
2. Diff cookie flags pre/post-auth; check whether the session id **rotates** on privilege change.
3. Enumerate state-changing endpoints (transfer, email/password change) for CSRF surface.

## MCP Tool Orchestration Logic
- `attack_login` — capture the authenticated session (CSRF-aware).
- `attack_auth_session check=cookies` — audit `Set-Cookie` (Secure/HttpOnly/SameSite/scope).
- `attack_auth_session check=csrf` — replay a state-change without/with-bad token + cross-origin.
- `attack_auth_session check=reset_poison` — Host / X-Forwarded-Host password-reset poisoning.
- `attack_jwt` — decode/forge (alg=none, weak secret, HS/RS confusion, kid) for replay.
- `attack_access_control` — same resource as two identities (horizontal IDOR).

## Reasoning Heuristics
- Session id unchanged across login → **fixation**.
- Reset link built from a request header → **account takeover** via poisoning.
- `SameSite=None` without `Secure`, or no anti-CSRF token honored → CSRF class.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Session fixation (no rotation on auth) |
| H2 | CSRF on email/password change → ATO |
| H3 | Host-header password-reset poisoning → ATO |
| H4 | Forgeable JWT (alg=none / weak secret) → impersonation |

## Validation Workflow
1. Require **two independent signals** (e.g. tokenless-accept + cross-origin-accept for CSRF).
2. Reverify with `attack_reverify` before reporting.

## False-Positive Reduction
- A reflected reset host in an error page ≠ a poisoned link — confirm the link in the delivered email/flow.
- 200 on a tokenless POST that performs **no** state change is not CSRF.

## Stealth + OPSEC Guidance
- Throttle auth endpoints; never trigger account lockout on shared/real accounts.

## Replay Procedures
- Persist the captured session JSON and the exact CSRF/reset requests (redact tokens).

## Evidence Requirements
- Cookie-attribute table, the accepted cross-origin request, and a screenshot per platform rules.

## Confidence Scoring Logic
- Demonstrated ATO path: **0.95**; single-signal CSRF candidate: suspected only.

## Adaptive Branching Logic
- JWT present → branch to `attack_jwt`; SSO redirect → branch to `skills/oauth/oauth_oidc_abuse_patterns.md`.

## Related Exploit Chains
- `skills/api/jwt_weaknesses.md`, `skills/oauth/oauth_oidc_abuse_patterns.md`

## Safety Boundaries
No credential stuffing, no real-user account manipulation.

## Output Artifact Requirements
`output/<target_slug>/auth/` — `session_notes.md`, `cookie_audit.csv`, `csrf_pocs/`
