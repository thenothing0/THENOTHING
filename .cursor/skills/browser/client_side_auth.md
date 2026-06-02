# Skill: Client-Side Auth Flows

## Metadata
| **id** | `browser_client_side_auth` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/browser/auth/` |

## Objective
Find **client-only** gates (hidden buttons, disabled routes) that server APIs do not enforce—prove with **direct API** calls using session from browser.

## Trigger Conditions
Route guards in JS; admin panels “hidden” in UI; feature flags in localStorage.

## Technology Fingerprints
React router, Next middleware (note server vs client), mobile BFF.

## Reasoning Heuristics
If API returns 200 for privileged action with user cookie, UI hiding is irrelevant.

## Exploit Hypotheses
BFLA; missing checks on alternate verbs; GraphQL field exposed without UI.

## MCP Orchestration Logic
`katana_crawl` for API routes; `httpx_probe` with copied **test** session headers (redacted).

## Stealth Guidance
Do not brute force sessions; use your test account only.

## Validation Workflow
UI-denied action succeeds via API with same session.

## Evidence Requirements
Side-by-side UI screenshot + API response (redacted).

## Adaptive Branching
JWT in header → `api/jwt_attacks.md`.

## Confidence Scoring
0.9 clear BFLA on sensitive function.

## Replay Logic
curl with session header redacted pattern `Authorization: ***`.

## Reporting Guidance
Server-side authZ on all endpoints, deny by default, tests for every role.
