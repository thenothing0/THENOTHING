# Skill: Token Propagation (Browser ↔ API)

## Metadata
| **id** | `browser_token_propagation` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/browser/tokens/` |

## Objective
Map how **tokens** move: `HttpOnly` cookies vs `localStorage`, `postMessage`, service workers, and XSS blast radius implications—without harvesting real secrets.

## Trigger Conditions
SPA auth, silent refresh, mobile web parity, multiple API hosts.

## Technology Fingerprints
OAuth PKCE SPAs, BFF patterns, SameSite policies.

## Reasoning Heuristics
Token in `localStorage` + XSS = chain hypothesis; cross-subdomain cookie scope issues.

## Exploit Hypotheses
Token theft via XSS; postMessage token leak; SW cache poisoning of auth JS.

## MCP Orchestration Logic
`httpx_probe` for `Set-Cookie` patterns; manual browser notes → redacted `logs/`.

## Stealth Guidance
Redact all tokens from artifacts; use placeholders.

## Validation Workflow
Describe chain with synthetic token markers only.

## Evidence Requirements
Header policy table + chain narrative (no secrets).

## Adaptive Branching
XSS primitive → `xss/advanced_xss.md` or `web/xss.md`.

## Confidence Scoring
Chain strength = min(primitive confidence, transport misconfig confidence).

## Replay Logic
Cookie attribute matrix export (redacted).

## Reporting Guidance
HttpOnly + secure cookies, BFF, token binding, short TTL, rotation.
