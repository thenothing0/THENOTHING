# Skill: CSP Bypass Reasoning

## Metadata
| **id** | `web_csp_bypass` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/csp/` |

## Objective
Analyze CSP for weaknesses that enable script execution **given** an injection primitive, or standalone unsafe policy patterns.

## Trigger Conditions
`Content-Security-Policy` present; XSS primitive suspected; JSONP/allowlisted CDNs.

## Technology Fingerprints
`strict-dynamic`, nonces, hashes, JSONP endpoints, Angular CSP quirks.

## Reasoning Heuristics
Map allowlist graph; `base-uri` gaps; nonce reuse across navigations; upload same-origin script risks.

## Exploit Hypotheses
**H1** JSONP gadget; **H2** strict-dynamic import chain; **H3** wildcard `https:` overreach.

## MCP Orchestration Logic
`httpx_probe` (per-path headers) → `katana_crawl` (route diversity) → manual policy diff notes.

## Stealth Guidance
Console-only PoCs; no public malware hosting.

## Validation Workflow
CSP string + execution screenshot with policy active.

## Evidence Requirements
Policy text, bypass chain diagram, XSS linkage.

## Adaptive Branching
If no XSS primitive → report policy weakness severity per program rubric.

## Confidence Scoring
0.9 XSS + bypass; 0.55 theoretical gadget only.

## Replay Logic
Save exact URL + versioned CSP snapshot.

## Reporting Guidance
Tighten `script-src`, add `base-uri`, remove JSONP, correct nonce lifecycle.
