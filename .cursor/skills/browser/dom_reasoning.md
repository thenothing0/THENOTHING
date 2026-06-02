# Skill: DOM Reasoning & Client-Side Sinks

## Metadata
| **id** | `browser_dom_reasoning` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/browser/dom/` |

## Objective
Trace **sources → sinks** in SPAs: `postMessage`, `location`, `localStorage`, WebSocket messages into `innerHTML`, `eval`, template renderers—pair with XSS skill for execution proofs.

## Trigger Conditions
Heavy client routing; reflected fragments in client-only contexts; sourcemaps in scope.

## Technology Fingerprints
React, Vue, Svelte, webpack/vite bundles.

## Reasoning Heuristics
Use static JS reading (authorized) + runtime DOM checks; prioritize high-value auth routes.

## Exploit Hypotheses
DOM XSS; client template injection; unsafe `v-html`/dangerous HTML APIs.

## MCP Orchestration Logic
`katana_crawl` for JS URLs; `httpx_probe` for headers; manual DevTools notes → `screenshots/`.

## Stealth Guidance
Avoid noisy DOM mutation fuzzers on prod; prefer single-session traces.

## Validation Workflow
Minimal sink proof + replay URL/hash steps.

## Evidence Requirements
Screenshot + script line reference (sourcemap path if allowed).

## Adaptive Branching
CSP active → `web/csp_bypass.md`.

## Confidence Scoring
0.85 execution proof on in-scope route.

## Replay Logic
URL with hash/query sequence documented.

## Reporting Guidance
Safe DOM APIs, Trusted Types, sanitize pipeline, CSP.
