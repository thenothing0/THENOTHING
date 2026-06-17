# Skill: JavaScript Bundle Intelligence

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `javascript_bundle_intelligence` |
| **version** | `1.0.0` |
| **category** | Frontend / Recon |
| **correlates_with** | Hidden endpoints, leaked secrets, params, DOM XSS, prototype pollution |

## Objective
Mine SPA/JS bundles for hidden **endpoints**, **parameter names**, **secrets**, feature flags, and
client-side sinks — converting static frontend code into fresh injectable surface for the scanners.

## Scope Rules
- Read-only analysis of in-scope JS; validate any discovered secret read-only before reporting.
- Treat extracted endpoints as in-scope only if they are.

## Trigger Conditions
- `spa`, `webpack`, `sourcemaps`; bundle URLs, `*.js`, `*.map`.

## Technology Fingerprints
- React, Next.js, Vue, Angular, webpack/vite chunks, source maps.

## Recon Methodology
1. Crawl for JS bundles and source maps.
2. Extract endpoints/params/secrets; recover original sources from `.map` when exposed.
3. Locate client-side sinks (`innerHTML`, `eval`, `postMessage`, `__proto__` access).

## MCP Tool Orchestration Logic
- `katana_crawl` / `hakrawler_crawl` — discover bundle URLs.
- `attack_js_extract` — endpoints / params / high-signal secrets (redacted previews).
- `attack_param_mine` — confirm discovered params are live/injectable.
- `attack_scan_crawled` — scan the newly-discovered endpoints.

## Reasoning Heuristics
- Hidden admin/internal endpoints in bundles are frequent high-value finds.
- Exposed source maps recover full logic + comments.
- Client-side `__proto__` writes → prototype pollution gadget.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Leaked API key/token in bundle (validate read-only) |
| H2 | Hidden endpoint with weak authz |
| H3 | DOM XSS / client-side prototype pollution sink |

## Validation Workflow
1. Confirm a discovered endpoint is live + in-scope, then scan it.
2. Validate secrets read-only; reverify any injection found downstream.

## False-Positive Reduction
- A `key`-looking string may be a public/publishable key by design — confirm what it unlocks, not its presence.
- Minified noise can match regexes — verify before reporting.

## Stealth + OPSEC Guidance
- Fetch bundles politely; do not hammer CDNs.

## Replay Procedures
- Save bundle URLs, extracted lists, and any recovered source-map paths.

## Evidence Requirements
- The extracted artifact + the downstream confirmed finding it enabled.

## Confidence Scoring Logic
- Secret that grants access (validated): high; endpoint discovery alone: recon (feeds scans).

## Adaptive Branching Logic
- DOM sink → branch to `skills/xss/advanced_xss_hunting.md` / `skills/prototype_pollution/prototype_pollution.md`.

## Related Exploit Chains
- `skills/api/rest_api_auth_flaws.md`, `skills/recon/*`

## Safety Boundaries
No use of leaked production secrets beyond a minimal read-only proof.

## Output Artifact Requirements
`output/<target_slug>/js/` — `endpoints.txt`, `params.txt`, `secrets_redacted.json`
