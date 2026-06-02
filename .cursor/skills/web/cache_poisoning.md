# Skill: Web Cache Poisoning

## Metadata
| **id** | `web_cache_poisoning` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/cache/` |

## Objective
Find unkeyed inputs that change cacheable responses and prove **cross-user** impact with benign canaries.

## Trigger Conditions
CDN cache headers; unkeyed `X-Forwarded-Host` / fat GET; weak `Vary`.

## Technology Fingerprints
Cloudflare, Fastly, Varnish, nginx `proxy_cache`, API gateways.

## Reasoning Heuristics
Body diff + HIT on second request; distinguish browser private cache from CDN.

## Exploit Hypotheses
**H1** header unkeyed reflection; **H2** parameter fat GET; **H3** CDN host header split.

## MCP Orchestration Logic
`httpx_probe` → `katana_crawl` → `nuclei_scan` (cache templates) → paired client simulation (logged manually if needed).

## Stealth Guidance
Low volume; avoid poisoning high-traffic homepages; purge if supported post-test.

## Validation Workflow
Baseline HIT/MISS → inject canary → second context receives canary → document purge.

## Evidence Requirements
Paired responses, cache status lines, redacted bodies.

## Adaptive Branching
If authenticated pages cache → PII risk branch; tighten validation and scope checks.

## Confidence Scoring
0.9 cross-user canary; <0.4 single-echo without second user.

## Replay Logic
Two curl scripts with/without poison headers.

## Reporting Guidance
Proper cache keying, `Cache-Control` on sensitive routes, CDN rules.
