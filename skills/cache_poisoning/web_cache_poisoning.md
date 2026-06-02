# Skill: Web Cache Poisoning & Unkeyed Input Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `web_cache_poisoning` |
| **version** | `1.0.0` |
| **category** | Web / Caching / HTTP semantics |
| **correlates_with** | Host header injection, Vary bugs, CDN keying, smuggling |

## Objective
Identify **cache key** vs **unkeyed** input divergences that allow **stored malicious responses** to be served to other users. Use **differential** analysis and **OAST** only if permitted; avoid poisoning production caches without approval.

## Scope Rules
- Confirm program allows **cache manipulation** tests; some treat as DoS.
- Limit poisoned content to **benign** markers (unique strings) unless ROE says otherwise.
- Do not persist illegal or offensive content in caches.

## Trigger Conditions
- CDN/proxy present (`CF-Cache-Status`, `Age`, `X-Cache`).
- Reflection of `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, query params in HTML without keying.
- Fat GET responses cacheable.

## Technology Fingerprints
- Varnish, Cloudflare, Fastly, Akamai, nginx `proxy_cache`, API gateways.

## Recon Methodology
1. Identify **cacheable** routes (GET, cache headers, TTL).
2. Param miner mindset: which headers/query **change body** but not **cache key**.
3. Test **Vary** correctness vs `Accept`, `Accept-Encoding`, `Cookie`.
4. Cross-user simulation: two clients, same URL, different poison header.

## MCP Tool Orchestration Logic
- `httpx_probe` — header echo, cache status fingerprint.
- `katana_crawl` — surface cacheable URLs.
- `nuclei_scan` — cache poisoning templates if allowed.
- `ffuf_fuzz` — unkeyed header wordlists (slow, careful).

**Branching:** If `Cookie` in cache key → pivot auth cache split; if `Accept-Encoding` mishandled → Brotli/gzip branch.

## Reasoning Heuristics
- **Body diff** + **cache HIT** on second request = strong signal.
- Distinguish **personalized** pages (should not cache) from static.
- Link **routing** bugs (rewrite) to cache.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Unkeyed header reflected in title/body |
| H2 | Param fat GET poisoning |
| H3 | CDN route + host header split |
| H4 | Web cache deception via content-type |

## Validation Workflow
1. Baseline HIT/MISS behavior.
2. Inject benign canary; confirm second client receives canary.
3. Revert/purge if possible post-test.

## False-Positive Reduction
- **Private cache** in browser only ≠ CDN poison.
- ETag/Vary noise—use stable content hashes.

## Stealth + OPSEC Guidance
- Low volume; avoid poisoning high-traffic homepages; coordinate TTL.

## Replay Procedures
- Two curl sequences with/without poison; document cache headers.

## Evidence Requirements
- Side-by-side responses; cache status lines; purge evidence if obtained.

## Reporting Methodology
- Keying fix, `Cache-Control` for sensitive routes, CDN rules.

## Confidence Scoring Logic
- Cross-user canary: **0.9+**; single reflection: low until second user proven.

## Adaptive Branching Logic
- **Authenticated pages** caching → high priority PII branch (stop if out of scope).

## Related Exploit Chains
- `skills/request_smuggling/http_request_smuggling.md`
- `skills/cors/cors_exploitation.md`

## Safety Boundaries
No mass user impact; no permanent defacement; follow coordinated disclosure.

## Output Artifact Requirements
`output/<target_slug>/cache_poisoning/` — `headers_matrix.csv`, `replay_pair.sh`, `impact.md`
