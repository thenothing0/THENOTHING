# Skill: Recon Asset Pipeline (Passive → Active)

## Metadata
| **id** | `recon_asset_pipeline` |
| **version** | `1.0.0` |
| **mode** | THENOTHING / Cursor Agent |
| **output_root** | `output/<target>/recon/` |

## Objective
Build an in-scope **host and URL inventory** with maximal signal and minimal noise, then rank assets for downstream web/API/cloud testing.

## Trigger Conditions
- New program or domain set; expanded wildcard scope; post-scope refresh.

## Technology Fingerprints
- Any stack; prioritize TLS anomalies, CDN fronting, non-standard ports, and auth-gated hosts.

## Reasoning Heuristics
- Weight **staging/dev** labels higher for defect density only if **in scope**.
- Correlate **DNS** → **HTTP** → **tech** before deep fuzz; drop dead hosts early.
- Treat scanner output as **candidates**, not findings.

## Exploit Hypotheses
| **H1** | Forgotten admin on low-traffic subdomain |
| **H2** | Exposed internal tooling behind weak gate |
| **H3** | Version drift between mobile and web API hosts |

## MCP Orchestration Logic
1. `check_tools` — verify MCP tool availability.  
2. `subfinder_scan` + `amass_enum` (passive when stealth matters).  
3. `httpx_probe` — live detection, status, title, tech hints.  
4. `gau_urls` + `katana_crawl` — historical and crawl-derived URLs (rate-aware).  
5. `whatweb_detect` / `wafw00f_detect` — fingerprint and WAF presence.  
6. Optional `full_recon` — orchestrated chain when scope allows.

**Branch:** WAF strict → shorten crawl depth and defer aggressive fuzz to `validation`-gated phases.

## Stealth Guidance
Passive-first; throttle parallel probes; backoff on 429/403; avoid scanning out-of-scope TLDs inferred from CT noise.

## Validation Workflow
- Tag each asset `in_scope` / `needs_review` / `out_of_scope` with rationale file in `memory/`.
- Re-verify scope after **major** inventory expansion.

## Evidence Requirements
- `hosts.csv`, `urls.txt`, MCP raw logs under `recon/`, WAF notes in `logs/`.

## Adaptive Branching
- **Many** APIs discovered → activate `api/` + `graphql/` skills.  
- **Cloud CNAMEs** → activate `cloud/` + `osint/`.  
- **Heavy JS** → activate `browser/`.

## Confidence Scoring
- **0.9** inventory completeness when multiple passive sources agree; **0.5** when only single-source DNS.

## Replay Logic
- Document exact MCP invocations and timestamps; reproduce inventory from saved seed list.

## Reporting Guidance
Deliver prioritized table: host, role guess, tech, WAF, next recommended skill id.
