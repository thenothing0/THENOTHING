# Skill: Subdomain Intelligence & Asset Correlation

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `subdomain_intelligence` |
| **version** | `1.0.0` |
| **category** | Recon / OSINT |
| **correlates_with** | CT logs, permutations, takeover, cloud endpoints |

## Objective
Build a **high-signal** subdomain/asset graph using **passive-first** sources, correlate with **tech stack** and **ownership**, and feed downstream skills (web, API, cloud) without noisy blind brute force beyond program limits.

## Scope Rules
- Only domains under **program scope**; exclude out-of-scope TLDs and third parties unless explicitly included.
- Respect **robots** and provider ToS for passive sources.

## Trigger Conditions
- New program domain; wide wildcard scope; API hints of multi-tenant hosts.

## Technology Fingerprints
- Passive: CT, DNSDB, search engines, GitHub (if allowed), JS asset discovery.

## Recon Methodology
1. Passive enumeration (`subfinder`, `amass passive`, `gau`, `katana` seeds).
2. **Resolve** and **HTTP probe** live hosts; bucket by status/title/CNAME.
3. **Cluster** by ASN and cloud provider (heuristic).
4. **Prioritize** auth surfaces and admin panels for manual review.

## MCP Tool Orchestration Logic
| Step | Tools |
|------|--------|
| Enum | `subfinder_scan`, `amass_enum` (passive if stealth required) |
| Live | `httpx_probe` |
| Crawl | `katana_crawl` on selected seeds |
| URLs | `gau_urls` |
| Full chain | `full_recon` when appropriate |

**Branching:** Wildcard DNS → permutation depth limited; **dead** takeovers → `subdomain takeover` style manual validation.

## Reasoning Heuristics
- Weight **dev/staging** subdomains higher for vuln density but check scope allows them.
- Correlate **SPF/DMARC** misconfigs separately—do not conflate with web vulns.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Hidden admin on obscure subdomain |
| H2 | Staging mirrors prod secrets |
| H3 | Orphan service with default creds |

## Validation Workflow
- Confirm **in-scope** ownership (WHOIS/scope doc) before deep testing.
- Tag each host: `in_scope`, `out_of_scope`, `needs_clarification`.

## False-Positive Reduction
- **Parked** domains and **shared** hosting neighbors—exclude.

## Stealth + OPSEC Guidance
- Passive first; throttle active probes; rotate resolvers if program specifies.

## Replay Procedures
- Save command invocations and timestamped raw outputs under `output/`.

## Evidence Requirements
- CSV of hosts with status + tech fingerprint summary.

## Reporting Methodology
- Attack surface summary table + prioritized test plan.

## Confidence Scoring Logic
- **Ownership** confidence affects downstream vuln confidence—track separately.

## Adaptive Branching Logic
- **Many** 403 admin panels → pivot auth/API skills; **cloud** CNAMEs → cloud skills.

## Related Exploit Chains
- `skills/recon/cloud_asset_discovery.md`

## Safety Boundaries
No scanning of critical infrastructure outside brief.

## Output Artifact Requirements
`output/<target_slug>/recon/subdomains/` — `hosts.csv`, `notes.md`
