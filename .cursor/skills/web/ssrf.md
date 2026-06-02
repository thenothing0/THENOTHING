# Skill: SSRF (Chains & Metadata)

## Metadata
| **id** | `web_ssrf` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ssrf/` |

## Objective
Identify server-side fetch primitives and prove **server-initiated** requests with minimal internal touch, strictly within authorization.

## Trigger Conditions
URL-like parameters, webhooks, importers, PDF/image renderers, GraphQL URL scalars.

## Technology Fingerprints
Cloud metadata paths, enterprise HTTP stacks, reverse proxies.

## Reasoning Heuristics
Parser differentials (IPv6, `@`, schemes); follow-up hops to cache or internal APIs; blind signals via timing/OAST **if allowed**.

## Exploit Hypotheses
**H1** internal port/service; **H2** metadata credential exposure (ROE); **H3** protocol smuggling where stack permits; **H4** cache interaction.

## MCP Orchestration Logic
`katana_crawl` / `gau_urls` → `httpx_probe` → `nuclei_scan` (SSRF templates) → manual OAST only per program.

## Stealth Guidance
Low QPS; no broad internal sweeps; backoff on errors.

## Validation Workflow
Prove **server** fetch (not redirect-only); document blast radius; stop at scope edge.

## Evidence Requirements
Request, proof of initiation, redacted response; policy note for metadata tests.

## Adaptive Branching
Cloud CNAMEs → `cloud/aws_privesc.md` **only** if metadata path is in-scope and approved.

## Confidence Scoring
0.85+ with collaborator or strong differential; <0.5 for ambiguous errors.

## Replay Logic
Single minimal repro + control URL.

## Reporting Guidance
Root cause in URL handling, allowlists, network egress, metadata hardening.
