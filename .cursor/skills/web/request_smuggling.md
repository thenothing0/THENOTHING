# Skill: HTTP Request Smuggling / Desync

## Metadata
| **id** | `web_request_smuggling` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/smuggling/` |

## Objective
Reason about CL.TE / TE.CL style desync in multi-hop HTTP stacks **only with explicit authorization**; prioritize safety and stability.

## Trigger Conditions
Multiple proxies; CL+TE anomalies; vendor-specific desync advisories matching stack.

## Technology Fingerprints
nginx, Apache, CDNs, HTTP/2 downgrade paths.

## Reasoning Heuristics
Treat as graph of parsing possibilities; prefer minimal probes; correlate with 502 patterns carefully (many FPs).

## Exploit Hypotheses
**H1** CL.TE; **H2** TE.CL; **H3** H2 downgrade; **H4** cache interaction.

## MCP Orchestration Logic
`httpx_probe` (HTTP versions) → `nuclei_scan` **only if** program allows smuggling templates → otherwise architecture review only.

## Stealth Guidance
Extreme throttling; stop on origin instability; maintenance-window coordination if required.

## Validation Workflow
Program approval on file → minimal repro → independent confirmation → impact scoped to in-scope assets.

## Evidence Requirements
Hop diagram, minimal repro, disclaimer on disruption risk.

## Adaptive Branching
Link `cache_poisoning.md` if cache layer implicated.

## Confidence Scoring
Low for single 502; high only with controlled second-request behavior (if permitted).

## Replay Logic
Version-locked raw reproduction notes in `replay/`.

## Reporting Guidance
Patch proxy versions, disable ambiguous TE, HTTP/2 policy, vendor guidance.
