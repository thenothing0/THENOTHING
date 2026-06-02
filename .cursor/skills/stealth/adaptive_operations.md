# Skill: Adaptive Stealth Operations (Meta)

## Metadata
| **id** | `stealth_adaptive_operations` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/logs/stealth/` |

## Objective
Tune recon and testing intensity dynamically from **WAF signals**, **429/403 rates**, **program rules**, and **asset criticality**—this is a **meta** overlay on all other skills.

## Trigger Conditions
WAF detected; high error rates; sensitive industries; narrow time windows per brief.

## Technology Fingerprints
Any CDN/WAF vendor; rate-limit headers.

## Reasoning Heuristics
Switch passive→active thresholds; reduce parallelism; change payload classes; pause and document when noisy.

## Exploit Hypotheses
N/A—operational hypothesis: “continuing active fuzz will reduce signal or violate rules.”

## MCP Orchestration Logic
Use `wafw00f_detect` early; prefer `gau_urls`/`katana_crawl` with conservative depth before `ffuf_fuzz`.

## Stealth Guidance
Jitter; backoff; business-hour windows; avoid destructive tests.

## Validation Workflow
Log decisions in `logs/stealth/decisions.md` with timestamps and triggers.

## Evidence Requirements
Rate timeline CSV optional.

## Adaptive Branching
If WAF strict → pivot to `browser/` and `graphql/` reasoning-heavy paths.

## Confidence Scoring
N/A for vulns; track “operational risk” low/med/high.

## Replay Logic
Decision log is replay of operator intent.

## Reporting Guidance
Include methodology note in final report for triage teams.
