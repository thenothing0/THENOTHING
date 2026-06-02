# Skill: False-Positive Reduction & Triage

## Metadata
| **id** | `validation_fp_reduction` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/memory/validation/` |

## Objective
Systematically downgrade or reject noisy hits: banners, CDN replace pages, one-off 500s, version-only fingerprints, and duplicate scanner templates.

## Trigger Conditions
High scanner volume; conflicting signals; need submission triage.

## Technology Fingerprints
Scanner templates (Nuclei), WAF HTML, load balancers.

## Reasoning Heuristics
Require **second signal**; prefer differential pairs; compare with **control** routes; check **stability** across time.

## Exploit Hypotheses
Meta: “Finding F is a false positive because …”

## MCP Orchestration Logic
Re-run `httpx_probe` with variants; selective `nuclei_scan` with proof templates disabled; manual replay.

## Stealth Guidance
Triage should not increase traffic much—small N of confirmatory requests.

## Validation Workflow
Checklist file per candidate finding with ✅/❌ gates.

## Evidence Requirements
Links to disproof artifacts (control responses).

## Adaptive Branching
If near-miss → spawn targeted skill (e.g. `web/xss.md`) with narrowed scope.

## Confidence Scoring
Explicitly set post-triage confidence; document math.

## Replay Logic
Disproof requests in `replay/fp_checks/`.

## Reporting Guidance
Only ship ≥ agreed threshold; list rejected candidates internally.
