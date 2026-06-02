# Skill: Mass Assignment

## Metadata
| **id** | `api_mass_assignment` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/mass_assignment/` |

## Objective
Find endpoints binding client-supplied fields to privileged model properties (`role`, `plan`, `isAdmin`) and prove persistence on **test** accounts without financial harm.

## Trigger Conditions
`PATCH`/`PUT` JSON blobs; frameworks with object binding; hidden fields in GET responses.

## Technology Fingerprints
Rails, Laravel, Node `...req.body`, Django mass-assignment patterns.

## Reasoning Heuristics
Echo of unexpected keys; PATCH returns expanded objects; role strings in diff.

## Exploit Hypotheses
Privilege field accepted; billing/plan manipulation; org-wide settings via user endpoint.

## MCP Orchestration Logic
`httpx_probe` → `katana_crawl` → `ffuf_fuzz` (field keys, throttled).

## Stealth Guidance
Single-field probes; avoid thousands of keys per second.

## Validation Workflow
Benign probe keys → privileged key on sandbox → rollback if requested.

## Evidence Requirements
Before/after JSON diff; minimal repro.

## Adaptive Branching
GraphQL input types → combine with `graphql/graphql_attack_surface.md`.

## Confidence Scoring
0.9 persisted privilege flip on test; ignored keys = low.

## Replay Logic
Exact JSON body files in `replay/`.

## Reporting Guidance
DTOs, allowlists, serializer views, server defaults.
