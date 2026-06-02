# Skill: BOLA / IDOR

## Metadata
| **id** | `api_bola_idor` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/idor/` |

## Objective
Prove broken object-level authorization using **two in-scope accounts** and minimal ID enumeration—prefer IDs from public references over brute force.

## Trigger Conditions
Resource IDs in URLs/JSON; GraphQL `node`; export endpoints.

## Technology Fingerprints
REST, GraphQL, gRPC (if in scope), mobile BFFs.

## Reasoning Heuristics
Compare 200 bodies across tokens; watch 404 vs 403 semantics; check org/tenant headers.

## Exploit Hypotheses
Horizontal read/write; vertical admin function on user token; bulk export IDOR.

## MCP Orchestration Logic
`katana_crawl` → `httpx_probe` (token swap scripts noted) → limited `ffuf_fuzz` **only if** program permits enumeration.

## Stealth Guidance
Low QPS ID tests; stop on rate limits.

## Validation Workflow
A vs B token on same ID; redact sensitive fields; confirm not intentionally public.

## Evidence Requirements
Paired responses; account IDs synthetic; scope confirmation.

## Adaptive Branching
Tenant headers → `business_logic/tenant_escape.md`.

## Confidence Scoring
0.95 cross-account private data; no second account = not submission-ready.

## Replay Logic
Two curl commands differing only by `Authorization`.

## Reporting Guidance
Server-side authz on every route/resolver, monitoring, strong IDs as secondary control.
