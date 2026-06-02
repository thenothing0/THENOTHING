# Skill: Tenant Escape

## Metadata
| **id** | `bl_tenant_escape` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/tenant/` |

## Objective
Test isolation between tenants/workspaces using **two synthetic tenants** only; prove cross-tenant data access or actions.

## Trigger Conditions
`X-Workspace-Id`, org path prefixes, shared buckets with predictable keys.

## Technology Fingerprints
Multi-tenant SaaS, Postgres RLS claims, S3 key prefixes.

## Reasoning Heuristics
Search/export endpoints often weaker than primary CRUD; async jobs may mix tenants.

## Exploit Hypotheses
Cross-tenant read/write; webhook replay across tenants.

## MCP Orchestration Logic
`httpx_probe` matrix with header swaps; `ffuf_fuzz` limited to **your** org slugs.

## Stealth Guidance
Minimal exfil; redact all foreign tenant data from artifacts.

## Validation Workflow
Strict A/B tenant proof; confirm not intentionally public template.

## Evidence Requirements
Redacted JSON diff; synthetic tenant IDs.

## Adaptive Branching
IDOR patterns → `api/bola_idor.md`.

## Confidence Scoring
0.95 confirmed cross-private tenant data.

## Replay Logic
Header matrix saved as CSV.

## Reporting Guidance
RLS + app checks, per-tenant indexes, webhook signing, storage policy.
