# Skill: Multi-Tenant Isolation & Tenant Escape

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `tenant_escape` |
| **version** | `1.0.0` |
| **category** | Business logic / SaaS isolation |
| **correlates_with** | IDOR, header `X-Org-Id`, subdomain mapping, RLS gaps |

## Objective
Validate **tenant boundaries**: org/workspace/project scoping on APIs, storage URLs, websocket rooms, and background jobs. Prove **cross-tenant** data access only with **two program-created tenants**.

## Scope Rules
- Never access **real customer** workspaces; use synthetic orgs.
- Some programs forbid multi-tenant testing—**read rules**.

## Trigger Conditions
- Headers like `X-Workspace-Id`, `Team-Id`, path `/orgs/{id}/`.
- Shared object storage URLs with predictable keys.

## Technology Fingerprints
- Postgres **RLS** claims vs app-layer checks; S3 key prefixes per tenant.

## Recon Methodology
1. Map **tenant identifier** propagation across API + websocket + exports.
2. Swap identifiers between **your** two tenants only.
3. Check **async** exports and **search** indices for stale cross-links.

## MCP Tool Orchestration Logic
- `httpx_probe`, `katana_crawl`, `ffuf_fuzz` (tenant slug wordlist on **your** assets).

## Reasoning Heuristics
- **Search** endpoints often weaker than primary CRUD.
- **Import** jobs may run with elevated privileges—test isolation.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Cross-tenant read |
| H2 | Cross-tenant write |
| H3 | Webhook replay across tenants |

## Validation Workflow
1. Side-by-side token + tenant header matrix.
2. Minimal data exfil proof (redacted).

## False-Positive Reduction
- **Shared templates** intentionally public ≠ escape.

## Stealth + OPSEC Guidance
- Minimal data pull; encrypted artifacts at rest locally.

## Replay Procedures
- Curl matrix with headers annotated.

## Evidence Requirements
- Tenant IDs (synthetic), response diff.

## Reporting Methodology
- RLS + app checks, consistent tenant context middleware, storage policy.

## Confidence Scoring Logic
- Cross-tenant private record: **0.95**.

## Adaptive Branching Logic
- **Custom domains** per tenant → DNS takeover + session mixups branch (careful scope).

## Related Exploit Chains
- `skills/api/bola_idor.md`

## Safety Boundaries
No real customer data access.

## Output Artifact Requirements
`output/<target_slug>/tenant/` — `matrix.csv`, `proof_redacted.json`
