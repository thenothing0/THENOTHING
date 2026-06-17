# Skill: GraphQL Attack Surface

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `graphql_attack_surface` |
| **version** | `1.0.0` |
| **category** | GraphQL / API |
| **correlates_with** | BOLA/BFLA, mass assignment, IDOR, rate-limit bypass, info disclosure |

## Objective
Map and abuse a GraphQL endpoint: schema disclosure via **introspection** (and field-suggestion when
"disabled"), **mutation** write surface, **alias/array batching** for brute-force and rate-limit bypass,
and object/field-level authorization gaps (GraphQL-flavored BOLA/BFLA).

## Scope Rules
- Detection-only on schema/errors; never mutate real data — use test objects.
- Respect query depth/complexity limits; do not amplify load.

## Trigger Conditions
- `graphql_endpoint`, `introspection_hint`; `/graphql`, `/v1/graphql`, `application/json` POST with `query`.

## Technology Fingerprints
- Apollo, Hasura, GraphQL Yoga, Graphene, Absinthe, AWS AppSync.

## Recon Methodology
1. Probe introspection + GET-introspection; if blocked, try field-suggestion ("did you mean").
2. Enumerate `mutationType` to find the write surface.
3. Test alias/array batching for single-request fan-out.

## MCP Tool Orchestration Logic
- `attack_graphql` — introspection / field-suggestion / GET-introspection / batching / mutations-exposed
  / alias-batching (all detection-only).
- `ffuf_fuzz` — discover alternate GraphQL paths.
- `attack_api check=bola|bfla` — apply object/function-level authz tests to resolved object ids.

## Reasoning Heuristics
- Introspection off but field-suggestion on → schema still recoverable.
- Alias batching enabled → brute-force/2FA-bypass and rate-limit-bypass surface.
- A query returning another tenant's node by id → GraphQL BOLA.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | Introspection/field-suggestion → full schema map |
| H2 | Alias batching → OTP/coupon brute-force |
| H3 | Object-level authz gap on `node(id:)` → BOLA |
| H4 | Exposed mutation → unauthorized write |

## Validation Workflow
1. Two signals (e.g. schema disclosure + a resolved cross-tenant field).
2. Reverify; map confirmed authz gaps into `bola_ato` chain.

## False-Positive Reduction
- A 400 with a generic error is not introspection — require schema/types in the body.
- Batching that returns one result is not enabled.

## Stealth + OPSEC Guidance
- Cap batch size; do not weaponize batching into a real brute-force.

## Replay Procedures
- Save the introspection document and each PoC query/response.

## Evidence Requirements
- Schema excerpt, the BOLA query/response pair, remediation (disable introspection in prod, enforce
  per-object authz, cap batching/depth).

## Confidence Scoring Logic
- Cross-tenant data via a query: **0.9+**; introspection alone: info/medium.

## Adaptive Branching Logic
- Auth on resolvers → branch to `skills/api/bola_idor.md` and `skills/api/mass_assignment.md`.

## Related Exploit Chains
- `skills/api/graphql_introspection_abuse.md`, `skills/api/bola_idor.md`

## Safety Boundaries
No destructive mutations; no real-data exfiltration beyond a minimal PoC.

## Output Artifact Requirements
`output/<target_slug>/graphql/` — `schema.json`, `queries/`, `authz_matrix.csv`
