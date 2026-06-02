# Skill: GraphQL Introspection, Depth, and Authorization Abuse

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `graphql_introspection_abuse` |
| **version** | `1.0.0` |
| **category** | API / GraphQL |
| **correlates_with** | BOLA, SSRF via fields, batching, persisted queries |

## Objective
Map the **GraphQL attack surface**: introspection (if allowed), **field-level authz**, **batching/aliases**, **depth/complexity**, and **file upload** paths. Treat introspection as **recon**, not impact—impact comes from **unauthorized data access** or **DoS** within scope.

## Scope Rules
- Follow program rules on **introspection** and **automated load**; some programs forbid DoS-style deep queries.
- Do not exfiltrate **bulk PII**—minimal field proof on synthetic IDs.

## Trigger Conditions
- `/graphql`, `apollo-server`, `Hasura`, `AppSync`, `POST` with `query` JSON.
- Errors leaking schema fragments (`Cannot query field`).

## Technology Fingerprints
- Apollo, Yoga, Mercurius, Hasura, Dgraph, AWS AppSync.

## Recon Methodology
1. Confirm endpoint + auth mode (cookie, header, JWT).
2. Run **minimal** introspection query if permitted; else **field guessing** from errors.
3. Build **type graph** for object IDs and nested resolvers.
4. Test **batching** and **alias** parallel ID enumeration (BOLA).

## MCP Tool Orchestration Logic
- `httpx_probe` — discover endpoints, methods.
- `ffuf_fuzz` — path discovery for alternate GraphQL routes.
- `nuclei_scan` — GraphQL templates.
- Manual GraphQL playground—log in `output/`.

**Branching:** If **persisted queries** only → hash/id leak branch; if **subscriptions** → auth + fanout branch.

## Reasoning Heuristics
- **Node interface** + global IDs → predictable object references.
- **Resolver-level** auth misses vs **gateway** auth—where is enforcement?
- Correlate **errors** to stack leaks (separate finding class).

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Introspection enabled in prod |
| H2 | BOLA via `node(id)` |
| H3 | SSRF via custom scalar/url field |
| H4 | DoS via nested query / alias explosion |
| H5 | SQL/NoSQLi via resolver args |

## Validation Workflow
1. Prove **unauthorized** field access vs same-role control.
2. Replay with **second account** / ID pair.
3. Capture **minimal** JSON response.

## False-Positive Reduction
- Introspection alone may be accepted risk—pair with **sensitive** type exposure.
- Field exists but **always null** without auth—verify resolver guards.

## Stealth + OPSEC Guidance
- Query cost limits; backoff; avoid massive alias storms.

## Replay Procedures
- `curl` with JSON body; include `operationName` and variables.

## Evidence Requirements
- Redacted schema snippet if needed; PoC query; impact statement.

## Reporting Methodology
- Disable introspection in prod, query cost analysis, field authz review, persisted query allowlist.

## Confidence Scoring Logic
- BOLA with two accounts: **0.9**; introspection only: **0.25–0.45** unless program values it highly.

## Adaptive Branching Logic
- **Hasura** → admin/metadata endpoints branch.
- **Relay** conventions → node(id) focus.

## Related Exploit Chains
- `skills/api/bola_idor.md`
- `skills/ssrf/chained_ssrf.md`

## Safety Boundaries
No production DoS; no scraping entire user tables.

## Output Artifact Requirements
`output/<target_slug>/graphql/` — `schema_redacted.graphql`, `queries/`, `bola_pairs.json`
