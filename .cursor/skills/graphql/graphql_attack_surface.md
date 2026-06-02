# Skill: GraphQL Attack Surface Intelligence

## Metadata
| **id** | `graphql_attack_surface` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/graphql/` |

## Objective
Discover high-value GraphQL surfaces: introspection (if allowed), type graph, resolver authz, batching/aliases, and depth/DoS policy—then validate BOLA-style issues with two accounts.

## Trigger Conditions
`/graphql`, Apollo/Hasura headers, `errors[].extensions`, persisted queries.

## Technology Fingerprints
Apollo, Yoga, Hasura, AppSync, Mercurius, Graphene.

## Reasoning Heuristics
Infer hidden admin mutations from role-gated errors; map tenant boundaries via `orgId`-style args; correlate excessive field exposure.

## Exploit Hypotheses
Introspection abuse; BOLA via `node(id)`; SSRF via URL scalars; alias batch IDOR; DoS via nested queries (program-gated).

## MCP Orchestration Logic
`httpx_probe` → `katana_crawl` → `ffuf_fuzz` (endpoint discovery) → `nuclei_scan` (GraphQL) → manual queries logged to `replay/`.

## Stealth Guidance
Avoid aggressive alias storms; backoff on cost limit errors; respect introspection bans.

## Validation Workflow
Two-account field access diff; minimal JSON proof; redact PII.

## Evidence Requirements
Redacted schema fragments; PoC queries; policy compliance note on introspection.

## Adaptive Branching
SSRF-like fields → `web/ssrf.md`; JWT in headers → `api/jwt_attacks.md`.

## Confidence Scoring
0.9 cross-account private types; 0.35 introspection only.

## Replay Logic
curl with `--data-binary` JSON; operationName + variables file.

## Reporting Guidance
Disable introspection where required, query cost limits, resolver authz, persisted query allowlists.
