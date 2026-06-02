# Skill: SQLi Hypothesis Engine

## Metadata
| **id** | `web_sqli` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/sqli/` |

## Objective
Build SQLi hypotheses (error, boolean, time, second-order) with differential evidence; align tool use with program rules.

## Trigger Conditions
SQL errors; search/sort/filter parameters; ORM raw fragments.

## Technology Fingerprints
MySQL, Postgres, MSSQL, Oracle, SQLite dialect cues.

## Reasoning Heuristics
Prefer **boolean pairs** over noisy time-based; map ORM vs raw SQL; watch WAF normalization.

## Exploit Hypotheses
**H1** error-based; **H2** blind boolean; **H3** time-based; **H4** second-order stored input.

## MCP Orchestration Logic
`httpx_probe` → `nuclei_scan` (SQLi) → `sqlmap` **only if** MCP + program allow → else manual differentials.

## Stealth Guidance
Slow timing; cap concurrency; stop on sustained 500s.

## Validation Workflow
Syntax oracle → boolean pair → replay; no destructive statements.

## Evidence Requirements
Minimal diff proof; no bulk dumps.

## Adaptive Branching
GraphQL layer → `graphql/graphql_attack_surface.md`.

## Confidence Scoring
0.9 clear SQL grammar break; single 500 without diff ≤0.35.

## Replay Logic
Paired requests stored under `replay/`.

## Reporting Guidance
Parameterized queries, ORM safety, least privilege, WAF as secondary control.
