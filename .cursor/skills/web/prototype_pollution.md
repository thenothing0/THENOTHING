# Skill: Prototype Pollution (JS Object Graph)

## Metadata
| **id** | `web_prototype_pollution` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/proto_pollution/` |

## Objective
Find `__proto__` / `constructor.prototype` merges that alter security-sensitive properties; prove with observable state change and gadget path **in scope**.

## Trigger Conditions
Deep merge of user JSON/query; libraries lodash/set, qs, hoek, minimist patterns.

## Technology Fingerprints
Node/Express; client hydration merging server+client config.

## Reasoning Heuristics
Pollution without gadget = informational; map gadget to auth/privilege flags.

## Exploit Hypotheses
**H1** auth flag flip; **H2** RCE gadget (ROE); **H3** client-only dangerous action.

## MCP Orchestration Logic
`katana_crawl` → `ffuf_fuzz` (nested keys, slow) → `httpx_probe` → `nuclei_scan` hints.

## Stealth Guidance
Throttle fuzz; watch for 500 storms; encode variants carefully.

## Validation Workflow
Observable marker property → security-sensitive toggle on **test** account → replay.

## Evidence Requirements
Diff JSON, library/version hints, redacted stack traces.

## Adaptive Branching
GraphQL variables deep merge → combine with `graphql_attack_surface.md`.

## Confidence Scoring
0.85+ with gadget; 0.4 pollution marker only.

## Replay Logic
Exact nested JSON and Content-Type.

## Reporting Guidance
Schema validation, safe maps (`Object.create(null)`), library upgrades, disable dangerous merge.
