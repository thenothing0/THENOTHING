# Skill: JavaScript Prototype Pollution Reasoning

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `prototype_pollution` |
| **version** | `1.0.0` |
| **category** | Web / Logic / JS runtime |
| **correlates_with** | `Object.assign`, deep merge libs, JSON parsing, Express `qs` |

## Objective
Find **key collision** paths (`__proto__`, `constructor.prototype`) that alter object prototypes and lead to **auth bypass**, **RCE gadgets**, or **client/server** logic abuse. Validate with **minimal** property deltas and observable **security gates**.

## Scope Rules
- Server-side pollution tests must avoid DoS (mass object allocation) unless approved.
- Client-side only findings need **realistic** exploit path to sensitive action.

## Trigger Conditions
- Deep merge of JSON/query/body into objects.
- Libraries: lodash merge/set, hoek, minimist, yargs, `qs` parsing, unsafe `JSON.parse` revivers.

## Technology Fingerprints
- Node/Express APIs; client SPA config hydration; bundler polyfills.

## Recon Methodology
1. Map **parsers** of nested objects from query, JSON, multipart metadata.
2. Identify **merge** utilities and versions (CVE correlation allowed).
3. Client: look for `Object.assign({}, user)` patterns via sourcemaps if in scope.

## MCP Tool Orchestration Logic
- `katana_crawl` — endpoints with rich query strings.
- `httpx_probe` — tech headers.
- `ffuf_fuzz` — nested keys **slowly** (`__proto__`, `constructor][prototype`, etc.) per encoding rules.
- `nuclei_scan` — prototype pollution templates as hints.

**Branching:** If WAF blocks `__proto__` → encoding variants (`__proto__` unicode, arrays) **within** ethics.

## Reasoning Heuristics
- Pollution without **gadget** to security property = informational unless program cares.
- Correlate **server** vs **client** pollution via error stacks.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Denylist bypass via alternative keys |
| H2 | Auth flag `isAdmin` via merged JWT body |
| H3 | RCE gadget chain in template/runtime |
| H4 | Client-only gadget enabling action |

## Validation Workflow
1. Observable property change (`polluted: true` in response JSON if safe).
2. Security-sensitive flag flip **in scope** sandbox account.
3. Replay minimal curl.

## False-Positive Reduction
- Keys stripped but no behavior change → not a vuln.
- Client console tricks without server trust → clarify impact.

## Stealth + OPSEC Guidance
- Throttle fuzz; watch for 500 cascades.

## Replay Procedures
- Exact JSON/query with Content-Type; include version of library if known.

## Evidence Requirements
- Before/after object diff; gadget chain narrative.

## Reporting Methodology
- Patch merge strategy (`Object.create(null)` maps), schema validation, library upgrade.

## Confidence Scoring Logic
- Gadget to critical impact: **0.85+**; pollution only: **0.35–0.55**.

## Adaptive Branching Logic
- **GraphQL variables** deep merge → dedicated branch.
- **Multipart** metadata → parser-specific fuzz.

## Related Exploit Chains
- `skills/deserialization/insecure_deserialization_web.md`

## Safety Boundaries
No RCE on third-party; no wormable payloads.

## Output Artifact Requirements
`output/<target_slug>/proto_pollution/` — `payloads.md`, `diff.json`, `replay.sh`
