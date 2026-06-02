# Skill: Mass Assignment & Dangerous Parameter Binding

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `mass_assignment` |
| **version** | `1.0.0` |
| **category** | API / Object binding |
| **correlates_with** | Rails strong params, Mongoose, Prisma, Django serializers |

## Objective
Detect endpoints that bind client-supplied fields into **privileged model properties** (`role`, `isAdmin`, `plan`, `balance`). Use **differential** property injection with **control** objects—never real financial harm.

## Scope Rules
- No illegal balance manipulation on production; use **sandbox** ledgers when provided.
- Stop if changes affect **other users** or **global** config.

## Trigger Conditions
- `PUT`/`PATCH` user/profile/org endpoints accepting JSON blobs.
- Frameworks known for binding whole objects.

## Technology Fingerprints
- Rails, Laravel mass assignment, Node ORMs with `...req.body`.

## Recon Methodology
1. Schema inference from responses (hidden fields returned on GET).
2. Add **benign** extra keys (`_debug`, `zzz_probe`) to detect reflection/persistence.
3. Escalate to privilege keys only with approval.

## MCP Tool Orchestration Logic
- `httpx_probe` — discover verbs.
- `ffuf_fuzz` — parameter keys from wordlist (slow).
- `katana_crawl` — find forms mapping to API.

## Reasoning Heuristics
- If **PATCH** echoes full object, binding surface is larger.
- Compare **role** string before/after with synthetic values in **test** account.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Hidden `role` accepted |
| H2 | Price/plan fields mutable |
| H3 | Org-wide settings via user PATCH |

## Validation Workflow
1. Prove field not in UI but accepted by API.
2. Show persistent effect on **self** account.
3. Roll back if program requests.

## False-Positive Reduction
- Read-only echo without persistence ≠ mass assignment.
- Validation rejects silently—check DB via UI state if possible.

## Stealth + OPSEC Guidance
- Single-field probes; avoid spraying thousands of keys.

## Replay Procedures
- JSON diff of PATCH; store ETags.

## Evidence Requirements
- Before/after JSON; minimal repro.

## Reporting Methodology
- DTOs, allowlists, serializer views, server-side defaults.

## Confidence Scoring Logic
- Privilege field persisted: **0.9+**; ignored key: low.

## Adaptive Branching Logic
- **GraphQL** input types → parallel `variables` injection branch.

## Related Exploit Chains
- `skills/api/bola_idor.md`

## Safety Boundaries
No fraud; no org-wide sabotage.

## Output Artifact Requirements
`output/<target_slug>/mass_assignment/` — `payloads.json`, `diffs/`
