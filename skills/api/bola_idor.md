# Skill: BOLA / IDOR & Object-Level Authorization

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `bola_idor` |
| **version** | `1.0.0` |
| **category** | API / Authorization |
| **correlates_with** | UUID vs int IDs, horizontal privilege, GraphQL `node` |

## Objective
Systematically test **object references** for **horizontal** and **vertical** access control breaks using **two in-scope accounts**. Prefer **predictable** ID discovery from public references over brute forcing large ranges.

## Scope Rules
- Use only **program-supplied** or **self-created** secondary accounts.
- ID enumeration must respect program caps; no high-volume guessing on production.

## Trigger Conditions
- Sequential integers, UUIDs in URLs, encrypted-but-static tokens.
- APIs returning objects for `userId`, `orderId`, `invoiceId`.

## Technology Fingerprints
- REST resources, GraphQL `node(id:)`, gRPC reflection (if in scope).

## Recon Methodology
1. Inventory IDs visible in UI, emails, PDFs, public profiles.
2. Map **authorization** dependencies (org scoping, tenant headers).
3. Test **cross-user** read then **cross-user** write separately.

## MCP Tool Orchestration Logic
- `katana_crawl` — collect ID-bearing URLs.
- `httpx_probe` — scripted requests with token swap (manual token injection documented).
- `ffuf_fuzz` — **only** small ranges with approval.

## Reasoning Heuristics
- **204/404** uniformity may hide IDOR—compare **body** and **side channels** (timing).
- **Secondary keys** (`orgId`, `workspaceId`) often weaker than `userId`.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Horizontal read |
| H2 | Horizontal write/delete |
| H3 | Vertical escalation via role parameter |
| H4 | IDOR in export/bulk endpoints |

## Validation Workflow
1. Same resource ID with **User A** token vs **User B** token.
2. Document **minimal** PII in response (redact).
3. Confirm not a **shared** resource by design (business logic check).

## False-Positive Reduction
- Public resources (blog posts) ≠ IDOR.
- **Collaboration** features—verify sharing model with docs.

## Stealth + OPSEC Guidance
- Low QPS; avoid downloading full corpora of other users’ files.

## Replay Procedures
- Two curl commands with swapped `Authorization`.

## Evidence Requirements
- Redacted JSON; IDs; explicit statement of cross-account proof.

## Reporting Methodology
- Server-side authz on every resolver/controller, unpredictable IDs as defense-in-depth only.

## Confidence Scoring Logic
- Cross-account private data: **0.95**; guess without second account: not submission-ready.

## Adaptive Branching Logic
- **File storage** URLs with signatures → timing/signature bypass branch if in scope.

## Related Exploit Chains
- `skills/business_logic/tenant_escape.md`
- `skills/api/graphql_introspection_abuse.md`

## Safety Boundaries
No extortion content collection; minimal disclosure.

## Output Artifact Requirements
`output/<target_slug>/idor/` — `pairs.md`, `evidence_redacted.json`
