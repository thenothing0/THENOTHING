# Skill: RAG Poisoning & Retrieval Integrity

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `rag_poisoning` |
| **version** | `1.0.0` |
| **category** | AI Security / Retrieval |
| **correlates_with** | Prompt injection, document uploads, web crawl ingestion |

## Objective
Assess whether an attacker can **insert** or **modify** corpus documents that are later **retrieved** for many users, causing **persistent** misinformation or **indirect prompt injection**. Prove with **canary documents** in **authorized** test tenants only.

## Scope Rules
- No poisoning of **production** knowledge bases without approval.
- Respect **copyright** on crawled content tests.

## Trigger Conditions
- User-uploaded KB, public wiki crawl, GitHub repo indexer, shared Notion/Google Drive connectors.

## Technology Fingerprints
- Pinecone/Weaviate/Chroma + chunking pipelines; hybrid search.

## Recon Methodology
1. Map **write** path to corpus vs **read** path in assistant.
2. Test **access control** on upload/list/delete APIs.
3. Measure **staleness** and **re-index** triggers.

## MCP Tool Orchestration Logic
- `httpx_probe` / `katana_crawl` for upload endpoints.
- Vector DB admin UIs—`nuclei_scan` for default creds **only** if in scope.

## Reasoning Heuristics
- **Shared** corpus + **low** trust uploads = high risk.
- **Web crawl** without domain allowlist → drive-by poisoning risk.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Unauthorized write to shared index |
| H2 | Authorized write but cross-user visibility |
| H3 | Crawler SSRF pulling attacker page into corpus |

## Validation Workflow
1. Insert benign canary text unique per test.
2. Query assistant to retrieve canary in **another** user context if applicable.

## False-Positive Reduction
- **Personal** isolated index per user → lower cross-user impact.

## Stealth + OPSEC Guidance
- Remove canary docs post-test; document cleanup.

## Replay Procedures
- Upload API + retrieval query logs (redacted).

## Evidence Requirements
- Cross-user retrieval proof or ACL failure proof.

## Reporting Methodology
- Per-tenant indexes, authz on writes, domain allowlists, content signing, retrieval filters.

## Confidence Scoring Logic
- Cross-user poison retrieval: **0.9+**.

## Adaptive Branching Logic
- **Hybrid** BM25 + vectors → test both channels.

## Related Exploit Chains
- `skills/ai_security/prompt_injection.md`

## Safety Boundaries
No harmful misinformation in public prod.

## Output Artifact Requirements
`output/<target_slug>/ai/rag/` — `canary_proof.md`
