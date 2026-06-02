# Skill: RAG Poisoning

## Metadata
| **id** | `ai_rag_poisoning` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ai/rag/` |

## Objective
Assess whether attackers can persist poison documents in shared corpora later retrieved for other users—**test tenants only**.

## Trigger Conditions
User uploads to KB; crawlers without domain allowlist; shared vector index.

## Technology Fingerprints
Chroma/Pinecone/Weaviate + chunk pipelines.

## Reasoning Heuristics
Cross-user retrieval of unique canary strings; ACL on write/delete; crawler SSRF into corpus.

## Exploit Hypotheses
Unauthorized write; cross-tenant chunk retrieval; crawler poisoning.

## MCP Orchestration Logic
`httpx_probe` / `katana_crawl` for upload/search endpoints.

## Stealth Guidance
Remove canary docs post-test; document cleanup.

## Validation Workflow
Insert benign canary → retrieve as other test user if applicable.

## Evidence Requirements
Redacted retrieval snippet; ACL failure narrative.

## Adaptive Branching
Prompt injection → `prompt_injection.md`.

## Confidence Scoring
0.9 confirmed cross-user poison retrieval.

## Replay Logic
Upload + query request pair.

## Reporting Guidance
Per-tenant indexes, authz on writes, domain allowlists, content signing.
