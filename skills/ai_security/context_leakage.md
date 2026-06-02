# Skill: Context Leakage & Cross-Session Data Exposure

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `context_leakage` |
| **version** | `1.0.0` |
| **category** | AI Security / Privacy |
| **correlates_with** | Multi-tenant chat, caching, RAG, logging |

## Objective
Detect **cross-user** or **cross-session** leakage via **shared** vector stores, **bad** cache keys, **logs** containing prompts, or **browser** session confusion in AI products.

## Scope Rules
- No accessing **other users’** sessions illegally—use **two** test accounts only.

## Trigger Conditions
- Shared conversation IDs, cache keys missing user id, admin debug endpoints returning prompts.

## Technology Fingerprints
- Multi-tenant SaaS assistants, browser extensions, enterprise search bars.

## Recon Methodology
1. Map **persistence** layers (Redis keys, DB rows, CDN).
2. Two-account **A/B** retrieval tests on similar queries.
3. Inspect **telemetry** endpoints for prompt echo (authorized).

## MCP Tool Orchestration Logic
- `httpx_probe` for debug routes; manual UI tests.

## Reasoning Heuristics
- **Conversation resume** tokens may be guessable—rate-limited audit.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | User B retrieves user A chunks |
| H2 | Logs leak PII prompts |
| H3 | Shared browser profile leaks local model context |

## Validation Workflow
- Strict two-account proof with unique canary strings.

## False-Positive Reduction
- **Global** public FAQ retrieval ≠ leakage.

## Stealth + OPSEC Guidance
- Redact PII from any captured logs immediately.

## Replay Procedures
- Steps + timestamps + session IDs (synthetic).

## Evidence Requirements
- Minimal cross-leak snippet (redacted).

## Reporting Methodology
- Partitioned storage, per-user retrieval filters, log scrubbing, TTLs.

## Confidence Scoring Logic
- Confirmed cross-tenant chunk: **0.95**.

## Adaptive Branching Logic
- **Enterprise SSO** shared drive connectors → large blast radius branch.

## Related Exploit Chains
- `skills/ai_security/rag_poisoning.md`

## Safety Boundaries
No exploitation of real user privacy.

## Output Artifact Requirements
`output/<target_slug>/ai/leakage/` — `ab_proof_redacted.md`
