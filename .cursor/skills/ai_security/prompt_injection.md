# Skill: Prompt Injection

## Metadata
| **id** | `ai_prompt_injection` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ai/prompt/` |

## Objective
Evaluate instruction hierarchy failures and indirect injection via retrieved content—**benign** canaries, authorized systems only.

## Trigger Conditions
User text enters model context; RAG retrieval; tool observations looped into planner.

## Technology Fingerprints
OpenAI, Anthropic, local Llama stacks, LangChain/LlamaIndex.

## Reasoning Heuristics
Multi-turn persistence; delimiter attacks; tool misuse steering.

## Exploit Hypotheses
Jailbreak; tool call with attacker args; cross-user context bleed (see `context` skill if split).

## MCP Orchestration Logic
`httpx_probe` on LLM HTTP endpoints (rate limited); transcripts in `logs/` redacted.

## Stealth Guidance
Low request rate; no harmful content generation.

## Validation Workflow
Repeatable transcript + control runs; document model/version/settings.

## Evidence Requirements
Redacted transcript; impact class (data vs action).

## Adaptive Branching
RAG present → `rag_poisoning.md`; tools/MCP → `mcp_abuse.md`.

## Confidence Scoring
0.85 reliable control hijack or tool misuse on test tenant.

## Replay Logic
Request JSON + temperature + tool schema version.

## Reporting Guidance
Prompt isolation, structured outputs, tool allowlists, monitoring.
