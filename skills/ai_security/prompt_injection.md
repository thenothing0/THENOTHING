# Skill: Prompt Injection & LLM Control Hijack

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `prompt_injection` |
| **version** | `1.0.0` |
| **category** | AI Security / LLM |
| **correlates_with** | RAG, tools, MCP, multi-user chat |

## Objective
Evaluate **instruction hierarchy** failures: **direct** injections overriding system prompts, **delimiter** confusion, and **role** swaps. Prove impact with **benign** exfil markers (e.g. canary string) only on **systems you own** or **explicit** bug bounty AI scope.

## Scope Rules
- No extraction of **real user** conversations from production multi-tenant chat without authorization.
- Follow program rules on **automated** LLM probing volume.

## Trigger Conditions
- User-controlled text rendered into model context (chat, email summarization, doc Q&A).
- System prompts concatenated unsafely with user content.

## Technology Fingerprints
- OpenAI, Anthropic, local Llama deployments, LangChain/LlamaIndex glue.

## Recon Methodology
1. Map **context assembly** order (system, developer, user, tool outputs).
2. Test **boundary tokens** and **encoding** tricks conservatively.
3. Check **multi-turn** persistence of injected instructions.

## MCP Tool Orchestration Logic
- `httpx_probe` on LLM HTTP endpoints (rate limited).
- Manual chat UI testing—log transcripts under `output/` with redaction.

## Reasoning Heuristics
- **Indirect** injection via retrieved docs is higher risk in enterprise assistants.
- **Tool** schemas may leak capabilities—pair with `mcp_abuse` skill.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Direct jailbreak enabling policy bypass |
| H2 | Steer model to call tools with attacker args |
| H3 | Multi-user context leakage |

## Validation Workflow
1. Reproducible transcript with **minimal** injection.
2. Second session confirms absence of randomness (multiple trials).

## False-Positive Reduction
- One-off weird output ≠ injection; need **reliable** control hijack.

## Stealth + OPSEC Guidance
- Low rate; avoid training data poisoning attempts.

## Replay Procedures
- Save request JSON + model version + temperature settings.

## Evidence Requirements
- Redacted transcript; impact: data accessed, actions attempted.

## Reporting Methodology
- Prompt isolation, structured outputs, tool allowlists, monitoring, safety layers.

## Confidence Scoring Logic
- Reliable tool misuse or data exfil canary: **0.85+**.

## Adaptive Branching Logic
- **RAG** present → pivot `rag_poisoning.md`.

## Related Exploit Chains
- `skills/ai_security/mcp_abuse.md`

## Safety Boundaries
No harassment content generation; no illegal exfiltration.

## Output Artifact Requirements
`output/<target_slug>/ai/prompt/` — `transcripts_redacted.md`, `versions.txt`
