# Skill: Tool Poisoning & Agentic Toolchains

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `tool_poisoning` |
| **version** | `1.0.0` |
| **category** | AI Security / Agents |
| **correlates_with** | MCP, function calling, plugin ecosystems |

## Objective
Identify risks where **tool metadata**, **descriptions**, or **returned observations** are attacker-controlled and **steer** agents to **unsafe** sequences (e.g. deleting files, sending webhooks). Focus on **developer** and **CI** agent contexts.

## Scope Rules
- No social engineering of real developers; technical proofs in **lab** repos only.

## Trigger Conditions
- Dynamic tool registration from **untrusted** plugins.
- Observations from **browsing** attacker pages returned to planner verbatim.

## Technology Fingerprints
- OpenAI function calling, Anthropic tools, LangGraph, AutoGen-style loops.

## Recon Methodology
1. Trace **tool result → planner** path for HTML/escape issues.
2. Check **tool name** collisions and **shadowing**.
3. Review **approval** UI bypasses (auto-run).

## MCP Tool Orchestration Logic
- Static review + controlled **lab** agent run logs.

## Reasoning Heuristics
- **Second-order**: attacker updates tool description in a **shared** MCP package.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Malicious tool description causes destructive call |
| H2 | Poisoned observation triggers secret exfil tool |
| H3 | Dependency confusion on MCP package name |

## Validation Workflow
- Minimal agent transcript showing **unintended** tool call from poisoned input.

## False-Positive Reduction
- User **explicitly** approved destructive action—exclude.

## Stealth + OPSEC Guidance
- Pin MCP package versions; verify checksums.

## Replay Procedures
- Poison payload + transcript.

## Evidence Requirements
- Clear causal chain; remediation: sanitize observations, human gates.

## Confidence Scoring Logic
- Reliable unintended destructive action in lab: **0.9**.

## Adaptive Branching Logic
- **Browser tools** + untrusted web → dedicated browsing sandbox branch.

## Related Exploit Chains
- `skills/ai_security/mcp_abuse.md`

## Safety Boundaries
No real data destruction outside disposable environments.

## Output Artifact Requirements
`output/<target_slug>/ai/tools/` — `transcript_redacted.md`
