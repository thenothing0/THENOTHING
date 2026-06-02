# Skill: Agent Manipulation

## Metadata
| **id** | `ai_agent_manipulation` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ai/agent/` |

## Objective
Evaluate planner/executor loops for goal hijack, observation injection, and unsafe auto-run policies—lab only.

## Trigger Conditions
Multi-step agents with web access, file write, shell, or send-email tools.

## Technology Fingerprints
Cursor Agent mode patterns, autonomous chains, auto-approve tool lists.

## Reasoning Heuristics
Control of intermediate observations = control of next tool args; check approval UX bypass.

## Exploit Hypotheses
Goal hijack via malicious doc in workspace; indirect injection via fetched HTML; tool argument injection.

## MCP Orchestration Logic
Review agent config + tool allowlist; reproduce with benign harmful intent blocked by policy.

## Stealth Guidance
No real user social engineering; no external spam.

## Validation Workflow
Controlled lab repo with poisoned `README` or fetched page; capture planner decisions redacted.

## Evidence Requirements
Transcript + policy recommendation.

## Adaptive Branching
MCP tools involved → `mcp_abuse.md`.

## Confidence Scoring
0.85 reliable hijack to unsafe tool in lab with auto-approve misconfig.

## Replay Logic
Workspace file list + prompt sequence.

## Reporting Guidance
Narrow auto-approve, sandbox filesystem, separate read/write servers, human confirmation steps.
