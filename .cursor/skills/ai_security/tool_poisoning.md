# Skill: Tool Poisoning

## Metadata
| **id** | `ai_tool_poisoning` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ai/tools/` |

## Objective
Find poisoned tool metadata/descriptions or poisoned observations that steer agents toward destructive or exfiltrating tool sequences.

## Trigger Conditions
Dynamic tool registration; plugins from untrusted sources; HTML observations from browsing.

## Technology Fingerprints
Function-calling agents, MCP tool packages, browser-use loops.

## Reasoning Heuristics
Second-order: supply-chain update to MCP package; collision in tool names.

## Exploit Hypotheses
Malicious tool description causes delete/exfil; poisoned page steers browser tool.

## MCP Orchestration Logic
Static review + isolated lab agent transcript.

## Stealth Guidance
Disposable environments only for destructive proofs.

## Validation Workflow
Minimal transcript showing unintended tool call from poisoned input.

## Evidence Requirements
Redacted transcript + root cause class.

## Adaptive Branching
MCP server specifics → `mcp_abuse.md`.

## Confidence Scoring
0.9 unintended destructive tool call in lab.

## Replay Logic
Poison payload artifact + agent version.

## Reporting Guidance
Pin versions, verify checksums, sanitize observations, human gates.
