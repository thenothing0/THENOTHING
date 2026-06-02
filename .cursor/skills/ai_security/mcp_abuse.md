# Skill: MCP Abuse (Tool Plane)

## Metadata
| **id** | `ai_mcp_abuse` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/ai/mcp/` |

## Objective
Threat-model MCP servers (including `hydra-security`): overpowered tools, path traversal in file tools, unsafe env secrets, and repo-driven MCP config risks.

## Trigger Conditions
`.mcp.json`, auto-approve lists, tools wrapping shell/filesystem/network.

## Technology Fingerprints
Cursor MCP, stdio servers, multi-server graphs.

## Reasoning Heuristics
Least privilege per tool; repo `.mcp.json` from untrusted code executing in workspace.

## Exploit Hypotheses
Arbitrary file read/write; SSRF via fetch tool; malicious MCP package update.

## MCP Orchestration Logic
Meta-review of MCP schemas + `check_tools`; **no** hostile calls outside isolated VM proofs.

## Stealth Guidance
Redact secrets from config dumps stored in `evidence/`.

## Validation Workflow
Lab repro of unsafe path or policy gap; document blast radius.

## Evidence Requirements
Redacted config + tool schema excerpts.

## Adaptive Branching
Agent planners → `agent_manipulation.md`.

## Confidence Scoring
0.95 demonstrable arbitrary read in lab; theoretical misconfig lower.

## Replay Logic
Version-pinned package notes.

## Reporting Guidance
Split servers, sandbox roots, human approvals, secret scanning on MCP env.
