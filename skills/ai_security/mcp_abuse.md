# Skill: MCP Abuse & Tool Plane Threat Modeling

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `mcp_abuse` |
| **version** | `1.0.0` |
| **category** | AI Security / MCP |
| **correlates_with** | Prompt injection, IDE agents, supply chain, path traversal |

## Objective
Analyze **MCP server** trust: **overpowered tools**, **path traversal** in file tools, **credential** exposure in env, and **prompt-driven** tool invocation chains. Applies to **custom** MCP servers (e.g. `hydra-security`) and third-party servers in the IDE.

## Scope Rules
- Test only **local** developer machines you own or **lab** VMs.
- Do not use MCP tools to attack **third-party** systems.

## Trigger Conditions
- MCP servers with `run_terminal_cmd`, unrestricted `read_file` roots, or network exfil tools callable by the model.

## Technology Fingerprints
- Cursor/Claude Code MCP configs (`.mcp.json`), stdio servers, SSE servers.

## Recon Methodology
1. Inventory **each tool** schema and **filesystem** roots.
2. Review **env** vars passed to MCP process for secrets.
3. Model **agent** policies: auto-approve lists (dangerous if broad).

## MCP Tool Orchestration Logic
- Meta: use **documented** `check_tools` style probes if present; otherwise static config review dominates.

## Reasoning Heuristics
- **Least privilege** per tool; separate read vs write servers.
- **Prompt injection** in repo can steer agent to call dangerous MCP tools—pair skills.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Malicious repo `.mcp.json` instructs harmful server |
| H2 | Tool accepts arbitrary paths → read `/etc/passwd` |
| H3 | SSRF via fetch tool without allowlist |

## Validation Workflow
1. Attempt **benign** path outside allowed root in **lab**.
2. Confirm policy blocks or allow.

## False-Positive Reduction
- Expected powerful tools in **local** pentest MCP—risk is **context** (untrusted repo).

## Stealth + OPSEC Guidance
- Keep MCP configs out of public dotfiles with secrets.

## Replay Procedures
- Config JSON + tool schema excerpt.

## Evidence Requirements
- Threat model + repro in isolated VM.

## Reporting Methodology
- Split servers, path sandboxing, human approval gates, secret scanning on MCP env.

## Confidence Scoring Logic
- Demonstrable arbitrary file read via MCP tool: **0.95** in lab.

## Adaptive Branching Logic
- **Multi-server** graphs → composite risk scoring.

## Related Exploit Chains
- `skills/ai_security/tool_poisoning.md`

## Safety Boundaries
No weaponizing MCP against others.

## Output Artifact Requirements
`output/<target_slug>/ai/mcp/` — `threat_model.md`, `config_redacted.json`
