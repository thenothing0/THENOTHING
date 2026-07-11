# Commands & Entry Points

## Entry points

HYDRA has three entry points:

| Command | Module | Description |
|---------|--------|-------------|
| `hydra` | `control_center.run:main` | TUI (Textual-based interactive interface) |
| `hydra-engine` | `hydra.main:entry` | CLI engine (argparse-based) |
| `python -m hydra` | `hydra/__main__.py` | Same as `hydra-engine` |

## CLI flags (hydra-engine)

```
hydra-engine [OPTIONS]

Options:
  -t, --target TARGET         Target domain or URL
  -v, --verbose               Debug logging
  -w, --workflow WORKFLOW     Workflow template (default: quick_recon)
  --list-workflows            Show available workflows
  --check-tools               Check tool availability
  --install-tools             Auto-install missing tools
  --no-ai                     Disable AI features (tool-only mode)
  --output-dir DIR            Output directory
  --scope-url URL             Bug bounty program URL for scope
  --timeout SECONDS           Global timeout
  --budget N                  API call budget
  --llm-backend BACKEND       LLM backend (openai/anthropic)
  --llm-model MODEL           LLM model name
  --llm-base-url URL          Custom LLM API base URL
  --resume SESSION_ID         Resume a previous session
  --json-logs                 JSON structured logging output
```

## Workflows

```bash
# List all available workflows
hydra-engine --list-workflows
```

| Workflow | Use case |
|----------|----------|
| `quick_recon` | Fast passive reconnaissance (default) |
| `full_bounty` | Complete bug bounty assessment |
| `api_only` | API-focused security testing |
| `osint_recon` | OSINT-first reconnaissance |
| `full_auto` | Full autonomous pipeline |
| `cognitive_auto` | Cognitive autonomous campaign with reasoning loop |
| `bounty_hunt` | Autonomous bounty hunting with target discovery |
| `web3_audit` | Web3/blockchain security audit |
| `blackbox` | Black-box assessment |
| `code_review` | Source code security review |

## MCP server

```bash
# stdio transport (for Claude Code / Cursor / Cline)
python mcp_server.py

# SSE transport (remote / HTTP)
python mcp_server.py --transport sse --port 8900
```

## Examples

```bash
# Quick recon on a target
hydra-engine -t example.com

# Full bounty assessment with scope enforcement
hydra-engine -t example.com -w full_bounty --scope-url https://hackerone.com/example

# Cognitive autonomous campaign with verbose logging
hydra-engine -t example.com -w cognitive_auto -v

# Check which security tools are available
hydra-engine --check-tools

# JSON-formatted logs for production
hydra-engine -t example.com --json-logs
```
