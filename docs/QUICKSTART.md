# Quick Start

Get from zero to your first recon in 5 minutes.

## 1. Install

```bash
git clone https://github.com/thenothing-sec/hydra.git
cd hydra
pip install -e .
```

## 2. Register your scope

HYDRA enforces deny-by-default authorization. Register your bug bounty program first:

```python
# Via MCP tool
register_bounty_program(
    program="acme",
    platform="hackerone",
    in_scope="*.acme.com, app.acme.io"
)
```

Or load scope directly from the program page:

```python
load_bounty_scope(url="https://hackerone.com/acme")
```

## 3. Run reconnaissance

```bash
# Quick passive recon
python -m hydra -t acme.com -w quick_recon

# Full bounty assessment
python -m hydra -t acme.com -w full_bounty

# Cognitive autonomous campaign
python -m hydra -t acme.com -w cognitive_auto
```

## 4. Use the MCP server

Start the MCP server for Claude Code / Cursor / Cline integration:

```bash
python mcp_server.py
```

Then use any of the 239 MCP tools. See [MCP_TOOLS.md](MCP_TOOLS.md) for the full catalog.

## 5. View findings

```python
# List findings
get_findings(severity="high")

# Generate report
generate_report(target="acme.com", findings_json="[...]")
```

## 6. Launch the TUI

```bash
hydra
```

## Available workflows

| Workflow | Description |
|----------|-------------|
| `quick_recon` | Fast passive reconnaissance |
| `full_bounty` | Full bug bounty assessment |
| `api_only` | API-focused testing |
| `osint_recon` | OSINT-first reconnaissance |
| `full_auto` | Full autonomous pipeline |
| `cognitive_auto` | Cognitive autonomous campaign |
| `bounty_hunt` | Autonomous bounty hunting |
| `web3_audit` | Web3/blockchain audit |
| `blackbox` | Black-box assessment |
| `code_review` | Source code review |

## Next steps

- [Configuration](CONFIGURATION.md) — environment variables and profiles
- [Commands](COMMANDS.md) — CLI flags and entry points
- [MCP Integration](MCP_INTEGRATION.md) — IDE setup
- [Architecture](ARCHITECTURE.md) — system design
