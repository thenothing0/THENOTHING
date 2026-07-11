# FAQ

## General

### What is HYDRA?

HYDRA is an autonomous AI security intelligence and orchestration platform for bug bounty hunting and penetration testing. It coordinates 239 MCP tools through a cognitive reasoning loop with 22 subsystems.

### Does HYDRA require AI/LLM access?

No. HYDRA operates fully offline by default. AI features (OpenAI, Anthropic) are optional enhancements installed via `pip install hydra-security[ai]`.

### What security tools does HYDRA need?

HYDRA works best on Kali Linux where tools are pre-installed. On other systems, run `python -m hydra --install-tools` to install Go-based tools. System tools (nmap, whatweb) need your package manager.

### Is HYDRA safe to run?

HYDRA enforces deny-by-default authorization. It will not test any target without an explicitly registered scope. Four absolute prohibitions (DoS, destructive actions, data exfiltration, social engineering) are enforced at all times.

## Usage

### How do I test a target?

1. Register the target's bug bounty scope
2. Run a workflow: `python -m hydra -t target.com -w quick_recon`
3. Review findings: `get_findings()`

### What's the difference between `hydra` and `hydra-engine`?

- `hydra` launches the TUI (Textual interactive interface)
- `hydra-engine` / `python -m hydra` launches the CLI engine with argparse flags

### How does the two-signal rule work?

A finding needs two independent confirmation signals before being promoted to "confirmed." For example, an XSS finding needs both response reflection AND DOM execution confirmation. Single-signal results are reported as "suspected."

### Can I use HYDRA with Claude Code?

Yes. HYDRA is designed as an MCP server. Add the config to `.mcp.json` and all 239 tools become available in Claude Code. See [MCP_INTEGRATION.md](MCP_INTEGRATION.md).

## Technical

### Why both `hydra/config.py` and `hydra/config/`?

Historical: `hydra/config.py` holds the original dataclass-based configuration. `hydra/config/` was added later for profile-based ConfigManager and SecretStore. The package re-exports symbols from both.

### Where is data stored?

- `wiki/` — canonical knowledge base (Markdown + YAML frontmatter)
- `data/` — derived SQLite stores (rebuildable from wiki)
- `output/` — tool output artifacts
- `logs/` — structured log files

### How do plugins work?

Plugins are declarative YAML files that extend the capability catalog. They are never executed directly — they declare capabilities, tools, and agents that the orchestration layer uses. See [PLUGINS.md](PLUGINS.md).

### What Python versions are supported?

Python 3.10, 3.11, 3.12, and 3.13. CI tests all four versions.
