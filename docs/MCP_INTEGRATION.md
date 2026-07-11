# MCP Integration

HYDRA exposes 239 tools via the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP). This enables integration with Claude Code, Cursor, Cline, and other MCP-compatible clients.

## Server setup

### stdio transport (default)

```bash
python mcp_server.py
```

### SSE transport (remote)

```bash
python mcp_server.py --transport sse --port 8900
```

## Client configuration

### Claude Code (project)

File: `.mcp.json` (auto-loaded)

```json
{
  "mcpServers": {
    "hydra-security": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/hydra"
    }
  }
}
```

### Cursor

File: `.cursor/mcp.json` (auto-loaded)

```json
{
  "mcpServers": {
    "hydra-security": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/hydra"
    }
  }
}
```

### Cline

File: `cline_mcp_settings.json` (manual import)

```json
{
  "mcpServers": {
    "hydra-security": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/hydra"
    }
  }
}
```

### Windows

If `python` is not on PATH, use `py`:

```json
{
  "command": "py",
  "args": ["-3", "mcp_server.py"]
}
```

## Tool catalog

See [MCP_TOOLS.md](MCP_TOOLS.md) for the complete catalog of 239 tools with exact names and one-line descriptions.

Tools are **deferred / search-loaded** — schemas load on demand per agent. You can invoke any tool by name without having all schemas in context.

## Tool categories

- **Attack section** — gated PoC-only scanning, injection testing, API Top 10, auth protocols
- **Recon & surface** — subfinder, amass, httpx, katana, gau, hakrawler, dnsx, subzy
- **Post-exploitation** — gated AD/SMB/credential enumeration (impact demonstration)
- **General execution** — `shell_exec` (curl-first, any Kali tool)
- **Browser & Burp** — Playwright crawling, Burp capture store
- **Vulnerability scanning** — nuclei, sqlmap, dalfox, gxss
- **Fuzzing** — ffuf, dirsearch
- **Knowledge OS** — Phases A–U intelligence system
- **Engagement** — findings lifecycle, coverage, RBAC, reporting

## Authorization

All active testing tools enforce deny-by-default authorization:

```python
# Register scope first
register_bounty_program(program="acme", platform="hackerone", in_scope="*.acme.com")

# Then authorize before any active action
authorize_target(target="https://app.acme.com", action="vulnerability_scan")
```
