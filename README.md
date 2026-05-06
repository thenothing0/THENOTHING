# 🔥 HYDRA — AI Bug Bounty Operating System

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗                               ║
║  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗                              ║
║  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║                               ║
║  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║                               ║
║  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║                               ║
║  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                            ║
║                                                                           ║
║  Next-Generation Multi-Agent AI Bug Bounty Operating System               ║
║  Claude Code + MCP Tools • Self-Learning • Plug-and-Play                  ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

## 🚀 Quick Start with Claude Code

This is how you use HYDRA — like the NahamSec approach. Claude Code becomes your AI bug bounty agent with full access to real security tools.

### Step 1: Install Dependencies

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File setup.ps1

# Linux/macOS
chmod +x setup.sh && ./setup.sh
```

### Step 2: Install MCP SDK

```bash
pip install "mcp[cli]"
```

### Step 3: Launch Claude Code in the HYDRA directory

```bash
cd newpro
claude
```

That's it! Claude Code auto-detects the `.mcp.json` config and loads the HYDRA security tools. The `CLAUDE.md` file gives Claude the bug bounty hunting methodology.

### Step 4: Start Hunting

In Claude Code, just say:

```
Run full recon on target.com
```

Or be more specific:

```
Scan target.com for vulnerabilities. Start with subdomain enumeration,
then probe for live hosts, run nuclei with high and critical severity,
and generate a report.
```

---

## 📋 How It Works

```
┌──────────────────────────────────────────────────────────────┐
│                      Claude Code                             │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  CLAUDE.md (agent instructions + methodology)          │  │
│  │  Skills (recon, vuln hunting, reporting, etc.)          │  │
│  └───────────────────────┬────────────────────────────────┘  │
│                          │ MCP Protocol (stdio)              │
│  ┌───────────────────────▼────────────────────────────────┐  │
│  │  mcp_server.py (HYDRA MCP Server)                      │  │
│  │  ┌──────┐ ┌──────┐ ┌───────┐ ┌──────┐ ┌──────┐       │  │
│  │  │subfnd│ │httpx │ │nuclei │ │ ffuf │ │amass │  ...   │  │
│  │  └──────┘ └──────┘ └───────┘ └──────┘ └──────┘       │  │
│  │  All tools run as REAL subprocesses                    │  │
│  └────────────────────────────────────────────────────────┘  │
│                          │                                    │
│  ┌───────────────────────▼────────────────────────────────┐  │
│  │  Knowledge Base (SQLite) + Reports (JSON/Markdown)     │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Available MCP Tools

Claude Code has access to these **real security tools** as callable skills:

| Tool | Function | What It Does |
|------|----------|-------------|
| `subfinder_scan` | Recon | Fast passive subdomain enumeration |
| `amass_enum` | Recon | Deep DNS enumeration (passive/active) |
| `httpx_probe` | Recon | Probe hosts for live HTTP services |
| `katana_crawl` | Recon | Crawl websites to discover endpoints |
| `gau_urls` | Recon | Get historical URLs (Wayback, etc.) |
| `nuclei_scan` | Vuln Scan | Template-based vulnerability scanner |
| `nuclei_scan_list` | Vuln Scan | Scan multiple targets at once |
| `ffuf_fuzz` | Fuzzing | Fast web fuzzer (dirs, params, etc.) |
| `dirsearch_scan` | Fuzzing | Directory brute-force scanner |
| `whatweb_detect` | Fingerprint | Detect CMS, frameworks, tech stack |
| `wafw00f_detect` | Fingerprint | Detect Web Application Firewalls |
| `nmap_scan` | Network | Port scanning & service detection |
| `full_recon` | Workflow | Complete recon pipeline (all-in-one) |
| `check_tools` | Utility | Verify installed tools |
| `save_finding` | Knowledge | Save findings to knowledge base |
| `get_findings` | Knowledge | Retrieve past findings |
| `generate_report` | Reporting | Generate structured reports |

---

## 📖 Skills (Reusable Methodologies)

Skills are `.md` files in the `skills/` directory that define specific hunting methodologies:

| Skill | File | Purpose |
|-------|------|---------|
| Recon Pipeline | `skills/recon_pipeline.md` | Full recon methodology |
| Vuln Hunting | `skills/vuln_hunting.md` | Systematic vulnerability scanning |
| Report Writer | `skills/report_writer.md` | Professional bug bounty reports |
| Blind XSS | `skills/blind_xss_hunter.md` | Blind XSS hunting methodology |
| API Security | `skills/api_security.md` | API vulnerability testing |

### Creating Custom Skills

Add a new `.md` file to `skills/` with your methodology. Claude Code will use it:

```markdown
# Skill: My Custom Methodology

## Steps
1. First, run `subfinder_scan` on the target
2. Then check for specific vulnerability...
```

---

## 🔧 Manual MCP Registration

If auto-detection doesn't work, register manually:

```bash
# Add the HYDRA MCP server to Claude Code
claude mcp add hydra-security python mcp_server.py
```

Or add to your Claude settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "hydra-security": {
      "command": "python",
      "args": ["/full/path/to/newpro/mcp_server.py"]
    }
  }
}
```

Verify it's working:
```bash
claude mcp list
```

---

## 🐳 Docker Deployment (Standalone Mode)

For running HYDRA as a standalone multi-agent system (without Claude Code):

```bash
docker compose up
```

Scale workers:
```bash
docker compose up --scale worker=5
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

Key settings:
- `OPENAI_API_KEY` — For AI-powered analysis (optional with Claude Code)
- `ANTHROPIC_API_KEY` — For Claude API access (optional with Claude Code)
- `OLLAMA_URL` — Local LLM for offline operation
- `SHODAN_API_KEY` — Enhanced recon capabilities

---

## 📁 Project Structure

```
newpro/
├── mcp_server.py           ← MCP server for Claude Code (MAIN ENTRY)
├── CLAUDE.md               ← Agent instructions for Claude Code
├── .mcp.json               ← MCP server auto-registration config
├── setup.ps1               ← Windows setup script
├── setup.sh                ← Linux/macOS setup script
├── requirements.txt        ← Python dependencies
├── .env.example            ← Configuration template
│
├── skills/                 ← Reusable hunting methodologies
│   ├── recon_pipeline.md
│   ├── vuln_hunting.md
│   ├── report_writer.md
│   ├── blind_xss_hunter.md
│   └── api_security.md
│
├── hydra/                  ← Core platform (standalone mode)
│   ├── config.py           ← Central configuration
│   ├── main.py             ← Standalone entry point
│   ├── swarm/              ← Multi-agent swarm
│   ├── mcp/                ← MCP tool execution layer
│   ├── ai/                 ← Multi-LLM routing
│   ├── memory/             ← Redis-backed message bus
│   ├── learning/           ← Self-learning engine
│   ├── graph/              ← Attack graph intelligence
│   └── bootstrap/          ← Auto-installer
│
├── docker-compose.yml      ← One-command Docker deployment
├── Dockerfile              ← Multi-stage build with all tools
├── wordlists/              ← Fuzzing wordlists
├── results/                ← Scan results
└── reports/                ← Generated reports
```

---

## 🎯 Example Prompts for Claude Code

```
# Basic recon
Run full recon on target.com and summarize the attack surface

# Vulnerability scan
Scan https://app.target.com for vulnerabilities using nuclei
with high and critical severity

# Focused hunting
Check target.com for subdomain takeover vulnerabilities

# API testing
Find and test all API endpoints on api.target.com

# Technology specific
target.com runs WordPress — find WordPress-specific vulnerabilities

# Full engagement
Perform a complete security assessment of target.com:
enumerate subdomains, find live hosts, scan for vulnerabilities,
check for misconfigurations, and generate a full bug bounty report
```

## License

MIT
