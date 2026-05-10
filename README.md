<p align="center">
  <img src="https://img.shields.io/badge/HYDRA-v4.0-00ff88?style=for-the-badge&labelColor=000000" alt="HYDRA v4.0"/>
  <img src="https://img.shields.io/badge/Agents-50+-blueviolet?style=for-the-badge&labelColor=000000" alt="Agents"/>
  <img src="https://img.shields.io/badge/Tools-19-orange?style=for-the-badge&labelColor=000000" alt="Tools"/>
  <img src="https://img.shields.io/badge/Intel_Packs-11-ff6600?style=for-the-badge&labelColor=000000" alt="Packs"/>
  <img src="https://img.shields.io/badge/MCP_Servers-3-cyan?style=for-the-badge&labelColor=000000" alt="MCP"/>
  <img src="https://img.shields.io/badge/IDEs-7-ff69b4?style=for-the-badge&labelColor=000000" alt="IDEs"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&labelColor=000000" alt="License"/>
</p>

<h1 align="center">🐉 HYDRA v4.0</h1>
<h3 align="center">Next-Gen AI Security Orchestration Platform</h3>

<p align="center">
  <b>OSINT intelligence · Tech fingerprinting · Intelligence packs · Heuristic reasoning · Hallucination defense · Multi-agent swarm · Attack graphs · Semantic memory · 7 IDE support</b>
</p>

<p align="center">
  The most advanced open-source autonomous bug bounty & pentest orchestration platform.<br/>
  HYDRA deploys intelligent agent swarms that plan, hunt, validate, and report — with zero false positives.
</p>

---

## 🆕 What's New in v4.0

| Module | Description |
|--------|-------------|
| 🔍 **OSINT Intelligence** | Passive recon via crt.sh, Shodan, Censys, SecurityTrails, Wayback Machine, DNS/WHOIS |
| 🐙 **GitHub Intelligence** | Secret scanning (20+ patterns), endpoint extraction, employee-to-infra correlation |
| 🔬 **Tech Fingerprinting** | Wappalyzer-style detection — 80+ signatures across headers, HTML, cookies, meta tags |
| 📦 **Intelligence Packs** | 11 hot-loadable packs: WordPress, Next.js, GraphQL, AWS, Laravel, OAuth, K8s, Firebase, Supabase, Cloudflare, API Security |
| 🧠 **Heuristic Reasoning** | Bayesian vulnerability likelihood with tech-specific boosters for 15+ frameworks |
| 🛡️ **Hallucination Defense** | Evidence-first verification, contradiction detection, confidence scoring — blocks unsupported claims |
| 🕵️ **OSINT Swarm Agent** | Stateless agent handling 8 OSINT task types in the multi-agent architecture |
| 🚀 **New Workflows** | `osint_recon` (OSINT → fingerprint → targeted scan) and `full_auto` (complete autonomous pipeline) |

---

## ⚡ One-Command Install

```bash
# Linux / macOS
git clone https://github.com/thenothing0/HYDRA.git && cd HYDRA && ./setup.sh

# Windows (PowerShell)
git clone https://github.com/thenothing0/HYDRA.git; cd HYDRA; .\setup.ps1

# Docker (production)
docker compose up -d
```

---

## 🏗️ Architecture

```mermaid
graph TB
    subgraph IDE["🖥️ IDE Layer (7 IDEs)"]
        CC[Claude Code]
        CX[Codex]
        GM[Gemini]
        CR[Cursor]
        WS[Windsurf]
        CP[Copilot]
        OC[OpenClaw]
    end

    subgraph MCP["🔌 MCP Layer"]
        MTS["Tool Server — 19 security tools"]
        MBS["Bounty Server — H1 + BC + Intigriti"]
        MWS["Writeup RAG Server"]
    end

    subgraph BRAIN["🧠 HYDRA Brain"]
        PA["Strategic Planner — HTN"]
        CO["Coordinator — Orchestration"]
        CE["Consensus Engine — Voting"]
        HR["Heuristic Reasoning"]
        HD["Hallucination Defense"]
    end

    subgraph SWARM["🐝 Agent Swarm"]
        RA[Recon Agent]
        OA["OSINT Agent — NEW"]
        VR[Vuln Research]
        EH[Exploit Hypothesis]
        VA[Validation Agent]
        RP[Reporting Agent]
    end

    subgraph V4["🆕 v4 Intelligence Layer"]
        OSINT["OSINT Engine — crt.sh, Shodan, Wayback"]
        GH["GitHub Intel — Secrets + Endpoints"]
        FP["Tech Fingerprinter — 80+ signatures"]
        IP["Intelligence Packs — 11 built-in"]
    end

    subgraph INTEL["📊 Data Layer"]
        AG["Attack Graph — NetworkX"]
        SM["Semantic Memory — ChromaDB"]
        KG["Self-Learning — SQLite"]
        SC["Scope Intelligence — Policy Engine"]
    end

    IDE --> MCP
    MCP --> BRAIN
    PA --> CO
    CO --> SWARM
    SWARM --> V4
    SWARM --> MCP
    V4 --> BRAIN
    INTEL --> BRAIN
    HR --> PA
    FP --> IP
    IP --> HR
    HD --> RP
```

---

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.10+
pip install rich aiohttp

# Security tools (Go 1.20+ required)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

### CLI Mode
```bash
# Check which tools are installed
python -m hydra.main --check-tools

# List available workflows
python -m hydra.main --list-workflows

# ── v4 Workflows ──────────────────────────
# OSINT-first recon (passive intel → fingerprint → targeted scan)
python -m hydra.main -t example.com -w osint_recon

# Full autonomous (OSINT → fingerprint → heuristic scan → crawl → fuzz → validate)
python -m hydra.main -t example.com -w full_auto

# With scope enforcement from HackerOne/Bugcrowd
python -m hydra.main -t example.com -w full_auto --scope-url https://hackerone.com/example

# ── Classic Workflows ─────────────────────
# Quick recon (subdomains → probe → tech → nuclei)
python -m hydra.main -t example.com -w quick_recon

# Full bug bounty assessment
python -m hydra.main -t example.com -w full_bounty

# API-focused scan
python -m hydra.main -t api.example.com -w api_only

# Black-box aggressive recon
python -m hydra.main -t example.com -w blackbox
```

All outputs saved to `output/<target>/` → `recon/`, `osint/`, `scans/`, `reports/`, `evidence/`, `attack_graph/`, `logs/`

### Claude Code Mode
```bash
claude  # open Claude Code in the project folder

# Slash commands:
/recon example.com           # Full reconnaissance
/hunt example.com            # Autonomous vulnerability hunting
/autopilot example.com       # Full autonomous mode
/chain                       # Build exploit chains from findings
/report                      # Generate submission-ready report
/scope hackerone tesla       # Load scope from platform
```

---

## 📦 Project Structure

```
hydra/
├── main.py                        # 🚀 Entry Point (v4 engine)
├── config.py                      # ⚙️  Environment-driven Config
├── osint/                         # 🔍 OSINT Intelligence Layer (NEW)
│   ├── __init__.py                #     crt.sh, Shodan, Censys, DNS, Wayback
│   └── github_intel.py            #     GitHub secret scanning + endpoint extraction
├── fingerprint/                   # 🔬 Technology Fingerprinting (NEW)
│   └── __init__.py                #     80+ Wappalyzer-style signatures
├── packs/                         # 📦 Intelligence Packs (NEW)
│   └── __init__.py                #     11 built-in packs, hot-loadable
├── heuristics/                    # 🧠 Heuristic Reasoning (NEW)
│   └── __init__.py                #     Bayesian vulnerability likelihood
├── hallucination/                 # 🛡️ Hallucination Defense (NEW)
│   └── __init__.py                #     Evidence-first verification
├── planner/                       # 🧠 Strategic Planner + HTN
│   ├── planner_agent.py           #     Scope-driven plan generation
│   ├── task_decomposer.py         #     Goal → subtask decomposition
│   └── htn.py                     #     Hierarchical Task Network
├── swarm/                         # 🐝 Agent Swarm
│   ├── coordinator.py             #     Scan orchestration
│   ├── agent_factory.py           #     Dynamic agent spawning
│   ├── osint_agent.py             #     OSINT Intelligence Agent (NEW)
│   ├── base_agent.py              #     Stateless agent base class
│   └── specialized/               #     API, Web3, Mobile, Cloud agents
├── scope/                         # 🎯 Scope Intelligence Layer
├── graph/                         # 📊 Attack Graph + Scoring
├── memory/                        # 💾 Memory Bus + Semantic Memory
├── mcp/                           # 🔧 MCP Tool Server (19 tools)
├── consensus/                     # 🤝 Multi-Agent Consensus
├── validation/                    # ✅ Evidence-Based Validation
├── learning/                      # 🧠 Self-Learning Engine
├── sandbox/                       # 🔒 Security Sandbox
├── dashboard/                     # 📈 Real-Time Web Dashboard
├── queue/                         # 📦 Distributed Queue (Redis Streams)
├── hunt/                          # 🎯 Autonomous Hunt Loops
├── chains/                        # ⛓️  Exploit Chain Builder
├── reporting/                     # 📄 Advanced Reports
├── cost/                          # 💰 Cost & Token Management
├── ai/                            # 🤖 Multi-LLM Router
├── recovery/                      # 🔄 Workflow Recovery
├── observability/                 # 📊 Prometheus + Grafana
└── plugins/                       # 🔌 Plugin System
```

---

## 🧩 v4 Intelligence Layer

### 🔍 OSINT Intelligence Engine
Passive reconnaissance with zero active scanning:
- **crt.sh** — Certificate transparency subdomain discovery
- **Shodan** — Open ports, CVEs, SSL certificates
- **Censys** — Host and service discovery
- **SecurityTrails** — DNS history, WHOIS, subdomain enumeration
- **Wayback Machine** — Historical URL discovery with endpoint categorization
- **DNS/WHOIS** — IP resolution, ASN attribution, reverse DNS

### 🐙 GitHub Intelligence
Employee-to-infrastructure correlation chains:
- **20+ secret patterns** — AWS keys, GitHub tokens, Slack webhooks, JWTs, private keys, database URLs
- **Endpoint extraction** — API routes, GraphQL endpoints, webhooks from source code
- **Internal domain discovery** — staging/dev/internal subdomains leaked in repos
- **Employee correlation** — `employee → repository → secret → infrastructure → attack path`

### 🔬 Technology Fingerprinting
Wappalyzer-style detection with 80+ signatures:
- **Headers** — Server, X-Powered-By, CDN, WAF detection
- **HTML** — CMS, JS frameworks, analytics, auth systems
- **Cookies** — Framework detection (PHP, Rails, Django, Express)
- **Meta tags** — Generator-based CMS version extraction
- **Auto-triggers** intelligence pack activation based on detected stack

### 📦 Intelligence Packs (11 Built-in)
Hot-loadable, versioned attack intelligence:

| Pack | Exploit Hypotheses | Key Checks |
|------|-------------------|------------|
| **WordPress** | User enum, XML-RPC brute, plugin vulns | xmlrpc, wp-json, debug.log |
| **Next.js** | SSRF, auth bypass, env exposure | `__NEXT_DATA__`, API routes, source maps |
| **GraphQL** | IDOR, injection, DoS | Introspection, GraphiQL, depth limits |
| **AWS** | SSRF to metadata, S3 misconfig | 169.254.169.254, bucket perms |
| **Laravel** | Debug RCE, deserialization | .env, Telescope, Ignition |
| **OAuth** | Redirect steal, state bypass, scope escalation | redirect_uri, state param |
| **Kubernetes** | Unauth API, dashboard exposure | /api/v1, privileged pods |
| **API Security** | BOLA/IDOR, mass assignment, rate limit bypass | CORS, Swagger, auth endpoints |
| **Firebase** | Unauth read/write | .json endpoint, storage bucket |
| **Supabase** | RLS bypass, anon key exposure | PostgREST, service role key |
| **Cloudflare** | Origin IP leak, WAF bypass | DNS history, direct origin |

### 🧠 Heuristic Reasoning Engine
Bayesian vulnerability likelihood estimation:
- **Prior probabilities** from real-world bug bounty data
- **Technology boosters** — WordPress boosts XSS/SQLi/file upload likelihood; GraphQL boosts IDOR 1.8×
- **Adaptive decisions** — expand investigation on critical findings, reduce noise on low-value targets
- **WAF-aware scanning** — automatic stealth mode with delay and header randomization

### 🛡️ Hallucination Defense
No unsupported AI-generated claim appears in reports:
- **Evidence presence check** — requires tool output, matched_at, or registered evidence
- **Hallucination indicator scanning** — detects vague language ("likely", "possibly")
- **Contradiction detection** — flags "critical" + "low risk" in same finding
- **Multi-agent consensus** — aggregates verification across agents
- **Confidence scoring** — findings below threshold are filtered out

---

## 🧩 Core Components

### 🧠 Strategic Planner (HTN)
Generates adaptive, scope-aware execution plans using Hierarchical Task Network decomposition.
- Accepts scope intelligence directives (`DISABLE:`, `RATE_LIMIT:`, `FOCUS_API:`)
- Dynamically replans when critical findings emerge
- Intelligence pack workflows feed directly into plan generation

### 🐝 Agent Swarm + Dynamic Spawning
50+ specialized agents with on-the-fly spawning:
- **Core agents**: Recon, OSINT, Vuln Research, Exploit Hypothesis, Validation, Reporting
- **Specialized agents**: API, Web3, Mobile, Cloud — spawned dynamically
- **OSINT Agent** (v4): handles 8 task types — full OSINT, cert transparency, DNS intel, Wayback, Shodan, GitHub, employee intel, attack surface mapping

### 📊 Attack Graph Intelligence
NetworkX-based graph with risk propagation:
- **Scoring Engine**: CVSS-weighted risk scores
- **Blast Radius Estimation**: Impact propagation from any compromised node
- **Privilege Escalation Detection**: Multi-hop chain analysis
- **Visualization**: DOT, JSON, Cytoscape, interactive HTML export

### 🤝 Multi-Agent Consensus
Weighted voting eliminates false positives (<2% FP rate):
- Agent-type expertise weighting (validation > exploit > vuln_research > recon)
- Quorum requirements for severity levels
- Contradiction detection between agents

### 🎯 Scope Intelligence Layer
Mandatory pre-execution scope analysis:
- Platform adapters: **HackerOne**, **Bugcrowd**, **Intigriti**, Custom
- `--scope-url` CLI flag for automatic scope loading
- MCP layer blocks out-of-scope scans at every level

### ✅ Validation-First Reporting
No finding reported unless all checks pass:
- Evidence must exist (HTTP artifacts, screenshots, matched patterns)
- Reproduction path must be documented
- Hallucination defense check passes
- Rejected findings saved separately for audit

---

## 📋 Workflow Templates

| Workflow | Duration | Description |
|----------|----------|-------------|
| `osint_recon` | ~10 min | **NEW** — OSINT → fingerprint → pack activation → heuristic-guided scan |
| `full_auto` | ~40 min | **NEW** — Full autonomous: OSINT → fingerprint → crawl → deep scan → validate |
| `quick_recon` | ~5 min | Fast subdomain + tech + nuclei scan |
| `full_bounty` | ~30 min | Complete assessment with exploit chains |
| `api_only` | ~15 min | API endpoint discovery + auth testing |
| `blackbox` | ~25 min | Black-box testing without source code |
| `web3_audit` | ~20 min | Smart contract vulnerability analysis |
| `code_review` | ~15 min | Source code security review |

---

## ⚙️ Configuration

All configuration is environment-driven:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | | OpenAI API key |
| `ANTHROPIC_API_KEY` | | Anthropic API key |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama endpoint |
| `SHODAN_API_KEY` | | Shodan API key (OSINT) |
| `GITHUB_TOKEN` | | GitHub token (OSINT) |
| `ST_API_KEY` | | SecurityTrails API key |
| `CENSYS_ID` / `CENSYS_SECRET` | | Censys credentials |
| `REDIS_HOST` | `127.0.0.1` | Redis host |
| `HYDRA_MONTHLY_CAP` | `100` | Monthly AI budget (USD) |
| `HYDRA_RATE_LIMIT` | `50` | Max requests/second |
| `HYDRA_SANDBOX` | `true` | Enable sandbox |
| `HYDRA_DASHBOARD` | `true` | Enable dashboard |
| `HYDRA_QUEUE_MODE` | `local` | `local` or `distributed` |

> **Note**: OSINT API keys are optional. crt.sh, Wayback Machine, and DNS work without any keys.

---

## 🛡️ Safety Rules

1. **No scan without scope validation** — MCP layer blocks every out-of-scope target
2. **No finding without evidence** — validation-first filter rejects unsupported findings
3. **No hallucinated reports** — hallucination defense blocks vague/contradictory claims
4. **No uncontrolled execution** — all tools run through security sandbox + scope policy engine
5. **No budget overrun** — automatic model downgrading when thresholds hit
6. **No data loss** — workflow checkpointing ensures recovery from failures
7. **No unreproducible work** — all outputs auto-saved with timestamps and content hashes

---

## 🐋 Deployment

### Docker Compose (Recommended)
```bash
docker compose up -d
# Services: hydra, redis, chromadb, prometheus, grafana
# Dashboard: http://localhost:8080
```

### Kubernetes (Production)
```bash
kubectl apply -f k8s/manifests/
```

### Standalone
```bash
pip install -r requirements.txt
python -m hydra.main -t example.com -w full_auto
```

---

## 🧪 Tests

```bash
python -m pytest tests/ -v --tb=short
# 18 tests: consensus, planner, scope
```

---

## ⚠️ Legal Disclaimer

**HYDRA is designed for authorized security testing only.**

- Only test targets within approved bug bounty program scopes
- Always verify scope before scanning
- The scope enforcement engine will block out-of-scope targets, but **you are ultimately responsible**
- Unauthorized scanning is illegal and unethical

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. We welcome:
- New intelligence packs (add to `hydra/packs/`)
- OSINT data source integrations
- Tool integrations (add to `TOOL_REGISTRY`)
- Bug bounty platform adapters
- Fingerprint signatures

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Built for bug bounty hunters, by bug bounty hunters.</b><br/>
  <sub>HYDRA v4.0 — Next-Gen AI Security Orchestration Platform</sub>
</p>
