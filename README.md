# 🔥 HYDRA v2.0 — Autonomous AI Security Orchestration Platform

> **Multi-Agent Swarm • Strategic Planner • Attack Graph Intelligence • Semantic Memory •
> Consensus System • Scope Intelligence • Self-Learning • Production-Grade Infrastructure**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HYDRA v2.0 Architecture                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐    │
│  │   Planner    │──▶│  Coordinator │──▶│  Distributed Queue   │    │
│  │   Agent      │   │              │   │  (Redis Streams)     │    │
│  └──────┬───────┘   └──────┬───────┘   └──────────┬───────────┘    │
│         │                  │                       │               │
│  ┌──────▼───────┐   ┌──────▼───────┐   ┌──────────▼───────────┐    │
│  │   Attack     │   │  Consensus   │   │   Worker Agents      │    │
│  │   Graph +    │   │  Engine      │   │  ┌─────┐ ┌────────┐  │    │
│  │   Scoring    │   │  (Voting)    │   │  │Recon│ │VulnScan│  │    │
│  └──────┬───────┘   └──────────────┘   │  └─────┘ └────────┘  │    │
│         │                              │  ┌─────┐ ┌────────┐  │    │
│  ┌──────▼───────┐   ┌──────────────┐   │  │Hypo │ │Validate│  │    │
│  │  Semantic    │   │  Cost/Token  │   │  └─────┘ └────────┘  │    │
│  │  Memory      │   │  Manager    │   │  ┌─────┐              │    │
│  │  (ChromaDB)  │   │  + Budget   │   │  │Report│             │    │
│  └──────────────┘   └──────────────┘   │  └─────┘              │    │
│                                        └───────────────────────┘    │
│  ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐    │
│  │  Security    │   │  Workflow    │   │   Observability       │    │
│  │  Sandbox     │   │  Recovery    │   │  Prometheus + Grafana │    │
│  └──────────────┘   └──────────────┘   └───────────────────────┘    │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐    │
│  │  HackerOne   │   │  Plugin      │   │   Real-Time           │    │
│  │  Scope Intel │   │  System      │   │   Dashboard           │    │
│  └──────────────┘   └──────────────┘   └───────────────────────┘    │
│                                                                     │
│  ╔══════════════════════════════════════════════════════════════╗    │
│  ║  MCP Tool Server — Real subprocess execution ONLY           ║    │
│  ║  subfinder | amass | httpx | nuclei | ffuf | katana | nmap  ║    │
│  ╚══════════════════════════════════════════════════════════════╝    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# 1. Clone and enter
git clone <repo> && cd newpro

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env with your API keys

# 4. Run a scan
python -m hydra.main -t example.com --workflow full_assessment

# 5. With dashboard
python -m hydra.main -t example.com --dashboard

# 6. With scope enforcement
python -m hydra.main -t example.com --scope-file scope.json --platform hackerone
```

### Docker Deployment
```bash
docker compose up -d
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/manifests/hydra.yaml
```

---

## 📦 Project Structure

```
hydra/
├── config.py                    # Central configuration (env-driven)
├── main.py                      # Entry point — wires all subsystems
├── planner/                     # 🧠 Strategic Planner Agent
│   ├── planner_agent.py         #   Adaptive planning & replanning
│   └── task_decomposer.py       #   Goal → subtask decomposition
├── graph/                       # 🕸️ Attack Graph Intelligence
│   ├── engine.py                #   Graph construction & querying
│   ├── scoring.py               #   Risk propagation & blast radius
│   └── visualization.py         #   DOT, JSON, HTML export
├── queue/                       # 📬 Distributed Task Queue
│   ├── distributed_queue.py     #   Redis Streams + deduplication
│   └── worker_manager.py        #   Heartbeats & failover
├── memory/                      # 💾 Memory Layer
│   ├── bus.py                   #   Redis-backed message bus
│   └── semantic.py              #   Vector DB (ChromaDB) integration
├── consensus/                   # 🤝 Multi-Agent Consensus
│   └── __init__.py              #   Voting, confidence fusion
├── validation/                  # ✅ Advanced Validation
│   └── __init__.py              #   HTTP replay, evidence collection
├── sandbox/                     # 🔒 Security Sandbox
│   └── __init__.py              #   Scope enforcement, rate limiting
├── cost/                        # 💰 Cost & Token Management
│   └── __init__.py              #   Budget enforcement, model routing
├── ai/                          # 🤖 AI Layer
│   ├── router.py                #   Multi-LLM intelligent routing
│   ├── parallel.py              #   Parallel model reasoning
│   └── safety.py                #   Hallucination defense
├── recovery/                    # 🔄 Workflow Recovery
│   └── __init__.py              #   Checkpointing, auto-retry
├── observability/               # 📊 Observability Stack
│   └── __init__.py              #   Prometheus, tracing, health
├── reporting/                   # 📄 Advanced Reports
│   └── __init__.py              #   CVSS, CWE, MITRE ATT&CK
├── dashboard/                   # 📈 Real-Time Dashboard
│   └── __init__.py              #   FastAPI + WebSocket
├── plugins/                     # 🔌 Plugin System
│   └── __init__.py              #   Hot-loadable extensions
├── scope/                       # 🎯 Scope Intelligence
│   └── __init__.py              #   HackerOne/Bugcrowd adapters
├── recon/                       # 🔍 Advanced Reconnaissance
│   └── __init__.py              #   ASN, GitHub, JS, params
├── learning/                    # 🧠 Self-Learning
│   ├── engine.py                #   Feedback-driven learning
│   └── knowledge_graph.py       #   Methodology correlation
├── swarm/                       # 🐝 Agent Swarm
│   ├── coordinator.py           #   Scan orchestration
│   ├── base_agent.py            #   Agent contract
│   ├── recon_agent.py           #   Asset discovery
│   ├── vuln_research_agent.py   #   Vulnerability scanning
│   ├── exploit_hypothesis_agent.py  # Attack chain generation
│   ├── validation_agent.py      #   False positive filtering
│   └── reporting_agent.py       #   Report generation
├── mcp/                         # 🔧 MCP Tool Server
│   ├── tool_server.py           #   Real subprocess execution
│   ├── client.py                #   Tool invocation client
│   └── http_server.py           #   HTTP bridge
└── bootstrap/                   # 📦 Setup & Installation
    └── installer.py             #   Tool auto-installer
```

---

## 🧩 Components

### 1. Planner Agent (NEW)
Strategic planning above the Coordinator. Generates adaptive workflows from templates (`full_assessment`, `quick_scan`, `api_assessment`), dynamically replans when critical findings emerge, and injects investigation steps.

### 2. Attack Graph Intelligence
NetworkX-based attack graph with:
- **Scoring Engine**: Risk propagation, blast radius estimation
- **Privilege Escalation Detection**: Chain analysis
- **Visualization**: DOT, JSON, Cytoscape, interactive HTML

### 3. Distributed Task Queue
Redis Streams backend with:
- Task deduplication via content hashing
- Dead letter queue for failed tasks
- Task leasing with expiration
- Priority ordering

### 4. Semantic Memory
ChromaDB vector database for:
- Similarity search across historical findings
- Attack chain pattern matching
- Methodology retrieval
- False positive pattern detection

### 5. Multi-Agent Consensus
Weighted voting system where agents rate findings:
- Agent-type expertise weighting
- Quorum requirements
- Contradiction detection
- Confidence fusion

### 6. Advanced Validation Engine
Every finding requires:
- HTTP replay verification
- Evidence collection
- Reproducibility proof
- Impact scoring
- CVSS/CWE/MITRE mapping

### 7. Security Sandbox
Mandatory for all tool execution:
- Command allowlisting
- Target scope enforcement
- Token-bucket rate limiting
- Concurrent tool limits

### 8. Cost & Token Management
- Per-scan, daily, monthly budget caps
- Automatic model downgrading (premium → economy → local)
- Usage analytics per provider/task

### 9. Parallel Model Reasoning
- Same prompt → multiple LLMs simultaneously
- Consensus analysis across outputs
- Hallucination risk detection
- Best-response selection

### 10. AI Safety / Hallucination Defense
- Required field validation
- Hallucination language detection
- Evidence-backed claims only
- No finding without proof

### 11. Workflow Recovery
- Automatic checkpointing
- Failure classification (transient vs permanent)
- Exponential backoff retry
- Degraded operation mode

### 12. Observability Stack
- Prometheus metrics export
- Distributed tracing
- Health monitoring
- Grafana dashboards

### 13. Advanced Report Generation
- CVSS 3.1 scoring
- CWE classification
- MITRE ATT&CK mapping
- Markdown, HTML, JSON output

### 14. Real-Time Dashboard
FastAPI + WebSocket backend with embedded UI:
- Live scan progress
- Agent activity feed
- Queue depth monitoring
- Finding timeline

### 15. Plugin System
- Python module hot-loading
- Tool, Agent, and Integration plugin types
- Plugin registry with discovery

### 16. Scope Intelligence (HackerOne)
- Platform adapters (HackerOne, Bugcrowd, custom)
- Scope policy engine
- Pre-scan intelligence reports
- Program memory (learns per-program patterns)

### 17. Advanced Reconnaissance
- ASN mapping
- GitHub leak scanning
- JavaScript endpoint extraction
- Parameter mining
- CDN detection
- DNS history

### 18. Knowledge Graph
SQLite-backed learning correlation:
- Workflow outcome tracking
- Tool sequence effectiveness
- Exploit pattern validation
- Target profiling

### 19. Kubernetes Deployment
- Full K8s manifests
- Horizontal Pod Autoscaler
- Secret management
- Prometheus + Grafana stack

---

## ⚙️ Configuration

All configuration is environment-driven. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | | OpenAI API key |
| `ANTHROPIC_API_KEY` | | Anthropic API key |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama endpoint |
| `REDIS_HOST` | `127.0.0.1` | Redis host |
| `HYDRA_MONTHLY_CAP` | `100` | Monthly AI budget (USD) |
| `HYDRA_DAILY_CAP` | `10` | Daily AI budget (USD) |
| `HYDRA_SCAN_CAP` | `5` | Per-scan AI budget (USD) |
| `HYDRA_RATE_LIMIT` | `50` | Max requests/second |
| `HYDRA_SANDBOX` | `true` | Enable sandbox |
| `HYDRA_DASHBOARD` | `true` | Enable dashboard |
| `HYDRA_CONSENSUS` | `true` | Enable consensus |
| `HYDRA_QUEUE_MODE` | `local` | `local` or `distributed` |
| `DASHBOARD_PORT` | `8080` | Dashboard port |

---

## 🛡️ Safety Rules

1. **No scan without scope validation** — all targets are checked against loaded scope
2. **No finding without evidence** — hallucination defense rejects unsupported claims
3. **No uncontrolled execution** — all tools run through the security sandbox
4. **No budget overrun** — automatic model downgrading when thresholds hit
5. **No data loss** — workflow checkpointing ensures recovery from failures

---

## 📊 CLI Usage

```bash
# Full assessment with dashboard
python -m hydra.main -t example.com --dashboard --workflow full_assessment

# Quick scan with budget limit
python -m hydra.main -t example.com --workflow quick_scan --budget 2.0

# API-focused assessment
python -m hydra.main -t api.example.com --workflow api_assessment

# Scope-enforced scan
python -m hydra.main -t example.com --scope-file scope.json --platform hackerone --program example

# MCP server only (for Claude Code integration)
python -m hydra.main -t example.com --mcp-only --mcp-port 8900

# Check tool availability
python -m hydra.main -t example.com --check-tools

# Auto-install missing tools
python -m hydra.main -t example.com --install-tools
```

---

## License

MIT
