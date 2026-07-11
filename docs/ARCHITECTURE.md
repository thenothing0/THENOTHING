# Architecture

## System layers

```
┌─────────────────────────────────────────────────┐
│  Entry Points: TUI (hydra) · CLI (hydra-engine) │
│  MCP Server (mcp_server.py — 239 tools)         │
├─────────────────────────────────────────────────┤
│  Cognitive Loop (9-phase reasoning)             │
│  Observe → Understand → Reason → Simulate →     │
│  Plan → Execute → Validate → Learn → Replan     │
├─────────────────────────────────────────────────┤
│  22 Cognitive Subsystems                         │
│  World Model · Causal Reasoning · Simulation ·   │
│  Stealth · Debate · Payload · Chain Builder ·    │
│  Bounty Hunter · Profiles · Guardrails · ...     │
├─────────────────────────────────────────────────┤
│  Services Layer (ServiceContainer + EventBus)    │
│  35 services: system, network, scanner,          │
│  reporting, swarm, monitor, ...                  │
├─────────────────────────────────────────────────┤
│  Knowledge OS (Phases A–U)                       │
│  Wiki-as-truth · Confidence bands · Two-signal · │
│  Source/verification learning · Federation       │
├─────────────────────────────────────────────────┤
│  Tool Layer                                      │
│  Kali binaries · MCP tools · Adapters · Skills   │
└─────────────────────────────────────────────────┘
```

## Core principles

### Offline-first

All data is stored locally. No external services are required for core operation. Redis, PostgreSQL, and AI providers are optional enhancements.

### Wiki-as-truth

The canonical knowledge base lives in `wiki/` as Markdown files with YAML frontmatter. All derived stores (SQLite DBs under `data/`) are rebuildable from the wiki. See `wiki/SCHEMA.md`.

### Two-signal rule

A finding is only promoted to "confirmed" when supported by two independent signals (e.g., reflection + DOM execution, or two different tool confirmations). Single-signal results are reported as "suspected."

### Deny-by-default authorization

All active testing requires explicit authorization via a registered bug bounty program scope. The `authorize_target` gate must be called before any active action. Four absolute prohibitions (DoS, destructive, exfiltration, social engineering) are never permitted.

### Capability-first tool model

Tools are organized by capability (e.g., `discover_subdomains`), not by tool name. Multiple tools can fulfill the same capability. The learning system ranks tools by effectiveness and selects the best one automatically.

## Key subsystems

See [HYDRA_SYSTEM_CONTEXT.md](HYDRA_SYSTEM_CONTEXT.md) for the full system context document.

## Data flow

```
Target → Scope Gate → Passive Recon → Correlation → Hypothesis Generation
  → Simulation → Active Testing (gated) → Two-Signal Validation
  → Finding → Evidence Collection → Report
```

## Directory structure

```
hydra/                  # Core Python package
  ai/                   # AI provider integration
  capabilities/         # Capability catalog
  cognitive/            # Cognitive loop engine
  commands/             # Command registry and dispatcher
  config/               # Configuration management
  knowledge/            # Knowledge OS phases
  learning/             # Continuous learning system
  mcp/                  # MCP tool server
  observability/        # Logging, telemetry, health
  plugins/              # Plugin system
  recon_fusion/         # Reconnaissance fusion
  services/             # Service container
  skills/               # Skill registry
  threat_intel/         # Threat intelligence
  ...
control_center/         # TUI application
wiki/                   # Canonical knowledge base
data/                   # Derived stores (SQLite)
docs/                   # Documentation
tests/                  # Test suite
skills/                 # YAML skill definitions
```
