# Changelog

All notable changes to HYDRA are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-28

### Added

- **Python packaging** — PEP 517/518 compliant `pyproject.toml` with `hydra-security` distribution name
- **Entry points** — `hydra` (TUI), `hydra-engine` (CLI), `python -m hydra` support
- **Optional extras** — `dev`, `ai`, `dashboard`, `vector`, `browser`, `docs`, `all`
- **Docker hardening** — non-root user, HEALTHCHECK, OCI labels, slim target
- **CI/CD** — build validation job in CI, tag-triggered release workflow
- **Documentation suite** — INSTALL, QUICKSTART, CONFIGURATION, COMMANDS, ARCHITECTURE, PLUGINS, MCP_INTEGRATION, TROUBLESHOOTING, FAQ
- **Developer tooling** — Makefile, smoke test script, release checklist
- **Stage 1: Code Quality** — import hygiene, dead-code removal, type annotations on public APIs
- **Stage 2: Performance** — lazy imports, connection pooling, startup benchmarks
- **Stage 3: Observability** — structured logging, telemetry, crash diagnostics, health registry, resource monitor
- **Knowledge OS (Phases A–U)** — 22-phase offline-first intelligence system with 239 MCP tools
- **22 cognitive subsystems** — autonomous reasoning loop, world model, simulation, stealth, debate engine
- **10 workflow templates** — quick_recon, full_bounty, api_only, cognitive_auto, bounty_hunt, and more
- **10 researcher profiles** — dynamic persona switching for adaptive testing
- **Attack section** — two-signal differential scanning, API Top 10, OAuth/SAML, stored/OOB, campaign orchestration
- **Post-exploitation tooling** — gated, PoC-only AD/SMB/credential impact demonstration
- **Burp integration** — capture store, site-map import, scanner issue promotion, repeater
- **4-tier learning system** — project → personal → cross → org with poison-gate quarantine
- **Signed skill registry** — declarative skills with SemVer dependency resolution
- **Risk-tiered HITL** — low/medium/high/critical approval tiers with operator mode
- **Multi-client engagements** — RBAC, finding lifecycle, coverage tracking, SARIF/MD/JSON export
- **Federation** — peer digest exchange, consensus scoring, ecosystem opportunities

### Fixed

- `hydra/config.py` module shadowed by `hydra/config/` package — added re-exports to bridge

### Security

- Deny-by-default authorization gate on all active testing
- Four absolute prohibitions enforced: no DoS, no destructive actions, no data exfiltration, no social engineering
- Catastrophic-command denylist in `shell_exec` (hard block regardless of operator mode)
- Secret redaction in evidence storage
- Poison-gate quarantine on cross-session learning

[1.0.0]: https://github.com/thenothing-sec/hydra/releases/tag/v1.0.0
