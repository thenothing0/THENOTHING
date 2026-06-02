# ADR 0003 — Capability registry architecture

- **Status:** Accepted (Phase A)
- **Date:** 2026-06-02

## Context

The planner and MCP tools historically reasoned in terms of **specific tools** (`subfinder`,
`httpx`). That couples plans to whichever binary is installed, makes multi-source corroboration
ad hoc, and gives no place to record per-source trust/performance. The spec demands the system
reason about **capabilities**, with the planner selecting sources automatically.

## Decision

Introduce a declarative, data-first **capability registry** (`hydra/capabilities/`, mirroring the
`hydra/skills` YAML-loader pattern):

- A **capability** (`capabilities/*.yaml`) declares `inputs`, `outputs`, its `sources`, and
  `confidence_rules`. Phase A ships nine: `discover_subdomains`, `discover_urls`, `http_probe`,
  `dns_intelligence`, `asn_intelligence`, `cloud_asset_discovery`, `repository_intelligence`,
  `technology_fingerprinting`, `attack_surface_mapping`.
- A **source** has a **stable immutable `id`** (`source.fofa`) that is the primary key everywhere —
  YAML, the `Source` dataclass, confidence inputs, and the future Phase-D performance schema.
  Display `name` is cosmetic. **Renaming never breaks history or learning.**
- Sources carry a **trust + historical-performance block from day one** (`trust_score`,
  `discoveries`, `unique_assets`, `duplicates`, `confidence_weight`, `success_rate`,
  `average_value`) so Phase-D source-learning needs **no migration**.
- Sources are categorized: `passive`, `active`, `code_intelligence`, `cloud_intelligence`,
  `threat_intelligence`, `contact_intelligence`.
- `CapabilityRegistry.select(capability, policy)` returns the runnable source subset; callers
  (fusion, planner) reason over capabilities, never tool names.

## Consequences

- Swapping/adding tools is a YAML edit, not a code change; plans are tool-agnostic.
- The registry models the full recon knowledge space independent of the current machine.
- Confidence and learning have a stable key (`id`) to attach to, avoiding a future migration.
- Capability YAML becomes a contract surface — covered by golden scenarios so drift fails CI.
