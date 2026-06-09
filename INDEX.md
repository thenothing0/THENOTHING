# HYDRA — Root Index (navigational STEP-1 input)

> Navigational catalog for the Hydra Offensive Knowledge OS. Content-light by design: it points to the
> authoritative documents. If this file and code disagree, **code + wiki + CLAUDE.md** win.
> Created 2026-06-09 (Harness V4.1) to close the long-standing "no root INDEX.md" gap.

## Current state (verify live before relying on it)
| Field | Value |
|-------|-------|
| Current Phase | **O — Temporal Knowledge Intelligence** (released) |
| Commit / Tag / Branch | `f8ffdf0` / `phase-o-temporal` / `phase-o-temporal` |
| Next Phase | **P — Offensive Capability Intelligence** (designed, not implemented) |
| MCP tools | 108 · Capabilities 153 eff (87 core) · Adapters 439 eff (175 core) · Agents 7 · Plugins 6 |

## Authoritative documents
- **`CLAUDE.md`** — operating instructions + the canonical MCP tool palette (108 tools, doc-sync enforced in CI).
- **`docs/HYDRA_SYSTEM_CONTEXT.md`** — permanent architecture memory: phase lineage A→O, invariant registry, inventory, data-flow, performance history, open risks, roadmap O→Z.
- **`docs/PHASE_O_RELEASE_REPORT.md`** — Phase O release report (commit/tag/branch/counts/invariants).
- **`docs/PHASE_P_DESIGN.md`** — Phase P architecture design (Offensive Capability Intelligence; design only).
- **`docs/adr/`** — architecture decision records (e.g. wiki-as-canonical-source-of-truth).
- **`wiki/`** — the single canonical knowledge store; catalog at `wiki/index.md`, schema at `wiki/SCHEMA.md`, timeline at `wiki/log.md`.

## Derived stores (all under `data/`, gitignored, rebuildable, non-canonical)
`knowledge_index` · `source_learning` · `source_metrics` · `verification_learning` · `tool_health` ·
`decision_learning` · `plugin_health` · `knowledge_governance` · `workflows` · `federation` · `temporal`.

## Invariants (full registry in HYDRA_SYSTEM_CONTEXT.md)
Wiki canonical · no dual-write · `promotion.py`/`confidence.py` immutable (since Phase A `9bfec0c`) ·
discovery propose-only · learning derived/rebuildable · deterministic · offline-first · advisory-only ·
federation metadata-only · no autonomous exploitation/execution/confirmation/promotion · MCP backward-compatible.
