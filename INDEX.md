# HYDRA — Root Index (navigational STEP-1 input)

> Navigational catalog for the Hydra Offensive Knowledge OS. Content-light by design: it points to the
> authoritative documents. If this file and code disagree, **code + wiki + CLAUDE.md** win.
> Created 2026-06-09 (Harness V4.1); updated 2026-06-10 (Phase R).

## Current state (verify live before relying on it)
| Field | Value |
|-------|-------|
| Current Phase | **R — Skill Composition & Skill Graph Intelligence** (released) |
| Commit / Tag / Branch | `45e05d1`→Phase R commit / `phase-r-skill-intelligence` / `phase-r-skill-intelligence` |
| Next Phase | **S — Knowledge Compaction & Snapshotting** (roadmap; not started) |
| MCP tools | 132 · Capabilities 153 eff (87 core) · Adapters 439 eff (175 core) · Skills 31 · Agents 7 · Plugins 6 |

## Authoritative documents
- **`CLAUDE.md`** — operating instructions + the canonical MCP tool palette (132 tools, doc-sync enforced in CI).
- **`docs/HYDRA_SYSTEM_CONTEXT.md`** — permanent architecture memory: phase lineage A→R, invariant registry, inventory, data-flow, performance history, open risks, roadmap S→Z.
- **`docs/PHASE_{O,P,Q,R}_RELEASE_REPORT.md`** — per-phase release reports (commit/tag/branch/counts/invariants).
- **`docs/PHASE_{P,Q}_DESIGN.md`** — Phase P/Q architecture designs.
- **`docs/adr/`** — architecture decision records (e.g. wiki-as-canonical-source-of-truth).
- **`wiki/`** — the single canonical knowledge store; catalog at `wiki/index.md`, schema at `wiki/SCHEMA.md`, timeline at `wiki/log.md`.

## Derived stores (all under `data/`, gitignored, rebuildable, non-canonical)
`knowledge_index` · `source_learning` · `source_metrics` · `verification_learning` · `tool_health` ·
`decision_learning` · `plugin_health` · `knowledge_governance` · `workflows` · `federation` · `temporal`.

## Invariants (full registry in HYDRA_SYSTEM_CONTEXT.md)
Wiki canonical · no dual-write · `promotion.py`/`confidence.py` immutable (since Phase A `9bfec0c`) ·
discovery propose-only · learning derived/rebuildable · deterministic · offline-first · advisory-only ·
federation metadata-only · no autonomous exploitation/execution/confirmation/promotion · MCP backward-compatible.
