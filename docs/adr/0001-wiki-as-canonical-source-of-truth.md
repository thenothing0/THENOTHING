# ADR 0001 — The wiki is the canonical source of truth

- **Status:** Accepted (Phase A)
- **Date:** 2026-06-02
- **Deciders:** THENOTHING operator + harness engineering

## Context

THENOTHING accumulates offensive knowledge across sessions. That knowledge can live in
several places: markdown pages under `wiki/`, the ephemeral runtime attack graph
(`hydra/graph/engine.py`), and SQLite learning stores (`hydra/learning/knowledge_graph.py`).
Without a single authority these drift apart, and "which store is right?" becomes unanswerable.

`wiki/SCHEMA.md` already established the wiki as the human-readable synthesis layer with the
8 page types, linking discipline, and evidence rules. Phase A made the wiki *machine-operable*.

## Decision

The **`wiki/` markdown tree is the single canonical store** of structured knowledge, versioned
in git. Every other representation is **derived and rebuildable**:

- `hydra/knowledge/graph_index.py` builds a graph purely by walking the wiki; it persists only a
  disposable SQLite snapshot (`data/knowledge_index.db`, gitignored) and can be thrown away and
  rebuilt at any time. It is **never** an authoritative store and is never written to as a source
  of new knowledge.
- All writes to structured knowledge go through `hydra/knowledge/wiki_store.py`, which is
  conservative (create / append / section-merge), preserves unknown frontmatter keys, and never
  blindly clobbers hand-authored pages.
- **No dual-write.** Derived stores are refreshed from the wiki (`bridge.rebuild_index()`), never
  in parallel with it.

Raw evidence (scans, APK extractions, disclosed reports) stays immutable under `output/`
(gitignored) and is **referenced** by wiki pages, never duplicated into them.

## Consequences

- Knowledge survives in diffable, reviewable markdown; history lives in git.
- The graph index can be deleted/corrupted with zero knowledge loss (`kb_rebuild_index`).
- Tooling must tolerate hand edits to the wiki between runs (it does — round-trip tested).
- Queries that need speed pay a rebuild cost; acceptable at current wiki size, revisit if the
  wiki grows to thousands of pages (incremental indexing would be the escape hatch).
