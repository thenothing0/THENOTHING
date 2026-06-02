# ADR 0005 — Discovery is propose-only; evidence weighting is configuration

- **Status:** Accepted (Phase C)
- **Date:** 2026-06-02

## Context

Phase C is the first phase allowed to create higher-tier synthesis knowledge — recurring
**patterns** and multi-step **chains** — from the knowledge already in the wiki. This is exactly
where confidence inflation and "machine-invented" knowledge could erode the evidence discipline
that Phases A and B established. We needed discovery that is powerful but cannot quietly grow the
canonical graph or re-implement confidence rules.

## Decision

1. **Propose-only by default.** `discover_patterns` / `discover_chains` are pure, read-only and
   side-effect-free: they return ranked *candidates* and write nothing. Canonical `pattern`/`chain`
   pages are created only through an explicit `confirm_candidate(...)` step — a human checkpoint.

2. **Weighted evidence, but no magic constants in Phase C.** Discovery only *classifies* evidence
   (`validated_finding`, `report_intel`, `hypothesis`). The weights live in a **declarative
   configuration** module, `hydra/knowledge/evidence_policy.py`, and the actual band is computed by
   the **existing** `confidence.score_from_sources`. Two validated findings → high; a finding plus
   report-intel → medium; hypotheses carry weight 0 and are dropped before scoring, so they can never
   satisfy a threshold.

3. **`evidence_policy.py` is configuration ONLY — never a second confidence engine.** It contains a
   class→weight table plus two trivial lookups (`weight_for`, `is_excluded`) and nothing else: no
   scoring math, no thresholds, no banding, no decay. All confidence logic (scoring, two-signal,
   decay, contradiction) remains owned **exclusively** by `confidence.py`. A test
   (`test_evidence_policy_is_config_only_not_a_second_engine`) enforces this — it fails if any scoring
   vocabulary appears in the policy module.

4. **`promotion.py` and `confidence.py` stay byte-for-byte unchanged.** Discovery is *synthesis*
   (creating a new higher-tier node from multiple validated sources), not single-page stage promotion,
   so it never calls and never weakens promotion. The two-signal gate is enforced by reusing
   `confidence.meets_two_signal`.

5. **Pluggable signatures, conservative chains, single canonical node.** Pattern grouping uses a
   `SignatureProvider` interface (swappable without touching discovery). Chains are formed only from a
   shared target, a shared asset, or an explicit graph path — never semantic similarity. A candidate
   matching an existing canonical page becomes a `strengthen_existing` recommendation, never a
   duplicate slug.

## Consequences

- The canonical wiki only ever gains a machine-proposed pattern/chain after an explicit confirm, with
  full provenance frontmatter (`status: candidate`, `discovered_by: phase_c`, `candidate_id`,
  `confidence`, `source_refs`, `signature_provider`, `confirmed_at`).
- Evidence weighting can be tuned by editing one declarative table; the math has a single home.
- Future signature strategies (embeddings, richer taxonomies) drop in behind the provider interface.
- The legacy SQLite `exploit_patterns` store is intentionally untouched (no dual-write); reconciling it
  is left to a later phase.
