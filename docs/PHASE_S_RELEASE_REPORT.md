# PHASE_S_RELEASE_REPORT — Opportunity Intelligence

> Generated after the full validation pipeline · 2026-06-15 · all values verified live.
>
> **Scope note.** Phase T's spec required reusing an `OpportunityIntelligence` (Phase S) layer that
> did not exist (HEAD was Phase R / 132 tools; the architecture doc had earmarked the S slot for
> "Knowledge Compaction"). Per explicit operator decision, the **full Opportunity Intelligence
> layer was built first as Phase S** (no shim, no reuse of the Phase-D `OpportunityScore`
> primitive). Phase T was **not** started. This report consolidates the eight requested
> deliverables (Architecture / Coverage / Benchmark / Risk / Invariant Verification / Test / MCP
> Contract Delta / Release).

---

## Release identity
| Field | Value |
|-------|-------|
| **Release** | Phase S — Opportunity Intelligence |
| **Parent commit** | `270141a` (Phase R — `phase-r-skill-intelligence`) |
| **Tag** | `phase-s-opportunity-intelligence` (annotated; `git describe --exact-match HEAD` ✓) |
| **Branch** | `phase-s-opportunity-intelligence` (cut from `phase-r-skill-intelligence` `270141a`) |
| **Package** | `hydra/opportunity_intel/` (10 modules, **store-free**; NEW — no earlier layer modified) |
| **HEAD == tag** | **YES** (verified at release; see Verdict) |

## System inventory (live)
| Dimension | Count |
|-----------|-------|
| **MCP tools** | **140** (+8 opportunity vs Phase R's 132) |
| **Capabilities** | **153 effective** (87 core + 66 plugin) |
| **Adapters** | **439 effective** (175 core + 264 plugin) |
| **Skills** | **31** · **Agents** 7 · **Plugins** 6 |

---

## 1. Architecture Report

A store-free, offline-first opportunity-intelligence layer that answers **"where are Hydra's
highest-value, least-covered, most-leveraged offensive opportunities?"** It is derived, advisory,
deterministic and **NON-executing** — it scores and advises over the capability MODEL and never
exploits, validates, confirms, promotes, or executes.

**Modules (`hydra/opportunity_intel/`):**

| Module | Class | Responsibility |
|--------|-------|----------------|
| `context.py` | `OpportunityContext` | Load-once shared substrate. Wraps ONE Phase-P `OffensiveIntelligence` and threads that **same instance** into Phase-Q `CampaignIntelligence` and Phase-R `SkillGraphIntelligence` (no duplicate scans). Lazy, guarded Phase-O (emerging) + Phase-N (peer-demand) signals. |
| `surface.py` | `AttackSurfaceModel` | Models Hydra's OWN modelled reach by category (addressable finding/target types, effectiveness, verification, exercised). NON-executing — not a live target. |
| `coverage.py` | `CoverageSynthesizer` | Fuses 5 coverage dimensions (effectiveness / verification / exercise / agent / skill) → per-category `coverage_index` + overall index. |
| `blindspots.py` | `BlindSpotAnalyzer` | Severity-ranked blind spots fused across layers; post-exploitation campaign phases flagged **INTENTIONAL** (never a defect). |
| `opportunity_graph.py` | `OpportunityGraph` | Capability↔finding-type bipartite + dependency edges; hub capabilities (high leverage) + bottleneck finding-types (single-provider). |
| `ranker.py` | `OpportunityRanker` / `Opportunity` | Versioned `OpportunityScore` per capability, fully explainable. |
| `advisor.py` | `OpportunityAdvisor` | Bounded SAFE-verb recommendations. |
| `intelligence.py` | `OpportunityIntelligence` | Unified read surface (the 8 MCP views + `opportunity_health`). |
| `util.py` | — | Re-exports Phase-P math; versioned scoring constants. |
| `__init__.py` | — | Public exports. |

**OpportunityScore (versioned, `OPPORTUNITY_SCORING_VERSION = 1`):**

```
score = clamp01( 0.35·value            # Phase-P utility (effectiveness × breadth)
               + 0.30·coverage_deficit  # mean(not_exercised, no_skill, no_owner, verification_blind)
               + 0.15·chain_potential   # Phase-P dependency contribution / centrality
               + 0.10·uniqueness         # Phase-P (1 − redundancy)
               + 0.10·novelty            # never-exercised (prior-only) capability
               + temporal_bonus          # Phase-O "emerging"  (capped 0.05)
               + federation_bonus )      # Phase-N peer demand (capped 0.05, 0.01/peer)
```

The five primary weights sum to 1.0 and the two cross-layer bonuses are capped, so a high score
means **"valuable AND under-exploited"** — the classic definition of an opportunity. Every term is
emitted in `components` + a `rationale` string. **Distinct** from the Phase-D `OpportunityScore`
(`hydra/knowledge/opportunity.py`), which ranks discovery *candidates* (findings); Phase S ranks the
capability *model* — complementary domains, no overlap, no collision (`opportunity_*` tool prefix vs
`rank_opportunities`).

**Reuse map (single OffensiveContext load):** P everywhere · Q (model-only phases → blind spots) ·
R (uncovered capabilities → blind spots & coverage) · O (emerging → novelty bonus) · N (peer demand
→ bonus). O and N are loaded lazily and fully guarded → cold-start / offline yields empty signals
(never an error), preserving determinism and rebuild-identity.

## 2. Coverage Report (live, catalog-only)

| View | Result |
|------|--------|
| Attack surface | 153 capabilities · 9 categories · **71 addressable finding-types** · 27 target-types · 50 verification-capable · mean breadth 2.23 |
| Synthesized coverage | overall `coverage_index` **0.4179**; weakest: reconnaissance 0.291, infrastructure 0.339, api 0.346 |
| Blind spots | **124 total → 118 actionable + 6 intentional**; by type: capability_no_skill 106, weak_chain 11, model_only_phase 6 (intentional), uncovered_finding_type 1 |
| Opportunity graph | 153 capability nodes · 71 finding-type nodes · **29 bottleneck finding-types** (single-provider) |
| Top opportunities | http_probing 0.598 · port_scanning 0.571 · asn_mapping 0.537 · secret_scanning 0.528 · dns_resolution 0.526 |
| Opportunity health | **33.62 / 100 (degrading)** — honest catalog-only signal (0 exercise events, 106/153 caps skill-less). Rises as the learning logs fill. |

The `capability_no_skill = 106` figure is consistent with Phase R's observation that only 47/153
capabilities are skill-covered (153 − 47 = 106). The 6 intentional blind spots are exactly the
post-exploitation tactic phases Hydra deliberately does not cover.

## 3. Benchmark Report

| Path | Time | Notes |
|------|------|-------|
| Cold full summary | **493.6 ms** | first-touch load of catalog + dependency graph + adapters + skills + campaign model (shared, amortized across P/Q/R/S) |
| Warm `opportunity_summary` | 7.39 ms | assembles all sub-reports |
| Warm `opportunity_ranking` | 0.047 ms | cached ranking |
| Warm `opportunity_health` | 1.89 ms | |
| Warm `opportunity_graph` | ~0.00 ms | memoized `build()` |
| Warm `opportunity_blindspots` | 1.78 ms | |

**Complexity:** O(C + D) on cached data (C = capabilities, D = dependency edges); no O(C²) — overlap
reuse is bucketed by Phase P; ranking/graph/coverage are linear with memoization. The single shared
`OffensiveContext` load is O(E) and is reused by P/Q/R/S (no duplicate scans).

## 4. Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Cross-store coupling pulls O/N into the deterministic core | Med | O/N are **lazy + fully guarded** (`try/except → empty`) and contribute only **capped additive bonuses**; cold/offline → 0 bonus. Verified rebuild-identical. |
| Determinism vs. derived stores | Med | `now` is a *reference-time stamp only* (scoring is `now`-independent, exactly like P/Q/R); given fixed stores the output is identical. Cold tests redirect tool-health/verification DBs. |
| Naming collision with Phase-D `rank_opportunities` | Low | All 8 tools use the `opportunity_*` prefix; the model-ranking vs candidate-ranking distinction is documented in code + CLAUDE.md. |
| Low health score (33.62) misread as a defect | Low | It is an **honest** catalog-only signal (no learning events). `data_mode` is reported; the score is bounded and explainable. |
| MCP registry / doc drift | Low | Contract baseline regenerated (purely additive); doc-sync test green; per-phase count tests relaxed to `>=` per existing convention. |
| Roadmap divergence (S was earmarked "Knowledge Compaction") | Low | Operator-directed; doc updated; Knowledge Compaction explicitly deferred to a later slot. |

## 5. Invariant Verification

| Invariant | Status |
|-----------|--------|
| `promotion.py` / `confidence.py` immutable | ✅ untouched (absent from diff; last `9bfec0c`) |
| Canonical wiki — no write / no dual-write | ✅ no wiki writer imported (import-guard test) |
| Store-free / rebuild-identical | ✅ no `sqlite3` in package; pure function of catalogs + reused intel; rebuild-identical test green |
| Advisory-only / NON-executing | ✅ every payload `advisory:true`; no subprocess/network/exec/eval (token test) |
| SAFE verbs only | ✅ advisor ∈ {prioritize, strengthen, expand, diversify, investigate, improve}; never execute/exploit/attack/deploy |
| Shared OffensiveIntelligence load | ✅ test asserts Phase-Q & Phase-R contexts share the one `oi`/`ctx` instance |
| Deterministic / offline-first | ✅ injected `now`; cold-start; O/N guarded |
| No coupling cycle | ✅ only `governance.py` (lazy) + `mcp_server.py` reference `opportunity_intel`; no earlier-phase module imports it |
| MCP backward compatibility | ✅ purely additive (+8); existing 132 unchanged (baseline diff additive-only) |
| Post-exploitation guard preserved | ✅ Phase-Q model-only phases surface as INTENTIONAL blind spots (zero capabilities, zero execution) |

## 6. Test Report

| Gate | Result |
|------|--------|
| **Full suite** | **634 passed, 6 deselected** (integration/e2e) — was 603 at Phase R (+31) |
| Phase S unit | **15/15** (`tests/opportunity_intel/test_opportunity_intel.py`) |
| Phase S MCP | **16/16** (`tests/mcp/test_opportunity_tools.py`) |
| MCP contract | **12/12** (live == baseline == documented == 140) |
| Phase R MCP (relaxed) | 15/15 (`test_mcp_count_at_least_132`) |

Coverage of the new layer: surface totals, coverage-index bounds + ordering, blind-spot
typing/ranking/partition (+ intentional flag), graph structure (bottleneck single-provider, hub
leverage bounds), ranker bounds/ordering/explainability + single/unknown lookup, advisor
safe-verbs/bounds, health bounds, summary shape, shared-load identity, rebuild-identity, store-free,
no-execution/no-canonical imports, promotion/confidence untouched.

## 7. MCP Contract Delta

Purely additive: **132 → 140**. New tools (all read-only / deterministic / advisory / NON-executing):

| Tool | params | required |
|------|--------|----------|
| `opportunity_summary` | `now` | — |
| `opportunity_surface` | `now` | — |
| `opportunity_coverage` | `now` | — |
| `opportunity_blindspots` | `now` | — |
| `opportunity_graph` | `now` | — |
| `opportunity_ranking` | `capability_id`, `limit`, `now` | — |
| `opportunity_advisor` | `limit`, `now` | — |
| `opportunity_health` | `now` | — |

Governance: `governance_summary` gains a read-only, lazy-loaded `opportunity_intelligence` block.
`tests/mcp/tool_contract_baseline.json` regenerated (additive only); `CLAUDE.md` MCP palette + doc-sync
updated.

## Verdict

**ALL GATES PASS → PHASE S RELEASED.** Phase T deliberately NOT started (per operator instruction);
its `OpportunityIntelligence` dependency now exists.
