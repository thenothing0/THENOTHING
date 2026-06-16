# HYDRA — System Context (Permanent Architecture Memory)

> Authoritative architecture memory for the Hydra Offensive Knowledge OS.
> Maintained by the Architecture Steward. Updated automatically after every phase.
> If this file and code disagree, the **code + wiki + CLAUDE.md** win — reconcile here.

---

## Project Overview

| Field | Value |
|-------|-------|
| Current Phase | **Phase R — Skill Composition & Skill Graph Intelligence** (implemented & released) |
| Latest Commit | Phase R commit on branch `phase-r-skill-intelligence`, tagged `phase-r-skill-intelligence` (supersedes Phase Q `45e05d1`) |
| Latest Tag | `phase-r-skill-intelligence` |
| Active Branch | `phase-r-skill-intelligence` (cut from `phase-q-campaign-reasoning`) |
| Last Updated | 2026-06-10 (Phase R released — Skill Composition & Skill Graph Intelligence) |
| MCP Tools | **132** (Phase R added +8 skill tools) |

> ✅ **Release note (Phase R):** `hydra/skill_intel/` (12 modules, **store-free**) + `tests/skill_intel/`
> + `tests/mcp/test_skill_tools.py` + 8 MCP tools, committed on branch `phase-r-skill-intelligence`,
> tagged `phase-r-skill-intelligence`. Promotes Skills to first-class entities — skill dependency graph
> **DERIVED from the capability graph** (declarative `chain_to` is unpopulated), composition graph, bundles,
> effectiveness, coverage, gaps, marketplace. Reuses the Phase-P `OffensiveContext`; legacy `hydra/skills/`
> **untouched** (NEW package `hydra/skill_intel/`). Unrelated wiki/PDF/artifact files **excluded**. MCP count
> **132**; **603 tests pass**, 6 deselected; ruff clean; promotion.py/confidence.py untouched; **NON-executing**.
> Benchmark O(S+C+D): graph 0.04 ms warm / 0.442 s cold; summary 0.63 ms; marketplace 0.30 ms. Phase Q remains
> tagged `phase-q-campaign-reasoning` (`45e05d1`, MCP 124).

---

## Architecture Lineage

Build order is **locked A → R**. Every phase is derived/advisory unless noted; none mutate
`promotion.py`, `confidence.py`, or the canonical wiki schema behavior.

### Phase A — Offensive Knowledge OS Foundations
- **Purpose:** Capability-first recon + machine-operable wiki as the single canonical store.
- **Components:** CapabilityRegistry, WikiStore, recon-fusion (Two-Signal confidence), graph index, `promotion.py`, `confidence.py`, safety/test harness.
- **Learning stores:** — · **Runtime stores:** — · **Governance:** —
- **MCP Δ:** +10 (`capability_list`, `capability_sources`, `recon_fuse`, `kb_recall`, `kb_lint`, `kb_promote`, `kb_rebuild_index`, `asset_lookup`, `graph_neighbors`, `graph_path`)
- **Benchmarks:** offline recon fusion; index rebuild from canonical wiki.
- **Tests:** `tests/knowledge/*`, `tests/capabilities/test_registry.py`, `tests/recon_fusion/*`.
- **Invariants:** Wiki canonical; promotion/confidence introduced here and frozen thereafter.

### Phase B — Report Intelligence
- **Purpose:** Distill disclosed reports/writeups into reusable, scored attacker knowledge.
- **Components:** ReportIntelligencePipeline; only `report`+`intel` pages; `unresolved_references` (never auto-created links); deterministic 1–10 learning score.
- **MCP Δ:** +3 (`ingest_report`, `report_lookup`, `list_reports`)
- **Tests:** `tests/knowledge/test_report_intel.py`, `test_learning_score.py`.
- **Invariants:** No findings/patterns/chains created; LLM-free deterministic scoring.

### Phase C — Pattern & Chain Discovery (propose-only)
- **Purpose:** Cross-document synthesis → `pattern`/`chain` candidates.
- **Components:** PatternDiscovery, ChainDiscovery, evidence weighting (validated > report-intel; hypotheses never count), `confirm_candidate` as the only write path.
- **MCP Δ:** +3 (`discover_patterns`, `discover_chains`, `confirm_candidate`)
- **Tests:** `tests/knowledge/test_discovery.py`, `test_signatures.py`.
- **Invariants:** Discovery is dry-run; canonical pages only via explicit confirm.

### Phase C.5 — Scalability Hardening
- **Purpose:** Remove O(F²) ChainDiscovery; rebuild amplification fixes.
- **Components:** Bounded chain discovery; canonical signatures from structured fields only (Fix F-1).
- **MCP Δ:** 0 · **Tests:** `tests/knowledge/test_scalability.py`.
- **Invariants:** Determinism preserved; complexity reduced to O(E).

### Phase D — Source Performance Learning & Opportunity Ranking
- **Purpose:** Event-sourced learning to prioritize without touching canonical state.
- **Components:** SourceLearningStore, OpportunityScorer, prioritization report.
- **Learning stores:** `source_learning.db`, `source_metrics.db`
- **MCP Δ:** +4 (`record_outcome`, `source_scores`, `rank_opportunities`, `prioritization_report`)
- **Tests:** `tests/capabilities/test_source_learning.py`, `test_source_metrics.py`, `test_opportunity.py`.
- **Invariants:** Learning derived/rebuildable; never touches wiki/promotion/confidence bands.

### Phase D.1 — Learning Hardening (F-D1…F-D5)
- **Purpose:** Robustness of derived scores (no dead-zones, stable cold-start).
- **MCP Δ:** 0 · **Tests:** `tests/knowledge/test_learning_hardening.py`.
- **Invariants:** Pure functions of the event log; idempotent.

### Phase E — Adaptive Recon & Autonomous Source Selection
- **Purpose:** Use Phase-D learning to advise recon planning.
- **Components:** AdaptiveSourceSelector, ReconPlanner.
- **MCP Δ:** +2 (`select_sources`, `recon_plan`)
- **Tests:** `tests/capabilities/test_source_selection.py`.
- **Invariants:** Advisory; recommends, never executes/confirms/writes.

### Phase F — Verification Learning & Validation Intelligence
- **Purpose:** Learn how findings get validated; advisory verification playbooks.
- **Components:** VerificationLearningStore, ValidationIntelligence, PlaybookGenerator, ToolCapabilityRegistry.
- **Learning stores:** `verification_learning.db`
- **MCP Δ:** +4 (`record_verification`, `verification_stats`, `verification_playbook`, `tool_capabilities`)
- **Tests:** `tests/knowledge/test_verification.py`.
- **Invariants:** Never auto-confirms/auto-exploits; WAL, idempotent.

### Phase G — Capability Expansion & Tool Orchestration
- **Purpose:** Capability-centric catalog v2 (87 caps / 9 categories) + learning tool selector.
- **Components:** CapabilityCatalog, CapabilityCoverage, ToolSelector.
- **MCP Δ:** +4 (`capability_catalog`, `capability_coverage`, `rank_tools`, `select_tool`)
- **Tests:** `tests/capabilities/test_tool_orchestration.py`.
- **Invariants:** Capability modeling only; no integrations; read-only.

### Phase H — Multi-Agent Orchestration
- **Purpose:** Declarative agents over the capability layer; deterministic routing.
- **Components:** AgentRegistry (6 agents), AgentPlanner; Target→Agent→Capability→Tool.
- **MCP Δ:** +4 (`agent_catalog`, `agent_plan`, `agent_route`, `agent_coverage`)
- **Tests:** `tests/agents/*`.
- **Invariants:** Agents never execute/confirm/write; advisory.

### Phase I — Execution Runtime & Workflow Engine
- **Purpose:** Deterministic workflow STATE coordination (no execution). Adds `mobile_agent` → 87/87 owned.
- **Components:** RuntimeEngine, WorkflowStore.
- **Runtime stores:** `workflows.db`
- **MCP Δ:** +4 (`workflow_create`, `workflow_status`, `workflow_history`, `runtime_summary`)
- **Tests:** `tests/runtime/*`, `tests/workflows/*`.
- **Invariants:** Executes no tools; materializes nothing canonical.

### Phase J — Knowledge Governance, Drift & QA
- **Purpose:** Derived health/freshness/consistency evaluation.
- **Components:** DriftDetector, KnowledgeQualityAnalyzer, GovernanceIntelligence.
- **Governance stores:** `knowledge_governance.db`
- **MCP Δ:** +6 (`governance_summary`, `drift_report`, `knowledge_health`, `stale_entities`, `duplicate_patterns`, `contradiction_report`)
- **Tests:** `tests/knowledge/test_governance.py`.
- **Invariants:** Read-only; writes nothing canonical.

### Phase K — Adapter Framework & Sandboxed Tool Integrations
- **Purpose:** Capability×tool adapter definitions (175 core) + sandboxed runtime + tool-health learning.
- **Components:** AdapterRegistry, ToolHealthStore, AdapterIntelligence, CapabilityExerciseAnalyzer, RuntimeAnalytics, AdapterSelector.
- **Learning stores:** `tool_health.db`
- **MCP Δ:** +6 (`adapter_catalog`, `adapter_coverage`, `adapter_health`, `adapter_summary`, `adapter_select`, `runtime_analytics`)
- **Benchmarks:** 175 adapters / 87 caps; SAFE profiles only (offline/passive/validation/simulation).
- **Tests:** `tests/adapters/*`.
- **Invariants:** No offensive execution; unsupported profiles rejected at load.

### Phase L — Autonomous Knowledge Simulation & Decision Intelligence
- **Purpose:** Predict workflow/plan/strategy outcomes from historical learning before execution.
- **Components:** SimulationContext (load-once O(E)), WorkflowSimulator, StrategyComparator, OutcomePredictor, CapabilityImpactAnalyzer, PredictionAnalytics, AgentSimulation, WorkflowOptimizationAdvisor.
- **Learning stores:** `decision_learning.db`
- **MCP Δ:** +8 (`simulate_workflow`, `simulate_strategy`, `predict_outcome`, `capability_impact`, `prediction_accuracy`, `agent_effectiveness`, `workflow_optimization`, `decision_health`)
- **Tests:** `tests/intelligence/*`.
- **Invariants:** Advisory; Phase-J gains a `decision_intelligence` block; no execution/promotion/confidence.

### Phase M — Capability Marketplace & Plugin Ecosystem
- **Purpose:** Declarative plugins extend capabilities/adapters/agents without core code change. core(87)+plugins(66) = **153 effective**, **439 adapters**.
- **Components:** PluginRegistry, EffectiveCapabilityCatalog, CapabilityDependencyGraph, AgentOwnershipResolver, EcosystemAnalyzer, CapabilityMarketplace, PluginHealthStore.
- **Learning stores:** `plugin_health.db`
- **MCP Δ:** +12 (`plugin_catalog`, `plugin_summary`, `plugin_health`, `plugin_dependencies`, `plugin_capabilities`, `plugin_coverage`, `capability_graph`, `dependency_paths`, `critical_capabilities`, `agent_ownership`, `ownership_conflicts`, `ecosystem_summary`)
- **Benchmarks:** 6 reference packs (cloud/mobile/container/iot/supply_chain/osint); acyclic dependency graph; O(C) incremental loading.
- **Tests:** `tests/plugins/*` (18).
- **Invariants:** Globally-unique capability ids; no plugin execution; promotion/confidence untouched.

### Phase N — Federated Knowledge Exchange & Intelligence Mesh
- **Purpose:** Exchange anonymized, aggregated intelligence digests between Hydra instances — metadata only.
- **Components:** `hydra/federation/`: `safety.py` (metadata-only guard), KnowledgeExchangeStore, FederationRegistry/PeerRecord, KnowledgeDigestGenerator (+4 digest types), IntelligenceMesh, ConsensusEngine, FederationMarketplace.
- **Federation stores:** `federation.db` (WAL, append-only, idempotent, rebuildable)
- **MCP Δ:** +10 (`federation_peers`, `federation_summary`, `export_digest`, `import_digest`, `capability_trends`, `verification_trends`, `source_trends`, `federation_consensus`, `ecosystem_opportunities`, `federation_health`)
- **Benchmarks:** read cost flat **~1.6–2.0 µs/event** across 2k→40k events ⇒ **O(E) confirmed**; rebuild-identical digests.
- **Tests:** `tests/federation/test_federation.py` (19) + `tests/mcp/test_federation_tools.py` (7) = **26**.
- **Invariants:** Metadata-only (`assert_safe` on export+import); no wiki/evidence/finding/target/source/secret exchange; advisory; promotion/confidence untouched.

### Phase O — Temporal Knowledge Intelligence
- **Purpose:** Understand how knowledge EVOLVES over time — trends, momentum, decay, emerging/declining areas, bounded forecasts, temporal anomalies. Built entirely from existing derived event logs.
- **Components (`hydra/temporal_intel/`, NEW package — legacy `hydra/temporal/` untouched):** `util` (deterministic math/bucketing), `TemporalStore` (`data/temporal.db`), `TemporalContext` (load-once, memoized bucketing, single scan per physical table), `TrendAnalyzer`, `MomentumAnalyzer`, `TemporalForecastEngine` (MA + linear slope, bounded, non-stochastic), `DecayAnalyzer`+`TemporalDecayFinding`, `TemporalAnomalyDetector`, `TemporalAdvisor`, `TemporalIntelligence`.
- **Intelligence/derived stores:** `temporal.db` (WAL, event-sourced, idempotent, rebuildable).
- **MCP Δ:** +6 (108 total) — `temporal_summary`, `temporal_trends`, `temporal_forecast`, `temporal_decay`, `temporal_anomalies`, `temporal_health`.
- **Governance:** Phase-J `governance_summary` gains a read-only `temporal_intelligence` block (lazy import, no cycle).
- **Benchmarks:** O(E); **9.35 s at 1M rows (2M derived events)** — under the 10 s target; per-event cost flattens (61→15→9 µs).
- **Tests:** `tests/temporal/test_temporal.py` (18) + `tests/mcp/test_temporal_tools.py` (5) = **23**.
- **Invariants:** derived/advisory/deterministic/rebuild-identical; no wiki mutation; promotion.py/confidence.py untouched; no execution.

### Phase P — Offensive Capability Intelligence
- **Purpose:** Score the EFFECTIVENESS / COVERAGE / composition / OVERLAP / ATTACK-PATH value of capabilities, workflows, agents, plugins and skills — the offensive analog of the knowledge-intelligence layers.
- **Components (`hydra/offensive_intel/`, NEW package, store-free):** `util`, `OffensiveContext` (load-once O(E) over tool-health + verification logs ⊕ static catalogs / dependency-graph / adapters / ownership / skills), `CapabilityEffectivenessEngine`, `OffensiveCoverageAnalyzer`, `AttackChainIntelligence`, `OverlapAnalyzer`, `OffensiveGapAnalyzer`, `SkillIntelligence` (Capability→Skill→Workflow→Agent bridge), `OffensiveAdvisor`, `OffensiveIntelligence`.
- **Stores:** **none** — store-free, pure function of upstream derived logs + static catalogs (rebuild-identical by construction).
- **MCP Δ:** +8 (116 total) — `offensive_summary`, `offensive_effectiveness`, `offensive_coverage`, `offensive_chains`, `offensive_overlap`, `offensive_gaps`, `offensive_skills`, `offensive_health`.
- **Governance:** Phase-J `governance_summary` gains a read-only `offensive_intelligence` block (lazy import, no cycle).
- **Benchmarks:** O(E); **3.6 µs/event** (300k events in ~1.1 s ⇒ ≈3.6 s @ 1M); cold-start = catalog priors.
- **Tests:** `tests/offensive/test_offensive.py` (17) + `tests/mcp/test_offensive_tools.py` (15) = **32**; full suite **531**.
- **Invariants:** derived/advisory/deterministic/rebuild-identical; **NON-executing**; no exploitation/validation/confirmation/promotion; no wiki mutation; promotion.py/confidence.py untouched.

### Phase Q — Offensive Campaign Reasoning Engine
- **Purpose:** Lift Hydra from capability intelligence (P) to CAMPAIGN-level reasoning — attack objectives, the 12 attack-tactic phases, capability sequencing, skill composition, attack-path generation, gaps, alternative strategies. Skills are first-class; a campaign is explainable as BOTH a Capability Graph and a Skill Graph.
- **Components (`hydra/campaigns/`, NEW package, store-free):** `util`, `CampaignContext` (load-once, reuses the Phase-P OffensiveIntelligence), `CampaignModel` (12 tactic phases; post-exploitation = model-only), `CampaignSkillBridge` (4 campaign facets + dual graphs), `WorkflowGraph`, `ObjectiveMapping` (Objective→Skills→Capabilities→Adapters→Agents), `PlaybookGenerator` (5 templates), `PathGeneration`, `StrategyComparator`, `CampaignSimulator` (counterfactual), `CampaignAdvisor`, `CampaignIntelligence`.
- **Stores:** **none** — store-free (pure function of static catalogs + Phase-P offensive intelligence + declarative templates).
- **MCP Δ:** +8 (124 total) — `campaign_summary`, `campaign_objectives`, `campaign_playbooks`, `campaign_paths`, `campaign_strategies`, `campaign_simulation`, `campaign_gaps`, `campaign_health`.
- **Governance:** Phase-J `governance_summary` gains a read-only `campaign_intelligence` block (lazy import, no cycle).
- **Benchmarks:** campaign reasoning **O(C+D)** ~2.6 ms warm / 0.378 s cold-start; path 0.3 ms; simulation 0.1 s.
- **Tests:** `tests/campaigns/test_campaigns.py` (22) + `tests/mcp/test_campaign_tools.py` (16) = **38**; full suite **569**.
- **Invariants:** derived/advisory/deterministic/rebuild-identical; store-free; **NON-executing**; no exploitation/validation/confirmation/promotion; no wiki mutation; promotion.py/confidence.py untouched. **Post-exploitation guard:** persistence/privilege_escalation/defense_evasion/lateral_movement/collection/exfiltration are model-only (`hydra_capability_coverage=none`, `advisory_model_only=true`).

### Phase R — Skill Composition & Skill Graph Intelligence
- **Purpose:** Promote Skills into first-class architecture entities — a skill dependency graph, composition graph, bundles, per-skill effectiveness, coverage, gaps, and an advisory skill marketplace.
- **Components (`hydra/skill_intel/`, NEW package, store-free — does NOT modify the legacy `hydra/skills/` subsystem):** `util`, `SkillContext` (load-once, reuses the Phase-P OffensiveIntelligence), `SkillGraph` (dependency edges **derived from the capability dependency graph** since `chain_to` is unpopulated; composition edges from shared capabilities), `SkillDependencyAnalyzer`, `SkillComposition`, `SkillBundles`, `SkillEffectivenessAnalyzer`, `SkillCoverageAnalyzer`, `SkillGapAnalyzer`, `SkillMarketplace`, `SkillAdvisor`, `SkillGraphIntelligence`.
- **Stores:** **none** — store-free (pure function of static catalogs + Phase-P offensive intelligence).
- **MCP Δ:** +8 (132 total) — `skill_summary`, `skill_graph`, `skill_dependencies`, `skill_bundles`, `skill_effectiveness`, `skill_coverage`, `skill_gaps`, `skill_marketplace`.
- **Governance:** Phase-J `governance_summary` gains a read-only `skill_intelligence` block (lazy import, no cycle).
- **Benchmarks:** O(S+C+D); graph 0.04 ms warm / 0.442 s cold; summary 0.63 ms; marketplace 0.30 ms.
- **Tests:** `tests/skill_intel/test_skill_intel.py` (19) + `tests/mcp/test_skill_tools.py` (15) = **34**; full suite **603**.
- **Invariants:** derived/advisory/deterministic/rebuild-identical; store-free; **NON-executing**; skills never execute / modify capability-promotion-confidence state / create runtime actions / become a canonical source; legacy `hydra/skills/` untouched; promotion.py/confidence.py untouched.

### Current Phase
**T (implemented & released: tag + branch `phase-t-adversary-intelligence`, cut from `phase-s-opportunity-intelligence` `0407491`).** Next: **Phase U** (see Roadmap).

---

## Architecture Invariants (Registry)

### Canonical Knowledge
- Wiki is the **only** canonical source of truth.
- No second canonical source.
- No dual-write.

### Protected Core
- `hydra/knowledge/promotion.py` immutable (last changed Phase A, `9bfec0c`).
- `hydra/knowledge/confidence.py` immutable (last changed Phase A, `9bfec0c`).

### Discovery Rules
- Discovery is propose-only.
- No autonomous confirmation.
- No autonomous promotion.

### Execution Rules
- No autonomous exploitation.
- No offensive execution.
- No hidden execution paths. (Adapters permit only SAFE profiles: offline/passive/validation/simulation.)

### Learning Rules
- Learning is derived.
- Learning is disposable.
- Learning is rebuildable (pure function of event logs).

### System Rules
- Offline-first.
- Deterministic (injected clocks; sorted outputs).
- Rebuild-identical.
- Advisory-only decision systems.
- MCP backward compatibility (contract baseline + CLAUDE.md doc-sync enforced in CI).

### Federation Rules
- Metadata-only exchange.
- No knowledge leakage.
- No evidence exchange.
- No target exchange.
- No source disclosure (`source_id` is an exact-forbidden key).
- No secret sharing.

---

## System Inventory

### Core
| Item | Count |
|------|-------|
| Capabilities (core) | 87 |
| Capabilities (effective: core + plugins) | 153 |
| Adapters (core) | 175 |
| Adapters (effective) | 439 |
| Agents | 7 (recon, attack_surface, cloud, verification, mobile, correlation, reporting) |
| Plugins (reference packs) | 6 (cloud, mobile, container, iot, supply_chain, osint) |
| MCP Tools (live registry) | 132 |

### Stores (by layer — v2 taxonomy)
| Class | Stores |
|-------|--------|
| Learning | `source_learning.db`, `source_metrics.db`, `verification_learning.db`, `tool_health.db`, `plugin_health.db` |
| Intelligence | `decision_learning.db` (simulation / forecasting / strategy), `temporal.db` (Phase O temporal evolution) |
| Runtime | `workflows.db` |
| Governance | `knowledge_governance.db` |
| Federation | `federation.db` |
| Canonical Index | `knowledge_index.db` (derived graph index, rebuildable from wiki) |

### Coverage Snapshot (live, 2026-06-05)
| Dimension | Value |
|-----------|-------|
| Effective capability ownership | **153 / 153** owned · 0 gaps · 0 conflicts |
| Agent workflow coverage (core) | **87 / 87** (100%) · 0 uncovered categories |
| Adapter ownership | 87 / 87 core have adapters; **439** effective adapters |
| Plugin contribution | +66 capabilities · +264 adapters |
| Verification-capable capabilities | **50 / 153** effective (32.7%) |
| Adapter **exercise** (cold-start) | exercised 2 / 87 (2.3%), verified 0 — reflects near-empty learning stores, not a structural gap |

### Databases (all derived/disposable under `data/`, gitignored)
1. `knowledge_index.db` — derived graph index (rebuild from canonical wiki)
2. `source_learning.db` — Phase D source performance learning
3. `source_metrics.db` — Phase D source run metrics
4. `verification_learning.db` — Phase F verification learning
5. `tool_health.db` — Phase K adapter tool-health
6. `decision_learning.db` — Phase L decision/simulation learning
7. `plugin_health.db` — Phase M plugin usage learning (on-demand)
8. `knowledge_governance.db` — Phase J governance snapshots (on-demand)
9. `workflows.db` — Phase I workflow runtime state
10. `federation.db` — Phase N federation ledger (on-demand)

---

## Data Flow Map

### Canonical
- **Wiki** (`wiki/`) — the single source of truth. Pages: target / technique / asset / report / intel / pattern / chain / finding.

### Derived (rebuildable; never canonical)
- Learning stores (source / verification / tool-health / decision / plugin)
- Governance store
- Simulation/decision store
- Federation ledger
- Adapter health store
- Knowledge graph index

### Runtime
- Workflow runtime (`workflows.db`) — deterministic state, no execution.
- Runtime analytics (derived from adapter + workflow stores).

```
                        ┌──────────────────────────┐
        recon-fusion ──▶│   CANONICAL WIKI (only)  │◀── ingest_report / confirm_candidate
                        │  promotion.py confidence  │     (explicit, propose-only)
                        └─────────────┬────────────┘
                                      │ rebuild (one-way, read)
                                      ▼
                        ┌──────────────────────────┐
                        │   knowledge_index.db     │  (derived graph index)
                        └─────────────┬────────────┘
                                      │ read-only
        ┌─────────────────────────────┼──────────────────────────────┐
        ▼                             ▼                               ▼
 LEARNING stores              GOVERNANCE store                 RUNTIME store
 (source/verif/tool/          (knowledge_governance.db)        (workflows.db)
  decision/plugin)                    │                               │
        │                             ▼                               ▼
        ▼                     governance/drift                  runtime_analytics
 SIMULATION (decision_learning.db) ──▶ predictions (advisory)
        │
        ▼
 ADAPTERS (tool_health.db) ──▶ adapter intelligence (advisory)
        │
        ▼
 FEDERATION (federation.db) ──▶ digests (metadata-only) ──▶ IntelligenceMesh / Consensus / Marketplace (advisory)

 RULE: every arrow below the wiki is READ-ONLY derived; no arrow writes back to the wiki
       except the explicit propose-only paths at the top.
```

---

## Architecture Graph

```
Capabilities (catalog, 87 core / 153 effective)
   ├── owned by ──▶ Agents (7)            [Phase H/I, deterministic routing]
   ├── realized by ──▶ Adapters (175/439) [Phase K, SAFE profiles only]
   │                       └── health ──▶ Adapter Intelligence (advisory)
   ├── extended by ──▶ Plugins (6 packs)  [Phase M, declarative]
   │                       └── dependency graph (acyclic) + ownership
   ├── planned by ──▶ Runtime Engine (workflows.db) [Phase I, state only]
   ├── predicted by ──▶ Simulation (decision_learning.db) [Phase L, advisory]
   ├── evaluated by ──▶ Governance (knowledge_governance.db) [Phase J, read-only]
   └── shared by ──▶ Federation (federation.db) [Phase N, metadata-only]
                          ├── Registry (peers, trust/health)
                          ├── IntelligenceMesh (trends, O(E))
                          ├── ConsensusEngine (advisory)
                          └── Marketplace (advisory discovery)

All derived subsystems read the canonical wiki/index; none write it.
```

---

## Performance History

| Phase | Capabilities | Adapters | Agents | MCP (cum.) | New store | Scaling characteristic |
|-------|-------------|----------|--------|-----------|-----------|------------------------|
| A | 87 | — | — | 10 | index | recon fusion; index rebuild |
| B | 87 | — | — | 13 | — | deterministic scoring |
| C | 87 | — | — | 16 | — | propose-only synthesis |
| C.5 | 87 | — | — | 16 | — | **removed O(F²)** → O(E) |
| D / D.1 | 87 | — | — | 20 | source_learning, source_metrics | O(E) event-sourced |
| E | 87 | — | — | 22 | — | O(caps×sources) |
| F | 87 | — | — | 26 | verification_learning | O(E), WAL |
| G | 87 | — | — | 30 | — | read-only catalog |
| H | 87 | — | 6 | 34 | — | deterministic routing |
| I | 87 | — | 7 | 38 | workflows | O(steps) state |
| J | 87 | — | 7 | 44 | knowledge_governance | O(pages+events) |
| K | 87 | 175 | 7 | 50 | tool_health | O(E) health |
| L | 87 | 175 | 7 | 58 | decision_learning | O(E) load-once |
| M | 153 | 439 | 7 | 70 | plugin_health | O(C) incremental |
| N | 153 | 439 | 7 | **102**¹ | federation | **O(E), ~2µs/event reads** |

¹ Live registry total includes ~22 legacy operational tools (subfinder/httpx/nuclei/sqlmap/…) +
base tools (save_finding/get_findings/generate_report/full_recon/check_tools) alongside the
80 Knowledge-OS phase tools (A–N).

---

## Open Risks

### Architectural Debt
- ~~Branch/version drift (Phase N uncommitted, `phase-c-discovery` name)~~ **RESOLVED (2026-06-09):** Phase N tagged `phase-n-federation`; Phase O committed `f8ffdf0`, tagged **and** branched `phase-o-temporal` (dedicated release branch). History preserved.
- ~~No root `INDEX.md` (the spec's STEP-1 input)~~ **RESOLVED (2026-06-09):** root `INDEX.md` created as the navigational STEP-1 input, alongside `wiki/index.md` (wiki catalog) and `docs/adr/`.

### Scaling Risks
- IntelligenceMesh/Consensus re-materialize the imported-digest log per public method (constant multiplier, still O(E)); at very large ledgers a single shared load-once context (à la Phase-L `SimulationContext`) would cut the constant.
- Federation read latency is O(E) but absolute cost grows with total events; periodic snapshot compaction may be wanted beyond ~10⁶ events.

### Performance Risks
- Multiple independent SQLite stores each open their own connections; no shared pool. Fine offline, but many-store fan-out per MCP call adds fixed overhead.

### Coverage Gaps
- Temporal evolution of knowledge/scores is **not** tracked (no time-series layer) — governance sees "stale" but not trend trajectories.
- No unified cross-store query/correlation layer; callers wire stores individually.

### Future Bottlenecks
- `SimulationContext`-style single-load pattern not yet applied to federation.
- Plugin dependency graph is acyclic-validated but not yet versioned across federation peers.

### Dependency Concerns
- `mcp_server.py` is a single large module importing every phase; import-time failure is guarded (`_kb_guard`) but the file is a growing coupling point.

---

## Future Roadmap (Phase O → Phase Z)

> Updated automatically after every completed phase. All future phases inherit every invariant
> A–O: derived, deterministic, offline-first, advisory-only, rebuildable, canonical-wiki-centered.

### Phase O — Temporal Knowledge Intelligence & Evolution Tracking ✅ **DELIVERED**
- Implemented as `hydra/temporal_intel/` (+6 MCP tools → 108; `temporal.db`; governance block).
  O(E), 9.35 s @ 1M rows. See Architecture Lineage → Phase O. Next is Phase P.

### Phase P — Offensive Capability Intelligence ✅ **DELIVERED** (Harness V4.1)
- Implemented as `hydra/offensive_intel/` (store-free; +8 MCP tools → 116; governance block). O(E), 3.6 µs/event. 531 tests. See Architecture Lineage → Phase P. Next is Phase Q.
- **Goal:** Bring the OFFENSIVE layer to parity with Knowledge / Decision / Simulation / Marketplace /
  Federation / Temporal intelligence. Derived, advisory analytics on the **effectiveness, coverage, composition,
  overlap and attack-path value** of capabilities, workflows, agents, plugins and **skills**.
- **Package:** `hydra/offensive_intel/` — `context` (load-once O(E)) · `effectiveness` · `coverage` · `chains`
  (AttackChainIntelligence) · `overlap` · `gaps` · `skills` (Capability→Skill→Workflow→Agent bridge) · `advisor`
  (bounded) · `intelligence` (unified surface).
- **Store:** `offensive_intel.db` (derived, event-sourced, WAL, rebuildable). **MCP:** +~8 → **116**. **Perf:** O(E),
  single shared load-once context. **Integrations (read-only, no cycles):** Effective Capability Catalog, Adapter
  Registry, Dependency Graph, Agent ownership, Phase L Simulation, Phase M Marketplace, Phase N Federation, Phase O Temporal.
- **Invariants:** advisory-only · deterministic · offline-first · rebuild-identical · **NON-executing** · no
  exploitation/validation/confirmation/promotion · promotion.py/confidence.py & canonical wiki untouched.
- *(Earlier "Unified Intelligence & Cross-Store Correlation" is partially realized by `OffensiveContext`'s shared
  load-once reads; a general cross-domain correlation layer is deferred.)*
- **Full design:** `docs/PHASE_P_DESIGN.md`.

### Phase Q — Offensive Campaign Reasoning Engine ✅ **DELIVERED**
- Implemented as `hydra/campaigns/` (store-free; +8 MCP tools → 124; governance block). Campaign-level reasoning over the 12 attack-tactic phases; skills first-class (dual capability+skill graphs); post-exploitation model-only; NON-executing. O(C+D). 569 tests. See Architecture Lineage → Phase Q. Next is Phase R.
- *(The earlier "Federated Trust Graph & Reputation Hardening" concept is deferred to a later federation-track phase.)*

### Phase R — Skill Composition & Skill Graph Intelligence ✅ **DELIVERED**
- Implemented as `hydra/skill_intel/` (store-free; +8 MCP tools → 132; governance block). Skill dependency graph (derived from the capability graph), composition graph, bundles, effectiveness, coverage, gaps, marketplace; NON-executing; legacy `hydra/skills/` untouched. O(S+C+D). 603 tests. See Architecture Lineage → Phase R. Next is Phase S.
- *(The earlier "Reporting & Deliverable Synthesis Intelligence" concept is deferred to a later reporting-track phase.)*

### Phase S — Opportunity Intelligence ✅ **DELIVERED**
- Implemented as `hydra/opportunity_intel/` (store-free; +8 MCP tools → 140; governance block). Identifies **WHERE** the highest-value, least-covered, most-leveraged offensive opportunities are: an attack-surface model (Hydra's own modelled reach, NON-executing), a fused coverage synthesizer (`coverage_index` over effectiveness/verification/exercise/agent/skill), a severity-ranked blind-spot analyzer (post-exploitation phases flagged INTENTIONAL), an opportunity graph (capability↔finding-type hub/bottleneck leverage), a versioned `OpportunityScore` ranker (value + coverage_deficit + chain_potential + uniqueness + novelty + capped temporal/federation bonuses, fully explainable), and a SAFE-verb advisor. Reuses **P** (shared `OffensiveIntelligence` load) + **Q** + **R** + bounded **O**/**N** signals via one load-once `OpportunityContext`. NON-executing; O(C+D). 634 tests. See Architecture Lineage → Phase S. Next is Phase T. Distinct from the Phase-D `rank_opportunities` (discovery-candidate ranking).
- *(This supersedes the earlier "Knowledge Compaction & Snapshotting" plan for the S slot, which is deferred to a later infrastructure-track phase.)*

### Phase T — Adversary & ATT&CK Intelligence ✅ **DELIVERED**
- Implemented as `hydra/adversary_intel/` (store-free; +8 MCP tools → 148; governance block). Models Hydra's offensive tradecraft coverage against MITRE ATT&CK: a static declarative `AttackMapping` ties the 14 ATT&CK Enterprise tactics + a curated technique set onto Hydra's real capability categories; technique coverage is scored from the Phase-P effectiveness engine (`covered`/`weak`—incl. single-provider *fragile*—/`uncovered`/`model_only`). Tactic & technique coverage, skill→technique + capability→technique maps, declarative adversary-profile support scoring, gap analysis (bridging Phase-Q campaign phases + Phase-S opportunities), SAFE-verb advisor, 0-100 health. Reuses **P** (shared `OffensiveIntelligence` load) + **S** (→ **Q**/**R**) + bounded **O** via one load-once `AdversaryContext`. **Post-exploitation guard:** Resource Development / Execution / Persistence / Privilege Escalation / Defense Evasion / Lateral Movement / Collection / C2 / Exfiltration / Impact are MODEL-ONLY (zero capabilities, zero execution). NON-executing; O(T·C). 669 tests. See Architecture Lineage → Phase T. Next is Phase U.
- *(This supersedes the earlier "Multi-Tenant Scope & Isolation" plan for the T slot, which is deferred to a later infrastructure-track phase.)*

### Phase U — Observability & Audit Intelligence
- **Goal:** Derived audit/replay analytics over the immutable chain-of-thought log.
- **MCP:** +~3. **Perf:** O(events). **Invariants:** read-only.

### Phase V — Capability Confidence Calibration (advisory)
- **Goal:** Calibrate advisory predictions vs. outcomes (Brier/calibration), never altering canonical confidence bands.
- **MCP:** +~2. **Invariants:** `confidence.py` untouched.

### Phase W — Federated Simulation Exchange
- **Goal:** Exchange anonymized simulation/prediction-accuracy digests (metadata-only).
- **Dependencies:** L, N. **MCP:** +~3. **Invariants:** federation rules.

### Phase X — Adaptive Roadmap & Self-Planning Intelligence
- **Goal:** Advisory recommendation of the next capability/plugin/agent investments from all learning.
- **MCP:** +~2. **Invariants:** advisory.

### Phase Y — Cross-Ecosystem Interop & Schema Federation
- **Goal:** Versioned schema negotiation across federation protocol versions.
- **Dependencies:** N, W. **MCP:** +~2. **Invariants:** backward-compatible contracts.

### Phase Z — Architecture Self-Audit & Invariant Enforcement Engine
- **Goal:** Automated, continuous invariant verification (promotion/confidence immutability, no dual-write, determinism, federation-safety) as a first-class subsystem + steward automation.
- **Dependencies:** all. **MCP:** +~3. **Invariants:** enforces the entire registry.

---

## Maintenance Protocol
After any future phase completes, automatically update: **INDEX.md** (if/when created), **this file**,
and **CLAUDE.md** — with architecture changes, MCP count, capability/adapter counts, benchmarks,
tests, risks, and the roadmap. No manual reminder required.
