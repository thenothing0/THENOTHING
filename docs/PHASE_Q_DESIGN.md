# Phase Q — Offensive Campaign Reasoning Engine (Architecture & Harness Analysis)

> Status: **ANALYSIS ONLY — READY_FOR_IMPLEMENTATION** (no code until the approval gate).
> Author: Architecture Steward · 2026-06-09 · Baseline: Phase P released (`3cf2b0d`, tag+branch `phase-p-offensive-intelligence`).
> Inherits every A–P invariant: derived · advisory-only · deterministic · offline-first · rebuild-identical ·
> **NON-executing** · no exploitation/validation/confirmation/promotion · promotion.py/confidence.py/wiki untouched.

---

## 0. Thesis & honest scope
Phase Q lifts Hydra from **capability** intelligence (P) to **campaign-level** reasoning: it reasons about attack
objectives, campaign phases, capability sequencing, skill composition, attack-path generation, gaps, and alternative
strategies — **as a planning/coverage scaffold, never as execution**. `hydra/campaigns/` is **store-free** (a pure
function of the static catalogs + the Phase-P offensive intelligence + declarative templates), so it is trivially
rebuild-identical.

**Honest capability scope (reinforces NON-executing).** Hydra is a recon / bug-bounty *intelligence* platform. The
12 campaign tactics are modeled as **declarative knowledge objects** for completeness, but Hydra capabilities map
ONLY to the early phases it actually covers (recon / enumeration / initial-access *candidate probing* / verification /
credential-access *discovery* / discovery). The post-exploitation tactics (persistence, privilege_escalation,
defense_evasion, lateral_movement, collection, exfiltration) are modeled with **`hydra_capability_coverage: none`,
`advisory_model_only: true`** — Hydra provides **zero capabilities and zero execution** for them. The engine reasons
about campaign *structure*; it never builds, enables, or runs attack capability.

---

## 1. Package layout (`hydra/campaigns/`, store-free)
```
campaign_model.py      # CampaignModel — 12 tactic phases as knowledge objects + category mapping; CampaignContext (load-once, reuses Phase-P OffensiveContext)
campaign_templates.py  # declarative playbook templates (web/cloud/container/supply_chain/red_team_prep)
workflow_graph.py      # phase→capability campaign DAG (over the 12 phases + owning agents)
objective_mapping.py   # Objective → Skills → Capabilities → Adapters → Agents (explainable)
playbooks.py           # PlaybookGenerator — materialize + score templates from Phase-P effectiveness/coverage
path_generation.py     # capability sequencing — reuses Phase-P AttackChainIntelligence + dependency graph
strategy.py            # StrategyComparator — coverage/diversity/effectiveness/dependency-risk/redundancy
simulation.py          # CampaignSimulator — counterfactual "what-if" deltas (NON-executing)
advisor.py             # CampaignAdvisor — bounded recs (missing caps / weak skills/workflows / bottlenecks / over-deps)
intelligence.py        # CampaignIntelligence — unified surface + campaign_health
util.py                # versioned deterministic scoring helpers
```

### Shared load-once substrate
`CampaignContext` builds **one** `OffensiveIntelligence` (Phase P) — which already holds one load-once
`OffensiveContext` and memoizes its analyzers — plus the effective catalog, dependency graph, ownership and skill
bridge. Every Phase-Q analyzer shares that one context ⇒ Phase Q adds only **O(C+D)** on top of cached Phase-P data
(no re-scan, no new store).

### Campaign model → Hydra category mapping (deterministic, declarative)
| Tactic phase | Hydra categories | Coverage |
|---|---|---|
| recon | reconnaissance | full |
| enumeration | reconnaissance, web, api | full |
| initial_access | web, api, cloud | candidate-probing only (advisory) |
| execution | verification | validation/simulation profile only |
| credential_access | secrets, source_code | leaked-secret discovery |
| discovery | reconnaissance, cloud | full |
| persistence / privilege_escalation / defense_evasion / lateral_movement / collection / exfiltration | — | **none — advisory model only, NON-executing** |

---

## 2. Core features → implementation (all reuse, no new offensive primitives)
1. **Campaign modeling** — 12 declarative phases + the mapping table above (knowledge objects, no execution).
2. **Objective mapping** — `objective_mapping.py` joins Phase-P `SkillIntelligence.skill_map()` → capabilities →
   `AdapterRegistry.adapters_for_capability()` → `AgentOwnershipResolver` owners; explainable chains.
3. **Capability sequencing** — `path_generation.py` wraps Phase-P `AttackChainIntelligence` (bounded DFS over
   reverse-`requires`) + effectiveness ranking → ranked plans per phase/objective.
4. **Playbook generation** — `campaign_templates.py` (5 declarative templates) materialized + scored by Phase-P
   effectiveness/coverage; advisory only.
5. **Strategy comparison** — `strategy.py` scores two strategies on coverage / diversity / effectiveness /
   dependency-risk (critical-capability reliance) / redundancy (Phase-P overlap).
6. **Campaign simulation** — `simulation.py` counterfactuals: remove capability X / damp verification quality /
   remove plugin Y / shift category coverage → recompute campaign coverage+effectiveness deltas. Bounded scenario set,
   each O(C). NON-executing, no target interaction.
7. **Campaign advisor** — `advisor.py` bounded recs: missing capabilities per phase, weak skills/workflows,
   bottlenecks (`dependency_graph.critical_capabilities()`), over-dependencies. ≤N, deterministic.
8. **Governance** — `governance_summary` gains a lazy read-only `campaign_intelligence` block (no cycle).

---

## 3. MCP Contract Delta (+8 → 124, additive)
`campaign_summary` · `campaign_objectives` · `campaign_playbooks` · `campaign_paths` · `campaign_strategies` ·
`campaign_simulation` · `campaign_gaps` · `campaign_health`. Each mirrors the Phase-P shape:
`(… , now: float = 0.0) -> str`, `_kb_guard()`, `json.dumps(_CampaignIntelligence().<view>(), indent=2)`, lazy
singleton. No rename/removal; existing 116 unchanged; baseline regen (sorted) + CLAUDE.md palette required (enforced).

---

## 4. The eight Harness analyses

### 4.1 Repository Intelligence (live)
Branch `phase-p-offensive-intelligence` · HEAD `3cf2b0d` · tag `phase-p-offensive-intelligence`. 70 hydra subpackages
(now incl. `offensive_intel`). MCP **116** (live==baseline, 0 undocumented). Caps **153**, adapters **439**, agents
**7**, plugins **6**. `hydra/campaigns/` absent (clean slate). Integration surfaces importable: `OffensiveIntelligence`,
`SimulationContext`, `CapabilityDependencyGraph`, `AgentOwnershipResolver`, `AgentRegistry`.

### 4.2 Architecture Verification
Full suite **531 passed / 6 deselected**. Phase-P offensive layer in place and green; governance already composes
decision/temporal/offensive blocks. No drift: live inventory == `HYDRA_SYSTEM_CONTEXT.md`.

### 4.3 MCP Registry Audit
live **116** == baseline **116** == documented; 0 missing / 0 orphan / 0 duplicate / 0 undocumented. Forward gate:
Phase-Q +8 will fail `test_tool_contract.py` until baseline regen (sorted) + a CLAUDE.md "Phase Q" palette section.

### 4.4 Invariant Regression Audit
promotion.py / confidence.py last changed Phase A `9bfec0c` (frozen). `offensive_intel` exec/net grep CLEAN. All A–P
invariants intact. **New Phase-Q invariant:** the campaign model is a *reasoning scaffold* — post-exploitation tactics
carry **no capabilities and no execution path** (`advisory_model_only`), preserving NON-executing.

### 4.5 Architecture Impact Analysis
Purely additive: **+1 package** `hydra/campaigns/` (~11 modules, est. ~1.0–1.3k LOC), **+8** MCP (→124), **+1** lazy
governance block, **no new store**. Edits at the edges only: `governance.py` (+~10 lines), `mcp_server.py` (+~8 thin
wrappers + import), `CLAUDE.md` (+palette), `tool_contract_baseline.json` (+8). **Zero** change to
promotion/confidence/wiki. **Dependency DAG:** `campaigns → offensive_intel(P) → {L,M,N,O,catalogs}`; `campaigns →
{simulation(L), dependency_graph, ownership, adapters, agents}`; nothing imports `campaigns`; governance lazy. Acyclic.

### 4.6 Risk Analysis
| Risk | Severity | Mitigation |
|---|---|---|
| Implying post-exploitation capability/execution | **High** | tactics mapped to `none` + `advisory_model_only`; NON-executing test; no adapter/exec path |
| Quadratic blow-up | Med | reuse the single memoized Phase-P `OffensiveIntelligence`; campaign ops O(C+D); no new O(C²) |
| Coupling cycle | Med | DAG rule + lazy governance + `test_no_import_cycle` |
| Counterfactual non-determinism | Med | fixed scenario set, injected `now`, sorted deltas, versioned weights |
| Advisory misread | Low | `advisory:true`; advisor verbs add/strengthen/diversify/rebalance — never exploit/run |
| Read amplification | Low | one shared load-once context (Phase-P) |

### 4.7 Benchmark Plan
Targets: campaign generation **< 1 s**, path generation **< 500 ms**, simulation **< 1 s**; complexity **O(C + D)**.
Plan: build one `CampaignContext` (reuses Phase-P load-once; ~0.7 s at 300k events, ms at cold-start), then assert
each campaign op adds only O(C+D) cached work; rebuild-identical (twice-equal with injected `now`); dense-graph path
bound (depth/fan-out caps inherited from Phase P); no per-call re-scan (load-once proof). No quadratic scans.

### 4.8 Test Plan (≥ +25; target ≈ +28 → ≈ 559)
`tests/campaigns/test_campaigns.py`: campaign model (12 phases, post-exploitation = no caps), objective mapping
(explainable chain shape), path generation (bounded, requires-ordering), playbooks (5 templates, scored, advisory),
strategy comparison (5 metrics, deterministic), simulation (counterfactual deltas, NON-executing, determinism),
advisor (bounded + safe verbs), health (0–100 bounded), **rebuild-identical twice-equal**, **no-exec / no-cycle /
no-canonical-import guards**. `tests/mcp/test_campaign_tools.py`: 8 tools run/JSON/deterministic/guarded/advisory,
124-count, governance `campaign_intelligence` block, promotion/confidence unchanged. Baseline +8 (sorted) + CLAUDE.md
doc-sync. **All 531 existing tests must stay green.**

---

## 5. Success criteria
advisory · deterministic · rebuildable · offline-first · NON-executing · no offensive execution · promotion/confidence
unchanged · wiki canonical · no dual-write · MCP backward-compatible · O(C+D) within benchmark targets.

**READY_FOR_IMPLEMENTATION**
