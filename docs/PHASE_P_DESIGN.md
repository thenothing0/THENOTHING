# Phase P — Offensive Capability Intelligence (Architecture Design · Harness V4.1)

> Status: **DESIGN ONLY — READY_FOR_IMPLEMENTATION** (no code, no codegen).
> Author: Architecture Steward · 2026-06-09 · Baseline: Phase O released (`f8ffdf0`, tag+branch `phase-o-temporal`).
> Inherits every A–O invariant: derived · advisory-only · deterministic · offline-first · rebuild-identical ·
> **NON-executing** · no exploitation/validation/confirmation/promotion · `promotion.py`/`confidence.py`/canonical wiki untouched.

---

## 0. Thesis & scope

A–O built **meta** intelligence about Hydra's *knowledge*. Phase P adds the **offensive** read: a derived, advisory,
deterministic, offline-first layer (`hydra/offensive_intel/`) that measures the **effectiveness, coverage,
composition, overlap, and attack-path value** of capabilities, workflows, agents, plugins, and **skills** — by
synthesizing the **same derived event logs** (D/F/K/L/M/N) and the **same temporal substrate** (O), indexed by
offensive dimension.

**Phase P MUST NOT perform:** exploitation · validation · confirmation · promotion · execution. It only *reads,
scores, and advises*.

**Invariant-critical insight — measure *attributed* outcomes, never canonical findings.** "Findings produced by a
capability" come from the **derived attribution already recorded** in the learning logs (Phase D `source_events`
`record_outcome`; Phase F `verification_events`; Phase K `health_events`; Phase L `outcome_events`) — never from
canonical wiki finding pages. Identical to how L and O already operate.

**Store-free core.** Every Phase P output is a **pure function of upstream derived logs + static catalogs** → no new
persistent store is required (trivially rebuild-identical). An optional `offensive_intel.db` snapshot store is an
*expansion hook* only (see §10/Future), deliberately omitted from the core module set.

---

## 1. Package layout (V4.1 module set)
```
hydra/offensive_intel/
  __init__.py        # exports the public classes
  context.py         # OffensiveContext         — load-once shared context (O(E))
  effectiveness.py   # CapabilityEffectivenessEngine — effectiveness/utility/contribution/uniqueness/redundancy
  coverage.py        # OffensiveCoverageAnalyzer — category / workflow / attack-path coverage
  chains.py          # AttackChainIntelligence  — chain popularity / effectiveness / diversity (advisory)
  overlap.py         # OverlapAnalyzer          — capability & workflow overlap / redundancy clusters
  gaps.py            # OffensiveGapAnalyzer      — missing capabilities / weak categories / weak chains
  skills.py          # SkillIntelligence        — Capability→Skill→Workflow→Agent bridge + skill effectiveness/quality
  advisor.py         # OffensiveAdvisor         — bounded recommendations (add/remove-redundancy/diversify)
  intelligence.py    # OffensiveIntelligence    — unified read surface + offensive_health (0–100)
```

### Component responsibilities (grounded in real Phase-O/L patterns)

**OffensiveContext (`context.py`)** — load-once (mirror `TemporalContext`/`SimulationContext`).
- Reads ONCE, read-only (`sqlite3 mode=ro`): the derived event logs `verification_learning/verification_events`,
  `tool_health/health_events` (→ capability **and** adapter), `source_learning/source_events`,
  `decision_learning/{outcome_events,prediction_events}`, `plugin_health/plugin_events`. Absent DB → cold-start.
- Caches the static declarative catalogs: `EffectiveCapabilityCatalog` (153), `CapabilityDependencyGraph`
  (`requires`/`enhances`/`related_to`, acyclic), adapter registry (capability×tool, SAFE `execution_profile`),
  `AgentOwnershipResolver`, and the **skill registry** (`skills/**/SKILL.yaml` + `hydra/skills/`).
- **Reuses higher intelligence as read-only priors:** Phase O `temporal_intel.TemporalContext` (trend series),
  Phase N `IntelligenceMesh` (capability/verification trend priors), Phase M `EcosystemAnalyzer` (ecosystem gaps).
- Builds per-capability / per-vuln-class / per-adapter / per-skill rollups in the single pass; memoized; injected `now`.
- O(E); every analyzer shares ONE context.

**CapabilityEffectivenessEngine (`effectiveness.py`)** — per capability:
`effectiveness` = blend(finding_yield, verification_rate, success_rate, static `confidence_weight` prior) ·
`utility` = effectiveness × breadth(finding_types×target_types) · `contribution` = marginal value across the
chains/workflows it joins · `uniqueness` = inverse overlap · `redundancy` = shared-finding_type/tool overlap with
peers. Cold-start → `status="prior_only"`. Dataclass `to_dict()` with full **explain** block; deterministic `rank()`.

**OffensiveCoverageAnalyzer (`coverage.py`)** — `category_coverage` (per-category effectiveness/verification/
exercise), `workflow_coverage` (capabilities reachable through workflows/agents), `attack_path_coverage`
(dependency-graph paths that are exercised vs dormant).

**AttackChainIntelligence (`chains.py`)** — chains built from the acyclic `requires`/`enhances` graph (bounded DFS,
depth-cap D=6, fan-out-cap F) overlaid with observed co-occurrence in `workflows.db`. `popularity` (co-occurrence
frequency) · `effectiveness` (aggregate per-cap effectiveness × verification-terminal bonus) · `diversity`
(finding-type/category spread). **Advisory; no execution** — it never runs a chain, only scores the model.

**OverlapAnalyzer (`overlap.py`)** — pairwise capability overlap (shared finding_types + shared tools + dependency
proximity) → **redundant clusters** (interchangeable capabilities) + workflow overlap (plans covering the same
capability set). Feeds `redundancy` back to effectiveness and "remove redundancy" to the advisor.

**OffensiveGapAnalyzer (`gaps.py`)** — `missing_capabilities` (finding/target types with no or only-weak capability;
categories popular in M/N but absent locally) · `weak_categories` (low mean effectiveness/verification) ·
`weak_chains` (paths with a weak/missing link or no verifying terminal).

**SkillIntelligence (`skills.py`)** — the **Capability→Skill→Workflow→Agent bridge** (inspired by Anthropic
Cybersecurity Skills, concept only). Maps each declarative skill to the capabilities it activates, then up to the
workflows/agents that compose them. `skill_effectiveness` = aggregate effectiveness of a skill's capabilities ·
`skill_quality` = coverage × verification × freshness (reusing `output/attack_memory.jsonl` outcomes when present) ·
`capability_grouping` / `task_composition` / `workflow_reasoning` = which capabilities compose a skill/task and how
skills compose into agent workflows. **Read-only — maps and scores skills, never activates/executes them.**

**OffensiveAdvisor (`advisor.py`)** — bounded (≤10), deterministic recommendations: *add capability* (gap with high
prior) · *remove redundancy* (overlap cluster, lowest-value member) · *diversify workflow* (low-diversity chain).
Each `{type, rationale, evidence, suggested_action, confidence, advisory:true}`; verbs are invest/cover/diversify/
review — **never** exploit/run/validate/confirm/promote.

**OffensiveIntelligence (`intelligence.py`)** — unified surface over ONE shared context: `offensive_summary`,
`offensive_effectiveness`, `offensive_coverage`, `offensive_chains`, `offensive_overlap`, `offensive_gaps`,
`offensive_skills`, and `offensive_health` (0–100 bounded blend: rewards verified effectiveness + coverage breadth +
chain diversity; penalizes weak categories + redundancy + gaps). Cold-start → `{score:None,status:"no_offensive_data"}`.
Every output `"advisory": True`.

---

## 2. External Reference Models (concepts extracted; **no implementation copied**)

**Anthropic Cybersecurity Skills** → adopted concepts: *skills* as declarative units, *skill quality* &
*skill effectiveness* scoring, *capability grouping*, *task composition*, *workflow reasoning*. These shape `skills.py`
and the effectiveness rubric (the repo's `offensive-osint` skill already uses a 0–100 interest rubric — generalized
here to versioned capability/skill-effectiveness scoring). **Rejected:** skill auto-activation/execution.

**Agent-Field** → adopted concepts: *offensive agents*, *attack chains*, *attack workflows*, *orchestration*,
*capability relationships*. These shape `chains.py` + `coverage.py` (attack-path coverage) + the agent bridge in
`skills.py`. **Rejected:** autonomous agent execution / closed-loop attack. Distillation for both: *analyze and advise
over a capability/skill model; never close the loop to execution.*

---

## 3. STEP-4 Deliverables

### 3.1 Architecture Impact Analysis
Purely additive, minimal blast radius: **+1 package** `hydra/offensive_intel/` (9 modules, est. ~1.0–1.3k LOC by the
Phase-O 1,099-LOC sibling), **+8** MCP tools (→ **116**), **+1** lazy `offensive_intelligence` block in
`governance_summary`. **No new store** (store-free core). Touches existing files only at the edges: `governance.py`
(+~10 lines, lazy), `mcp_server.py` (+~8 thin wrappers), `CLAUDE.md` (+palette), `tool_contract_baseline.json` (+8).
**Zero** change to `promotion.py`/`confidence.py`/wiki. Dependency direction strictly acyclic.

### 3.2 Invariant Impact Analysis
| Invariant | Impact | Preserved by |
|---|---|---|
| promotion/confidence immutable | none | not imported/touched |
| wiki canonical / no dual-write | none | reads derived attribution only; no writer import |
| derived / rebuildable | strengthened | store-free ⇒ pure function of logs |
| advisory-only / non-executing | none | `advisory:true`; verb whitelist; no subprocess/exec |
| deterministic / offline-first | none | injected `now`; cold-start; no network |
| federation metadata-only | none | consumes anonymized digests as priors; never exports |
| MCP backward-compat | additive | baseline + CLAUDE.md doc-sync test |
**New invariant — DAG rule:** `offensive_intel` imports O/L/M/N + catalogs; none import it back; governance touches it
only via lazy in-method import (enforced by a `test_no_import_cycle`).

### 3.3 Dependency Analysis
Imports (read-only): `hydra.plugins.plugin_catalog.EffectiveCapabilityCatalog`, `capabilities` dependency graph,
`hydra.adapters.adapter_registry`, `hydra.plugins.ownership`, `hydra.skills`, `hydra.temporal_intel` (O),
`hydra.intelligence.simulation` (L), `hydra.plugins`/`EcosystemAnalyzer` (M), federation `IntelligenceMesh` (N), and
the derived SQLite logs. **Reverse imports: none.** Governance → offensive only via lazy import. Acyclic, verified by test.

### 3.4 Complexity Analysis
Load **O(E)** single pass · effectiveness O(C log C) · chains bounded **O(V+E_graph)** + O(W·s) co-occurrence ·
overlap O(C²) **capped** (only within shared-finding_type buckets ⇒ near-linear in practice; hard cap on pair output) ·
coverage O(C+cat) · gaps O(C) · skills O(S·c) · summary = **O(E)** dominant. Single shared context ⇒ no re-scan.
Matches the L/N/O load-once contract; resolves the federation read-amplification Open-Risk.

### 3.5 Risk Analysis
| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | Chain/path explosion | High | depth/fan-out caps + acyclic `requires` ⇒ bounded |
| R2 | Overlap O(C²) blow-up | High | bucket by shared finding_type; cap emitted pairs |
| R3 | Coupling cycle | High | DAG rule + lazy governance + cycle test |
| R4 | Advisory misread as actionable | Med | `advisory:true` + verb whitelist + test |
| R5 | Read amplification | Med | single load-once OffensiveContext |
| R6 | Canonical/federation leakage | Med | grep-guard; anonymized digests only |
| R7 | Determinism drift / cold-start | Low | versioned constants + injected `now`; `prior_only`/`None` |
| R8 | Skill-registry coupling | Low | skills read as data; absent registry → empty, not error |

### 3.6 Benchmark Plan
Rebuild-identical (twice-equal `offensive_summary`, fixed `now`; trivial since store-free) · O(E) @ **1M events < 10 s**
(reuse Phase O's harness) · load-once proof (one scan per table) · overlap/chain worst-case dense-graph bench (bounded) ·
cold-start instant · flat per-event memory (NamedTuple).

### 3.7 Test Plan (≈ +28 → ≈ 527)
`tests/offensive/test_offensive.py`: context/cold-start; effectiveness + uniqueness/redundancy + prior fallback;
coverage (category/workflow/path); chains bounds/popularity/effectiveness/diversity; overlap clusters + cap;
gaps; skill bridge + skill effectiveness/quality; advisor cap + advisory framing; health blend; **determinism
twice-equal**. `tests/mcp/test_offensive_tools.py`: 8 tools run/JSON/deterministic/guarded/advisory. Invariant guards:
`no_exec_grep`, `no_wiki_write`, `no_import_cycle`, `protected_core_untouched`. Baseline (+8) + CLAUDE.md doc-sync.

### 3.8 MCP Contract Delta (+8 → **116**, purely additive)
`offensive_summary` · `offensive_effectiveness` · `offensive_coverage` · `offensive_chains` · `offensive_overlap` ·
`offensive_gaps` · `offensive_skills` · `offensive_health`. Each mirrors the temporal shape:
`def <tool>(… , now: float = 0.0) -> str`, `_kb_guard()` guard, `json.dumps(_OffensiveIntelligence().<view>(), indent=2)`,
lazy singleton. **No rename/removal** of the existing 108; **no write tool**. Baseline regen + palette section
**required** (enforced by `test_tool_contract.py`); `governance_summary` gains the lazy `offensive_intelligence` block.

### 3.9 Rollback Strategy
New isolated package + additive tools + one lazy governance block; **store-free** ⇒ nothing to clean in `data/`.
Rollback = `git revert` the Phase-P commit, or drop the package + revert 3 edits (governance, mcp_server, CLAUDE.md/
baseline). Lazy `try/except` governance ⇒ a broken Phase P degrades gracefully (A–O never hard-fail). Kill-switch:
env `HYDRA_DISABLE_OFFENSIVE_INTEL`. No schema migration, no canonical change.

### 3.10 Failure Mode Analysis
| Failure mode | Detection | Containment | Blast radius |
|---|---|---|---|
| Missing/absent learning DB | `path.exists()` skip | cold-start `prior_only`/`None` | none (advisory degrades) |
| Corrupt SQLite row | `sqlite3.Error` caught per-table | table skipped, partial context | that domain only |
| Skill registry malformed | YAML parse guarded | skill layer empty | `offensive_skills` only |
| Dependency-graph cycle (data error) | acyclic validator (Phase M) | chains skip cyclic edge | chains/coverage only |
| Stale federation prior | priors labeled + capped weight | offline default ignores | none authoritative |
| Governance import failure | lazy `try/except` | `{unknown}` fallback block | governance summary only |
| MCP tool exception | `_kb_guard` + handler try | JSON error string | that one tool call |
| Determinism regression | rebuild twice-equal test (CI) | block merge | caught pre-release |

---

## 4. Success Criteria
Phase P succeeds **only if**: zero invariant regressions · zero changes to `promotion.py` · zero changes to
`confidence.py` · no wiki writes · no execution capability · deterministic outputs · advisory-only behavior · MCP
backward compatibility preserved. At completion Hydra possesses, with equal analytical depth across knowledge **and**
offense: Knowledge (J) · Decision/Simulation (L) · Marketplace (M) · Federation (N) · Temporal (O) · **Offensive (P)**.

**READY_FOR_IMPLEMENTATION**
