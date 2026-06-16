# PHASE_T_RELEASE_REPORT — Adversary & ATT&CK Intelligence

> Generated after the full validation pipeline · 2026-06-16 · all values verified live.

## Release identity
| Field | Value |
|-------|-------|
| **Release** | Phase T — Adversary & ATT&CK Intelligence |
| **Parent commit** | `0407491` (Phase S — `phase-s-opportunity-intelligence`) |
| **Tag** | `phase-t-adversary-intelligence` (annotated; `git describe --exact-match HEAD` ✓) |
| **Branch** | `phase-t-adversary-intelligence` (cut from `phase-s-opportunity-intelligence` `0407491`) |
| **Package** | `hydra/adversary_intel/` (11 modules, **store-free**; NEW — no earlier layer modified) |
| **HEAD == tag** | **YES** (verified at release; see Verdict) |

## System inventory (live)
| Dimension | Count |
|-----------|-------|
| **MCP tools** | **148** (+8 adversary vs Phase S's 140) |
| **Capabilities** | **153 effective** (87 core + 66 plugin) |
| **ATT&CK tactics modelled** | **14** (4 Hydra-covered + 10 model-only) |
| **ATT&CK techniques modelled** | **40** (27 in-scope + 13 model-only) |
| **Adversary profiles** | **6** |

---

## 1. Architecture Report

A store-free, offline-first layer that models Hydra's offensive tradecraft coverage against MITRE
ATT&CK. Derived, advisory, deterministic and **NON-executing** — it scores and advises over the
capability MODEL and never exploits, **emulates**, validates, confirms, promotes, or executes.

**Modules (`hydra/adversary_intel/`):**

| Module | Class | Responsibility |
|--------|-------|----------------|
| `context.py` | `AdversaryContext` | Load-once substrate. Wraps ONE Phase-P `OffensiveIntelligence` and threads that **same instance** through Phase-S `OpportunityIntelligence` (→ Phase-Q `CampaignIntelligence` + Phase-R `SkillGraphIntelligence`). Lazy, guarded Phase-O signal. |
| `attack_mapping.py` | `AttackMapping` / `AttackTactic` / `AttackTechnique` | The declarative ATT&CK knowledge object: 14 Enterprise tactics + 40 techniques mapped onto Hydra's real capability categories/finding-types. Post-exploitation guard. |
| `technique_coverage.py` | `TechniqueCoverageAnalyzer` | Per-technique status: `covered` / `weak` (incl. single-provider **fragile**) / `uncovered` / `model_only`. |
| `tactic_coverage.py` | `TacticCoverageAnalyzer` | Aggregates techniques → tactics; coverage % over in-scope techniques; model-only flagged. |
| `adversary_profiles.py` | `AdversaryProfileModeler` | 6 declarative adversary profiles scored by how well Hydra's coverage supports them. |
| `gap_analysis.py` | `AttackGapAnalyzer` | Weak/uncovered techniques, weak tactics, **Phase-Q campaign-path** bridge, **Phase-S opportunity** bridge. |
| `skill_mapping.py` | `SkillTechniqueMapper` | Which Phase-R skills contribute to which techniques/tactics. |
| `capability_mapping.py` | `CapabilityTechniqueMapper` | Capability → techniques; strongest technique coverage (effectiveness × breadth). |
| `advisor.py` | `AdversaryAdvisor` | Bounded SAFE-verb recommendations. |
| `intelligence.py` | `AdversaryIntelligence` | Unified read surface (the 8 MCP views + `attack_health`). |
| `util.py` | — | Re-exports Phase-P math; versioned scoring constants. |

**ATT&CK mapping & the post-exploitation guard.** Hydra is a left-of-boom recon & bug-bounty
platform, so the mapping is honest about scope: it covers **4 of 14** tactics — Reconnaissance
(TA0043), Initial Access (TA0001), Credential Access (TA0006), Discovery (TA0007). The other **10**
tactics (Resource Development, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral
Movement, Collection, Command and Control, Exfiltration, Impact) are **MODEL-ONLY** — zero mapped
capabilities, `advisory_model_only=true`, never a coverage defect, never executed. This extends the
Phase-Q post-exploitation guard to the full ATT&CK tactic set.

**Coverage scoring.** A technique is `covered` when ≥2 capabilities back it AND the best is effective
(≥ 0.40); `weak` when its best capability is below threshold **or** it has a single provider
(`fragile` — the Phase-S bottleneck insight applied to ATT&CK); `uncovered` when in-scope with no
capability; `model_only` otherwise. `attack_health` (versioned, `ADVERSARY_SCORING_VERSION=1`) =
`0.40·technique_coverage + 0.30·tactic_coverage + 0.30·mean_covered_effectiveness`, bounded 0-100.

**Reuse map (single OffensiveContext load):** P everywhere · S `OpportunityRanker` (gap → opportunity
bridge) · Q campaign phases (campaign-path bridge) · R skill map (skill→technique) · O emerging
(advisor `investigate`). O is lazy + guarded → cold/offline yields empty signals, preserving
determinism and rebuild-identity.

## 2. Coverage Report (live, catalog-only)

| View | Result |
|------|--------|
| Tactics | 14 modelled · **4 covered** (TA0043, TA0001, TA0006, TA0007) · **10 model-only** |
| Techniques | 40 modelled · 27 in-scope → **24 covered, 3 weak, 0 uncovered** · 13 model-only |
| Weak (fragile) techniques | T1083 File & Directory Discovery · T1133 External Remote Services · T1552.005 Cloud Instance Metadata API |
| Best-supported profiles | external_recon_operator · credential_harvester · supply_chain_recon |
| Least-supported profiles | cloud_attacker · web_app_attacker · attack_surface_mapper |
| Strongest capabilities | code_secret_scan · secret_scanning · network_mapping · passive_subdomain_intel · subdomain_discovery |
| Gap → opportunity bridge | network_mapping · directory_bruteforce · cloud_metadata_probe (lift the 3 weak techniques) |
| Adversary health | **77.55 / 100 (healthy)** — technique_coverage 0.889, tactic_coverage 0.852, mean covered effectiveness 0.548 |

The 3 weak techniques are precisely the single-provider (fragile) ones — a real, learning-independent
structural signal, not an artifact of cold-start.

## 3. Benchmark Report

| Path | Time |
|------|------|
| Cold full summary (incl. P/Q/R/S first load) | **404.3 ms** |
| Warm `adversary_summary` | 0.77 ms |
| Warm `attack_tactics` / `attack_techniques` | 0.04 / 0.02 ms |
| Warm `attack_gaps` | 0.26 ms |
| Warm `attack_health` | 0.10 ms |

**Complexity:** O(T·C) bounded by the small static technique set (T=40) over cached catalog data; the
single shared `OffensiveContext` load is O(E) and reused by P/Q/R/S/T (no duplicate scans).

## 4. Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| ATT&CK mapping read as "live coverage" | Med | Explicitly a MODEL of capability reach, NON-executing; `model_only` tactics/techniques flagged; docstrings + CLAUDE.md state scope. |
| Implying Hydra performs post-exploitation | High→mitigated | 10 tactics MODEL-ONLY with zero capabilities; advisor uses SAFE verbs only; tests assert the guard + that technique names containing "Exploit" never become executable advice. |
| Determinism vs. derived stores (O) | Low | `now` is a reference stamp; scoring is `now`-independent; O lazy + guarded → empty when absent. Rebuild-identical verified. |
| Catalog-only coverage looks complete | Low | Single-provider **fragile** rule yields honest weak techniques even with priors; health 77.55 (not 100). `data_mode` surfaced. |
| MCP registry / doc drift | Low | Baseline regenerated (additive only); doc-sync green; Phase-S count test relaxed to `>=`. |
| Roadmap divergence (T was earmarked "Multi-Tenant") | Low | Operator-directed; doc updated; Multi-Tenant deferred. |

## 5. Invariant Verification

| Invariant | Status |
|-----------|--------|
| `promotion.py` / `confidence.py` immutable | ✅ untouched (absent from diff) |
| Canonical wiki — no write / no dual-write | ✅ no wiki writer imported (import-guard test) |
| Store-free / rebuild-identical | ✅ no `sqlite3` in package; rebuild-identical test green |
| Advisory-only / NON-executing | ✅ every payload `advisory:true`; no subprocess/network/exec/eval (token test) |
| SAFE verbs only | ✅ advisor ∈ {strengthen, expand, improve, prioritize, investigate, diversify}; never execute/emulate/attack/deploy |
| Post-exploitation guard | ✅ 10 ATT&CK tactics MODEL-ONLY (zero capabilities, zero execution); asserted in unit + MCP tests |
| Shared OffensiveIntelligence load | ✅ test asserts P/Q/R/S share the one `oi`; the ATT&CK mapping shares the one `ctx` |
| Deterministic / offline-first | ✅ injected `now`; cold-start; O guarded |
| No coupling cycle | ✅ only `governance.py` (lazy) + `mcp_server.py` reference `adversary_intel`; no earlier-phase module imports it |
| MCP backward compatibility | ✅ purely additive (+8); existing 140 unchanged (baseline diff additive-only) |

## 6. Test Report

| Gate | Result |
|------|--------|
| **Full suite** | **669 passed, 6 deselected** (integration/e2e) — was 634 at Phase S (+35) |
| Phase T unit | **18/18** (`tests/adversary_intel/test_adversary_intel.py`) |
| Phase T MCP | **17/17** (`tests/mcp/test_adversary_tools.py`) |
| MCP contract | **12/12** (live == baseline == documented == 148) |
| Phase S MCP (relaxed) | 16/16 (`test_mcp_count_at_least_140`) |
| Lint | ruff clean |

Coverage of the new layer: ATT&CK mapping consistency + category/finding-type resolution, technique
status partition (incl. the 13 model-only / 27 in-scope split), single-provider fragile rule, tactic
coverage + post-exploitation guard, profile support bounds/ranking, skill & capability technique
maps, gap analysis (Phase-Q + Phase-S bridges), safe-verb advisor (action-verb safety even when
technique names contain "Exploit"), health bounds, summary shape, shared-load identity,
rebuild-identity, store-free, no-execution/no-canonical imports, promotion/confidence untouched.

## 7. MCP Contract Delta

Purely additive: **140 → 148**. New tools (all read-only / deterministic / advisory / NON-executing):

| Tool | params | required |
|------|--------|----------|
| `adversary_summary` | `now` | — |
| `attack_tactics` | `now` | — |
| `attack_techniques` | `now`, `tactic_id`, `technique_id` | — |
| `attack_gaps` | `now` | — |
| `attack_profiles` | `now`, `profile` | — |
| `attack_skills` | `now` | — |
| `attack_capabilities` | `limit`, `now` | — |
| `attack_health` | `now` | — |

Governance: `governance_summary` gains a read-only, lazy-loaded `adversary_intelligence` block.
`tests/mcp/tool_contract_baseline.json` regenerated (additive only); `CLAUDE.md` MCP palette + doc-sync
updated.

## Verdict

**ALL GATES PASS → PHASE T RELEASED.** No Phase U work begun (per operator instruction).
