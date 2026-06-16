"""
Phase T — Adversary & ATT&CK Intelligence tests.

Deterministic, store-free, NON-executing. Asserts the declarative ATT&CK mapping, technique & tactic
coverage, the model-only (post-exploitation) guard, adversary-profile support, skill/capability
technique maps, coverage-gap analysis (incl. the Phase-Q campaign-path and Phase-S opportunity
bridges), the safe-verb advisor, bounded health, the shared Phase-P/Q/R/S load, rebuild-identical
determinism, and the protected-core invariants.
"""

import json
import pathlib

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.adversary_intel import (
    AdversaryAdvisor,
    AdversaryContext,
    AdversaryIntelligence,
    AdversaryProfileModeler,
    AttackGapAnalyzer,
    CapabilityTechniqueMapper,
    SkillTechniqueMapper,
    TacticCoverageAnalyzer,
    TechniqueCoverageAnalyzer,
)
from hydra.adversary_intel.advisor import SAFE_VERBS
from hydra.adversary_intel.util import (
    ADVERSARY_SCORING_VERSION,
    COVERED,
    MODEL_ONLY,
    UNCOVERED,
    WEAK,
)

_STATUSES = {COVERED, WEAK, UNCOVERED, MODEL_ONLY}


@pytest.fixture
def cold(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "nope_th.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    return AdversaryContext()


# ── declarative ATT&CK mapping ───────────────────────────────────────────────────
def test_mapping_consistency(cold):
    m = cold.mapping()
    tactic_ids = {t.tactic_id for t in m.tactics()}
    assert len(m.tactics()) == 14                       # ATT&CK Enterprise tactics
    for t in m.techniques():
        assert t.tactic_id in tactic_ids                # every technique belongs to a known tactic
        # model-only techniques have no Hydra categories; in-scope ones do
        assert t.model_only == (not t.categories)
    # a technique in a model-only tactic must itself be model-only
    for t in m.techniques():
        tac = m.tactic(t.tactic_id)
        if tac.advisory_model_only:
            assert t.model_only


def test_capabilities_for_respects_category_and_findingtype(cold):
    m = cold.mapping()
    cat = cold.catalog()
    for t in m.techniques():
        caps = m.capabilities_for(t)
        if t.model_only:
            assert caps == []
            continue
        for cid in caps:
            c = cat.get(cid)
            assert c.category in t.categories
            if t.finding_types:
                assert set(c.supported_finding_types) & set(t.finding_types)


# ── technique coverage ───────────────────────────────────────────────────────────
def test_technique_status_partition(cold):
    rep = TechniqueCoverageAnalyzer(cold).report()
    assert rep["count"] == 40                            # 27 in-scope + 13 model-only
    for r in rep["techniques"]:
        assert r["status"] in _STATUSES
        assert 0.0 <= r["best_effectiveness"] <= 1.0
        assert r["advisory"] is True
        if r["status"] == MODEL_ONLY:
            assert r["advisory_model_only"] is True and r["capability_count"] == 0
    bs = rep["by_status"]
    assert bs.get(MODEL_ONLY, 0) == 13
    assert rep["in_scope"] == 27
    assert (bs.get(COVERED, 0) + bs.get(WEAK, 0) + bs.get(UNCOVERED, 0)) == 27


def test_single_provider_is_weak(cold):
    # a fragile (single-provider) in-scope technique is never reported as fully covered
    for r in TechniqueCoverageAnalyzer(cold).rank():
        if not r.model_only and r.fragile:
            assert r.status == WEAK


def test_technique_single_and_unknown(cold):
    tca = TechniqueCoverageAnalyzer(cold)
    assert tca.get("T1190").technique_id == "T1190"
    assert tca.get("T0000") is None


# ── tactic coverage + post-exploitation guard ────────────────────────────────────
def test_tactic_coverage_and_model_only_guard(cold):
    rep = TacticCoverageAnalyzer(cold).report()
    assert rep["count"] == 14
    # the post-exploitation / out-of-scope tactics are model-only with zero in-scope techniques
    model_only = set(rep["model_only_tactics"])
    assert {"TA0003", "TA0004", "TA0005", "TA0008", "TA0009", "TA0010", "TA0040"} <= model_only
    for t in rep["tactics"]:
        assert 0.0 <= t["coverage_pct"] <= 100.0
        if t["advisory_model_only"]:
            assert t["in_scope"] == 0 and t["coverage_pct"] == 0.0
    # Hydra covers the left-of-boom tactics
    assert set(rep["hydra_covered_tactics"]) == {"TA0043", "TA0001", "TA0006", "TA0007"}


# ── adversary profiles ───────────────────────────────────────────────────────────
def test_profiles_bounded_ranked(cold):
    rep = AdversaryProfileModeler(cold).report()
    assert rep["count"] == 6
    scores = [p["support_score"] for p in rep["profiles"]]
    assert scores == sorted(scores, reverse=True)
    for p in rep["profiles"]:
        assert 0.0 <= p["support_score"] <= 1.0
        assert 0.0 <= p["supported_pct"] <= 100.0
    assert AdversaryProfileModeler(cold).get("nope_profile") is None
    assert AdversaryProfileModeler(cold).report(profile_id="nope_profile")["error"] == "unknown profile"


# ── skill / capability technique maps ────────────────────────────────────────────
def test_skill_technique_map(cold):
    rep = SkillTechniqueMapper(cold).report()
    assert rep["count"] >= 1
    for s in rep["skills"]:
        assert s["technique_count"] == len(s["techniques"])
        assert s["tactic_count"] == len(s["tactics"])


def test_capability_technique_map_strength_bounded(cold):
    rep = CapabilityTechniqueMapper(cold).report()
    strengths = [c["coverage_strength"] for c in rep["capabilities"]]
    assert strengths == sorted(strengths, reverse=True)
    for c in rep["capabilities"]:
        assert 0.0 <= c["coverage_strength"] <= 1.0
        assert c["technique_count"] >= 1               # only mapped capabilities appear


# ── gap analysis (Phase-Q + Phase-S bridges) ─────────────────────────────────────
def test_gap_analysis_bridges(cold):
    rep = AttackGapAnalyzer(cold).report()
    for k in ("weak_techniques", "uncovered_techniques", "weak_tactics",
              "campaign_paths_lacking_coverage", "opportunities_improving_coverage"):
        assert k in rep
    # campaign-path bridge (Phase Q): non-model-only phases only, bounded percentages
    for p in rep["campaign_paths_lacking_coverage"]:
        assert 0.0 <= p["coverage_pct"] <= 100.0
    # opportunity bridge (Phase S): bounded scores, each helps >=1 weak technique
    for o in rep["opportunities_improving_coverage"]:
        assert 0.0 <= o["opportunity_score"] <= 1.0
        assert o["technique_count"] >= 1


# ── advisor (safe verbs only) ────────────────────────────────────────────────────
def test_advisor_bounded_and_safe(cold):
    # NOTE: ATT&CK technique NAMES legitimately contain words like "Exploit"/"Exploitation"
    # (T1190, T1212) — so the safety invariant is checked on the recommendation's ACTION VERB, not
    # on arbitrary substrings. The advisor must only ever advise a SAFE verb.
    recs = AdversaryAdvisor(cold).recommendations(limit=8)
    assert len(recs) <= 8
    for rec in recs:
        assert rec["type"] in SAFE_VERBS
        assert rec["suggested_action"].split()[0].lower() in SAFE_VERBS
        for unsafe in ("execute", "emulate", "deploy", "run "):
            assert not rec["suggested_action"].lower().startswith(unsafe)
        assert rec["advisory"] is True
        assert 0.0 <= rec["confidence"] <= 1.0


# ── health & summary ─────────────────────────────────────────────────────────────
def test_health_bounded(cold):
    h = AdversaryIntelligence(cold).attack_health()
    assert 0.0 <= h["adversary_health_score"] <= 100.0
    assert h["status"] in ("healthy", "watch", "degrading")
    assert h["data_mode"] == "catalog_only"
    assert 0.0 <= h["technique_coverage"] <= 1.0
    assert h["model_only_tactics"] == 10
    assert h["advisory"] is True


def test_summary_shape(cold):
    s = AdversaryIntelligence(cold).adversary_summary()
    assert s["advisory"] is True
    assert s["scoring_version"] == ADVERSARY_SCORING_VERSION
    for k in ("adversary_health", "tactics", "techniques", "best_supported_profiles",
              "gaps", "top_capabilities", "recommendations"):
        assert k in s


# ── shared load (P/Q/R/S/T share ONE OffensiveIntelligence) ──────────────────────
def test_shared_offensive_load(cold):
    assert cold.opportunity().oc.oi is cold.oi          # Phase-S shares it
    assert cold.skill().cc.oi is cold.oi                # Phase-R shares it (via S)
    assert cold.campaign().cc.oi is cold.oi             # Phase-Q shares it (via S)
    assert cold.mapping()._ctx is cold.ctx              # ATT&CK mapping shares the load-once ctx


# ── determinism / invariants ─────────────────────────────────────────────────────
def test_deterministic_rebuild_identical():
    a = AdversaryIntelligence().adversary_summary(now=5150.0)
    b = AdversaryIntelligence().adversary_summary(now=5150.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_store_free():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "adversary_intel"
    for p in sorted(pkg.glob("*.py")):
        assert "sqlite3" not in p.read_text(encoding="utf-8"), \
            f"adversary_intel must be store-free (sqlite3 in {p.name})"


def test_no_execution_or_canonical_imports():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "adversary_intel"
    exec_forbidden = ["subprocess", "os.system", "popen", "requests.", "urllib.request",
                      "socket.", "exec(", "eval("]
    import_forbidden = ["promotion", "confidence", "wiki_store", "WikiStore", "wiki_writer"]
    for p in sorted(pkg.glob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        full = "\n".join(lines)
        for token in exec_forbidden:
            assert token not in full, f"forbidden '{token}' in adversary_intel/{p.name}"
        for line in lines:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                for token in import_forbidden:
                    assert token not in line, \
                        f"forbidden import '{token}' in adversary_intel/{p.name}: {s}"


def test_promotion_confidence_untouched():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert hasattr(promotion_mod, "apply_promotion")
