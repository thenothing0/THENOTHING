"""
Phase Q — Offensive Campaign Reasoning Engine tests.

Deterministic, store-free, NON-executing. Asserts the post-exploitation guard, the four campaign
facets + dual graphs, skills as first-class entities, bounded/safe advisor, counterfactual
simulation (no execution), rebuild-identical determinism, and the protected-core invariants.
"""

import json
import pathlib

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.campaigns import (
    CampaignAdvisor,
    CampaignContext,
    CampaignIntelligence,
    CampaignModel,
    CampaignSimulator,
    CampaignSkillBridge,
    ObjectiveMapping,
    PathGeneration,
    PlaybookGenerator,
    StrategyComparator,
    WorkflowGraph,
)
from hydra.campaigns.campaign_model import POST_EXPLOITATION
from hydra.campaigns.campaign_templates import TEMPLATES
from hydra.campaigns.objective_mapping import OBJECTIVES, get_objective


@pytest.fixture
def cold(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "nope_th.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "nope_vr.db"))
    return CampaignContext()


def test_model_has_12_ordered_phases(cold):
    phases = CampaignModel(cold).phases()
    assert len(phases) == 12
    assert [p.order for p in phases] == list(range(1, 13))


def test_post_exploitation_guard(cold):
    for p in CampaignModel(cold).phases():
        if p.phase in POST_EXPLOITATION:
            assert p.advisory_model_only is True
            assert p.hydra_capability_coverage == "none"
            assert p.capabilities == []


def test_post_exploitation_set_is_exact():
    assert POST_EXPLOITATION == frozenset({
        "persistence", "privilege_escalation", "defense_evasion",
        "lateral_movement", "collection", "exfiltration"})


def test_skill_bridge_exposes_four_facets(cold):
    caps = [c.capability_id for c in cold.catalog().by_category("web")]
    f = CampaignSkillBridge(cold).facets(caps)
    for k in ("campaign_capabilities", "campaign_skills", "campaign_agents",
              "campaign_dependencies", "capability_graph", "skill_graph"):
        assert k in f
    assert f["advisory"] is True


def test_dual_graphs_well_formed(cold):
    caps = [c.capability_id for c in cold.catalog().by_category("web")]
    f = CampaignSkillBridge(cold).facets(caps)
    nodes = set(f["capability_graph"]["nodes"])
    for e in f["capability_graph"]["edges"]:
        assert e["from"] in nodes and e["to"] in nodes
    snodes = set(f["skill_graph"]["nodes"])
    for e in f["skill_graph"]["edges"]:
        assert e["from"] in snodes and e["to"] in snodes


def test_objective_mapping_chain(cold):
    o = ObjectiveMapping(cold).map_objective(get_objective("web_vuln_candidates"))
    assert o["objective"] == "web_vuln_candidates"
    assert len(o["capabilities"]) > 0
    for k in ("skills", "agents", "chain", "explanation"):
        assert k in o
    assert o["advisory"] is True


def test_objectives_catalog(cold):
    rep = ObjectiveMapping(cold).report()
    assert rep["count"] == len(OBJECTIVES) >= 5


def test_playbooks_generate_and_score(cold):
    pbs = PlaybookGenerator(cold).all_playbooks()
    assert len(pbs) == len(TEMPLATES) == 5
    for pb in pbs:
        assert 0.0 <= pb["effectiveness"] <= 1.0
        for k in ("campaign_capabilities", "campaign_skills", "campaign_agents",
                  "campaign_dependencies", "capability_graph", "skill_graph"):
            assert k in pb
        assert pb["advisory"] is True


def test_playbook_excludes_model_only_phases(cold):
    pb = PlaybookGenerator(cold).get("web_application_assessment")
    for ph in pb["phase_capabilities"]:
        assert ph not in POST_EXPLOITATION


def test_path_sequence_respects_requires(cold):
    pb = PlaybookGenerator(cold).get("web_application_assessment")
    caps = [c["capability_id"] for c in pb["campaign_capabilities"]]
    seq = PathGeneration(cold).sequence(caps)
    assert set(seq) == set(caps)
    if "parameter_discovery" in seq and "xss_probing" in seq:
        assert seq.index("parameter_discovery") < seq.index("xss_probing")


def test_strategy_compare_five_metrics(cold):
    out = StrategyComparator(cold).compare("web_application_assessment", "cloud_assessment")
    metrics = {"coverage", "diversity", "effectiveness", "dependency_risk", "redundancy"}
    for side in ("strategy_a", "strategy_b"):
        assert metrics <= set(out[side])
    assert set(out["better_per_metric"]) == metrics


def test_simulation_non_executing(cold):
    sim = CampaignSimulator(cold)
    out = sim.simulate("remove_capability", "http_probing")
    assert out["non_executing"] is True and out["advisory"] is True
    assert out["capabilities_lost"] >= 1
    assert sim.simulate("remove_plugin", "cloud_pack")["non_executing"] is True


def test_simulation_deterministic(cold):
    a = CampaignSimulator(cold).simulate("verification_drop", "")
    b = CampaignSimulator(cold).simulate("verification_drop", "")
    assert a == b


def test_advisor_bounded_and_safe(cold):
    recs = CampaignAdvisor(cold).recommendations(limit=6)
    assert len(recs) <= 6
    safe = {"strengthen_phase", "bottleneck", "weak_skill"}
    for r in recs:
        assert r["type"] in safe       # never exploit/run/validate/confirm/promote
        assert r["advisory"] is True


def test_workflow_graph(cold):
    g = WorkflowGraph(cold).build()
    assert g["phase_count"] == 12
    assert len(g["phase_edges"]) == 11
    assert g["advisory"] is True


def test_health_bounded(cold):
    h = CampaignIntelligence(cold).campaign_health()
    assert 0.0 <= h["campaign_health_score"] <= 100.0
    assert h["status"] in ("healthy", "watch", "degrading")
    assert h["hydra_covered_phases"] == 6
    assert h["model_only_phases"] == 6
    assert h["advisory"] is True


def test_summary_shape(cold):
    s = CampaignIntelligence(cold).campaign_summary()
    assert s["advisory"] is True
    for k in ("campaign_health", "campaign_model", "workflow_graph",
              "playbooks", "objectives", "recommendations"):
        assert k in s


def test_unknown_playbook_and_objective(cold):
    ci = CampaignIntelligence(cold)
    assert ci.campaign_playbooks(playbook="nope")["error"] == "unknown playbook"
    assert ci.campaign_objectives(objective="nope")["error"] == "unknown objective"


def test_deterministic_rebuild_identical(cold):
    a = CampaignIntelligence().campaign_summary(now=1234.0)
    b = CampaignIntelligence().campaign_summary(now=1234.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_store_free():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "campaigns"
    for p in sorted(pkg.glob("*.py")):
        assert "sqlite3" not in p.read_text(encoding="utf-8"), \
            f"campaigns must be store-free (sqlite3 in {p.name})"


def test_no_execution_or_canonical_imports():
    pkg = pathlib.Path(__file__).resolve().parents[2] / "hydra" / "campaigns"
    exec_forbidden = ["subprocess", "os.system", "popen", "requests.", "urllib.request",
                      "socket.", "exec(", "eval("]
    import_forbidden = ["promotion", "confidence", "wiki_store", "WikiStore", "wiki_writer"]
    for p in sorted(pkg.glob("*.py")):
        lines = p.read_text(encoding="utf-8").splitlines()
        full = "\n".join(lines)
        for token in exec_forbidden:
            assert token not in full, f"forbidden '{token}' in campaigns/{p.name}"
        for line in lines:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                for token in import_forbidden:
                    assert token not in line, f"forbidden import '{token}' in campaigns/{p.name}: {s}"


def test_promotion_confidence_untouched():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert hasattr(promotion_mod, "apply_promotion")
