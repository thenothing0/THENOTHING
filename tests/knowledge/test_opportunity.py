"""Phase D — opportunity ranking + feedback loop + invariant preservation."""

import hydra.knowledge.confidence as confidence_mod
from hydra.capabilities.source_learning import EV_CONFIRMED, EV_DISCOVERY, SourceLearningStore
from hydra.knowledge.discovery import PatternDiscovery
from hydra.knowledge.graph_index import KnowledgeGraphIndex
from hydra.knowledge.opportunity import (
    OpportunityScorer,
    record_fusion_discoveries,
    record_outcome,
)
from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiStore


def _seed(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    ws.upsert(NodeType.TARGET, "acme", {"tags": ["t"]}, "# acme\n")
    for s, st in (("a", "submitted"), ("b", "confirmed")):
        ws.upsert(NodeType.FINDING, f"idor-{s}",
                  {"tags": ["idor", "api"], "status": st, "target": "[[acme]]",
                   "sources": ["source.subfinder", "source.crt_sh"]},
                  f"# {s}\nidor broken access escalation\n")
    return ws


def _counts(ws):
    return {k: len(v) for k, v in KnowledgeGraphIndex.build(ws).by_type().items()}


def test_opportunity_score_components_and_range(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    cand = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor")
    o = OpportunityScorer(ws, learn).score(cand)
    assert 0.0 <= o.score <= 1.0
    assert set(o.components) == {"confidence", "effectiveness", "chain_potential",
                                 "novelty", "evidence_diversity"}
    assert o.source_ids == ["source.crt_sh", "source.subfinder"]


def test_ranking_is_deterministic(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    a = OpportunityScorer(ws, learn).rank()
    b = OpportunityScorer(ws, learn).rank()
    assert [(o.candidate_id, o.score) for o in a] == [(o.candidate_id, o.score) for o in b]


def test_feedback_raises_effectiveness(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    cand = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor")
    before = OpportunityScorer(ws, learn).score(cand).components["effectiveness"]
    # discoveries (so effectiveness has a denominator) + a confirmation
    for sid in ("source.subfinder", "source.crt_sh"):
        learn.record_source_event(sid, EV_DISCOVERY)
    record_outcome("pattern", cand.id, "confirmed", ws, learn)
    after = OpportunityScorer(ws, learn).score(cand).components["effectiveness"]
    assert after > before


def test_record_fusion_discoveries(tmp_path):
    learn = SourceLearningStore(tmp_path / "l.db")

    class _A:
        def __init__(self, sources):
            self.sources = sources

    class _R:
        assets = [_A(["source.subfinder", "source.crt_sh"]), _A(["source.subfinder"])]

    n = record_fusion_discoveries(_R(), learn)
    assert n == 3
    assert learn.scores("source.subfinder").discoveries == 2


# ── INVARIANTS: feedback touches learning only ───────────────────────────────
def test_feedback_does_not_change_wiki(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    cand = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor")
    before = _counts(ws)
    record_outcome("pattern", cand.id, "confirmed", ws, learn)
    record_outcome("pattern", cand.id, "rejected", ws, learn)
    OpportunityScorer(ws, learn).rank()
    assert _counts(ws) == before, "feedback/ranking must not mutate the canonical wiki"


def test_confidence_bands_unchanged_by_feedback(tmp_path):
    ws = _seed(tmp_path)
    learn = SourceLearningStore(tmp_path / "l.db")
    band_before = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor").confidence
    for sid in ("source.subfinder", "source.crt_sh"):
        learn.record_source_event(sid, EV_DISCOVERY)
        learn.record_source_event(sid, EV_CONFIRMED)
    record_outcome("pattern", "x", "rejected", ws, learn)
    band_after = next(c for c in PatternDiscovery(ws).discover() if c.signature == "idor").confidence
    assert band_before == band_after  # learning never feeds back into confidence


def test_confidence_module_behavior_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
