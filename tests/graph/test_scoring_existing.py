"""Tests for existing GraphScoringEngine."""

from hydra.graph.engine import AttackGraph, GraphEdge, GraphNode
from hydra.graph.scoring import GraphScoringEngine


def _node(nid, ntype="asset", severity="medium"):
    return GraphNode(id=nid, node_type=ntype, label=nid, severity=severity)


def _edge(src, tgt, etype="leads_to"):
    return GraphEdge(source_id=src, target_id=tgt, edge_type=etype)


def _make_graph():
    g = AttackGraph()
    g.add_node(_node("entry", severity="low"))
    g.add_node(_node("mid", severity="medium"))
    g.add_node(_node("target", ntype="vuln", severity="critical"))
    g.add_edge(_edge("entry", "mid"))
    g.add_edge(_edge("mid", "target"))
    return g


class TestGraphScoringEngine:
    def test_create(self):
        g = _make_graph()
        scorer = GraphScoringEngine(g)
        assert scorer is not None

    def test_blast_radius(self):
        g = _make_graph()
        scorer = GraphScoringEngine(g)
        radius = scorer.estimate_blast_radius("entry")
        assert hasattr(radius, "affected_count")

    def test_risk_propagation(self):
        g = _make_graph()
        scorer = GraphScoringEngine(g)
        scores = scorer.get_risk_propagation_scores()
        assert isinstance(scores, dict)

    def test_score_all_paths(self):
        g = _make_graph()
        scorer = GraphScoringEngine(g)
        paths = scorer.score_all_paths()
        assert isinstance(paths, list)

    def test_report(self):
        g = _make_graph()
        scorer = GraphScoringEngine(g)
        report = scorer.generate_scoring_report()
        assert isinstance(report, dict)

    def test_empty_graph(self):
        g = AttackGraph()
        scorer = GraphScoringEngine(g)
        scores = scorer.get_risk_propagation_scores()
        assert scores == {}
