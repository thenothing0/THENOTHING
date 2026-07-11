"""Tests for GraphIntelligence — link prediction, confidence, contradictions, IOC pivot."""

import pytest

from hydra.graph.intelligence import GraphIntelligence
from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, EntityType, Node, RelationshipType


@pytest.fixture()
def graph():
    return KnowledgeGraph(normalize=False)


@pytest.fixture()
def intel(graph):
    return GraphIntelligence(graph)


def _add(graph, nid, ntype=EntityType.HOST, **kw):
    graph.add_node(Node(id=nid, type=ntype, name=nid, **kw))


def _link(graph, src, tgt, rel=RelationshipType.RELATED_TO, **kw):
    graph.add_edge(Edge(source=src, target=tgt, relationship=rel, **kw))


# ── infer_missing_links ────────────────────────────────────────

class TestInferMissingLinks:
    def test_predicts_from_common_neighbors(self, graph, intel):
        _add(graph, "a")
        _add(graph, "b")
        _add(graph, "c")
        _add(graph, "d")
        _link(graph, "a", "c")
        _link(graph, "a", "d")
        _link(graph, "b", "c")
        _link(graph, "b", "d")
        predicted = intel.infer_missing_links(min_common_neighbors=2)
        ids = [(e.source, e.target) for e in predicted]
        assert any(("a" in p and "b" in p) for p in ids)

    def test_no_prediction_below_threshold(self, graph, intel):
        _add(graph, "a")
        _add(graph, "b")
        _add(graph, "c")
        _link(graph, "a", "c")
        predicted = intel.infer_missing_links(min_common_neighbors=2)
        assert len(predicted) == 0

    def test_skips_existing_edges(self, graph, intel):
        _add(graph, "a")
        _add(graph, "b")
        _link(graph, "a", "b")
        _link(graph, "b", "a")
        predicted = intel.infer_missing_links(min_common_neighbors=1)
        pairs = {(e.source, e.target) for e in predicted}
        assert ("a", "b") not in pairs and ("b", "a") not in pairs

    def test_empty_graph(self, graph, intel):
        assert intel.infer_missing_links() == []


# ── propagate_confidence ────────────────────────────────────────

class TestPropagateConfidence:
    def test_high_neighbors_raise_low(self, graph, intel):
        _add(graph, "low", confidence=0.1)
        _add(graph, "high", confidence=1.0)
        _link(graph, "low", "high")
        scores = intel.propagate_confidence(iterations=3, decay=0.7)
        assert scores["low"] > 0.1

    def test_isolated_node_unchanged(self, graph, intel):
        _add(graph, "alone", confidence=0.5)
        scores = intel.propagate_confidence()
        assert scores["alone"] == 0.5

    def test_clamped(self, graph, intel):
        _add(graph, "a", confidence=1.0)
        _add(graph, "b", confidence=1.0)
        _link(graph, "a", "b")
        scores = intel.propagate_confidence()
        assert all(0.0 <= v <= 1.0 for v in scores.values())


# ── aggregate_evidence ──────────────────────────────────────────

class TestAggregateEvidence:
    def test_collects_evidence(self, graph, intel):
        _add(graph, "src")
        _add(graph, "tgt")
        _link(graph, "src", "tgt", evidence=["scan-1"], provenance=["tool-a"])
        result = intel.aggregate_evidence("tgt")
        assert "scan-1" in result["evidence"]
        assert "tool-a" in result["provenance"]
        assert "src" in result["sources"]
        assert result["edge_count"] == 1

    def test_deduplicates(self, graph, intel):
        _add(graph, "a")
        _add(graph, "b")
        _add(graph, "c")
        _link(graph, "a", "c", evidence=["ev1"])
        _link(graph, "b", "c", evidence=["ev1"])
        result = intel.aggregate_evidence("c")
        assert result["evidence"].count("ev1") == 1

    def test_no_incoming(self, graph, intel):
        _add(graph, "solo")
        result = intel.aggregate_evidence("solo")
        assert result["edge_count"] == 0


# ── detect_duplicates ──────────────────────────────────────────

class TestDetectDuplicates:
    def test_finds_similar(self, graph, intel):
        graph.add_node(Node(id="api-1", type=EntityType.HOST, name="api production server"))
        graph.add_node(Node(id="api-2", type=EntityType.HOST, name="api production server"))
        dupes = intel.detect_duplicates(threshold=0.5)
        assert len(dupes) >= 1

    def test_different_types_excluded(self, graph, intel):
        _add(graph, "same-name", ntype=EntityType.HOST)
        _add(graph, "same-name-2", ntype=EntityType.DOMAIN)
        dupes = intel.detect_duplicates(threshold=0.5)
        assert len(dupes) == 0

    def test_empty(self, graph, intel):
        assert intel.detect_duplicates() == []


# ── detect_contradictions ──────────────────────────────────────

class TestDetectContradictions:
    def test_finds_conflict(self, graph, intel):
        _add(graph, "a")
        _add(graph, "b")
        _link(graph, "a", "b", rel=RelationshipType.HOSTS)
        _link(graph, "a", "b", rel=RelationshipType.TARGETS)
        contras = intel.detect_contradictions()
        assert len(contras) >= 1

    def test_no_conflict(self, graph, intel):
        _add(graph, "a")
        _add(graph, "b")
        _link(graph, "a", "b", rel=RelationshipType.HOSTS)
        assert intel.detect_contradictions() == []


# ── reconstruct_attack_chains ──────────────────────────────────

class TestAttackChains:
    def test_finds_chain(self, graph, intel):
        _add(graph, "entry", ntype=EntityType.URL)
        _add(graph, "mid", ntype=EntityType.HOST)
        _add(graph, "target", ntype=EntityType.VULNERABILITY)
        _link(graph, "entry", "mid")
        _link(graph, "mid", "target")
        chains = intel.reconstruct_attack_chains(EntityType.URL, EntityType.VULNERABILITY)
        assert len(chains) == 1
        assert chains[0] == ["entry", "mid", "target"]

    def test_no_chain(self, graph, intel):
        _add(graph, "a", ntype=EntityType.URL)
        _add(graph, "b", ntype=EntityType.HOST)
        chains = intel.reconstruct_attack_chains(EntityType.URL, EntityType.VULNERABILITY)
        assert chains == []


# ── ioc_pivot ──────────────────────────────────────────────────

class TestIOCPivot:
    def test_pivot(self, graph, intel):
        _add(graph, "ioc1", ntype=EntityType.IOC)
        _add(graph, "bad-ip", ntype=EntityType.IP)
        _add(graph, "malware-x", ntype=EntityType.MALWARE)
        _link(graph, "ioc1", "bad-ip")
        _link(graph, "bad-ip", "malware-x")
        result = intel.ioc_pivot("ioc1", max_depth=3)
        assert result["found"] is True
        assert "ip" in result["related"]

    def test_missing_ioc(self, graph, intel):
        result = intel.ioc_pivot("ghost")
        assert result["found"] is False


# ── risk_summary ────────────────────────────────────────────────

class TestRiskSummary:
    def test_counts(self, graph, intel):
        _add(graph, "vuln1", ntype=EntityType.VULNERABILITY, confidence=0.9)
        _add(graph, "cve1", ntype=EntityType.CVE, confidence=0.3)
        _add(graph, "host", ntype=EntityType.HOST)
        summary = intel.risk_summary()
        assert summary["vulnerability_count"] == 2
        assert summary["high_confidence_vulns"] == 1
        assert summary["total_nodes"] == 3

    def test_empty(self, graph, intel):
        summary = intel.risk_summary()
        assert summary["total_nodes"] == 0
        assert summary["avg_confidence"] == 0.0
