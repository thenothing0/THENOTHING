"""Tests for RelationshipEngine — inference, provenance, confidence propagation."""

import pytest

from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, EntityType, Node, RelationshipType
from hydra.graph.relationship_engine import RelationshipEngine


@pytest.fixture()
def graph():
    return KnowledgeGraph(normalize=False)


@pytest.fixture()
def engine(graph):
    return RelationshipEngine(graph)


# ── infer_relationships (single node) ───────────────────────────

class TestInferRelationships:
    def test_domain_ip_hosts(self, graph, engine):
        graph.add_node(Node(id="example.com", type=EntityType.DOMAIN, name="example.com"))
        graph.add_node(Node(id="1.2.3.4", type=EntityType.IP, name="1.2.3.4"))
        edges = engine.infer_relationships("example.com")
        assert len(edges) == 1
        assert edges[0].relationship == RelationshipType.HOSTS
        assert edges[0].confidence == 0.5
        assert "inferred" in edges[0].evidence

    def test_reverse_direction(self, graph, engine):
        """Calling infer on the target side also produces the edge."""
        graph.add_node(Node(id="d.com", type=EntityType.DOMAIN, name="d"))
        graph.add_node(Node(id="10.0.0.1", type=EntityType.IP, name="ip"))
        edges = engine.infer_relationships("10.0.0.1")
        assert len(edges) == 1
        assert edges[0].source == "d.com"

    def test_no_duplicate_inference(self, graph, engine):
        graph.add_node(Node(id="a.com", type=EntityType.DOMAIN, name="a"))
        graph.add_node(Node(id="1.1.1.1", type=EntityType.IP, name="ip"))
        engine.infer_relationships("a.com")
        edges2 = engine.infer_relationships("a.com")
        assert len(edges2) == 0
        assert graph.edge_count() == 1

    def test_nonexistent_node(self, graph, engine):
        assert engine.infer_relationships("ghost") == []

    def test_cve_affects_product(self, graph, engine):
        graph.add_node(Node(id="CVE-2024-1", type=EntityType.CVE, name="cve"))
        graph.add_node(Node(id="nginx", type=EntityType.PRODUCT, name="nginx"))
        edges = engine.infer_relationships("CVE-2024-1")
        assert any(e.relationship == RelationshipType.AFFECTS for e in edges)


# ── infer_all ───────────────────────────────────────────────────

class TestInferAll:
    def test_infers_multiple(self, graph, engine):
        graph.add_node(Node(id="x.com", type=EntityType.DOMAIN, name="x"))
        graph.add_node(Node(id="9.9.9.9", type=EntityType.IP, name="ip"))
        graph.add_node(Node(id="Apache", type=EntityType.TECHNOLOGY, name="apache"))
        count = engine.infer_all()
        assert count >= 2

    def test_idempotent(self, graph, engine):
        graph.add_node(Node(id="x.com", type=EntityType.DOMAIN, name="x"))
        graph.add_node(Node(id="5.5.5.5", type=EntityType.IP, name="ip"))
        c1 = engine.infer_all()
        c2 = engine.infer_all()
        assert c1 > 0
        assert c2 == 0

    def test_empty_graph(self, graph, engine):
        assert engine.infer_all() == 0


# ── propagate_confidence ────────────────────────────────────────

class TestPropagateConfidence:
    def test_high_confidence_endpoints(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a", confidence=1.0))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b", confidence=1.0))
        edge = Edge(source="a", target="b", relationship=RelationshipType.HOSTS,
                     evidence=["scan", "dns"])
        conf = engine.propagate_confidence(edge)
        assert conf > 0.8

    def test_low_confidence_endpoints(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a", confidence=0.1))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b", confidence=0.1))
        edge = Edge(source="a", target="b", relationship=RelationshipType.HOSTS)
        conf = engine.propagate_confidence(edge)
        assert conf < 0.5

    def test_clamped_to_one(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a", confidence=1.0))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b", confidence=1.0))
        edge = Edge(source="a", target="b", relationship=RelationshipType.HOSTS,
                     evidence=["a", "b", "c", "d", "e"])
        conf = engine.propagate_confidence(edge)
        assert conf <= 1.0


# ── provenance ──────────────────────────────────────────────────

class TestProvenance:
    def test_update_provenance(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a"))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b"))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.HOSTS))
        ok = engine.update_provenance("a", "b", "hosts", "scan-123")
        assert ok is True
        edges = graph.outgoing("a")
        assert "scan-123" in edges[0].provenance

    def test_update_provenance_idempotent(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a"))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b"))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.HOSTS))
        engine.update_provenance("a", "b", "hosts", "x")
        engine.update_provenance("a", "b", "hosts", "x")
        assert graph.outgoing("a")[0].provenance.count("x") == 1

    def test_update_provenance_missing_edge(self, graph, engine):
        assert engine.update_provenance("no", "such", "hosts", "x") is False

    def test_edges_by_provenance(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a"))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b"))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.HOSTS,
                             provenance=["tool-1"]))
        result = engine.edges_by_provenance("tool-1")
        assert len(result) == 1
        assert engine.edges_by_provenance("nope") == []
