"""Tests for the unified KnowledgeGraph facade."""

import json
import threading

import pytest

from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, EntityType, GraphStats, Node, RelationshipType


def _domain(name: str, **kw) -> Node:
    return Node(id=name, type=EntityType.DOMAIN, name=name, **kw)


def _ip(addr: str, **kw) -> Node:
    return Node(id=addr, type=EntityType.IP, name=addr, **kw)


def _edge(src: str, tgt: str, rel: RelationshipType = RelationshipType.HOSTS, **kw) -> Edge:
    return Edge(source=src, target=tgt, relationship=rel, **kw)


# ── CRUD ────────────────────────────────────────────────────────

class TestAddGetNode:
    def test_add_and_get(self):
        g = KnowledgeGraph()
        assert g.add_node(_domain("example.com")) is True
        n = g.get_node("example.com")
        assert n is not None
        assert n.name == "example.com"
        assert n.type == EntityType.DOMAIN

    def test_add_duplicate_merges(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com", confidence=0.5))
        assert g.add_node(_domain("a.com", confidence=0.9)) is False
        assert g.get_node("a.com").confidence == 0.9

    def test_get_nonexistent(self):
        g = KnowledgeGraph()
        assert g.get_node("nope") is None


class TestAddEdge:
    def test_add_edge(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_ip("1.2.3.4"))
        assert g.add_edge(_edge("a.com", "1.2.3.4")) is True
        assert g.edge_count() == 1

    def test_add_edge_missing_node(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        assert g.add_edge(_edge("a.com", "ghost")) is False

    def test_add_duplicate_edge_merges(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_ip("1.2.3.4"))
        g.add_edge(_edge("a.com", "1.2.3.4", confidence=0.3))
        assert g.add_edge(_edge("a.com", "1.2.3.4", confidence=0.8)) is False
        edges = g.outgoing("a.com")
        assert edges[0].confidence == 0.8


class TestRemove:
    def test_remove_node_cascades_edges(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_ip("1.2.3.4"))
        g.add_edge(_edge("a.com", "1.2.3.4"))
        assert g.remove_node("a.com") is True
        assert g.node_count() == 1
        assert g.edge_count() == 0

    def test_remove_nonexistent_node(self):
        g = KnowledgeGraph()
        assert g.remove_node("nope") is False

    def test_remove_edge(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_ip("1.2.3.4"))
        g.add_edge(_edge("a.com", "1.2.3.4"))
        assert g.remove_edge("a.com", "1.2.3.4", "hosts") is True
        assert g.edge_count() == 0

    def test_remove_edge_invalid_rel(self):
        g = KnowledgeGraph()
        assert g.remove_edge("a", "b", "nonexistent_rel") is False


# ── queries ─────────────────────────────────────────────────────

class TestQueries:
    @pytest.fixture()
    def triangle(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a"))
        g.add_node(_domain("b"))
        g.add_node(_domain("c"))
        g.add_edge(_edge("a", "b"))
        g.add_edge(_edge("b", "c"))
        g.add_edge(_edge("c", "a"))
        return g

    def test_neighbors(self, triangle):
        ns = set(triangle.neighbors("b"))
        assert ns == {"a", "c"}

    def test_outgoing(self, triangle):
        out = triangle.outgoing("a")
        assert len(out) == 1
        assert out[0].target == "b"

    def test_incoming(self, triangle):
        inc = triangle.incoming("a")
        assert len(inc) == 1
        assert inc[0].source == "c"

    def test_degree(self, triangle):
        assert triangle.degree("a") == 2  # 1 out + 1 in

    def test_all_nodes(self, triangle):
        assert len(triangle.all_nodes()) == 3

    def test_all_edges(self, triangle):
        assert len(triangle.all_edges()) == 3

    def test_node_count_edge_count(self, triangle):
        assert triangle.node_count() == 3
        assert triangle.edge_count() == 3


# ── index-backed queries ────────────────────────────────────────

class TestIndexQueries:
    def test_nodes_by_type(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_ip("1.2.3.4"))
        g.add_node(_domain("b.com"))
        domains = g.nodes_by_type(EntityType.DOMAIN)
        assert len(domains) == 2
        assert all(n.type == EntityType.DOMAIN for n in domains)

    def test_nodes_by_name(self):
        g = KnowledgeGraph()
        g.add_node(_domain("example.com"))
        g.add_node(_domain("example.org"))
        g.add_node(_domain("other.io"))
        results = g.nodes_by_name("example")
        assert len(results) == 2

    def test_edges_by_relationship(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a"))
        g.add_node(_ip("b"))
        g.add_node(Node(id="c", type=EntityType.CVE, name="CVE-2024-1234"))
        g.add_edge(_edge("a", "b", RelationshipType.HOSTS))
        g.add_edge(_edge("b", "c", RelationshipType.AFFECTS))
        hosts_edges = g.edges_by_relationship(RelationshipType.HOSTS)
        assert len(hosts_edges) == 1
        assert hosts_edges[0].source == "a"


# ── clear ───────────────────────────────────────────────────────

def test_clear():
    g = KnowledgeGraph()
    g.add_node(_domain("a"))
    g.add_node(_domain("b"))
    g.add_edge(_edge("a", "b"))
    g.clear()
    assert g.node_count() == 0
    assert g.edge_count() == 0


# ── serialization ───────────────────────────────────────────────

class TestSerialization:
    def test_export_import_roundtrip(self, tmp_path):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_ip("1.2.3.4"))
        g.add_edge(_edge("a.com", "1.2.3.4", evidence=["scan1"]))

        path = tmp_path / "graph.json"
        g.export_json(path)
        assert path.exists()

        g2 = KnowledgeGraph()
        g2.import_json(path)
        assert g2.node_count() == 2
        assert g2.edge_count() == 1

    def test_import_merges_existing(self, tmp_path):
        g1 = KnowledgeGraph()
        g1.add_node(_domain("a.com", confidence=0.5))
        path = tmp_path / "g.json"
        g1.export_json(path)

        g2 = KnowledgeGraph()
        g2.add_node(_domain("a.com", confidence=0.9))
        g2.import_json(path)
        assert g2.node_count() == 1
        assert g2.get_node("a.com").confidence == 0.9  # higher wins

    def test_export_empty_graph(self, tmp_path):
        g = KnowledgeGraph()
        path = tmp_path / "empty.json"
        g.export_json(path)
        data = json.loads(path.read_text())
        assert data["nodes"] == []
        assert data["edges"] == []


# ── stats ───────────────────────────────────────────────────────

class TestStats:
    def test_stats_populated(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a"))
        g.add_node(_ip("b"))
        g.add_edge(_edge("a", "b"))
        s = g.stats()
        assert isinstance(s, GraphStats)
        assert s.node_count == 2
        assert s.edge_count == 1
        assert s.node_types["domain"] == 1
        assert s.node_types["ip"] == 1
        assert s.edge_types["hosts"] == 1
        assert s.avg_degree > 0
        assert s.connected_components == 1

    def test_stats_two_components(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a"))
        g.add_node(_domain("b"))
        g.add_node(_domain("c"))
        g.add_node(_domain("d"))
        g.add_edge(_edge("a", "b"))
        g.add_edge(_edge("c", "d"))
        s = g.stats()
        assert s.connected_components == 2

    def test_stats_density(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a"))
        g.add_node(_domain("b"))
        g.add_node(_domain("c"))
        g.add_edge(_edge("a", "b"))
        g.add_edge(_edge("b", "c"))
        g.add_edge(_edge("c", "a"))
        s = g.stats()
        assert s.density == pytest.approx(0.5, abs=0.01)

    def test_stats_empty(self):
        g = KnowledgeGraph()
        s = g.stats()
        assert s.node_count == 0
        assert s.connected_components == 0


# ── thread safety ───────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_adds(self):
        g = KnowledgeGraph()
        errors = []

        def add_nodes(start: int):
            try:
                for i in range(50):
                    nid = f"node-{start}-{i}"
                    g.add_node(_domain(nid))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_nodes, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert g.node_count() == 500

    def test_concurrent_read_write(self):
        g = KnowledgeGraph()
        for i in range(100):
            g.add_node(_domain(f"n{i}"))
        errors = []

        def writer():
            try:
                for i in range(100, 200):
                    g.add_node(_domain(f"n{i}"))
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(200):
                    g.all_nodes()
                    g.node_count()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert g.node_count() == 200


# ── provenance & model edge cases ───────────────────────────────

class TestEdgeProvenance:
    def test_provenance_field(self):
        e = Edge(source="a", target="b", relationship=RelationshipType.HOSTS,
                 provenance=["scanner-1"])
        assert e.provenance == ["scanner-1"]

    def test_merge_provenance_dedup(self):
        e1 = Edge(source="a", target="b", relationship=RelationshipType.HOSTS,
                  provenance=["s1", "s2"])
        e2 = Edge(source="a", target="b", relationship=RelationshipType.HOSTS,
                  provenance=["s2", "s3"])
        e1.merge(e2)
        assert sorted(e1.provenance) == ["s1", "s2", "s3"]


class TestModelEdgeCases:
    def test_entity_type_coercion(self):
        n = Node(id="x", type="domain", name="x")
        assert n.type == EntityType.DOMAIN

    def test_confidence_clamped_high(self):
        n = Node(id="x", type=EntityType.DOMAIN, name="x", confidence=5.0)
        assert n.confidence == 1.0

    def test_confidence_clamped_low(self):
        n = Node(id="x", type=EntityType.DOMAIN, name="x", confidence=-1.0)
        assert n.confidence == 0.0

    def test_node_merge_higher_confidence_wins(self):
        n1 = Node(id="x", type=EntityType.DOMAIN, name="x", confidence=0.3, source="a")
        n2 = Node(id="x", type=EntityType.DOMAIN, name="x", confidence=0.8, source="b")
        n1.merge(n2)
        assert n1.confidence == 0.8
        assert n1.source == "b"

    def test_edge_key_deterministic(self):
        e = Edge(source="a", target="b", relationship=RelationshipType.HOSTS)
        assert e.key == ("a", "b", "hosts")

    def test_graph_index_sync(self):
        g = KnowledgeGraph()
        g.add_node(_domain("a.com"))
        g.add_node(_domain("b.com"))
        g.add_edge(_edge("a.com", "b.com"))
        assert len(g.nodes_by_type(EntityType.DOMAIN)) == 2
        g.remove_node("a.com")
        assert len(g.nodes_by_type(EntityType.DOMAIN)) == 1
