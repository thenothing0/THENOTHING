"""Tests for GraphQueryEngine — paths, filtering, components, centrality, search."""

import pytest

from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, EntityType, Node, RelationshipType
from hydra.graph.query import GraphQueryEngine


@pytest.fixture()
def graph():
    return KnowledgeGraph(normalize=False)


@pytest.fixture()
def engine(graph):
    return GraphQueryEngine(graph)


def _add_chain(graph, ids):
    """Add nodes A→B→C… and edges between consecutive nodes."""
    for nid in ids:
        graph.add_node(Node(id=nid, type=EntityType.HOST, name=nid))
    for i in range(len(ids) - 1):
        graph.add_edge(Edge(source=ids[i], target=ids[i + 1],
                             relationship=RelationshipType.RELATED_TO))


# ── shortest_path ───────────────────────────────────────────────

class TestShortestPath:
    def test_direct_edge(self, graph, engine):
        _add_chain(graph, ["a", "b"])
        assert engine.shortest_path("a", "b") == ["a", "b"]

    def test_two_hops(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        path = engine.shortest_path("a", "c")
        assert path == ["a", "b", "c"]

    def test_self_path(self, graph, engine):
        graph.add_node(Node(id="x", type=EntityType.HOST, name="x"))
        assert engine.shortest_path("x", "x") == ["x"]

    def test_unreachable(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        graph.add_node(Node(id="z", type=EntityType.HOST, name="z"))
        assert engine.shortest_path("a", "z") == []

    def test_nonexistent_node(self, graph, engine):
        assert engine.shortest_path("ghost", "phantom") == []


class TestAllShortestPaths:
    def test_diamond(self, graph, engine):
        for nid in ["a", "b", "c", "d"]:
            graph.add_node(Node(id=nid, type=EntityType.HOST, name=nid))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.RELATED_TO))
        graph.add_edge(Edge(source="a", target="c", relationship=RelationshipType.RELATED_TO))
        graph.add_edge(Edge(source="b", target="d", relationship=RelationshipType.RELATED_TO))
        graph.add_edge(Edge(source="c", target="d", relationship=RelationshipType.RELATED_TO))
        paths = engine.all_shortest_paths("a", "d")
        assert len(paths) == 2
        assert all(len(p) == 3 for p in paths)

    def test_cap(self, graph, engine):
        _add_chain(graph, ["a", "b"])
        paths = engine.all_shortest_paths("a", "b", cap=1)
        assert len(paths) <= 1


# ── k_hop_neighbors ────────────────────────────────────────────

class TestKHop:
    def test_one_hop(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        result = engine.k_hop_neighbors("a", 1)
        assert "b" in result
        assert "c" not in result

    def test_two_hops(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        result = engine.k_hop_neighbors("a", 2)
        assert result == {"b", "c"}

    def test_zero_k(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        assert engine.k_hop_neighbors("a", 0) == set()

    def test_nonexistent(self, graph, engine):
        assert engine.k_hop_neighbors("ghost", 5) == set()


# ── reachable / reverse_reachable ───────────────────────────────

class TestReachable:
    def test_forward(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        assert engine.reachable("a") == {"b", "c"}

    def test_forward_depth_limit(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        assert engine.reachable("a", max_depth=1) == {"b"}

    def test_reverse(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        assert engine.reverse_reachable("c") == {"a", "b"}

    def test_reverse_depth_limit(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        assert engine.reverse_reachable("c", max_depth=1) == {"b"}

    def test_nonexistent(self, graph, engine):
        assert engine.reachable("nope") == set()
        assert engine.reverse_reachable("nope") == set()


# ── filter_nodes ────────────────────────────────────────────────

class TestFilterNodes:
    def test_by_type(self, graph, engine):
        graph.add_node(Node(id="d", type=EntityType.DOMAIN, name="d"))
        graph.add_node(Node(id="i", type=EntityType.IP, name="i"))
        result = engine.filter_nodes(entity_type=EntityType.DOMAIN)
        assert len(result) == 1

    def test_by_confidence(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.HOST, name="a", confidence=0.9))
        graph.add_node(Node(id="b", type=EntityType.HOST, name="b", confidence=0.2))
        result = engine.filter_nodes(min_confidence=0.5)
        assert len(result) == 1

    def test_by_prefix(self, graph, engine):
        graph.add_node(Node(id="a1", type=EntityType.HOST, name="api-server"))
        graph.add_node(Node(id="a2", type=EntityType.HOST, name="web-server"))
        result = engine.filter_nodes(name_prefix="api")
        assert len(result) == 1

    def test_by_predicate(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.HOST, name="a", attributes={"port": 443}))
        graph.add_node(Node(id="b", type=EntityType.HOST, name="b", attributes={"port": 80}))
        result = engine.filter_nodes(predicate=lambda n: n.attributes.get("port") == 443)
        assert len(result) == 1


# ── filter_edges ────────────────────────────────────────────────

class TestFilterEdges:
    def test_by_relationship(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.DOMAIN, name="a"))
        graph.add_node(Node(id="b", type=EntityType.IP, name="b"))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.HOSTS))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.RELATED_TO))
        result = engine.filter_edges(relationship=RelationshipType.HOSTS)
        assert len(result) == 1

    def test_by_min_confidence(self, graph, engine):
        graph.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        graph.add_node(Node(id="b", type=EntityType.HOST, name="b"))
        graph.add_edge(Edge(source="a", target="b", relationship=RelationshipType.RELATED_TO, confidence=0.9))
        graph.add_edge(Edge(source="b", target="a", relationship=RelationshipType.RELATED_TO, confidence=0.1))
        result = engine.filter_edges(min_confidence=0.5)
        assert len(result) == 1

    def test_by_source_type(self, graph, engine):
        graph.add_node(Node(id="d", type=EntityType.DOMAIN, name="d"))
        graph.add_node(Node(id="i", type=EntityType.IP, name="i"))
        graph.add_edge(Edge(source="d", target="i", relationship=RelationshipType.HOSTS))
        result = engine.filter_edges(source_type=EntityType.DOMAIN)
        assert len(result) == 1
        assert engine.filter_edges(source_type=EntityType.CVE) == []


# ── search ──────────────────────────────────────────────────────

class TestSearch:
    def test_by_name(self, graph, engine):
        graph.add_node(Node(id="api.x.com", type=EntityType.HOST, name="api server"))
        graph.add_node(Node(id="db.x.com", type=EntityType.HOST, name="database"))
        result = engine.search("api server")
        assert result[0].id == "api.x.com"

    def test_by_id(self, graph, engine):
        graph.add_node(Node(id="CVE-2024-1234", type=EntityType.CVE, name="vuln"))
        result = engine.search("CVE-2024-1234")
        assert len(result) == 1

    def test_empty_query(self, graph, engine):
        assert engine.search("") == []

    def test_limit(self, graph, engine):
        for i in range(10):
            graph.add_node(Node(id=f"host-{i}", type=EntityType.HOST, name=f"server {i}"))
        result = engine.search("server", limit=3)
        assert len(result) == 3


# ── connected_components ────────────────────────────────────────

class TestConnectedComponents:
    def test_single_component(self, graph, engine):
        _add_chain(graph, ["a", "b", "c"])
        components = engine.connected_components()
        assert len(components) == 1

    def test_two_components(self, graph, engine):
        _add_chain(graph, ["a", "b"])
        graph.add_node(Node(id="z", type=EntityType.HOST, name="z"))
        components = engine.connected_components()
        assert len(components) == 2


# ── centrality ──────────────────────────────────────────────────

class TestCentrality:
    def test_hub(self, graph, engine):
        graph.add_node(Node(id="hub", type=EntityType.HOST, name="hub"))
        for i in range(4):
            nid = f"leaf{i}"
            graph.add_node(Node(id=nid, type=EntityType.HOST, name=nid))
            graph.add_edge(Edge(source="hub", target=nid, relationship=RelationshipType.RELATED_TO))
        cent = engine.centrality()
        assert cent["hub"] > cent["leaf0"]

    def test_single_node(self, graph, engine):
        graph.add_node(Node(id="solo", type=EntityType.HOST, name="solo"))
        cent = engine.centrality()
        assert cent["solo"] == 0.0


# ── subgraph ────────────────────────────────────────────────────

class TestSubgraph:
    def test_induced(self, graph, engine):
        _add_chain(graph, ["a", "b", "c", "d"])
        nodes, edges = engine.subgraph({"a", "b", "c"})
        assert len(nodes) == 3
        assert all(e.source in {"a", "b", "c"} and e.target in {"a", "b", "c"} for e in edges)

    def test_empty(self, graph, engine):
        nodes, edges = engine.subgraph(set())
        assert nodes == []
        assert edges == []
