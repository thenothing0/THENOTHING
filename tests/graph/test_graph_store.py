"""Tests for the low-level GraphStore."""

from hydra.graph.graph_store import GraphStore
from hydra.graph.models import Edge, EntityType, Node, RelationshipType


def _node(nid: str) -> Node:
    return Node(id=nid, type=EntityType.DOMAIN, name=nid)


def _edge(src: str, tgt: str) -> Edge:
    return Edge(source=src, target=tgt, relationship=RelationshipType.HOSTS)


def test_add_node():
    s = GraphStore()
    assert s.add_node(_node("a")) is True
    assert s.node_count() == 1


def test_add_edge_requires_nodes():
    s = GraphStore()
    s.add_node(_node("a"))
    assert s.add_edge(_edge("a", "ghost")) is False
    assert s.edge_count() == 0


def test_remove_node_removes_edges():
    s = GraphStore()
    s.add_node(_node("a"))
    s.add_node(_node("b"))
    s.add_edge(_edge("a", "b"))
    s.remove_node("a")
    assert s.node_count() == 1
    assert s.edge_count() == 0


def test_remove_edge():
    s = GraphStore()
    s.add_node(_node("a"))
    s.add_node(_node("b"))
    s.add_edge(_edge("a", "b"))
    assert s.remove_edge("a", "b", "hosts") is True
    assert s.edge_count() == 0


def test_get_nonexistent():
    s = GraphStore()
    assert s.get_node("x") is None


def test_neighbors_unknown():
    s = GraphStore()
    assert s.neighbors("x") == []


def test_clear():
    s = GraphStore()
    s.add_node(_node("a"))
    s.clear()
    assert s.node_count() == 0
