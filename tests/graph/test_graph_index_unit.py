"""Tests for the GraphIndex secondary index."""

from hydra.graph.graph_index import GraphIndex
from hydra.graph.models import EntityType, Node, RelationshipType


def _node(nid: str, etype: EntityType = EntityType.DOMAIN) -> Node:
    return Node(id=nid, type=etype, name=nid)


def test_index_by_type():
    idx = GraphIndex()
    idx.index_node(_node("a.com"))
    idx.index_node(_node("1.2.3.4", EntityType.IP))
    assert "a.com" in idx.nodes_by_type(EntityType.DOMAIN)
    assert "1.2.3.4" in idx.nodes_by_type(EntityType.IP)


def test_index_by_name_prefix():
    idx = GraphIndex()
    idx.index_node(_node("example.com"))
    idx.index_node(_node("example.org"))
    idx.index_node(_node("other.io"))
    assert len(idx.nodes_by_name("example")) == 2


def test_index_edge_by_relationship():
    idx = GraphIndex()
    idx.index_edge("a", "b", RelationshipType.HOSTS)
    idx.index_edge("c", "d", RelationshipType.USES)
    assert len(idx.edges_by_relationship(RelationshipType.HOSTS)) == 1


def test_remove_node_from_index():
    idx = GraphIndex()
    n = _node("a.com")
    idx.index_node(n)
    idx.remove_node(n)
    assert idx.nodes_by_type(EntityType.DOMAIN) == []


def test_remove_edge_from_index():
    idx = GraphIndex()
    idx.index_edge("a", "b", RelationshipType.HOSTS)
    idx.remove_edge("a", "b", RelationshipType.HOSTS)
    assert idx.edges_by_relationship(RelationshipType.HOSTS) == []


def test_clear():
    idx = GraphIndex()
    idx.index_node(_node("a"))
    idx.index_edge("a", "b", RelationshipType.HOSTS)
    idx.clear()
    assert idx.nodes_by_type(EntityType.DOMAIN) == []
    assert idx.edges_by_relationship(RelationshipType.HOSTS) == []
