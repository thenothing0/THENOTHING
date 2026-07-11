"""Integration tests — normalizer behavior inside KnowledgeGraph."""

from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, EntityType, Node, RelationshipType


def test_add_node_normalizes_domain():
    g = KnowledgeGraph(normalize=True)
    g.add_node(Node(id="WWW.Example.COM.", type=EntityType.DOMAIN, name="www.example.com"))
    assert g.get_node("example.com") is not None
    assert g.get_node("WWW.Example.COM.") is None


def test_add_node_normalizes_ip():
    g = KnowledgeGraph(normalize=True)
    g.add_node(Node(id="::ffff:10.0.0.1", type=EntityType.IP, name="10.0.0.1"))
    assert g.get_node("10.0.0.1") is not None


def test_add_edge_normalizes_ids():
    g = KnowledgeGraph(normalize=True)
    g.add_node(Node(id="WWW.A.COM", type=EntityType.DOMAIN, name="a"))
    g.add_node(Node(id="  1.2.3.4  ", type=EntityType.IP, name="b"))
    ok = g.add_edge(Edge(
        source="WWW.A.COM", target="  1.2.3.4  ",
        relationship=RelationshipType.HOSTS,
    ))
    assert ok is True
    assert g.edge_count() == 1


def test_dedup_on_normalized_collision():
    g = KnowledgeGraph(normalize=True)
    g.add_node(Node(id="www.x.com", type=EntityType.DOMAIN, name="www", confidence=0.3))
    g.add_node(Node(id="x.com", type=EntityType.DOMAIN, name="x", confidence=0.9))
    assert g.node_count() == 1
    assert g.get_node("x.com").confidence == 0.9


def test_normalizer_disabled():
    g = KnowledgeGraph(normalize=False)
    g.add_node(Node(id="WWW.A.COM", type=EntityType.DOMAIN, name="a"))
    assert g.get_node("WWW.A.COM") is not None
    assert g.get_node("a.com") is None
