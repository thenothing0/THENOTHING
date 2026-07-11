"""Tests for GraphSerializer."""

from hydra.graph.models import Edge, EntityType, Node, RelationshipType
from hydra.graph.serialization import GraphSerializer


def test_node_roundtrip():
    n = Node(id="x", type=EntityType.CVE, name="CVE-2024-1234",
             attributes={"score": 9.8}, confidence=0.95, source="nvd")
    d = GraphSerializer.node_to_dict(n)
    n2 = GraphSerializer.dict_to_node(d)
    assert n2.id == n.id
    assert n2.type == n.type
    assert n2.attributes == n.attributes
    assert n2.confidence == n.confidence


def test_edge_roundtrip():
    e = Edge(source="a", target="b", relationship=RelationshipType.EXPLOITS,
             confidence=0.7, evidence=["poc1"], provenance=["scanner"])
    d = GraphSerializer.edge_to_dict(e)
    e2 = GraphSerializer.dict_to_edge(d)
    assert e2.source == e.source
    assert e2.relationship == e.relationship
    assert e2.evidence == e.evidence


def test_export_import_file(tmp_path):
    nodes = [Node(id="a", type=EntityType.DOMAIN, name="a")]
    edges = [Edge(source="a", target="a", relationship=RelationshipType.RELATED_TO)]
    path = tmp_path / "g.json"
    GraphSerializer.export_graph(nodes, edges, path)
    n2, e2 = GraphSerializer.import_graph(path)
    assert len(n2) == 1
    assert len(e2) == 1


def test_import_missing_fields():
    data = {"id": "x", "type": "domain", "name": "x"}
    n = GraphSerializer.dict_to_node(data)
    assert n.confidence == 1.0
    assert n.source == "unknown"


def test_export_empty(tmp_path):
    path = tmp_path / "empty.json"
    GraphSerializer.export_graph([], [], path)
    n, e = GraphSerializer.import_graph(path)
    assert n == [] and e == []
