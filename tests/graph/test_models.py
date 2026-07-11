"""Tests for graph data models — Node, Edge, GraphStats."""



from hydra.graph.models import Edge, EntityType, GraphStats, Node, RelationshipType


class TestNode:
    def test_create_basic(self):
        n = Node(id="test", type=EntityType.HOST, name="test-host")
        assert n.id == "test"
        assert n.type == EntityType.HOST

    def test_type_coercion_from_string(self):
        n = Node(id="x", type="domain", name="x")
        assert n.type == EntityType.DOMAIN

    def test_confidence_clamped_high(self):
        n = Node(id="x", type=EntityType.HOST, name="x", confidence=2.0)
        assert n.confidence == 1.0

    def test_confidence_clamped_low(self):
        n = Node(id="x", type=EntityType.HOST, name="x", confidence=-0.5)
        assert n.confidence == 0.0

    def test_merge_higher_confidence_wins(self):
        a = Node(id="x", type=EntityType.HOST, name="x", confidence=0.5, source="scan1")
        b = Node(id="x", type=EntityType.HOST, name="x", confidence=0.9, source="scan2")
        a.merge(b)
        assert a.confidence == 0.9
        assert a.source == "scan2"

    def test_merge_keeps_own_if_higher(self):
        a = Node(id="x", type=EntityType.HOST, name="x", confidence=0.9)
        b = Node(id="x", type=EntityType.HOST, name="x", confidence=0.3)
        a.merge(b)
        assert a.confidence == 0.9

    def test_merge_adds_missing_attributes(self):
        a = Node(id="x", type=EntityType.HOST, name="x", attributes={"port": 80})
        b = Node(id="x", type=EntityType.HOST, name="x", attributes={"port": 443, "protocol": "https"})
        a.merge(b)
        assert a.attributes["port"] == 80
        assert a.attributes["protocol"] == "https"

    def test_merge_updates_timestamp(self):
        a = Node(id="x", type=EntityType.HOST, name="x")
        b = Node(id="x", type=EntityType.HOST, name="x")
        b.timestamp = a.timestamp + 100
        a.merge(b)
        assert a.timestamp == b.timestamp

    def test_default_attributes_empty(self):
        n = Node(id="x", type=EntityType.HOST, name="x")
        assert n.attributes == {}


class TestEdge:
    def test_create_basic(self):
        e = Edge(source="a", target="b", relationship=RelationshipType.HOSTS)
        assert e.source == "a"

    def test_relationship_coercion(self):
        e = Edge(source="a", target="b", relationship="hosts")
        assert e.relationship == RelationshipType.HOSTS

    def test_key(self):
        e = Edge(source="a", target="b", relationship=RelationshipType.HOSTS)
        assert e.key == ("a", "b", "hosts")

    def test_merge_evidence(self):
        a = Edge(source="x", target="y", relationship=RelationshipType.HOSTS, evidence=["scan1"])
        b = Edge(source="x", target="y", relationship=RelationshipType.HOSTS, evidence=["scan2"])
        a.merge(b)
        assert "scan1" in a.evidence
        assert "scan2" in a.evidence

    def test_merge_provenance(self):
        a = Edge(source="x", target="y", relationship=RelationshipType.HOSTS, provenance=["tool1"])
        b = Edge(source="x", target="y", relationship=RelationshipType.HOSTS, provenance=["tool2"])
        a.merge(b)
        assert set(a.provenance) == {"tool1", "tool2"}

    def test_confidence_clamped(self):
        e = Edge(source="a", target="b", relationship=RelationshipType.HOSTS, confidence=5.0)
        assert e.confidence == 1.0


class TestGraphStats:
    def test_defaults(self):
        s = GraphStats()
        assert s.node_count == 0
        assert s.density == 0.0
