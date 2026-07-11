"""Tests for KnowledgeGraphEngineService — events, delegation, health."""

import pytest

from hydra.graph.models import Edge, EntityType, Node, RelationshipType
from hydra.services.event_bus import EventBus
from hydra.services.knowledge_graph_engine import KnowledgeGraphEngineService


@pytest.fixture()
def bus():
    return EventBus()


@pytest.fixture()
def svc(bus):
    return KnowledgeGraphEngineService(bus)


class TestServiceEvents:
    def test_node_added_event(self, svc, bus):
        events = []
        bus.subscribe("knowledge_graph.node_added", lambda e: events.append(e))
        svc.add_node(Node(id="x.com", type=EntityType.DOMAIN, name="x"))
        assert len(events) == 1
        assert events[0].payload["type"] == "domain"

    def test_edge_added_event(self, svc, bus):
        events = []
        bus.subscribe("knowledge_graph.edge_added", lambda e: events.append(e))
        svc.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        svc.add_node(Node(id="b", type=EntityType.HOST, name="b"))
        svc.add_edge(Edge(source="a", target="b", relationship=RelationshipType.RELATED_TO))
        assert len(events) == 1

    def test_links_inferred_event(self, svc, bus):
        events = []
        bus.subscribe("knowledge_graph.links_inferred", lambda e: events.append(e))
        svc.add_node(Node(id="d.com", type=EntityType.DOMAIN, name="d"))
        svc.add_node(Node(id="1.2.3.4", type=EntityType.IP, name="ip"))
        count = svc.infer_all()
        assert count > 0
        assert len(events) == 1

    def test_no_event_on_dupe_node(self, svc, bus):
        events = []
        bus.subscribe("knowledge_graph.node_added", lambda e: events.append(e))
        svc.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        svc.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        assert len(events) == 1


class TestServiceDelegation:
    def test_graph_property(self, svc):
        assert svc.graph is not None

    def test_query_property(self, svc):
        assert svc.query is not None

    def test_relationships_property(self, svc):
        assert svc.relationships is not None

    def test_intelligence_property(self, svc):
        assert svc.intelligence is not None

    def test_stats(self, svc):
        svc.add_node(Node(id="h", type=EntityType.HOST, name="h"))
        s = svc.stats()
        assert s.node_count == 1


class TestServiceHealth:
    def test_health_empty(self, svc):
        h = svc.get_health()
        assert h["status"] == "empty"

    def test_health_with_data(self, svc):
        svc.add_node(Node(id="a", type=EntityType.HOST, name="a"))
        h = svc.get_health()
        assert h["status"] == "healthy"
        assert h["node_count"] == 1
