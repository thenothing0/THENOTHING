"""Tests for ServiceContainer knowledge_graph_engine integration."""

from hydra.services import ServiceContainer
from hydra.services.event_bus import EventBus


def test_lazy_init():
    container = ServiceContainer(EventBus())
    svc = container.knowledge_graph_engine
    assert svc is not None


def test_caching():
    container = ServiceContainer(EventBus())
    a = container.knowledge_graph_engine
    b = container.knowledge_graph_engine
    assert a is b
