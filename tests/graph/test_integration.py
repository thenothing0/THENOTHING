"""Integration tests — full pipeline, thread-safety, cross-component."""

import threading

from hydra.graph.intelligence import GraphIntelligence
from hydra.graph.knowledge_graph import KnowledgeGraph
from hydra.graph.models import Edge, EntityType, Node, RelationshipType
from hydra.graph.query import GraphQueryEngine
from hydra.graph.relationship_engine import RelationshipEngine


class TestFullPipeline:
    def test_end_to_end(self):
        g = KnowledgeGraph(normalize=True)
        qe = GraphQueryEngine(g)
        re = RelationshipEngine(g)
        intel = GraphIntelligence(g)

        g.add_node(Node(id="WWW.Target.COM", type=EntityType.DOMAIN, name="target.com"))
        g.add_node(Node(id="93.184.216.34", type=EntityType.IP, name="ip"))
        g.add_node(Node(id="Apache", type=EntityType.TECHNOLOGY, name="Apache"))
        g.add_node(Node(id="CVE-2024-1234", type=EntityType.CVE, name="cve"))
        g.add_node(Node(id="nginx", type=EntityType.PRODUCT, name="nginx"))

        inferred = re.infer_all()
        assert inferred > 0

        path = qe.shortest_path("target.com", "93.184.216.34")
        assert len(path) >= 1

        components = qe.connected_components()
        assert len(components) >= 1

        summary = intel.risk_summary()
        assert summary["total_nodes"] == 5

    def test_normalize_then_query(self):
        g = KnowledgeGraph(normalize=True)
        qe = GraphQueryEngine(g)

        g.add_node(Node(id="WWW.X.COM.", type=EntityType.DOMAIN, name="x"))
        g.add_node(Node(id="  10.0.0.1  ", type=EntityType.IP, name="ip"))
        g.add_edge(Edge(source="x.com", target="10.0.0.1",
                         relationship=RelationshipType.HOSTS))

        result = qe.search("x.com")
        assert len(result) >= 1


class TestThreadSafety:
    def test_concurrent_pipeline(self):
        g = KnowledgeGraph(normalize=False)
        qe = GraphQueryEngine(g)
        RelationshipEngine(g)
        errors = []

        def writer(tid):
            try:
                for i in range(20):
                    g.add_node(Node(id=f"t{tid}-n{i}", type=EntityType.HOST, name=f"n{i}"))
                    if i > 0:
                        g.add_edge(Edge(
                            source=f"t{tid}-n{i-1}", target=f"t{tid}-n{i}",
                            relationship=RelationshipType.RELATED_TO,
                        ))
            except Exception as exc:
                errors.append(exc)

        def reader():
            try:
                for _ in range(20):
                    qe.connected_components()
                    g.stats()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        threads.append(threading.Thread(target=reader))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert g.node_count() == 60


class TestPerformance:
    def test_1000_nodes(self):
        g = KnowledgeGraph(normalize=False)
        qe = GraphQueryEngine(g)

        for i in range(1000):
            g.add_node(Node(id=f"n{i}", type=EntityType.HOST, name=f"node-{i}"))
        for i in range(999):
            g.add_edge(Edge(source=f"n{i}", target=f"n{i+1}",
                             relationship=RelationshipType.RELATED_TO))

        path = qe.shortest_path("n0", "n999")
        assert len(path) == 1000

        components = qe.connected_components()
        assert len(components) == 1
