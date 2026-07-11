"""Tests for existing AttackGraph engine."""

from hydra.graph.engine import AttackGraph, GraphEdge, GraphNode


def _node(nid, ntype="asset", label=None):
    return GraphNode(id=nid, node_type=ntype, label=label or nid)


def _edge(src, tgt, etype="leads_to", label=""):
    return GraphEdge(source_id=src, target_id=tgt, edge_type=etype, label=label)


class TestAttackGraph:
    def test_add_and_get_node(self):
        g = AttackGraph()
        nid = g.add_node(_node("n1", label="Node 1"))
        assert nid == "n1"
        assert "n1" in g._nodes

    def test_add_edge(self):
        g = AttackGraph()
        g.add_node(_node("a"))
        g.add_node(_node("b"))
        g.add_edge(_edge("a", "b"))
        assert "b" in g._adjacency.get("a", [])

    def test_path_finding(self):
        g = AttackGraph()
        g.add_node(_node("a", ntype="asset"))
        g.add_node(_node("b", ntype="service"))
        g.add_node(_node("c", ntype="vuln"))
        g.add_edge(_edge("a", "b"))
        g.add_edge(_edge("b", "c"))
        paths = g.find_attack_paths(start_type="asset", end_type="vuln")
        assert len(paths) >= 1
        assert paths[0] == ["a", "b", "c"]

    def test_no_path(self):
        g = AttackGraph()
        g.add_node(_node("a", ntype="asset"))
        g.add_node(_node("z", ntype="vuln"))
        assert g.find_attack_paths(start_type="asset", end_type="vuln") == []

    def test_adjacency_empty(self):
        g = AttackGraph()
        g.add_node(_node("solo"))
        assert g._adjacency.get("solo", []) == []

    def test_to_dict(self):
        g = AttackGraph()
        g.add_node(_node("x"))
        d = g.to_dict()
        assert "nodes" in d
        assert "edges" in d

    def test_multiple_edges(self):
        g = AttackGraph()
        g.add_node(_node("a"))
        g.add_node(_node("b"))
        g.add_node(_node("c"))
        g.add_edge(_edge("a", "b"))
        g.add_edge(_edge("a", "c"))
        neighbors = g._adjacency.get("a", [])
        assert set(neighbors) == {"b", "c"}

    def test_summary(self):
        g = AttackGraph()
        g.add_node(_node("a"))
        s = g.summary()
        assert isinstance(s, str)
