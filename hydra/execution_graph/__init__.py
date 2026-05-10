"""
╔══════════════════════════════════════════════════════════════╗
║  Execution Graph Engine — DAG-Based Workflow Execution      ║
║  Replaces linear pipelines with branching, conditional,     ║
║  recursive task graphs with rollback + snapshot support      ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("hydra.execution_graph")


class NodeState(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class EdgeType(str, Enum):
    DEPENDENCY = "dependency"       # B runs after A completes
    CONDITIONAL = "conditional"     # B runs only if A's output matches condition
    EXPANSION = "expansion"         # A dynamically creates B at runtime
    ROLLBACK = "rollback"           # B runs if A fails


@dataclass
class ExecutionNode:
    """A single task node in the execution DAG."""
    id: str
    name: str
    task_type: str                          # tool, agent, decision, expansion
    payload: Dict[str, Any] = field(default_factory=dict)
    state: NodeState = NodeState.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: float = 0.0
    completed_at: float = 0.0
    retries: int = 0
    max_retries: int = 2
    timeout: int = 120
    priority: int = 2                       # 0=critical, 1=high, 2=normal, 3=low
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Conditions for conditional execution
    condition: Optional[Dict[str, Any]] = None  # {"field": "...", "op": "...", "value": ...}

    @property
    def duration(self) -> float:
        if self.started_at and self.completed_at:
            return round(self.completed_at - self.started_at, 2)
        return 0.0


@dataclass
class ExecutionEdge:
    """Directed edge between nodes."""
    source: str      # node ID
    target: str      # node ID
    edge_type: EdgeType = EdgeType.DEPENDENCY
    condition: Optional[Dict[str, Any]] = None  # for conditional edges
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphSnapshot:
    """Serializable snapshot of graph state for recovery."""
    timestamp: float
    nodes: Dict[str, Dict]
    edges: List[Dict]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionGraph:
    """
    DAG-based execution graph engine.

    Capabilities:
      - Branching execution (parallel paths)
      - Conditional execution (run if condition met)
      - Recursive task expansion (nodes spawn sub-graphs)
      - Dependency tracking (topological ordering)
      - Workflow rollback (undo on failure)
      - Execution snapshots (checkpoint/restore)
      - Multi-path exploration
      - Speculative execution
      - Priority-based scheduling
    """

    def __init__(self, name: str = "workflow"):
        self.name = name
        self.id = str(uuid.uuid4())[:8]
        self._nodes: Dict[str, ExecutionNode] = {}
        self._edges: List[ExecutionEdge] = []
        self._adjacency: Dict[str, List[str]] = {}    # node -> children
        self._reverse_adj: Dict[str, List[str]] = {}   # node -> parents
        self._snapshots: List[GraphSnapshot] = []
        self._on_complete: Dict[str, List[Callable]] = {}  # callbacks
        self._execution_order: List[str] = []
        self._start_time = 0.0

    # ── Graph Construction ────────────────────

    def add_node(self, node: ExecutionNode) -> str:
        """Add a node to the graph."""
        self._nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []
        if node.id not in self._reverse_adj:
            self._reverse_adj[node.id] = []
        return node.id

    def add_edge(self, edge: ExecutionEdge):
        """Add a directed edge between nodes."""
        if edge.source not in self._nodes or edge.target not in self._nodes:
            raise ValueError(f"Edge references unknown node: {edge.source} -> {edge.target}")
        self._edges.append(edge)
        if edge.target not in self._adjacency.get(edge.source, []):
            self._adjacency.setdefault(edge.source, []).append(edge.target)
        if edge.source not in self._reverse_adj.get(edge.target, []):
            self._reverse_adj.setdefault(edge.target, []).append(edge.source)

    def connect(self, source_id: str, target_id: str,
                edge_type: EdgeType = EdgeType.DEPENDENCY,
                condition: Optional[Dict] = None) -> ExecutionEdge:
        """Shorthand to create and add an edge."""
        edge = ExecutionEdge(source=source_id, target=target_id,
                             edge_type=edge_type, condition=condition)
        self.add_edge(edge)
        return edge

    def create_node(self, name: str, task_type: str = "tool",
                    payload: Optional[Dict] = None, **kwargs) -> ExecutionNode:
        """Create, add, and return a node."""
        node = ExecutionNode(
            id=f"{name}_{str(uuid.uuid4())[:6]}",
            name=name, task_type=task_type,
            payload=payload or {}, **kwargs,
        )
        self.add_node(node)
        return node

    # ── Graph Analysis ────────────────────────

    def get_ready_nodes(self) -> List[ExecutionNode]:
        """Get all nodes whose dependencies are satisfied."""
        ready = []
        for node_id, node in self._nodes.items():
            if node.state != NodeState.PENDING:
                continue
            parents = self._reverse_adj.get(node_id, [])
            if not parents:
                node.state = NodeState.READY
                ready.append(node)
                continue
            # Check all parent edges
            all_deps_met = True
            for parent_id in parents:
                parent = self._nodes.get(parent_id)
                edge = self._get_edge(parent_id, node_id)
                if not parent or not edge:
                    continue
                if edge.edge_type == EdgeType.DEPENDENCY:
                    if parent.state != NodeState.COMPLETED:
                        all_deps_met = False
                        break
                elif edge.edge_type == EdgeType.CONDITIONAL:
                    if parent.state != NodeState.COMPLETED:
                        all_deps_met = False
                        break
                    if not self._evaluate_condition(edge.condition, parent.result):
                        node.state = NodeState.SKIPPED
                        all_deps_met = False
                        break
                elif edge.edge_type == EdgeType.ROLLBACK:
                    if parent.state != NodeState.FAILED:
                        all_deps_met = False
                        break
            if all_deps_met and node.state == NodeState.PENDING:
                node.state = NodeState.READY
                ready.append(node)

        ready.sort(key=lambda n: n.priority)
        return ready

    def topological_sort(self) -> List[str]:
        """Compute topological execution order."""
        visited: Set[str] = set()
        order: List[str] = []

        def dfs(node_id: str):
            if node_id in visited:
                return
            visited.add(node_id)
            for child_id in self._adjacency.get(node_id, []):
                dfs(child_id)
            order.append(node_id)

        for nid in self._nodes:
            dfs(nid)

        order.reverse()
        self._execution_order = order
        return order

    def has_cycle(self) -> bool:
        """Detect cycles in the graph."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {nid: WHITE for nid in self._nodes}

        def dfs(nid):
            color[nid] = GRAY
            for child in self._adjacency.get(nid, []):
                if color[child] == GRAY:
                    return True
                if color[child] == WHITE and dfs(child):
                    return True
            color[nid] = BLACK
            return False

        return any(dfs(nid) for nid in self._nodes if color[nid] == WHITE)

    # ── Runtime Expansion ─────────────────────

    def expand_node(self, parent_id: str, sub_nodes: List[ExecutionNode],
                    sub_edges: Optional[List[ExecutionEdge]] = None):
        """Dynamically expand a node into a sub-graph at runtime."""
        if parent_id not in self._nodes:
            raise ValueError(f"Unknown parent node: {parent_id}")

        # Add all sub-nodes
        for node in sub_nodes:
            self.add_node(node)

        # Connect first sub-node to parent's dependencies
        if sub_nodes:
            self.connect(parent_id, sub_nodes[0].id, EdgeType.EXPANSION)

        # Add sub-edges
        if sub_edges:
            for edge in sub_edges:
                self.add_edge(edge)
        else:
            # Chain sub-nodes sequentially
            for i in range(len(sub_nodes) - 1):
                self.connect(sub_nodes[i].id, sub_nodes[i + 1].id)

        # Reconnect parent's children to last sub-node
        children = self._adjacency.get(parent_id, [])[:]
        last_sub = sub_nodes[-1] if sub_nodes else None
        if last_sub:
            for child_id in children:
                if child_id != sub_nodes[0].id:
                    self.connect(last_sub.id, child_id)

        # Mark parent as completed
        self._nodes[parent_id].state = NodeState.COMPLETED
        logger.info(f"Expanded {parent_id} into {len(sub_nodes)} sub-nodes")

    # ── Snapshot & Recovery ───────────────────

    def snapshot(self) -> GraphSnapshot:
        """Create a serializable snapshot of current state."""
        snap = GraphSnapshot(
            timestamp=time.time(),
            nodes={
                nid: {
                    "id": n.id, "name": n.name, "state": n.state.value,
                    "task_type": n.task_type, "priority": n.priority,
                    "duration": n.duration, "error": n.error,
                }
                for nid, n in self._nodes.items()
            },
            edges=[
                {"source": e.source, "target": e.target,
                 "type": e.edge_type.value}
                for e in self._edges
            ],
            metadata={"name": self.name, "id": self.id},
        )
        self._snapshots.append(snap)
        return snap

    def restore(self, snapshot: GraphSnapshot):
        """Restore graph state from a snapshot."""
        for nid, data in snapshot.nodes.items():
            if nid in self._nodes:
                self._nodes[nid].state = NodeState(data["state"])
                self._nodes[nid].error = data.get("error")

    def save_snapshot(self, path: str):
        """Save current snapshot to disk."""
        snap = self.snapshot()
        Path(path).write_text(json.dumps({
            "timestamp": snap.timestamp,
            "nodes": snap.nodes,
            "edges": snap.edges,
            "metadata": snap.metadata,
        }, indent=2), encoding="utf-8")

    # ── Execution ─────────────────────────────

    async def execute(self, executor: Callable, max_concurrent: int = 5):
        """
        Execute the graph using the provided executor function.

        executor(node: ExecutionNode) -> Dict[str, Any]
        """
        self._start_time = time.time()
        if self.has_cycle():
            raise RuntimeError("Execution graph contains cycles")

        active: Set[str] = set()
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_node(node: ExecutionNode):
            async with semaphore:
                node.state = NodeState.RUNNING
                node.started_at = time.time()
                active.add(node.id)
                try:
                    result = await asyncio.wait_for(
                        executor(node), timeout=node.timeout
                    )
                    node.result = result
                    node.state = NodeState.COMPLETED
                    node.completed_at = time.time()
                    logger.debug(f"Node {node.name} completed in {node.duration}s")
                except asyncio.TimeoutError:
                    node.error = "Timeout"
                    node.state = NodeState.FAILED
                    node.completed_at = time.time()
                except Exception as e:
                    node.error = str(e)
                    if node.retries < node.max_retries:
                        node.retries += 1
                        node.state = NodeState.PENDING
                        logger.warning(f"Retrying {node.name} ({node.retries}/{node.max_retries})")
                    else:
                        node.state = NodeState.FAILED
                        node.completed_at = time.time()
                finally:
                    active.discard(node.id)

        # Main execution loop
        while True:
            ready = self.get_ready_nodes()
            if not ready and not active:
                break  # All done
            if not ready:
                await asyncio.sleep(0.1)
                continue

            tasks = [asyncio.create_task(run_node(n)) for n in ready]
            await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = round(time.time() - self._start_time, 2)
        logger.info(f"Graph {self.name} completed in {elapsed}s "
                     f"({self.completed_count}/{self.total_count} nodes)")

    # ── Helpers ───────────────────────────────

    def _get_edge(self, source: str, target: str) -> Optional[ExecutionEdge]:
        for e in self._edges:
            if e.source == source and e.target == target:
                return e
        return None

    def _evaluate_condition(self, condition: Optional[Dict], result: Optional[Dict]) -> bool:
        if not condition or not result:
            return True
        field = condition.get("field", "")
        op = condition.get("op", "exists")
        value = condition.get("value")
        actual = result.get(field)
        if op == "exists":
            return actual is not None
        elif op == "eq":
            return actual == value
        elif op == "gt":
            return actual is not None and actual > value
        elif op == "contains":
            return value in str(actual) if actual else False
        elif op == "not_empty":
            return bool(actual)
        return True

    @property
    def total_count(self) -> int:
        return len(self._nodes)

    @property
    def completed_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.state == NodeState.COMPLETED)

    @property
    def failed_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.state == NodeState.FAILED)

    def get_summary(self) -> Dict[str, Any]:
        states = {}
        for n in self._nodes.values():
            states[n.state.value] = states.get(n.state.value, 0) + 1
        return {
            "name": self.name, "id": self.id,
            "total_nodes": self.total_count,
            "total_edges": len(self._edges),
            "states": states,
            "elapsed": round(time.time() - self._start_time, 2) if self._start_time else 0,
            "snapshots": len(self._snapshots),
        }


# ──────────────────────────────────────────────
#  Pre-built Graph Templates
# ──────────────────────────────────────────────

def build_osint_recon_graph(target: str) -> ExecutionGraph:
    """Build the OSINT recon DAG."""
    g = ExecutionGraph(name=f"osint_recon:{target}")

    # Phase 1: Parallel passive recon
    osint = g.create_node("osint_full", "agent", {"target": target}, priority=0)
    fingerprint = g.create_node("fingerprint", "agent", {"target": target}, priority=0)
    subfinder = g.create_node("subfinder", "tool", {"target": target}, priority=0)

    # Phase 2: Merge + probe (depends on phase 1)
    merge = g.create_node("merge_subdomains", "decision", {"target": target}, priority=1)
    g.connect(osint.id, merge.id)
    g.connect(subfinder.id, merge.id)

    httpx = g.create_node("httpx_probe", "tool", {"target": target}, priority=1)
    g.connect(merge.id, httpx.id)

    # Phase 2b: Pack activation (depends on fingerprint)
    activate_packs = g.create_node("activate_packs", "decision", {"target": target}, priority=1)
    g.connect(fingerprint.id, activate_packs.id)

    # Phase 3: Targeted scan (depends on both paths)
    nuclei = g.create_node("nuclei_scan", "tool", {"target": target, "severity": "medium,high,critical"}, priority=2)
    g.connect(httpx.id, nuclei.id)
    g.connect(activate_packs.id, nuclei.id)

    # Phase 4: Validation
    validate = g.create_node("validate_findings", "agent", {"target": target}, priority=2)
    g.connect(nuclei.id, validate.id)

    return g


def build_full_auto_graph(target: str) -> ExecutionGraph:
    """Build the full autonomous assessment DAG."""
    g = ExecutionGraph(name=f"full_auto:{target}")

    # Layer 1: Parallel intelligence gathering
    osint = g.create_node("osint", "agent", {"target": target}, priority=0)
    fp = g.create_node("fingerprint", "agent", {"target": target}, priority=0)
    subs = g.create_node("subfinder", "tool", {"target": target}, priority=0)
    github = g.create_node("github_intel", "agent", {"target": target}, priority=0)

    # Layer 2: Merge + activate
    merge = g.create_node("merge_recon", "decision", {"target": target})
    g.connect(osint.id, merge.id)
    g.connect(subs.id, merge.id)
    g.connect(github.id, merge.id)

    packs = g.create_node("activate_packs", "decision", {"target": target})
    g.connect(fp.id, packs.id)

    # Layer 3: Active recon (parallel)
    httpx = g.create_node("httpx", "tool", {"target": target})
    g.connect(merge.id, httpx.id)

    crawl = g.create_node("katana_crawl", "tool", {"target": target})
    g.connect(httpx.id, crawl.id)

    js_analysis = g.create_node("js_intelligence", "agent", {"target": target})
    g.connect(crawl.id, js_analysis.id)

    # Layer 4: Scanning (depends on packs + live hosts)
    nuclei = g.create_node("nuclei_full", "tool", {"target": target})
    g.connect(httpx.id, nuclei.id)
    g.connect(packs.id, nuclei.id)

    ffuf = g.create_node("ffuf_fuzz", "tool", {"target": target})
    g.connect(httpx.id, ffuf.id)

    # Layer 5: API testing (conditional — only if API detected)
    api_test = g.create_node("api_security", "agent", {"target": target},
                             condition={"field": "has_api", "op": "eq", "value": True})
    g.connect(js_analysis.id, api_test.id, EdgeType.CONDITIONAL,
              condition={"field": "has_api", "op": "eq", "value": True})

    # Layer 6: Validation + Reporting
    validate = g.create_node("validate", "agent", {"target": target})
    g.connect(nuclei.id, validate.id)
    g.connect(ffuf.id, validate.id)
    g.connect(api_test.id, validate.id)

    report = g.create_node("report", "agent", {"target": target})
    g.connect(validate.id, report.id)

    return g
