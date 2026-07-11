"""MA Batch 1 tests — models, task queue, shared memory."""

from __future__ import annotations

import threading

from hydra.multi_agent.models import (
    AgentRole,
    AgentTask,
    Campaign,
    CampaignStatus,
    Finding,
    Message,
    MessageType,
    MTaskState,
)
from hydra.multi_agent.shared_memory import (
    FINDINGS_MAX,
    HISTORY_MAX,
    SharedMemory,
)
from hydra.multi_agent.task_queue import TaskQueue
from hydra.services.event_bus import EventBus


# ── models ──

class TestModels:
    def test_task_state_values(self):
        assert {s.value for s in MTaskState} == {
            "ready", "assigned", "running", "waiting", "failed", "completed", "cancelled"}

    def test_roles(self):
        assert {r.value for r in AgentRole} == {
            "coordinator", "planner", "recon", "web", "network", "knowledge", "report"}

    def test_message_types(self):
        assert MessageType.TASK_REQUEST.value == "task_request"
        assert len(list(MessageType)) == 7

    def test_task_roundtrip(self):
        t = AgentTask(description="d", command="/recon a.com", role=AgentRole.RECON,
                      depends_on=["x"], priority=8)
        r = AgentTask.from_dict(t.to_dict())
        assert r.id == t.id and r.role == AgentRole.RECON and r.depends_on == ["x"]

    def test_task_is_terminal(self):
        assert AgentTask(description="d", state=MTaskState.COMPLETED).is_terminal
        assert not AgentTask(description="d", state=MTaskState.READY).is_terminal

    def test_message_roundtrip(self):
        m = Message(type=MessageType.TASK_RESULT, sender="recon", payload={"k": 1})
        r = Message.from_dict(m.to_dict())
        assert r.type == MessageType.TASK_RESULT and r.payload == {"k": 1}

    def test_finding_signature(self):
        f = Finding(title="t", vuln_class="XSS", target="A.com")
        assert f.signature() == "xss|a.com"

    def test_finding_roundtrip(self):
        f = Finding(title="t", severity="high", vuln_class="sqli", target="a.com",
                    confidence=0.8)
        r = Finding.from_dict(f.to_dict())
        assert r.severity == "high" and r.confidence == 0.8

    def test_campaign_roundtrip(self):
        c = Campaign(objective="assess a.com", target="a.com")
        c.tasks.append(AgentTask(description="d", command="/recon a.com"))
        c.findings.append(Finding(title="f"))
        c.add_event("started", "go")
        r = Campaign.from_dict(c.to_dict())
        assert r.id == c.id and len(r.tasks) == 1 and len(r.findings) == 1
        assert r.timeline and r.status == CampaignStatus.CREATED

    def test_unique_ids(self):
        assert len({AgentTask(description="d").id for _ in range(50)}) == 50


# ── task queue ──

class TestTaskQueue:
    def _linear(self):
        a = AgentTask(description="a", command="/scope x", role=AgentRole.RECON,
                      state=MTaskState.READY)
        b = AgentTask(description="b", command="/recon x", role=AgentRole.RECON,
                      depends_on=[a.id])
        c = AgentTask(description="c", command="/scan x xss", role=AgentRole.WEB,
                      depends_on=[b.id])
        q = TaskQueue()
        q.add_many([a, b, c])
        return q, a, b, c

    def test_add_and_all(self):
        q, a, b, c = self._linear()
        assert len(q.all()) == 3

    def test_ready_only_dep_free(self):
        q, a, b, c = self._linear()
        ready = q.ready()
        assert [t.id for t in ready] == [a.id]

    def test_refresh_on_completion(self):
        q, a, b, c = self._linear()
        q.mark(a, MTaskState.COMPLETED)
        assert b.state == MTaskState.READY

    def test_ready_by_role(self):
        q, a, b, c = self._linear()
        q.mark(a, MTaskState.COMPLETED)
        q.mark(b, MTaskState.COMPLETED)
        web = q.ready(role=AgentRole.WEB)
        assert [t.id for t in web] == [c.id]
        assert q.ready(role=AgentRole.NETWORK) == []

    def test_priority_order(self):
        t1 = AgentTask(description="lo", state=MTaskState.READY, priority=2)
        t2 = AgentTask(description="hi", state=MTaskState.READY, priority=9)
        q = TaskQueue()
        q.add_many([t1, t2])
        assert q.next_ready().id == t2.id

    def test_assign(self):
        q, a, b, c = self._linear()
        q.assign(a, "recon-1")
        assert a.state == MTaskState.ASSIGNED and a.assigned_to == "recon-1"

    def test_requeue(self):
        q, a, b, c = self._linear()
        a.state = MTaskState.FAILED
        q.requeue(a)
        assert a.state == MTaskState.READY and a.assigned_to == ""

    def test_all_terminal(self):
        q, a, b, c = self._linear()
        for t in (a, b, c):
            q.mark(t, MTaskState.COMPLETED)
        assert q.all_terminal()

    def test_is_stuck(self):
        q, a, b, c = self._linear()
        q.mark(a, MTaskState.FAILED)
        assert q.is_stuck()

    def test_cancel_all(self):
        q, a, b, c = self._linear()
        q.mark(a, MTaskState.COMPLETED)
        q.cancel_all()
        assert b.state == MTaskState.CANCELLED and c.state == MTaskState.CANCELLED

    def test_counts_and_depth(self):
        q, a, b, c = self._linear()
        q.mark(a, MTaskState.COMPLETED)
        assert q.counts().get("completed") == 1
        assert q.depth() == 2

    def test_snapshot(self):
        q, a, b, c = self._linear()
        snap = q.snapshot()
        assert snap["total"] == 3 and "by_state" in snap

    def test_bounded(self):
        q = TaskQueue(max_tasks=10)
        for i in range(20):
            t = AgentTask(description=f"t{i}", state=MTaskState.COMPLETED)
            q.add(t)
        assert len(q.all()) <= 10

    def test_emits_queue_updated(self):
        bus = EventBus()
        seen = []
        bus.subscribe("team.queue.updated", lambda e: seen.append(e.payload))
        q = TaskQueue(event_bus=bus)
        q.add(AgentTask(description="d", state=MTaskState.READY))
        assert seen

    def test_thread_safety(self):
        q = TaskQueue()
        errors = []

        def worker(i):
            try:
                for j in range(50):
                    t = AgentTask(description=f"{i}-{j}", state=MTaskState.READY)
                    q.add(t)
                    q.ready()
                    q.mark(t, MTaskState.COMPLETED)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ── shared memory ──

class TestSharedMemory:
    def test_goal(self):
        m = SharedMemory()
        m.set_goal("assess a.com", "a.com")
        assert m.goal == "assess a.com" and m.target == "a.com"

    def test_findings(self):
        m = SharedMemory()
        m.add_finding(Finding(title="f", source="web"))
        assert len(m.findings()) == 1 and m.findings()[0].title == "f"

    def test_findings_bounded(self):
        m = SharedMemory()
        for i in range(FINDINGS_MAX + 20):
            m.add_finding(Finding(title=f"f{i}"))
        assert len(m.findings()) == FINDINGS_MAX

    def test_knowledge_reasoning_outputs(self):
        m = SharedMemory()
        m.add_knowledge("kg", {"x": 1})
        m.add_reasoning("planner", "thinking")
        m.record_output("recon", "t1", {"subs": 3})
        assert m.knowledge()[0]["item"] == {"x": 1}
        assert m.reasoning()[0]["thought"] == "thinking"
        assert m.outputs()[0]["output"] == {"subs": 3}

    def test_history_bounded(self):
        m = SharedMemory()
        for i in range(HISTORY_MAX + 10):
            m.record_execution("recon", "/recon x", "completed")
        assert len(m.history()) == HISTORY_MAX

    def test_confidence(self):
        m = SharedMemory()
        m.set_confidence("xss|a.com", 0.9)
        assert m.get_confidence("xss|a.com") == 0.9
        assert m.get_confidence("missing", 0.1) == 0.1

    def test_summary(self):
        m = SharedMemory()
        m.set_goal("o", "a.com")
        m.add_finding(Finding(title="f"))
        summ = m.summary()
        assert summ["findings"] == 1 and summ["target"] == "a.com"

    def test_roundtrip(self):
        m = SharedMemory()
        m.set_goal("o", "a.com")
        m.add_finding(Finding(title="f", vuln_class="xss"))
        m.set_confidence("k", 0.5)
        r = SharedMemory.from_dict(m.to_dict())
        assert r.goal == "o" and r.findings()[0].vuln_class == "xss"
        assert r.get_confidence("k") == 0.5

    def test_thread_safety(self):
        m = SharedMemory()
        errors = []

        def worker(i):
            try:
                for j in range(100):
                    m.add_finding(Finding(title=f"{i}-{j}"))
                    m.add_reasoning("a", "t")
                    m.findings()
                    m.summary()
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
