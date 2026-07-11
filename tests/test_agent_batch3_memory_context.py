"""Batch 3 tests — memory and context builder."""

from __future__ import annotations

from hydra.agent.context import AgentContext, ContextBuilder
from hydra.agent.memory import (
    CONVERSATION_MAX,
    EXECUTION_MAX,
    WORKING_MAX,
    AgentMemory,
)
from hydra.agent.planner import Planner


# ── memory ──

class TestAgentMemory:
    def test_working_set_get(self):
        m = AgentMemory()
        m.set("k", 42)
        assert m.get("k") == 42
        assert m.get("missing", "d") == "d"

    def test_working_bounded(self):
        m = AgentMemory()
        for i in range(WORKING_MAX + 50):
            m.set(f"k{i}", i)
        assert len(m.working) <= WORKING_MAX

    def test_conversation_bounded(self):
        m = AgentMemory()
        for i in range(CONVERSATION_MAX + 20):
            m.add_message("user", f"m{i}")
        assert len(m.conversation) == CONVERSATION_MAX

    def test_execution_bounded(self):
        m = AgentMemory()
        for i in range(EXECUTION_MAX + 5):
            m.record_execution(f"t{i}", "/status", "completed")
        assert len(m.execution) == EXECUTION_MAX

    def test_recent(self):
        m = AgentMemory()
        for i in range(20):
            m.add_message("user", f"m{i}")
        recent = m.conversation.recent(3)
        assert [x["text"] for x in recent] == ["m17", "m18", "m19"]

    def test_roundtrip(self):
        m = AgentMemory(session_id="s1")
        m.set("k", "v")
        m.add_message("agent", "hi")
        m.record_execution("t1", "/recon a.com", "completed")
        m.add_knowledge("recon", {"subs": 3})
        r = AgentMemory.from_dict(m.to_dict())
        assert r.session_id == "s1"
        assert r.get("k") == "v"
        assert r.conversation.all()[0]["text"] == "hi"
        assert r.execution.all()[0]["command"] == "/recon a.com"
        assert r.knowledge.all()[0]["fact"] == {"subs": 3}

    def test_save_and_resume(self, tmp_path):
        m = AgentMemory(session_id="sess", data_dir=tmp_path)
        m.set("phase", "recon")
        m.add_message("user", "assess a.com")
        assert m.save()

        m2 = AgentMemory(session_id="sess", data_dir=tmp_path)
        assert m2.resume()
        assert m2.get("phase") == "recon"
        assert m2.conversation.all()[0]["text"] == "assess a.com"

    def test_resume_missing_returns_false(self, tmp_path):
        m = AgentMemory(session_id="nope", data_dir=tmp_path)
        assert not m.resume()


# ── context ──

class _FakeFacade:
    def __init__(self, raise_all=False):
        self._raise = raise_all

    def search_knowledge(self, target):
        if self._raise:
            raise RuntimeError("kg down")
        return [{"slug": "p1", "title": "prior", "score": 0.9}]

    def list_reports(self):
        if self._raise:
            raise RuntimeError("reports down")
        return [{"slug": "r1", "title": "report"}]

    def check_tools(self):
        if self._raise:
            raise RuntimeError("tools down")
        return {"nmap": True, "nuclei": False}


class TestContextBuilder:
    def test_build_no_facade(self):
        ctx = ContextBuilder().build("assess example.com")
        assert isinstance(ctx, AgentContext)
        assert ctx.target == "example.com"
        assert ctx.known_targets == ["example.com"]

    def test_extract_target_from_objective(self):
        ctx = ContextBuilder().build("please scan test.org for xss")
        assert ctx.target == "test.org"

    def test_known_targets_from_recent(self):
        ctx = ContextBuilder().build(
            "do something",
            recent_commands=["/recon a.com", "/scan b.com xss"],
        )
        assert "a.com" in ctx.known_targets and "b.com" in ctx.known_targets

    def test_recent_lists_bounded(self):
        many = [f"/recon h{i}.com" for i in range(50)]
        ctx = ContextBuilder().build("x", recent_commands=many)
        assert len(ctx.recent_commands) <= 20

    def test_build_with_facade(self):
        ctx = ContextBuilder(_FakeFacade()).build("assess example.com")
        assert ctx.knowledge_hits and ctx.knowledge_hits[0]["slug"] == "p1"
        assert ctx.reports and ctx.reports[0]["slug"] == "r1"
        assert ctx.tools == {"nmap": True, "nuclei": False}

    def test_facade_errors_guarded(self):
        ctx = ContextBuilder(_FakeFacade(raise_all=True)).build("assess example.com")
        assert ctx.knowledge_hits == []
        assert ctx.reports == []
        assert ctx.tools == {}

    def test_to_dict_keys(self):
        d = ContextBuilder().build("assess a.com").to_dict()
        for k in ("objective", "target", "known_targets", "scope", "findings",
                  "reports", "tools", "recent_commands", "recent_failures",
                  "knowledge_hits"):
            assert k in d

    def test_planner_uses_context_known_targets(self):
        ctx = ContextBuilder().build(
            "assess example.com", recent_commands=["/recon example.com"])
        plan = Planner().plan("assess example.com", context=ctx)
        scope = next(t for t in plan.tasks if t.command.startswith("/scope"))
        # known target → confidence boost applied
        assert scope.confidence >= 0.9
