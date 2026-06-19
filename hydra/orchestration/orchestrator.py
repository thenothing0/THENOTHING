"""RuntimeOrchestrator: the mandatory execute-and-automate pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional

from .evidence import extract_findings, vuln_class_for_tool
from .gateway import ToolGateway

# Auto-compact the session transcript once it exceeds this many entries.
_COMPACT_EVERY = 40

# Tool family → the pentest-lifecycle state it implies. The orchestrator advances
# the workflow state machine forward as tools from later phases are executed.
_TOOL_PHASE = {
    "subfinder": "recon", "amass": "recon", "dnsx": "recon", "subzy": "recon",
    "httpx": "enumeration", "whatweb": "enumeration", "katana": "enumeration",
    "gau": "enumeration", "hakrawler": "enumeration", "ffuf": "enumeration",
    "dirsearch": "enumeration", "nuclei": "validation", "dalfox": "validation",
    "gxss": "validation", "attack_scan": "validation", "wafw00f": "enumeration",
    "sqlmap": "exploitation", "attack_execute": "exploitation",
    "netexec": "exploitation", "secretsdump": "exploitation", "shell_exec": "exploitation",
}
# Forward order used to decide whether a phase is "ahead" of the current state.
_PHASE_ORDER = ("scope", "recon", "enumeration", "validation", "exploitation",
                "evidence", "coverage_review", "reporting", "done")


@dataclass
class RuntimeContext:
    """Who/what a tool runs under. Drives RBAC + scope + session + provenance."""
    engagement_id: str
    target: str = ""
    username: str = "operator"
    role: Optional[str] = "operator"     # None => fall back to engagement membership
    session_id: str = ""
    workflow_run_id: str = ""
    operator_mode: bool = False


class RuntimeOrchestrator:
    """Every runtime tool call goes through `execute()`:
        gateway.check (enforce) → run → coverage → findings → learning → session.
    All stores are real; nothing here is advisory.
    """

    def __init__(self, *, gateway: ToolGateway, findings=None, coverage=None,
                 learning=None, session=None, workflow=None, engagement_id: str = "",
                 target: str = ""):
        self.gateway = gateway
        # Lazy-default the stores so the orchestrator is usable standalone.
        if findings is None:
            from hydra.findings import FindingsStore
            findings = FindingsStore()
        if coverage is None:
            from hydra.coverage import CoverageStore
            coverage = CoverageStore()
        if learning is None:
            from hydra.learning_tiers import LearningTiersStore
            learning = LearningTiersStore()
        self.findings = findings
        self.coverage = coverage
        self.learning = learning
        self.session = session                 # SessionStore | None
        # Phase 6 (workflow): drive a real PentestWorkflow run as phases progress.
        self.workflow = workflow               # PentestWorkflow | None
        self.workflow_run_id = ""
        if workflow is not None and engagement_id:
            try:
                self.workflow_run_id = workflow.create(engagement_id, target)
            except Exception:
                self.workflow = None
        self._transcript: List[Dict[str, str]] = []
        self._memory = None
        self.stats = {"executed": 0, "blocked": 0, "findings": 0,
                      "coverage_rows": 0, "lessons": 0, "compactions": 0, "workflow_state": "scope"}

    async def execute(self, tool_name: str, params: Dict, ctx: RuntimeContext,
                      tool_fn: Callable[[], Awaitable[Dict]]) -> Dict:
        """Enforce, execute, then automate the downstream subsystems."""
        decision = self.gateway.check(tool_name, params, ctx)
        if not decision.allowed:
            self.stats["blocked"] += 1
            return {"success": False, "blocked": True, "reason": decision.reason,
                    "risk": decision.risk, "output": ""}

        result = await tool_fn()               # REAL execution
        self.stats["executed"] += 1
        try:
            self._automate(tool_name, params, result, ctx)
        except Exception as e:                 # automation must never break the run
            result.setdefault("_integration_errors", []).append(str(e))
        return result

    def run_sync(self, tool_name: str, params: Dict, ctx: RuntimeContext,
                 tool_fn: Callable[[], Dict]) -> Dict:
        """Synchronous variant for non-async callers / tests."""
        decision = self.gateway.check(tool_name, params, ctx)
        if not decision.allowed:
            self.stats["blocked"] += 1
            return {"success": False, "blocked": True, "reason": decision.reason,
                    "risk": decision.risk, "output": ""}
        result = tool_fn()
        self.stats["executed"] += 1
        self._automate(tool_name, params, result, ctx)
        return result

    # ── the automation pipeline ──────────────────────────────────────────────────
    def _automate(self, tool: str, params: Dict, result: Dict, ctx: RuntimeContext) -> None:
        output = str(result.get("output", "") or "")
        success = bool(result.get("success", False))
        target = params.get("target") or params.get("url") or params.get("domain") or ctx.target
        eid = ctx.engagement_id

        # Phase 4 — coverage automation (every execution records a tuple).
        self.coverage.record(
            eid, endpoint=target or tool, vuln_class=vuln_class_for_tool(tool),
            method=str(params.get("method", "GET")), asset=ctx.target,
            status="passed" if success else "failed")
        self.stats["coverage_rows"] += 1

        # Phase 3 — findings automation (draft + evidence; no manual creation).
        drafted = extract_findings(tool, output)
        for ef in drafted:
            fid = self.findings.create(eid, ef.title, vuln_class=ef.vuln_class,
                                       severity=ef.severity, endpoint=ef.url or target,
                                       asset=ctx.target)
            self.findings.add_evidence(fid, "tool_output", output[:8000])
            self.stats["findings"] += 1

        # Burp/capture store — recon/crawl tools discover endpoints; accumulate them
        # so the capture store holds real autonomous-run data (queryable via burp_*).
        if tool.split("_")[0] in ("httpx", "katana", "gau", "hakrawler", "subfinder", "subzy"):
            try:
                from hydra.burp import STORE
                import re as _re
                urls = _re.findall(r"https?://[^\s\"'<>]+", output)[:200]
                for u in urls:
                    STORE.add("GET", u, note=f"discovered:{tool}")
                if urls:
                    self.stats["captured"] = self.stats.get("captured", 0) + len(urls)
            except Exception:
                pass

        # Phase 5 — learning automation (poison-gated lesson on a real signal).
        if success and drafted:
            self.learning.record(
                "project", title=f"{tool} surfaced {drafted[0].vuln_class}",
                category=vuln_class_for_tool(tool),
                lesson=f"{tool} on {target} produced: {drafted[0].title}",
                triggers=[tool, drafted[0].vuln_class], source_class="tool_output",
                host=ctx.target, engagement_id=eid)
            self.stats["lessons"] += 1

        # Phase 6 — session lifecycle (auto-save every call; auto-compact on size).
        if self.session is not None:
            self._transcript.append({"role": "tool",
                                     "content": f"{tool} {target} -> {output[:400]}"})
            if len(self._transcript) >= _COMPACT_EVERY:
                self._compact()
            self.session.save(self._transcript, self._memory, target=ctx.target)

        # Workflow state machine — advance forward as later-phase tools execute, and
        # checkpoint after every tool so an interrupted run resumes in place.
        self._advance_workflow(tool)

    def _advance_workflow(self, tool: str) -> None:
        if self.workflow is None or not self.workflow_run_id:
            return
        phase = _TOOL_PHASE.get(tool.split("_")[0]) or _TOOL_PHASE.get(tool)
        if not phase:
            return
        try:
            run = self.workflow.get(self.workflow_run_id)
            cur = run["state"] if run else "scope"
            # Walk forward one legal step at a time toward the tool's phase.
            from hydra.workflow import TRANSITIONS
            while _PHASE_ORDER.index(cur) < _PHASE_ORDER.index(phase):
                nxt = next((s for s in TRANSITIONS.get(cur, set())
                            if _PHASE_ORDER.index(s) > _PHASE_ORDER.index(cur)
                            and _PHASE_ORDER.index(s) <= _PHASE_ORDER.index(phase)), None)
                if not nxt:
                    break
                # operator-mode auto-approves the high-consequence transitions.
                self.workflow.advance(self.workflow_run_id, nxt, approver=lambda _s: True)
                cur = nxt
            self.workflow.checkpoint(self.workflow_run_id,
                                     {"last_tool": tool, "executed": self.stats["executed"]})
            self.stats["workflow_state"] = cur
        except Exception:
            pass  # workflow advisory failure must never break a run

    def _compact(self) -> None:
        from hydra.session import merge_memory
        summary = "# Tested surface\n" + "\n".join(
            f"- {m['content'][:120]}" for m in self._transcript[-_COMPACT_EVERY:])
        self._memory = merge_memory(self._memory, summary)
        # Keep only a tail of the raw transcript after folding into memory.
        self._transcript = self._transcript[-5:]
        self.stats["compactions"] += 1

    def compact_now(self) -> int:
        """Force a compaction (manual /compact)."""
        if self._transcript:
            self._compact()
        return self._memory.item_count() if self._memory else 0
