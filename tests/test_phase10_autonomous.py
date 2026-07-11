"""Phase 10 — Autonomous Cyber Intelligence tests.

Validates all 12 sub-phases across 4 batches.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock



def make_services():
    from hydra.services.event_bus import EventBus
    from hydra.services import ServiceContainer
    bus = EventBus()
    return ServiceContainer(event_bus=bus, data_dir=tempfile.mkdtemp())


# ══════════════════════════════════════════════════════════════════════
# Batch 1 — LearningLoopService (10.1)
# ══════════════════════════════════════════════════════════════════════

class TestLearningLoopService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.learning_loop import LearningLoopService
        return LearningLoopService(EventBus(), Path(tempfile.mkdtemp()))

    def test_process_recon_activity(self):
        svc = self._make()
        result = svc.process_activity("recon", target="example.com",
                                      output_data={"assets_discovered": 15})
        assert result["status"] == "processed"
        assert result["activity_type"] == "recon"
        assert len(result["stages_completed"]) >= 5

    def test_process_finding_activity(self):
        svc = self._make()
        result = svc.process_activity("finding", target="x.com",
                                      output_data={"vuln_class": "xss"})
        assert result["status"] == "processed"
        assert any(lesson["type"] == "technique" for lesson in result["lessons"])
        assert any(i["type"] == "pattern_candidate" for i in result["improvements"])

    def test_process_scan_activity(self):
        svc = self._make()
        result = svc.process_activity("scan", target="x.com",
                                      output_data={"tool": "nuclei", "findings_count": 3})
        assert result["status"] == "processed"
        assert any(lesson["tool"] == "nuclei" for lesson in result["lessons"])

    def test_process_scan_zero_findings_improvement(self):
        svc = self._make()
        result = svc.process_activity("scan", target="x.com",
                                      output_data={"tool": "nuclei", "findings_count": 0})
        assert any(i["type"] == "tool_selection" for i in result["improvements"])

    def test_unknown_activity_type(self):
        svc = self._make()
        result = svc.process_activity("nonexistent")
        assert result["status"] == "error"

    def test_get_recent(self):
        svc = self._make()
        svc.process_activity("recon", target="a.com")
        svc.process_activity("scan", target="b.com")
        recent = svc.get_recent(limit=10)
        assert len(recent) == 2

    def test_improvement_queue(self):
        svc = self._make()
        svc.process_activity("scan", output_data={"findings_count": 0})
        queue = svc.get_improvement_queue()
        assert len(queue) >= 1

    def test_get_stats(self):
        svc = self._make()
        svc.process_activity("recon")
        stats = svc.get_stats()
        assert stats["total_events"] >= 1
        assert "recon" in stats["activity_types"]
        assert "capture" in stats["stages"]

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.learning_loop import LearningLoopService
        bus = EventBus()
        events = []
        bus.subscribe("learning_loop.completed", lambda e: events.append(e))
        svc = LearningLoopService(bus, Path(tempfile.mkdtemp()))
        svc.process_activity("recon")
        assert len(events) == 1

    def test_verification_activity(self):
        svc = self._make()
        result = svc.process_activity("verification",
                                      output_data={"outcome": "confirmed"})
        assert result["status"] == "processed"
        assert any(lesson["type"] == "verification_outcome" for lesson in result["lessons"])


# ══════════════════════════════════════════════════════════════════════
# Batch 1 — ConfidenceService (10.2)
# ══════════════════════════════════════════════════════════════════════

class TestConfidenceService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.confidence import ConfidenceService
        return ConfidenceService(EventBus())

    def test_score_basic(self):
        svc = self._make()
        result = svc.score("page-1")
        assert 0 <= result["score"] <= 1
        assert result["band"] in ("verified", "high", "medium", "low", "unverified")

    def test_score_high_confidence(self):
        svc = self._make()
        result = svc.score("page-1", source_count=5, confirmations=3,
                          ai_agreement=0.9, human_verified=True,
                          reliability=0.9)
        assert result["score"] >= 0.7
        assert result["band"] in ("verified", "high")

    def test_score_low_confidence(self):
        svc = self._make()
        result = svc.score("page-1", source_count=1, confirmations=0,
                          ai_agreement=0.0, human_verified=False,
                          reliability=0.1)
        assert result["score"] < 0.4

    def test_score_batch(self):
        svc = self._make()
        items = [
            {"slug": "a", "source_count": 3},
            {"slug": "b", "source_count": 1},
        ]
        results = svc.score_batch(items)
        assert len(results) == 2
        assert results[0]["slug"] == "a"

    def test_rank(self):
        svc = self._make()
        scores = {
            "a": svc.score("a", source_count=1),
            "b": svc.score("b", source_count=5, confirmations=3, reliability=0.9),
        }
        ranked = svc.rank(["a", "b"], scores)
        assert ranked[0]["slug"] == "b"

    def test_decay_check_fresh(self):
        svc = self._make()
        result = svc.decay_check(time.time())
        assert result["decayed"] is False
        assert result["freshness"] > 0.9

    def test_decay_check_old(self):
        svc = self._make()
        old_ts = time.time() - (365 * 86400)
        result = svc.decay_check(old_ts)
        assert result["decayed"] is True
        assert result["freshness"] < 0.3

    def test_get_band(self):
        svc = self._make()
        assert svc.get_band(0.85) == "verified"
        assert svc.get_band(0.65) == "high"
        assert svc.get_band(0.45) == "medium"
        assert svc.get_band(0.25) == "low"
        assert svc.get_band(0.1) == "unverified"

    def test_list_bands(self):
        svc = self._make()
        bands = svc.list_bands()
        assert len(bands) == 5
        names = {b["band"] for b in bands}
        assert "verified" in names

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["factor_count"] == 6
        assert stats["band_count"] == 5

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.confidence import ConfidenceService
        bus = EventBus()
        events = []
        bus.subscribe("confidence.scored", lambda e: events.append(e))
        svc = ConfidenceService(bus)
        svc.score("test-page")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 1 — QualityService (10.12)
# ══════════════════════════════════════════════════════════════════════

class TestQualityService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.quality import QualityService
        return QualityService(EventBus(), Path(tempfile.mkdtemp()))

    def test_audit_returns_structure(self):
        svc = self._make()
        result = svc.audit()
        assert result["status"] == "completed"
        assert "issues" in result
        assert "by_type" in result
        assert "by_severity" in result

    def test_audit_scoped(self):
        svc = self._make()
        result = svc.audit(scope="duplicates")
        assert result["status"] == "completed"

    def test_check_page_not_found(self):
        svc = self._make()
        result = svc.check_page("nonexistent-slug")
        assert result["status"] in ("not_found", "checked")

    def test_get_health_score(self):
        svc = self._make()
        result = svc.get_health_score()
        assert 0 <= result["health_score"] <= 100
        assert result["grade"] in ("A", "B", "C", "D", "F")

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["issue_type_count"] == 9
        assert "duplicate" in stats["issue_types"]

    def test_audit_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.quality import QualityService
        bus = EventBus()
        events = []
        bus.subscribe("quality.audit_completed", lambda e: events.append(e))
        svc = QualityService(bus, Path(tempfile.mkdtemp()))
        svc.audit()
        assert len(events) == 1

    def test_quality_issue_to_dict(self):
        from hydra.services.quality import QualityIssue
        qi = QualityIssue("duplicate", "page-a", "Duplicate of page-b")
        d = qi.to_dict()
        assert d["issue_type"] == "duplicate"
        assert d["slug"] == "page-a"
        assert d["resolved"] is False

    def test_extract_links(self):
        svc = self._make()
        links = svc._extract_links("See [[page-a]] and [[page-b]] for details")
        assert links == ["page-a", "page-b"]

    def test_grade_boundaries(self):
        svc = self._make()
        assert svc._grade(95) == "A"
        assert svc._grade(85) == "B"
        assert svc._grade(75) == "C"
        assert svc._grade(65) == "D"
        assert svc._grade(50) == "F"


# ══════════════════════════════════════════════════════════════════════
# Batch 1 — Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch1P10Commands:

    def _run(self, handler, args=None, kwargs=None):
        svc = make_services()
        ctx = MagicMock()
        ctx.services = svc
        from hydra.commands.builtins.learning_cmds import _learn, _confidence, _quality
        handlers = {"learning": _learn, "confidence": _confidence, "quality": _quality}
        return handlers[handler](args or [], kwargs or {}, ctx)

    def test_learn_stats(self):
        r = self._run("learning")
        assert r.ok
        assert r.output["type"] == "learning_stats"

    def test_learn_process(self):
        r = self._run("learning", ["process", "recon"], {"target": "x.com"})
        assert r.ok
        assert r.output["type"] == "learning_processed"

    def test_learn_recent(self):
        r = self._run("learning", ["recent"])
        assert r.ok

    def test_learn_queue(self):
        r = self._run("learning", ["queue"])
        assert r.ok

    def test_learn_bad_subcmd(self):
        r = self._run("learning", ["bad"])
        assert not r.ok

    def test_confidence_stats(self):
        r = self._run("confidence")
        assert r.ok
        assert r.output["type"] == "confidence_stats"

    def test_confidence_score(self):
        r = self._run("confidence", ["score", "page-1"], {"sources": "3"})
        assert r.ok
        assert r.output["type"] == "confidence_score"

    def test_confidence_bands(self):
        r = self._run("confidence", ["bands"])
        assert r.ok
        assert len(r.output["bands"]) == 5

    def test_confidence_decay(self):
        r = self._run("confidence", ["decay", "30"])
        assert r.ok
        assert r.output["type"] == "confidence_decay"

    def test_confidence_bad_subcmd(self):
        r = self._run("confidence", ["bad"])
        assert not r.ok

    def test_quality_stats(self):
        r = self._run("quality")
        assert r.ok
        assert r.output["type"] == "quality_stats"

    def test_quality_audit(self):
        r = self._run("quality", ["audit"])
        assert r.ok
        assert r.output["type"] == "quality_audit"

    def test_quality_health(self):
        r = self._run("quality", ["health"])
        assert r.ok
        assert r.output["type"] == "quality_health"

    def test_quality_bad_subcmd(self):
        r = self._run("quality", ["bad"])
        assert not r.ok


# ══════════════════════════════════════════════════════════════════════
# Batch 1 — Wiring
# ══════════════════════════════════════════════════════════════════════

class TestBatch1P10Wiring:

    def test_learning_loop_wired(self):
        svc = make_services()
        from hydra.services.learning_loop import LearningLoopService
        assert isinstance(svc.learning_loop, LearningLoopService)

    def test_confidence_wired(self):
        svc = make_services()
        from hydra.services.confidence import ConfidenceService
        assert isinstance(svc.confidence, ConfidenceService)

    def test_quality_wired(self):
        svc = make_services()
        from hydra.services.quality import QualityService
        assert isinstance(svc.quality, QualityService)

    def test_commands_registered(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        assert "learning" in names
        assert "confidence" in names
        assert "quality" in names


# ══════════════════════════════════════════════════════════════════════
# Batch 2 — ReasoningService (10.3)
# ══════════════════════════════════════════════════════════════════════

class TestReasoningService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.reasoning import ReasoningService
        return ReasoningService(EventBus(), Path(tempfile.mkdtemp()))

    def test_generate_from_tech(self):
        svc = self._make()
        obs = [{"type": "tech_stack", "value": "PHP 7.4"}]
        result = svc.generate_hypotheses(obs, target="x.com")
        assert result["status"] == "generated"
        assert result["count"] >= 1
        assert any("lfi" in h.get("vuln_class", "") for h in result["hypotheses"])

    def test_generate_from_port(self):
        svc = self._make()
        obs = [{"type": "open_port", "value": "8080"}]
        result = svc.generate_hypotheses(obs, target="x.com")
        assert result["count"] >= 1

    def test_generate_from_header(self):
        svc = self._make()
        obs = [{"type": "header", "name": "Server", "value": "Apache/2.4.49"}]
        result = svc.generate_hypotheses(obs, target="x.com")
        assert result["count"] >= 1

    def test_generate_from_error(self):
        svc = self._make()
        obs = [{"type": "error", "value": "500 Internal Server Error"}]
        result = svc.generate_hypotheses(obs, target="x.com")
        assert result["count"] >= 1

    def test_generate_generic(self):
        svc = self._make()
        obs = [{"type": "unknown_thing", "value": "something"}]
        result = svc.generate_hypotheses(obs, target="x.com")
        assert result["count"] >= 1

    def test_bad_mode(self):
        svc = self._make()
        result = svc.generate_hypotheses([], mode="invalid")
        assert result["status"] == "error"

    def test_counterfactual(self):
        svc = self._make()
        obs = [{"type": "tech_stack", "value": "PHP"}]
        gen = svc.generate_hypotheses(obs, target="x.com")
        hyp_id = gen["hypotheses"][0]["id"]
        result = svc.counterfactual(hyp_id, "waf", "none")
        assert result["status"] == "analyzed"
        assert "impact" in result

    def test_counterfactual_not_found(self):
        svc = self._make()
        result = svc.counterfactual("nonexistent", "x", "y")
        assert result["status"] == "error"

    def test_update_hypothesis_support(self):
        svc = self._make()
        obs = [{"type": "tech_stack", "value": "PHP"}]
        gen = svc.generate_hypotheses(obs)
        hyp_id = gen["hypotheses"][0]["id"]
        result = svc.update_hypothesis(hyp_id, "Found LFI endpoint", True)
        assert result["status"] == "updated"
        assert result["confidence"] > 0.5

    def test_update_hypothesis_refute(self):
        svc = self._make()
        obs = [{"type": "tech_stack", "value": "PHP"}]
        gen = svc.generate_hypotheses(obs)
        hyp_id = gen["hypotheses"][0]["id"]
        svc.update_hypothesis(hyp_id, "No LFI found", False)
        svc.update_hypothesis(hyp_id, "WAF blocks all", False)
        svc.update_hypothesis(hyp_id, "Not vulnerable", False)
        result = svc.update_hypothesis(hyp_id, "Confirmed safe", False)
        assert result["state"] == "refuted"

    def test_update_not_found(self):
        svc = self._make()
        result = svc.update_hypothesis("bad-id", "x", True)
        assert result["status"] == "error"

    def test_list_hypotheses(self):
        svc = self._make()
        svc.generate_hypotheses([{"type": "tech_stack", "value": "PHP"}], target="a.com")
        import time as _t
        _t.sleep(0.002)
        svc.generate_hypotheses([{"type": "tech_stack", "value": "Node"}], target="b.com")
        all_hyps = svc.list_hypotheses()
        assert len(all_hyps) >= 2
        filtered = svc.list_hypotheses(target="a.com")
        assert all(h["target"] == "a.com" for h in filtered)

    def test_get_stats(self):
        svc = self._make()
        svc.generate_hypotheses([{"type": "tech_stack", "value": "PHP"}])
        stats = svc.get_stats()
        assert stats["total_hypotheses"] >= 1
        assert "proposed" in stats["by_state"]

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.reasoning import ReasoningService
        bus = EventBus()
        events = []
        bus.subscribe("reasoning.hypotheses_generated", lambda e: events.append(e))
        svc = ReasoningService(bus, Path(tempfile.mkdtemp()))
        svc.generate_hypotheses([{"type": "tech_stack", "value": "PHP"}])
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 2 — ContextIntelService (10.7)
# ══════════════════════════════════════════════════════════════════════

class TestContextIntelService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.context_intel import ContextIntelService
        return ContextIntelService(EventBus(), Path(tempfile.mkdtemp()))

    def test_enrich_target(self):
        svc = self._make()
        result = svc.enrich(target="example.com", action="scan")
        assert result["status"] == "enriched"
        assert "wiki" in result["sources_queried"]
        assert len(result["enrichments"]) >= 1

    def test_enrich_vuln_class(self):
        svc = self._make()
        result = svc.enrich(vuln_class="xss")
        assert result["status"] == "enriched"
        assert "ttp" in result["sources_queried"]

    def test_enrich_tech(self):
        svc = self._make()
        result = svc.enrich(tech_stack="PHP")
        assert result["status"] == "enriched"
        assert "lessons" in result["sources_queried"]

    def test_enrich_generates_recommendations(self):
        svc = self._make()
        result = svc.enrich(target="x.com", vuln_class="sqli")
        assert len(result["recommendations"]) >= 1

    def test_get_target_history(self):
        svc = self._make()
        result = svc.get_target_history("example.com")
        assert result["target"] == "example.com"
        assert "findings" in result
        assert "scans" in result

    def test_get_vuln_intel(self):
        svc = self._make()
        result = svc.get_vuln_intel("xss")
        assert result["vuln_class"] == "xss"
        assert "dalfox" in result["recommended_tools"]
        assert result["payloads_available"] is True

    def test_get_vuln_intel_unknown(self):
        svc = self._make()
        result = svc.get_vuln_intel("unknown_class")
        assert result["vuln_class"] == "unknown_class"
        assert result["payloads_available"] is False

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["source_count"] == 9
        assert "wiki" in stats["context_sources"]

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.context_intel import ContextIntelService
        bus = EventBus()
        events = []
        bus.subscribe("context_intel.enriched", lambda e: events.append(e))
        svc = ContextIntelService(bus, Path(tempfile.mkdtemp()))
        svc.enrich(target="x.com")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 2 — DualIntelService (10.8)
# ══════════════════════════════════════════════════════════════════════

class TestDualIntelService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.dual_intel import DualIntelService
        return DualIntelService(EventBus(), Path(tempfile.mkdtemp()))

    def test_analyze_xss(self):
        svc = self._make()
        result = svc.analyze("xss", target="x.com", severity="high")
        assert result["status"] == "analyzed"
        assert len(result["offensive"]) >= 1
        assert len(result["defensive"]) >= 1
        assert "risk_assessment" in result

    def test_analyze_unknown_class(self):
        svc = self._make()
        result = svc.analyze("unknown_vuln")
        assert result["status"] == "analyzed"
        assert len(result["offensive"]) >= 1

    def test_get_offensive_intel(self):
        svc = self._make()
        result = svc.get_offensive_intel("sqli")
        assert result["vuln_class"] == "sqli"
        assert len(result["exploitation"]) >= 1
        assert len(result["payloads"]) >= 1

    def test_get_defensive_intel(self):
        svc = self._make()
        result = svc.get_defensive_intel("ssrf")
        assert result["vuln_class"] == "ssrf"
        assert len(result["detection"]) >= 1
        assert len(result["mitigation"]) >= 1

    def test_compare_perspectives(self):
        svc = self._make()
        result = svc.compare_perspectives("xss")
        assert result["vuln_class"] == "xss"
        assert "offensive" in result
        assert "defensive" in result
        assert "defensive_coverage" in result

    def test_risk_assessment_high(self):
        svc = self._make()
        result = svc.analyze("xss", severity="critical")
        risk = result["risk_assessment"]
        assert risk["attack_surface_score"] > 0
        assert risk["defense_depth_score"] > 0
        assert risk["risk_level"] in ("high", "medium", "low")

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["vuln_classes_with_offensive"] >= 5
        assert stats["vuln_classes_with_defensive"] >= 5

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.dual_intel import DualIntelService
        bus = EventBus()
        events = []
        bus.subscribe("dual_intel.analyzed", lambda e: events.append(e))
        svc = DualIntelService(bus, Path(tempfile.mkdtemp()))
        svc.analyze("xss")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 2 — Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch2P10Commands:

    def _run(self, handler, args=None, kwargs=None):
        svc = make_services()
        ctx = MagicMock()
        ctx.services = svc
        from hydra.commands.builtins.reasoning_cmds import (
            _reasoning, _context, _dualintel,
        )
        handlers = {
            "reasoning": _reasoning, "context": _context, "dualintel": _dualintel,
        }
        return handlers[handler](args or [], kwargs or {}, ctx)

    def test_reasoning_stats(self):
        r = self._run("reasoning")
        assert r.ok
        assert r.output["type"] == "reasoning_stats"

    def test_reasoning_generate(self):
        r = self._run("reasoning", ["generate", "tech_stack:PHP"], {"target": "x.com"})
        assert r.ok
        assert r.output["type"] == "reasoning_generated"

    def test_reasoning_hypotheses(self):
        r = self._run("reasoning", ["hypotheses"])
        assert r.ok

    def test_reasoning_bad_subcmd(self):
        r = self._run("reasoning", ["bad"])
        assert not r.ok

    def test_context_stats(self):
        r = self._run("context")
        assert r.ok
        assert r.output["type"] == "context_stats"

    def test_context_enrich(self):
        r = self._run("context", ["enrich"], {"target": "x.com"})
        assert r.ok
        assert r.output["type"] == "context_enriched"

    def test_context_history(self):
        r = self._run("context", ["history", "x.com"])
        assert r.ok
        assert r.output["type"] == "context_history"

    def test_context_vuln(self):
        r = self._run("context", ["vuln", "xss"])
        assert r.ok
        assert r.output["type"] == "context_vuln_intel"

    def test_context_bad_subcmd(self):
        r = self._run("context", ["bad"])
        assert not r.ok

    def test_dualintel_stats(self):
        r = self._run("dualintel")
        assert r.ok
        assert r.output["type"] == "dualintel_stats"

    def test_dualintel_analyze(self):
        r = self._run("dualintel", ["analyze", "xss"], {"severity": "high"})
        assert r.ok
        assert r.output["type"] == "dualintel_analysis"

    def test_dualintel_offensive(self):
        r = self._run("dualintel", ["offensive", "sqli"])
        assert r.ok
        assert r.output["type"] == "dualintel_offensive"

    def test_dualintel_defensive(self):
        r = self._run("dualintel", ["defensive", "ssrf"])
        assert r.ok
        assert r.output["type"] == "dualintel_defensive"

    def test_dualintel_compare(self):
        r = self._run("dualintel", ["compare", "xss"])
        assert r.ok
        assert r.output["type"] == "dualintel_comparison"

    def test_dualintel_bad_subcmd(self):
        r = self._run("dualintel", ["bad"])
        assert not r.ok


# ══════════════════════════════════════════════════════════════════════
# Batch 2 — Wiring
# ══════════════════════════════════════════════════════════════════════

class TestBatch2P10Wiring:

    def test_reasoning_wired(self):
        svc = make_services()
        from hydra.services.reasoning import ReasoningService
        assert isinstance(svc.reasoning, ReasoningService)

    def test_context_intel_wired(self):
        svc = make_services()
        from hydra.services.context_intel import ContextIntelService
        assert isinstance(svc.context_intel, ContextIntelService)

    def test_dual_intel_wired(self):
        svc = make_services()
        from hydra.services.dual_intel import DualIntelService
        assert isinstance(svc.dual_intel, DualIntelService)

    def test_commands_registered(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        assert "reasoning" in names
        assert "context" in names
        assert "dualintel" in names


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — CollaborationService (10.4)
# ══════════════════════════════════════════════════════════════════════

class TestCollaborationService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.collaboration import CollaborationService
        return CollaborationService(EventBus(), Path(tempfile.mkdtemp()))

    def test_create_task(self):
        svc = self._make()
        result = svc.create_task("Scan ports", role="scanner", target="x.com")
        assert result["status"] == "created"
        assert result["role"] == "scanner"

    def test_create_task_assigned(self):
        svc = self._make()
        result = svc.create_task("Validate XSS", role="validator", agent_id="agent-1")
        assert result["state"] == "assigned"

    def test_create_task_bad_role(self):
        svc = self._make()
        result = svc.create_task("X", role="invalid")
        assert result["status"] == "error"

    def test_complete_task(self):
        svc = self._make()
        created = svc.create_task("Test", role="scanner")
        tid = created["id"]
        result = svc.complete_task(tid, {"findings": 3})
        assert result["status"] == "completed"
        assert result["has_result"] is True

    def test_complete_task_not_found(self):
        svc = self._make()
        result = svc.complete_task("bad-id", {})
        assert result["status"] == "error"

    def test_share_finding(self):
        svc = self._make()
        result = svc.share_finding({"vuln": "xss"}, source_agent="a1")
        assert result["status"] == "shared"
        assert result["total_shared"] == 1

    def test_validate_finding(self):
        svc = self._make()
        svc.share_finding({"vuln": "xss"})
        result = svc.validate_finding(0, "validator-1", True)
        assert result["status"] == "validated"
        assert result["confirmed_count"] == 1

    def test_validate_out_of_range(self):
        svc = self._make()
        result = svc.validate_finding(99, "v", True)
        assert result["status"] == "error"

    def test_list_tasks(self):
        svc = self._make()
        svc.create_task("A", role="scanner")
        import time as _t
        _t.sleep(0.002)
        svc.create_task("B", role="analyzer")
        tasks = svc.list_tasks()
        assert len(tasks) == 2
        filtered = svc.list_tasks(role="scanner")
        assert len(filtered) == 1

    def test_get_stats(self):
        svc = self._make()
        svc.create_task("X", role="scanner")
        stats = svc.get_stats()
        assert stats["total_tasks"] == 1
        assert "scanner" in stats["by_role"]

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.collaboration import CollaborationService
        bus = EventBus()
        events = []
        bus.subscribe("collaboration.task_created", lambda e: events.append(e))
        svc = CollaborationService(bus, Path(tempfile.mkdtemp()))
        svc.create_task("X", role="scanner")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — SkillEvolutionService (10.5)
# ══════════════════════════════════════════════════════════════════════

class TestSkillEvolutionService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.skill_evolution import SkillEvolutionService
        return SkillEvolutionService(EventBus(), Path(tempfile.mkdtemp()))

    def test_register_skill(self):
        svc = self._make()
        result = svc.register_skill("XSS scanner", category="scanning")
        assert result["status"] == "registered"
        assert result["confidence"] == 0.5

    def test_register_bad_category(self):
        svc = self._make()
        result = svc.register_skill("X", category="invalid")
        assert result["status"] == "error"

    def test_record_outcome_success(self):
        svc = self._make()
        reg = svc.register_skill("Test", category="scanning")
        sid = reg["id"]
        result = svc.record_outcome(sid, True)
        assert result["status"] == "recorded"
        assert result["confidence"] > 0.5
        assert result["success_count"] == 1

    def test_record_outcome_failure(self):
        svc = self._make()
        reg = svc.register_skill("Test", category="scanning")
        sid = reg["id"]
        result = svc.record_outcome(sid, False)
        assert result["confidence"] < 0.5
        assert result["failure_count"] == 1

    def test_auto_deprecate(self):
        svc = self._make()
        reg = svc.register_skill("Bad skill", category="scanning", confidence=0.15)
        sid = reg["id"]
        for _ in range(6):
            svc.record_outcome(sid, False)
        result = svc.record_outcome(sid, False)
        assert result["deprecated"] is True

    def test_record_not_found(self):
        svc = self._make()
        result = svc.record_outcome("bad-id", True)
        assert result["status"] == "error"

    def test_create_variant(self):
        svc = self._make()
        reg = svc.register_skill("Parent", category="exploitation")
        pid = reg["id"]
        result = svc.create_variant(pid, "Child variant")
        assert result["status"] == "created"
        assert result["parent_id"] == pid
        assert result["confidence"] < reg["confidence"]

    def test_create_variant_not_found(self):
        svc = self._make()
        result = svc.create_variant("bad-id", "X")
        assert result["status"] == "error"

    def test_rank_skills(self):
        svc = self._make()
        svc.register_skill("Low", category="scanning", confidence=0.2)
        import time as _t
        _t.sleep(0.002)
        svc.register_skill("High", category="scanning", confidence=0.9)
        ranked = svc.rank_skills()
        assert ranked[0]["confidence"] > ranked[-1]["confidence"]

    def test_get_deprecated(self):
        svc = self._make()
        reg = svc.register_skill("Bad", category="scanning", confidence=0.05)
        for _ in range(6):
            svc.record_outcome(reg["id"], False)
        deps = svc.get_deprecated()
        assert len(deps) >= 1

    def test_get_stats(self):
        svc = self._make()
        svc.register_skill("X", category="scanning")
        stats = svc.get_stats()
        assert stats["total_skills"] == 1
        assert stats["active"] == 1
        assert "scanning" in stats["by_category"]


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — KnowledgeBuilderService (10.6)
# ══════════════════════════════════════════════════════════════════════

class TestKnowledgeBuilderService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.knowledge_builder import KnowledgeBuilderService
        return KnowledgeBuilderService(EventBus(), Path(tempfile.mkdtemp()))

    def test_add_node(self):
        svc = self._make()
        result = svc.add_node("t1", "target", {"name": "example.com"})
        assert result["status"] == "added"
        assert result["type"] == "target"

    def test_add_node_bad_type(self):
        svc = self._make()
        result = svc.add_node("x", "invalid_type")
        assert result["status"] == "error"

    def test_add_edge(self):
        svc = self._make()
        svc.add_node("t1", "target")
        svc.add_node("f1", "finding")
        result = svc.add_edge("t1", "f1", "has_finding")
        assert result["status"] == "added"
        assert result["type"] == "has_finding"

    def test_add_edge_bad_type(self):
        svc = self._make()
        svc.add_node("a", "target")
        svc.add_node("b", "finding")
        result = svc.add_edge("a", "b", "invalid_edge")
        assert result["status"] == "error"

    def test_add_edge_missing_node(self):
        svc = self._make()
        svc.add_node("a", "target")
        result = svc.add_edge("a", "missing", "has_finding")
        assert result["status"] == "error"

    def test_find_gaps(self):
        svc = self._make()
        svc.add_node("orphan", "target")
        svc.add_node("a", "target")
        svc.add_node("b", "finding")
        svc.add_edge("a", "b", "has_finding")
        gaps = svc.find_gaps()
        assert gaps["orphan_count"] >= 1
        assert "orphan" in gaps["orphans"]

    def test_get_subgraph(self):
        svc = self._make()
        svc.add_node("center", "target")
        svc.add_node("n1", "finding")
        svc.add_edge("center", "n1", "has_finding")
        result = svc.get_subgraph("center", depth=1)
        assert result["node_count"] >= 2
        assert result["edge_count"] >= 1

    def test_get_subgraph_not_found(self):
        svc = self._make()
        result = svc.get_subgraph("missing")
        assert result["status"] == "error"

    def test_build_from_findings(self):
        svc = self._make()
        findings = [
            {"id": "f1", "target": "x.com", "vuln_class": "xss"},
            {"id": "f2", "target": "x.com", "vuln_class": "sqli"},
        ]
        result = svc.build_from_findings(findings)
        assert result["status"] == "built"
        assert result["findings_processed"] == 2
        assert result["total_nodes"] >= 4
        assert result["total_edges"] >= 3

    def test_get_stats(self):
        svc = self._make()
        svc.add_node("t1", "target")
        stats = svc.get_stats()
        assert stats["total_nodes"] == 1
        assert "target" in stats["nodes_by_type"]

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.knowledge_builder import KnowledgeBuilderService
        bus = EventBus()
        events = []
        bus.subscribe("knowledge_builder.node_added", lambda e: events.append(e))
        svc = KnowledgeBuilderService(bus, Path(tempfile.mkdtemp()))
        svc.add_node("x", "target")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch3P10Commands:

    def _run(self, handler, args=None, kwargs=None):
        svc = make_services()
        ctx = MagicMock()
        ctx.services = svc
        from hydra.commands.builtins.collab_cmds import _collab, _evolve, _kbuild
        handlers = {"collab": _collab, "evolve": _evolve, "kbuild": _kbuild}
        return handlers[handler](args or [], kwargs or {}, ctx)

    def test_collab_stats(self):
        r = self._run("collab")
        assert r.ok
        assert r.output["type"] == "collab_stats"

    def test_collab_create(self):
        r = self._run("collab", ["create", "Scan", "ports"], {"role": "scanner"})
        assert r.ok
        assert r.output["type"] == "collab_task_created"

    def test_collab_tasks(self):
        r = self._run("collab", ["tasks"])
        assert r.ok

    def test_collab_share(self):
        r = self._run("collab", ["share", "Found XSS"])
        assert r.ok

    def test_collab_findings(self):
        r = self._run("collab", ["findings"])
        assert r.ok

    def test_collab_bad_subcmd(self):
        r = self._run("collab", ["bad"])
        assert not r.ok

    def test_evolve_stats(self):
        r = self._run("evolve")
        assert r.ok
        assert r.output["type"] == "evolve_stats"

    def test_evolve_register(self):
        r = self._run("evolve", ["register", "New skill"], {"category": "scanning"})
        assert r.ok
        assert r.output["type"] == "evolve_registered"

    def test_evolve_rank(self):
        r = self._run("evolve", ["rank"])
        assert r.ok

    def test_evolve_deprecated(self):
        r = self._run("evolve", ["deprecated"])
        assert r.ok

    def test_evolve_bad_subcmd(self):
        r = self._run("evolve", ["bad"])
        assert not r.ok

    def test_kbuild_stats(self):
        r = self._run("kbuild")
        assert r.ok
        assert r.output["type"] == "kbuild_stats"

    def test_kbuild_gaps(self):
        r = self._run("kbuild", ["gaps"])
        assert r.ok
        assert r.output["type"] == "kbuild_gaps"

    def test_kbuild_node(self):
        r = self._run("kbuild", ["node", "t1", "target"])
        assert r.ok
        assert r.output["type"] == "kbuild_node_added"

    def test_kbuild_bad_subcmd(self):
        r = self._run("kbuild", ["bad"])
        assert not r.ok


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — Wiring
# ══════════════════════════════════════════════════════════════════════

class TestBatch3P10Wiring:

    def test_collaboration_wired(self):
        svc = make_services()
        from hydra.services.collaboration import CollaborationService
        assert isinstance(svc.collaboration, CollaborationService)

    def test_skill_evolution_wired(self):
        svc = make_services()
        from hydra.services.skill_evolution import SkillEvolutionService
        assert isinstance(svc.skill_evolution, SkillEvolutionService)

    def test_knowledge_builder_wired(self):
        svc = make_services()
        from hydra.services.knowledge_builder import KnowledgeBuilderService
        assert isinstance(svc.knowledge_builder, KnowledgeBuilderService)

    def test_commands_registered(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        assert "collab" in names
        assert "evolve" in names
        assert "kbuild" in names


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — KnowledgeSyncService (10.9)
# ══════════════════════════════════════════════════════════════════════

class TestKnowledgeSyncService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.knowledge_sync import KnowledgeSyncService
        return KnowledgeSyncService(EventBus(), Path(tempfile.mkdtemp()))

    def test_create_snapshot(self):
        svc = self._make()
        result = svc.create_snapshot()
        assert result["status"] == "created"
        assert "id" in result
        assert len(result["sources"]) > 0

    def test_create_snapshot_filtered(self):
        svc = self._make()
        result = svc.create_snapshot(["wiki", "graph"])
        assert result["status"] == "created"
        assert set(result["sources"]) == {"wiki", "graph"}

    def test_create_snapshot_bad_source(self):
        svc = self._make()
        result = svc.create_snapshot(["invalid_source"])
        assert result["status"] == "error"

    def test_sync_to_peer(self):
        svc = self._make()
        result = svc.sync_to_peer("peer-1")
        assert result["status"] == "synced"
        assert result["direction"] == "push"

    def test_sync_to_peer_with_snapshot(self):
        svc = self._make()
        snap = svc.create_snapshot()
        result = svc.sync_to_peer("peer-1", snap["id"])
        assert result["status"] == "synced"
        assert result["snapshot_id"] == snap["id"]

    def test_sync_to_peer_bad_snapshot(self):
        svc = self._make()
        result = svc.sync_to_peer("peer-1", "bad-snap")
        assert result["status"] == "error"

    def test_sync_from_peer(self):
        svc = self._make()
        result = svc.sync_from_peer("peer-2", {"item": "data"})
        assert result["status"] == "synced"
        assert result["direction"] == "pull"

    def test_detect_conflicts(self):
        svc = self._make()
        local = [{"id": "a", "val": 1}]
        remote = [{"id": "a", "val": 2}]
        result = svc.detect_conflicts(local, remote)
        assert result["conflict_count"] == 1

    def test_detect_no_conflicts(self):
        svc = self._make()
        local = [{"id": "a", "val": 1}]
        remote = [{"id": "a", "val": 1}]
        result = svc.detect_conflicts(local, remote)
        assert result["conflict_count"] == 0

    def test_resolve_conflict(self):
        svc = self._make()
        svc.detect_conflicts([{"id": "x", "v": 1}], [{"id": "x", "v": 2}])
        result = svc.resolve_conflict("conflict-0", "local_wins")
        assert result["status"] == "resolved"
        assert result["strategy"] == "local_wins"

    def test_resolve_conflict_not_found(self):
        svc = self._make()
        result = svc.resolve_conflict("bad-id")
        assert result["status"] == "error"

    def test_resolve_conflict_bad_strategy(self):
        svc = self._make()
        result = svc.resolve_conflict("x", "bad_strategy")
        assert result["status"] == "error"

    def test_list_peers(self):
        svc = self._make()
        svc.sync_to_peer("p1")
        svc.sync_from_peer("p2")
        peers = svc.list_peers()
        assert len(peers) == 2

    def test_get_sync_history(self):
        svc = self._make()
        svc.sync_to_peer("p1")
        history = svc.get_sync_history()
        assert len(history) == 1

    def test_get_stats(self):
        svc = self._make()
        svc.sync_to_peer("p1")
        stats = svc.get_stats()
        assert stats["total_syncs"] == 1
        assert stats["by_direction"]["push"] == 1

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.knowledge_sync import KnowledgeSyncService
        bus = EventBus()
        events = []
        bus.subscribe("knowledge_sync.snapshot_created", lambda e: events.append(e))
        svc = KnowledgeSyncService(bus, Path(tempfile.mkdtemp()))
        svc.create_snapshot()
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — CopilotService (10.10)
# ══════════════════════════════════════════════════════════════════════

class TestCopilotService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.copilot import CopilotService
        return CopilotService(EventBus(), Path(tempfile.mkdtemp()))

    def test_suggest(self):
        svc = self._make()
        result = svc.suggest({"target": "x.com", "phase": "recon"})
        assert result["status"] == "generated"
        assert result["count"] > 0

    def test_suggest_with_vuln_class(self):
        svc = self._make()
        result = svc.suggest({"target": "x.com", "vuln_class": "xss", "phase": "scan"})
        assert result["count"] > 0
        types = {s["type"] for s in result["suggestions"]}
        assert "tool_recommendation" in types

    def test_accept_suggestion(self):
        svc = self._make()
        result = svc.suggest({"target": "x.com"})
        sid = result["suggestions"][0]["id"]
        acc = svc.accept_suggestion(sid)
        assert acc["status"] == "accepted"

    def test_accept_not_found(self):
        svc = self._make()
        result = svc.accept_suggestion("bad-id")
        assert result["status"] == "error"

    def test_reject_suggestion(self):
        svc = self._make()
        result = svc.suggest({"target": "x.com"})
        sid = result["suggestions"][0]["id"]
        rej = svc.reject_suggestion(sid, "not relevant")
        assert rej["status"] == "rejected"

    def test_set_mode(self):
        svc = self._make()
        result = svc.set_mode("active")
        assert result["status"] == "changed"
        assert result["new_mode"] == "active"

    def test_set_mode_bad(self):
        svc = self._make()
        result = svc.set_mode("invalid")
        assert result["status"] == "error"

    def test_set_context(self):
        svc = self._make()
        result = svc.set_context("target", {"host": "x.com"})
        assert result["status"] == "set"

    def test_set_context_bad_type(self):
        svc = self._make()
        result = svc.set_context("invalid_type", {})
        assert result["status"] == "error"

    def test_get_context(self):
        svc = self._make()
        svc.set_context("target", {"host": "x.com"})
        ctx = svc.get_context()
        assert ctx["mode"] == "passive"
        assert "target" in ctx["contexts"]

    def test_explain_known(self):
        svc = self._make()
        result = svc.explain("xss")
        assert result["status"] == "explained"
        assert len(result["techniques"]) > 0

    def test_explain_unknown(self):
        svc = self._make()
        result = svc.explain("unknown_topic")
        assert result["status"] == "explained"

    def test_get_stats(self):
        svc = self._make()
        svc.suggest({"target": "x.com"})
        stats = svc.get_stats()
        assert stats["total_suggestions"] > 0
        assert stats["mode"] == "passive"

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.copilot import CopilotService
        bus = EventBus()
        events = []
        bus.subscribe("copilot.suggestions_generated", lambda e: events.append(e))
        svc = CopilotService(bus, Path(tempfile.mkdtemp()))
        svc.suggest()
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — CampaignService (10.11)
# ══════════════════════════════════════════════════════════════════════

class TestCampaignService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.campaign import CampaignService
        return CampaignService(EventBus(), Path(tempfile.mkdtemp()))

    def test_create_campaign(self):
        svc = self._make()
        result = svc.create_campaign("x.com")
        assert result["status"] == "created"
        assert result["target"] == "x.com"
        assert result["state"] == "planning"

    def test_create_campaign_bad_type(self):
        svc = self._make()
        result = svc.create_campaign("x.com", campaign_type="invalid")
        assert result["status"] == "error"

    def test_start_campaign(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        result = svc.start_campaign(c["id"])
        assert result["status"] == "started"
        assert result["state"] == "running"
        assert result["current_phase"] == "recon"

    def test_start_not_found(self):
        svc = self._make()
        result = svc.start_campaign("bad-id")
        assert result["status"] == "error"

    def test_advance_phase(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        svc.start_campaign(c["id"])
        result = svc.advance_phase(c["id"])
        assert result["status"] == "advanced"
        assert result["phase"] == "enumeration"

    def test_advance_to_completion(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        svc.start_campaign(c["id"])
        for _ in range(6):
            result = svc.advance_phase(c["id"])
        assert result["status"] == "completed"

    def test_record_step(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        svc.start_campaign(c["id"])
        result = svc.record_step(c["id"], "subfinder scan")
        assert result["status"] == "recorded"
        assert result["phase"] == "recon"

    def test_record_step_not_found(self):
        svc = self._make()
        result = svc.record_step("bad-id", "x")
        assert result["status"] == "error"

    def test_record_finding(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        result = svc.record_finding(c["id"], {"vuln": "xss"})
        assert result["status"] == "recorded"
        assert result["findings_count"] == 1

    def test_pause_campaign(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        svc.start_campaign(c["id"])
        result = svc.pause_campaign(c["id"])
        assert result["status"] == "paused"
        assert result["state"] == "paused"

    def test_pause_not_running(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        result = svc.pause_campaign(c["id"])
        assert result["status"] == "error"

    def test_cancel_campaign(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        result = svc.cancel_campaign(c["id"])
        assert result["status"] == "cancelled"

    def test_list_campaigns(self):
        svc = self._make()
        svc.create_campaign("a.com")
        import time as _t
        _t.sleep(0.002)
        svc.create_campaign("b.com")
        all_c = svc.list_campaigns()
        assert len(all_c) == 2
        planning = svc.list_campaigns(state="planning")
        assert len(planning) == 2

    def test_get_campaign(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        svc.start_campaign(c["id"])
        svc.record_step(c["id"], "test step")
        detail = svc.get_campaign(c["id"])
        assert len(detail["steps"]) == 1

    def test_get_campaign_not_found(self):
        svc = self._make()
        result = svc.get_campaign("bad-id")
        assert result["status"] == "error"

    def test_resume_paused(self):
        svc = self._make()
        c = svc.create_campaign("x.com")
        svc.start_campaign(c["id"])
        svc.pause_campaign(c["id"])
        result = svc.start_campaign(c["id"])
        assert result["status"] == "started"

    def test_get_stats(self):
        svc = self._make()
        svc.create_campaign("x.com")
        stats = svc.get_stats()
        assert stats["total_campaigns"] == 1
        assert "planning" in stats["by_state"]

    def test_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.campaign import CampaignService
        bus = EventBus()
        events = []
        bus.subscribe("campaign.created", lambda e: events.append(e))
        svc = CampaignService(bus, Path(tempfile.mkdtemp()))
        svc.create_campaign("x.com")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch4P10Commands:

    def _run(self, handler, args=None, kwargs=None):
        svc = make_services()
        ctx = MagicMock()
        ctx.services = svc
        from hydra.commands.builtins.campaign_cmds import _sync, _copilot, _campaign
        handlers = {"sync": _sync, "copilot": _copilot, "campaign": _campaign}
        return handlers[handler](args or [], kwargs or {}, ctx)

    def test_sync_stats(self):
        r = self._run("sync")
        assert r.ok
        assert r.output["type"] == "sync_stats"

    def test_sync_snapshot(self):
        r = self._run("sync", ["snapshot"])
        assert r.ok
        assert r.output["type"] == "sync_snapshot"

    def test_sync_push(self):
        r = self._run("sync", ["push", "peer-1"])
        assert r.ok
        assert r.output["type"] == "sync_pushed"

    def test_sync_pull(self):
        r = self._run("sync", ["pull", "peer-1"])
        assert r.ok
        assert r.output["type"] == "sync_pulled"

    def test_sync_peers(self):
        r = self._run("sync", ["peers"])
        assert r.ok

    def test_sync_history(self):
        r = self._run("sync", ["history"])
        assert r.ok

    def test_sync_bad_subcmd(self):
        r = self._run("sync", ["bad"])
        assert not r.ok

    def test_copilot_stats(self):
        r = self._run("copilot")
        assert r.ok
        assert r.output["type"] == "copilot_stats"

    def test_copilot_suggest(self):
        r = self._run("copilot", ["suggest"], {"target": "x.com"})
        assert r.ok
        assert r.output["type"] == "copilot_suggestions"

    def test_copilot_mode(self):
        r = self._run("copilot", ["mode", "active"])
        assert r.ok
        assert r.output["type"] == "copilot_mode"

    def test_copilot_explain(self):
        r = self._run("copilot", ["explain", "xss"])
        assert r.ok
        assert r.output["type"] == "copilot_explain"

    def test_copilot_context(self):
        r = self._run("copilot", ["context"])
        assert r.ok

    def test_copilot_bad_subcmd(self):
        r = self._run("copilot", ["bad"])
        assert not r.ok

    def test_campaign_stats(self):
        r = self._run("campaign")
        assert r.ok
        assert r.output["type"] == "campaign_stats"

    def test_campaign_create(self):
        r = self._run("campaign", ["create", "x.com"])
        assert r.ok
        assert r.output["type"] == "campaign_created"

    def test_campaign_list(self):
        r = self._run("campaign", ["list"])
        assert r.ok
        assert r.output["type"] == "campaign_list"

    def test_campaign_bad_subcmd(self):
        r = self._run("campaign", ["bad"])
        assert not r.ok


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — Wiring
# ══════════════════════════════════════════════════════════════════════

class TestBatch4P10Wiring:

    def test_knowledge_sync_wired(self):
        svc = make_services()
        from hydra.services.knowledge_sync import KnowledgeSyncService
        assert isinstance(svc.knowledge_sync, KnowledgeSyncService)

    def test_copilot_wired(self):
        svc = make_services()
        from hydra.services.copilot import CopilotService
        assert isinstance(svc.copilot, CopilotService)

    def test_campaign_wired(self):
        svc = make_services()
        from hydra.services.campaign import CampaignService
        assert isinstance(svc.campaign, CampaignService)

    def test_commands_registered(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        assert "sync" in names
        assert "copilot" in names
        assert "campaign" in names
