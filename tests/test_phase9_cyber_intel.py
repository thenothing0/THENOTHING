"""Phase 9 — Cyber Intelligence Platform tests (Batches 1–3).

Validates:
  #1  IngestService — multi-source ingestion
  #2  ExtractionService — AI-enhanced field extraction
  #3  ReportStoreService — structured report queries
  #4  Intel commands — /ingest, /reports, /extract, /intel-stats
  #5  ServiceContainer wiring
  #6  Facade delegation
  #7  GraphService — knowledge graph queries
  #8  TTPService — MITRE ATT&CK extraction
  #9  MemoryService — unified cyber memory
  #10 AgentService — agent ecosystem
  #11 WorkflowService — autonomous workflows
  #12 RouterService — multi-model AI routing
  #13 Batch 3 commands — /agents, /workflow, /router
  #14 Batch 3 facade delegation
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock



# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def make_services():
    from hydra.services.event_bus import EventBus
    from hydra.services import ServiceContainer
    bus = EventBus()
    return ServiceContainer(event_bus=bus, data_dir=tempfile.mkdtemp())


# ══════════════════════════════════════════════════════════════════════
# #1 — IngestService
# ══════════════════════════════════════════════════════════════════════

class TestIngestService:
    def test_import(self):
        from hydra.services.ingest import IngestService
        assert IngestService is not None

    def test_init(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        assert svc is not None

    def test_list_sources(self):
        from hydra.services.ingest import IngestService, SOURCE_TYPES
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        sources = svc.list_sources()
        assert isinstance(sources, list)
        assert "writeup" in sources
        assert "hackerone" in sources
        assert "cve" in sources
        assert len(sources) == len(SOURCE_TYPES)

    def test_ingest_result_dataclass(self):
        from hydra.services.ingest import IngestResult
        r = IngestResult(slug="test-slug", title="Test", learning_score=7)
        assert r.ok is True
        assert r.slug == "test-slug"
        d = r.to_dict()
        assert d["slug"] == "test-slug"
        assert d["learning_score"] == 7

    def test_ingest_result_error(self):
        from hydra.services.ingest import IngestResult
        r = IngestResult(error="something broke")
        assert r.ok is False
        assert "something broke" in r.to_dict()["error"]

    def test_ingest_batch_result(self):
        from hydra.services.ingest import IngestBatchResult
        b = IngestBatchResult(total=3, succeeded=2, failed=1)
        d = b.to_dict()
        assert d["total"] == 3
        assert d["succeeded"] == 2
        assert d["failed"] == 1

    def test_ingest_text_with_mock_pipeline(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus

        bus = EventBus()
        svc = IngestService(bus)

        mock_result = MagicMock()
        mock_result.slug = "test-report"
        mock_result.title = "Test Report"
        mock_result.learning_score = 6
        mock_result.vuln_class = MagicMock(value="xss")
        mock_result.report_path = "wiki/reports/test-report.md"
        mock_result.intel_path = "wiki/intel/test-report-intel.md"

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.return_value = mock_result
            result = svc.ingest_text("some vuln text", title="Test")
            assert result.ok
            assert result.slug == "test-report"
            assert result.learning_score == 6

    def test_ingest_text_error_handling(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.side_effect = RuntimeError("boom")
            result = svc.ingest_text("broken")
            assert not result.ok
            assert "boom" in result.error

    def test_ingest_batch_with_mock(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus

        bus = EventBus()
        svc = IngestService(bus)

        mock_result = MagicMock()
        mock_result.slug = "batch-item"
        mock_result.title = "Batch"
        mock_result.learning_score = 5
        mock_result.vuln_class = MagicMock(value="sqli")
        mock_result.report_path = "wiki/reports/batch.md"
        mock_result.intel_path = "wiki/intel/batch-intel.md"

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.return_value = mock_result
            batch = svc.ingest_batch([
                {"text": "report one", "title": "R1"},
                {"text": "report two", "title": "R2"},
            ])
            assert batch.total == 2
            assert batch.succeeded == 2
            assert batch.failed == 0
            assert len(batch.results) == 2

    def test_ingest_batch_bad_item(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        batch = svc.ingest_batch([{"no_text_or_path": True}])
        assert batch.total == 1
        assert batch.failed == 1

    def test_normalize_hackerone(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        data = {
            "title": "IDOR on /api/users",
            "vulnerability_information": "User A can access User B data",
            "weakness": {"name": "IDOR", "external_id": "CWE-639"},
            "severity": {"rating": "high", "score": 8.1},
            "impact": "Full account data access",
            "structured_scope": {"asset_identifier": "api.example.com", "asset_type": "URL"},
        }
        text = svc._normalize_hackerone(data)
        assert "IDOR on /api/users" in text
        assert "CWE-639" in text
        assert "8.1" in text
        assert "api.example.com" in text

    def test_normalize_cve(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        data = {
            "id": "CVE-2024-1234",
            "descriptions": [{"value": "Buffer overflow in libfoo"}],
            "references": [{"url": "https://example.com/advisory"}],
            "weaknesses": [{"description": [{"value": "CWE-120"}]}],
        }
        text = svc._normalize_cve(data)
        assert "CVE-2024-1234" in text
        assert "Buffer overflow" in text
        assert "CWE-120" in text

    def test_normalize_github_advisory(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        data = {
            "ghsa_id": "GHSA-xxxx-yyyy",
            "summary": "RCE in foo-bar",
            "description": "Arbitrary code execution",
            "severity": "critical",
            "cve_id": "CVE-2024-9999",
            "cwes": [{"cwe_id": "CWE-94"}],
        }
        text = svc._normalize_github_advisory(data)
        assert "RCE in foo-bar" in text
        assert "CVE-2024-9999" in text
        assert "CWE-94" in text

    def test_ingest_hackerone_json(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())

        mock_result = MagicMock()
        mock_result.slug = "h1-report"
        mock_result.title = "IDOR"
        mock_result.learning_score = 8
        mock_result.vuln_class = MagicMock(value="idor")
        mock_result.report_path = "wiki/reports/h1.md"
        mock_result.intel_path = "wiki/intel/h1-intel.md"

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.return_value = mock_result
            data = {"title": "IDOR", "team": {"handle": "acme"}}
            result = svc.ingest_hackerone(json.dumps(data))
            assert result.ok
            assert result.slug == "h1-report"

    def test_ingest_cve_json(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())

        mock_result = MagicMock()
        mock_result.slug = "cve-report"
        mock_result.title = "CVE-2024-1234"
        mock_result.learning_score = 5
        mock_result.vuln_class = MagicMock(value="buffer_overflow")
        mock_result.report_path = "wiki/reports/cve.md"
        mock_result.intel_path = "wiki/intel/cve-intel.md"

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.return_value = mock_result
            data = {"id": "CVE-2024-1234", "descriptions": [{"value": "overflow"}]}
            result = svc.ingest_cve(json.dumps(data))
            assert result.ok

    def test_ingest_github_advisory_json(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())

        mock_result = MagicMock()
        mock_result.slug = "ghsa-report"
        mock_result.title = "GHSA-xxx"
        mock_result.learning_score = 6
        mock_result.vuln_class = MagicMock(value="rce")
        mock_result.report_path = "wiki/reports/ghsa.md"
        mock_result.intel_path = "wiki/intel/ghsa-intel.md"

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.return_value = mock_result
            data = {"ghsa_id": "GHSA-xxx", "summary": "RCE", "description": "arbitrary"}
            result = svc.ingest_github_advisory(json.dumps(data))
            assert result.ok

    def test_get_stats(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus
        svc = IngestService(EventBus())
        stats = svc.get_stats()
        assert "reports" in stats
        assert "intel" in stats
        assert "sources" in stats

    def test_events_emitted(self):
        from hydra.services.ingest import IngestService
        from hydra.services.event_bus import EventBus

        bus = EventBus()
        svc = IngestService(bus)
        events = []
        bus.subscribe("ingest.completed", lambda e: events.append(e))

        mock_result = MagicMock()
        mock_result.slug = "ev-test"
        mock_result.title = "Event Test"
        mock_result.learning_score = 4
        mock_result.vuln_class = MagicMock(value="xss")
        mock_result.report_path = ""
        mock_result.intel_path = ""

        with patch.object(svc, "_pipeline") as mock_pipe:
            mock_pipe.return_value.ingest.return_value = mock_result
            svc.ingest_text("test content")
            assert len(events) == 1
            assert events[0].type == "ingest.completed"
            assert events[0].payload["slug"] == "ev-test"


# ══════════════════════════════════════════════════════════════════════
# #2 — ExtractionService
# ══════════════════════════════════════════════════════════════════════

class TestExtractionService:
    def test_import(self):
        from hydra.services.extraction import ExtractionService
        assert ExtractionService is not None

    def test_init(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        assert svc is not None

    def test_list_field_types(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        types = svc.list_field_types()
        assert "root_cause" in types
        assert "exploitation_flow" in types
        assert "impact_analysis" in types
        assert "detection" in types
        assert "remediation" in types
        assert "ttp_extraction" in types

    def test_extraction_result_dataclass(self):
        from hydra.services.extraction import ExtractionResult
        r = ExtractionResult(fields={"key": "val"}, confidence=0.8, model_used="test")
        assert r.ok
        d = r.to_dict()
        assert d["confidence"] == 0.8
        assert d["fields"]["key"] == "val"

    def test_extraction_result_error(self):
        from hydra.services.extraction import ExtractionResult
        r = ExtractionResult(error="failed")
        assert not r.ok

    def test_unknown_field_type(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        result = svc.extract_field("text", "nonexistent_field")
        assert not result.ok
        assert "Unknown field type" in result.error

    def test_fallback_extract_root_cause(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        text = "The root cause is improper input validation. CWE-79."
        result = svc._fallback_extract(text, "Analyze root cause")
        parsed = json.loads(result)
        assert "cwe" in parsed or "root_cause" in parsed
        assert parsed.get("cwe") == "CWE-79"

    def test_fallback_extract_steps(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        text = "1. Navigate to /api\n2. Send payload\n3. Observe XSS"
        result = svc._fallback_extract(text, "Extract the step-by-step exploitation flow")
        parsed = json.loads(result)
        assert "steps" in parsed
        assert len(parsed["steps"]) >= 2

    def test_fallback_extract_detection(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        text = "Monitor access logs for unusual patterns. Alert on suspicious requests."
        result = svc._fallback_extract(text, "Extract detection opportunities and indicators")
        parsed = json.loads(result)
        assert "indicators" in parsed

    def test_fallback_extract_remediation(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        text = "Fix: sanitize input. Upgrade to version 2.0. Patch the library."
        result = svc._fallback_extract(text, "Extract remediation guidance")
        parsed = json.loads(result)
        assert "immediate" in parsed

    def test_fallback_extract_ttp(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        text = "Used TA0043 for recon. Technique T1190 was exploited."
        result = svc._fallback_extract(text, "Extract MITRE ATT&CK TTPs")
        parsed = json.loads(result)
        assert "tactics" in parsed
        assert "TA0043" in parsed["tactics"]
        assert "techniques" in parsed
        assert "T1190" in parsed["techniques"]

    def test_parse_json_response_clean(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        result = svc._parse_json_response('{"key": "value", "confidence": 0.9}')
        assert result["key"] == "value"

    def test_parse_json_response_wrapped(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        result = svc._parse_json_response('Here is the result: {"key": "value"} end.')
        assert result["key"] == "value"

    def test_parse_json_response_invalid(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())
        result = svc._parse_json_response("not json at all")
        assert "raw_response" in result

    def test_extract_field_with_fallback(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())

        with patch.object(svc, "_call_llm") as mock_llm:
            mock_llm.return_value = '{"root_cause": "injection", "cwe": "CWE-89", "confidence": 0.7}'
            result = svc.extract_field("SQL injection via user input", "root_cause")
            assert result.ok
            assert result.fields["root_cause"] == "injection"
            assert result.confidence == 0.7

    def test_extract_all(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())

        with patch.object(svc, "_call_llm") as mock_llm:
            mock_llm.return_value = '{"result": "ok", "confidence": 0.5}'
            results = svc.extract_all("some vuln text")
            assert isinstance(results, dict)
            assert "root_cause" in results
            assert "exploitation_flow" in results
            assert all(r.ok for r in results.values())

    def test_extract_custom(self):
        from hydra.services.extraction import ExtractionService
        from hydra.services.event_bus import EventBus
        svc = ExtractionService(EventBus())

        with patch.object(svc, "_call_llm") as mock_llm:
            mock_llm.return_value = '{"custom": "result", "confidence": 0.6}'
            result = svc.extract_custom("text", "Custom extraction prompt")
            assert result.ok
            assert result.fields["custom"] == "result"


# ══════════════════════════════════════════════════════════════════════
# #3 — ReportStoreService
# ══════════════════════════════════════════════════════════════════════

class TestReportStoreService:
    def test_import(self):
        from hydra.services.report_store import ReportStoreService
        assert ReportStoreService is not None

    def test_init(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        assert svc is not None

    def test_report_entry_dataclass(self):
        from hydra.services.report_store import ReportEntry
        e = ReportEntry(slug="test", title="Test", learning_score=8, vuln_class="xss")
        d = e.to_dict()
        assert d["slug"] == "test"
        assert d["learning_score"] == 8
        assert d["vuln_class"] == "xss"

    def test_list_reports_returns_list(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        reports = svc.list_reports()
        assert isinstance(reports, list)

    def test_list_intel_returns_list(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        intel = svc.list_intel()
        assert isinstance(intel, list)

    def test_get_report_not_found(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        report = svc.get_report("nonexistent-slug-12345")
        assert report is None

    def test_search_returns_list(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        results = svc.search("xss")
        assert isinstance(results, list)

    def test_aggregate_by_vuln_class(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        agg = svc.aggregate_by_vuln_class()
        assert isinstance(agg, list)

    def test_aggregate_by_target(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        agg = svc.aggregate_by_target()
        assert isinstance(agg, list)

    def test_get_stats(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        stats = svc.get_stats()
        assert "total_reports" in stats
        assert "total_intel" in stats

    def test_get_high_value(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        hv = svc.get_high_value()
        assert isinstance(hv, list)

    def test_get_related_nonexistent(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        related = svc.get_related("nonexistent-slug-xyz")
        assert isinstance(related, list)
        assert len(related) == 0

    def test_score_distribution(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())
        dist = svc._score_distribution([1, 3, 5, 7, 10])
        assert dist["low_1_3"] == 2
        assert dist["mid_4_6"] == 1
        assert dist["high_7_10"] == 2

    def test_list_reports_with_mock_store(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())

        mock_page = MagicMock()
        mock_page.slug = "test-report"
        mock_page.meta = {
            "title": "Test XSS",
            "target": "example.com",
            "vuln_class": "xss",
            "learning_score": 7,
            "source_type": "writeup",
            "source_url": "",
            "created": "2024-01-01",
        }

        with patch.object(svc, "_store") as mock_store:
            mock_store.return_value.iter_pages.return_value = [mock_page]
            reports = svc.list_reports()
            assert len(reports) == 1
            assert reports[0]["slug"] == "test-report"
            assert reports[0]["vuln_class"] == "xss"

    def test_list_reports_filter_target(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())

        pages = []
        for i, (tgt, vc) in enumerate([("example.com", "xss"), ("other.com", "sqli")]):
            p = MagicMock()
            p.slug = f"report-{i}"
            p.meta = {"title": f"R{i}", "target": tgt, "vuln_class": vc,
                       "learning_score": 5, "source_type": "", "source_url": "", "created": ""}
            pages.append(p)

        with patch.object(svc, "_store") as mock_store:
            mock_store.return_value.iter_pages.return_value = pages
            result = svc.list_reports(target="example")
            assert len(result) == 1
            assert result[0]["target"] == "example.com"

    def test_list_reports_filter_min_score(self):
        from hydra.services.report_store import ReportStoreService
        from hydra.services.event_bus import EventBus
        svc = ReportStoreService(EventBus())

        pages = []
        for score in [3, 5, 8]:
            p = MagicMock()
            p.slug = f"report-{score}"
            p.meta = {"title": f"R{score}", "target": "", "vuln_class": "",
                       "learning_score": score, "source_type": "", "source_url": "", "created": ""}
            pages.append(p)

        with patch.object(svc, "_store") as mock_store:
            mock_store.return_value.iter_pages.return_value = pages
            result = svc.list_reports(min_score=5)
            assert len(result) == 2


# ══════════════════════════════════════════════════════════════════════
# #4 — Intel Commands
# ══════════════════════════════════════════════════════════════════════

class TestIntelCommands:
    def test_import(self):
        from hydra.commands.builtins.intel import register_intel_commands
        assert register_intel_commands is not None

    def test_registration(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins.intel import register_intel_commands
        reg = CommandRegistry()
        register_intel_commands(reg)
        cmds = reg.list_commands()
        names = [c.name for c in cmds]
        assert "ingest" in names
        assert "reports" in names
        assert "extract" in names
        assert "intel-stats" in names

    def test_ingest_no_args(self):
        from hydra.commands.builtins.intel import _ingest
        result = _ingest([], {}, MagicMock())
        assert not result.ok
        assert any("Usage" in e for e in result.errors)

    def test_reports_command_stats(self):
        from hydra.commands.builtins.intel import _reports
        ctx = MagicMock()
        ctx.services.report_store.get_stats.return_value = {
            "total_reports": 10, "total_intel": 8,
        }
        result = _reports(["stats"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "report_stats"

    def test_reports_command_by_vuln(self):
        from hydra.commands.builtins.intel import _reports
        ctx = MagicMock()
        ctx.services.report_store.aggregate_by_vuln_class.return_value = [
            {"vuln_class": "xss", "count": 5},
        ]
        result = _reports(["by-vuln"], {}, ctx)
        assert result.ok
        assert result.output["by"] == "vuln_class"

    def test_reports_command_list(self):
        from hydra.commands.builtins.intel import _reports
        ctx = MagicMock()
        ctx.services.report_store.list_reports.return_value = []
        result = _reports([], {}, ctx)
        assert result.ok
        assert result.output["type"] == "report_list"

    def test_extract_no_args(self):
        from hydra.commands.builtins.intel import _extract
        ctx = MagicMock()
        ctx.services.extraction.list_field_types.return_value = ["root_cause", "ttp_extraction"]
        result = _extract([], {}, ctx)
        assert result.ok
        assert "available" in result.output

    def test_extract_missing_text(self):
        from hydra.commands.builtins.intel import _extract
        ctx = MagicMock()
        result = _extract(["root_cause"], {}, ctx)
        assert not result.ok

    def test_intel_stats_command(self):
        from hydra.commands.builtins.intel import _intel_stats
        ctx = MagicMock()
        ctx.services.ingest.get_stats.return_value = {
            "reports": 10, "intel": 5, "sources": ["writeup"],
        }
        result = _intel_stats([], {}, ctx)
        assert result.ok
        assert result.output["type"] == "intel_stats"


# ══════════════════════════════════════════════════════════════════════
# #5 — ServiceContainer wiring
# ══════════════════════════════════════════════════════════════════════

class TestServiceContainerWiring:
    def test_ingest_service_accessible(self):
        svc = make_services()
        from hydra.services.ingest import IngestService
        assert isinstance(svc.ingest, IngestService)

    def test_extraction_service_accessible(self):
        svc = make_services()
        from hydra.services.extraction import ExtractionService
        assert isinstance(svc.extraction, ExtractionService)

    def test_report_store_service_accessible(self):
        svc = make_services()
        from hydra.services.report_store import ReportStoreService
        assert isinstance(svc.report_store, ReportStoreService)

    def test_graph_service_accessible(self):
        svc = make_services()
        from hydra.services.graph import GraphService
        assert isinstance(svc.graph, GraphService)

    def test_ttp_service_accessible(self):
        svc = make_services()
        from hydra.services.ttp import TTPService
        assert isinstance(svc.ttp, TTPService)

    def test_memory_service_accessible(self):
        svc = make_services()
        from hydra.services.memory import MemoryService
        assert isinstance(svc.memory, MemoryService)

    def test_lazy_init_caching(self):
        svc = make_services()
        a = svc.ingest
        b = svc.ingest
        assert a is b

    def test_all_services_share_bus(self):
        svc = make_services()
        assert svc.ingest._bus is svc.extraction._bus
        assert svc.extraction._bus is svc.report_store._bus
        assert svc.graph._bus is svc.ttp._bus
        assert svc.ttp._bus is svc.memory._bus


# ══════════════════════════════════════════════════════════════════════
# #6 — Facade delegation
# ══════════════════════════════════════════════════════════════════════

class TestFacadeDelegation:
    def _make_facade(self):
        from hydra.services.event_bus import EventBus
        from hydra.services import ServiceContainer
        from hydra.registry.capability import CapabilityRegistry
        from hydra.commands.registry import CommandRegistry
        from hydra.facade import HydraFacade

        bus = EventBus()
        svc = ServiceContainer(event_bus=bus)
        reg = CapabilityRegistry()
        cmd_reg = CommandRegistry()
        return HydraFacade(svc, reg, bus, cmd_reg)

    def test_ingest_text_delegated(self):
        facade = self._make_facade()
        with patch.object(facade._svc.ingest, "ingest_text") as mock:
            mock.return_value = MagicMock(ok=True)
            facade.ingest_text("test text", title="Test")
            mock.assert_called_once()

    def test_ingest_file_delegated(self):
        facade = self._make_facade()
        with patch.object(facade._svc.ingest, "ingest_file") as mock:
            mock.return_value = MagicMock(ok=True)
            facade.ingest_file("/tmp/test.md", title="Test")
            mock.assert_called_once()

    def test_get_report_stats_delegated(self):
        facade = self._make_facade()
        with patch.object(facade._svc.report_store, "get_stats") as mock:
            mock.return_value = {"total_reports": 5}
            result = facade.get_report_stats()
            assert result["total_reports"] == 5

    def test_extract_field_delegated(self):
        facade = self._make_facade()
        with patch.object(facade._svc.extraction, "extract_field") as mock:
            mock.return_value = MagicMock(ok=True)
            facade.extract_field("text", "root_cause")
            mock.assert_called_once()

    def test_aggregate_reports_vuln_class(self):
        facade = self._make_facade()
        with patch.object(facade._svc.report_store, "aggregate_by_vuln_class") as mock:
            mock.return_value = [{"vuln_class": "xss", "count": 5}]
            result = facade.aggregate_reports("vuln_class")
            assert len(result) == 1

    def test_aggregate_reports_target(self):
        facade = self._make_facade()
        with patch.object(facade._svc.report_store, "aggregate_by_target") as mock:
            mock.return_value = [{"target": "example.com", "count": 3}]
            result = facade.aggregate_reports("target")
            assert len(result) == 1


# ══════════════════════════════════════════════════════════════════════
# #7 — Full builtin registration includes intel
# ══════════════════════════════════════════════════════════════════════

class TestBuiltinRegistrationIncludesIntel:
    def test_register_all_includes_intel_and_graph(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = [c.name for c in reg.list_commands()]
        # Batch 1
        assert "ingest" in names
        assert "reports" in names
        assert "extract" in names
        assert "intel-stats" in names
        # Batch 2
        assert "graph" in names
        assert "ttp" in names
        assert "memory" in names
        # existing
        assert "help" in names
        assert "search" in names


# ══════════════════════════════════════════════════════════════════════
# #8 — GraphService
# ══════════════════════════════════════════════════════════════════════

class TestGraphService:
    def test_import(self):
        from hydra.services.graph import GraphService
        assert GraphService is not None

    def test_init(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        assert svc is not None

    def test_relationship_types(self):
        from hydra.services.graph import RELATIONSHIP_TYPES
        assert "references" in RELATIONSHIP_TYPES
        assert "chains_to" in RELATIONSHIP_TYPES

    def test_neighbors_returns_list(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        result = svc.neighbors("nonexistent-slug-xyz")
        assert isinstance(result, list)

    def test_shortest_path_returns_list(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        result = svc.shortest_path("a", "b")
        assert isinstance(result, list)

    def test_subgraph_returns_dict(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        result = svc.subgraph("nonexistent")
        assert isinstance(result, dict)
        assert "nodes" in result
        assert "edges" in result

    def test_get_stats(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        stats = svc.get_stats()
        assert "total_nodes" in stats

    def test_entities_by_type(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        result = svc.entities_by_type("report")
        assert isinstance(result, list)

    def test_find_related(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())
        result = svc.find_related("nonexistent")
        assert isinstance(result, list)

    def test_neighbors_with_mock(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())

        mock_page = MagicMock()
        mock_page.meta = {"type": "finding", "title": "XSS on /api"}

        with patch.object(svc, "_index") as mock_idx, \
             patch.object(svc, "_store") as mock_store:
            mock_idx.return_value.neighbors.return_value = ["finding-xss"]
            mock_store.return_value.read.return_value = mock_page
            result = svc.neighbors("test-slug")
            assert len(result) == 1
            assert result[0]["type"] == "finding"

    def test_subgraph_with_mock(self):
        from hydra.services.graph import GraphService
        from hydra.services.event_bus import EventBus
        svc = GraphService(EventBus())

        mock_page = MagicMock()
        mock_page.meta = {"type": "report", "title": "Test"}

        with patch.object(svc, "_index") as mock_idx, \
             patch.object(svc, "_store") as mock_store:
            mock_idx.return_value.neighbors.return_value = []
            mock_store.return_value.read.return_value = mock_page
            result = svc.subgraph("center-node")
            assert result["center"] == "center-node"
            assert result["node_count"] == 1


# ══════════════════════════════════════════════════════════════════════
# #9 — TTPService
# ══════════════════════════════════════════════════════════════════════

class TestTTPService:
    def test_import(self):
        from hydra.services.ttp import TTPService
        assert TTPService is not None

    def test_init(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        assert svc is not None

    def test_extract_ttps_explicit_ids(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        result = svc.extract_ttps("Used TA0043 and T1190 for initial access")
        assert "TA0043" in result["tactics"]
        assert "T1190" in result["techniques"]
        assert result["tactic_count"] >= 1
        assert result["technique_count"] >= 1

    def test_extract_ttps_keyword_match(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        result = svc.extract_ttps("SQL injection was used for initial access via brute force")
        assert "T1190" in result["techniques"]
        assert "T1110" in result["techniques"]

    def test_extract_ttps_tactic_keyword(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        result = svc.extract_ttps("Used reconnaissance to discover the target")
        assert "TA0043" in result["tactics"]

    def test_extract_ttps_empty(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        result = svc.extract_ttps("No MITRE content here.")
        assert result["tactic_count"] == 0
        assert result["technique_count"] == 0

    def test_extract_ttps_event_emitted(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        svc = TTPService(bus)
        events = []
        bus.subscribe("ttp.extracted", lambda e: events.append(e))
        svc.extract_ttps("T1190 exploit")
        assert len(events) == 1

    def test_generate_playbook(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        findings = [
            {"title": "SSRF on /proxy", "vuln_class": "ssrf", "severity": "high", "endpoint": "/proxy"},
            {"title": "RCE via deserialization", "vuln_class": "rce", "severity": "critical", "endpoint": "/api"},
        ]
        playbook = svc.generate_playbook(findings)
        assert playbook["step_count"] == 2
        assert len(playbook["steps"]) == 2
        assert playbook["chain_count"] == 1
        assert "T1090" in playbook["techniques"]
        assert "T1203" in playbook["techniques"]

    def test_generate_playbook_empty(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        playbook = svc.generate_playbook([])
        assert playbook["step_count"] == 0
        assert playbook["chain_count"] == 0

    def test_get_stats(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        stats = svc.get_stats()
        assert "coverage_summary" in stats

    def test_capabilities_for_technique(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        with patch.object(svc, "_mapping") as mock:
            mock.return_value.capabilities_for.return_value = ["web_vuln_scan"]
            result = svc.capabilities_for_technique("T1190")
            assert result == ["web_vuln_scan"]

    def test_techniques_for_capability(self):
        from hydra.services.ttp import TTPService
        from hydra.services.event_bus import EventBus
        svc = TTPService(EventBus())
        with patch.object(svc, "_mapping") as mock:
            mock.return_value.techniques_for_capability.return_value = ["T1190"]
            result = svc.techniques_for_capability("web_vuln_scan")
            assert result == ["T1190"]


# ══════════════════════════════════════════════════════════════════════
# #10 — MemoryService
# ══════════════════════════════════════════════════════════════════════

class TestMemoryService:
    def test_import(self):
        from hydra.services.memory import MemoryService
        assert MemoryService is not None

    def test_init(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        svc = MemoryService(EventBus(), Path(tempfile.mkdtemp()))
        assert svc is not None

    def test_record_and_read(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        tmp = Path(tempfile.mkdtemp())
        svc = MemoryService(EventBus(), tmp)
        result = svc.record("test_kind", "test content", target="example.com")
        assert result["status"] == "ok"
        entries = svc._read_memory_file(limit=10)
        assert len(entries) == 1
        assert entries[0]["kind"] == "test_kind"
        assert entries[0]["content"] == "test content"

    def test_record_outcome(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        tmp = Path(tempfile.mkdtemp())
        svc = MemoryService(EventBus(), tmp)
        result = svc.record_outcome("example.com", "xss", "confirmed", "reflected in /search")
        assert result["status"] == "ok"
        entries = svc._read_memory_file()
        assert entries[0]["kind"] == "attack_outcome"

    def test_record_event_emitted(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        svc = MemoryService(bus, Path(tempfile.mkdtemp()))
        events = []
        bus.subscribe("memory.recorded", lambda e: events.append(e))
        svc.record("test", "content")
        assert len(events) == 1

    def test_recall_returns_list(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        svc = MemoryService(EventBus(), Path(tempfile.mkdtemp()))
        results = svc.recall("xss bypass")
        assert isinstance(results, list)

    def test_recall_event_emitted(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        bus = EventBus()
        svc = MemoryService(bus, Path(tempfile.mkdtemp()))
        events = []
        bus.subscribe("memory.recalled", lambda e: events.append(e))
        svc.recall("test query")
        assert len(events) == 1

    def test_get_recent_empty(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        svc = MemoryService(EventBus(), Path(tempfile.mkdtemp()))
        entries = svc.get_recent()
        assert isinstance(entries, list)

    def test_search_by_target(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        svc = MemoryService(EventBus(), Path(tempfile.mkdtemp()))
        results = svc.search_by_target("example.com")
        assert isinstance(results, list)

    def test_search_by_vuln_class(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        svc = MemoryService(EventBus(), Path(tempfile.mkdtemp()))
        results = svc.search_by_vuln_class("xss")
        assert isinstance(results, list)

    def test_get_stats(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        tmp = Path(tempfile.mkdtemp())
        svc = MemoryService(EventBus(), tmp)
        svc.record("a", "content1")
        svc.record("b", "content2")
        svc.record("a", "content3")
        with patch("hydra.services.memory.MemoryService.get_recent",
                    side_effect=lambda **kw: svc._read_memory_file(**kw)):
            stats = svc.get_stats()
        assert stats["total_entries"] == 3
        assert stats["by_kind"]["a"] == 2
        assert stats["by_kind"]["b"] == 1

    def test_content_truncation(self):
        from hydra.services.memory import MemoryService
        from hydra.services.event_bus import EventBus
        tmp = Path(tempfile.mkdtemp())
        svc = MemoryService(EventBus(), tmp)
        long_content = "x" * 5000
        svc.record("test", long_content)
        entries = svc._read_memory_file()
        assert len(entries[0]["content"]) == 2000


# ══════════════════════════════════════════════════════════════════════
# #11 — Graph/TTP/Memory Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch2Commands:
    def test_graph_cmd_import(self):
        from hydra.commands.builtins.graph_cmds import register_graph_commands
        assert register_graph_commands is not None

    def test_graph_cmd_registration(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins.graph_cmds import register_graph_commands
        reg = CommandRegistry()
        register_graph_commands(reg)
        names = [c.name for c in reg.list_commands()]
        assert "graph" in names
        assert "ttp" in names
        assert "memory" in names

    def test_graph_cmd_stats(self):
        from hydra.commands.builtins.graph_cmds import _graph
        ctx = MagicMock()
        ctx.services.graph.get_stats.return_value = {"total_nodes": 100}
        result = _graph([], {}, ctx)
        assert result.ok
        assert result.output["type"] == "graph_stats"

    def test_graph_cmd_neighbors(self):
        from hydra.commands.builtins.graph_cmds import _graph
        ctx = MagicMock()
        ctx.services.graph.neighbors.return_value = [{"slug": "test"}]
        result = _graph(["neighbors", "my-slug"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "graph_neighbors"

    def test_graph_cmd_path(self):
        from hydra.commands.builtins.graph_cmds import _graph
        ctx = MagicMock()
        ctx.services.graph.shortest_path.return_value = ["a", "b"]
        result = _graph(["path", "a", "b"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "graph_path"

    def test_ttp_cmd_stats(self):
        from hydra.commands.builtins.graph_cmds import _ttp
        ctx = MagicMock()
        ctx.services.ttp.get_stats.return_value = {"coverage_summary": {}}
        result = _ttp([], {}, ctx)
        assert result.ok
        assert result.output["type"] == "ttp_stats"

    def test_ttp_cmd_extract(self):
        from hydra.commands.builtins.graph_cmds import _ttp
        ctx = MagicMock()
        ctx.services.ttp.extract_ttps.return_value = {
            "tactics": ["TA0001"], "techniques": ["T1190"],
            "tactic_count": 1, "technique_count": 1,
        }
        result = _ttp(["extract", "SQL", "injection"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "ttp_extraction"

    def test_ttp_cmd_coverage(self):
        from hydra.commands.builtins.graph_cmds import _ttp
        ctx = MagicMock()
        ctx.services.ttp.get_coverage.return_value = []
        result = _ttp(["coverage"], {}, ctx)
        assert result.ok

    def test_memory_cmd_stats(self):
        from hydra.commands.builtins.graph_cmds import _memory
        ctx = MagicMock()
        ctx.services.memory.get_stats.return_value = {"total_entries": 5}
        result = _memory([], {}, ctx)
        assert result.ok
        assert result.output["type"] == "memory_stats"

    def test_memory_cmd_recall(self):
        from hydra.commands.builtins.graph_cmds import _memory
        ctx = MagicMock()
        ctx.services.memory.recall.return_value = [{"slug": "test"}]
        result = _memory(["recall", "xss", "bypass"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "memory_recall"

    def test_memory_cmd_recent(self):
        from hydra.commands.builtins.graph_cmds import _memory
        ctx = MagicMock()
        ctx.services.memory.get_recent.return_value = []
        result = _memory(["recent"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "memory_recent"

    def test_memory_cmd_record(self):
        from hydra.commands.builtins.graph_cmds import _memory
        ctx = MagicMock()
        ctx.services.memory.record.return_value = {"status": "ok", "kind": "note"}
        result = _memory(["record", "note", "important", "finding"], {}, ctx)
        assert result.ok
        assert result.output["type"] == "memory_recorded"


# ══════════════════════════════════════════════════════════════════════
# #12 — Facade Batch 2 delegation
# ══════════════════════════════════════════════════════════════════════

class TestFacadeBatch2:
    def _make_facade(self):
        from hydra.services.event_bus import EventBus
        from hydra.services import ServiceContainer
        from hydra.registry.capability import CapabilityRegistry
        from hydra.commands.registry import CommandRegistry
        from hydra.facade import HydraFacade
        bus = EventBus()
        svc = ServiceContainer(event_bus=bus)
        reg = CapabilityRegistry()
        cmd_reg = CommandRegistry()
        return HydraFacade(svc, reg, bus, cmd_reg)

    def test_graph_neighbors(self):
        facade = self._make_facade()
        with patch.object(facade._svc.graph, "neighbors") as mock:
            mock.return_value = [{"slug": "x"}]
            result = facade.graph_neighbors("test")
            assert len(result) == 1

    def test_graph_path(self):
        facade = self._make_facade()
        with patch.object(facade._svc.graph, "shortest_path") as mock:
            mock.return_value = ["a", "b", "c"]
            result = facade.graph_path("a", "c")
            assert result == ["a", "b", "c"]

    def test_extract_ttps(self):
        facade = self._make_facade()
        with patch.object(facade._svc.ttp, "extract_ttps") as mock:
            mock.return_value = {"tactics": [], "techniques": []}
            facade.extract_ttps("some text")
            mock.assert_called_once()

    def test_memory_recall(self):
        facade = self._make_facade()
        with patch.object(facade._svc.memory, "recall") as mock:
            mock.return_value = []
            facade.memory_recall("query")
            mock.assert_called_once()

    def test_memory_record(self):
        facade = self._make_facade()
        with patch.object(facade._svc.memory, "record") as mock:
            mock.return_value = {"status": "ok"}
            facade.memory_record("note", "content")
            mock.assert_called_once()


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — AgentService
# ══════════════════════════════════════════════════════════════════════

class TestAgentService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.agents import AgentService
        return AgentService(EventBus())

    def test_list_agents_returns_all_types(self):
        svc = self._make()
        agents = svc.list_agents()
        assert len(agents) == 10
        types = {a["type"] for a in agents}
        assert "recon" in types
        assert "coordinator" in types

    def test_list_agents_have_descriptions(self):
        svc = self._make()
        for a in svc.list_agents():
            assert a["description"]
            assert a["available"] is True

    def test_spawn_unknown_type(self):
        svc = self._make()
        result = svc.spawn_agent("nonexistent", {"id": "t1"})
        assert result["status"] == "error"

    def test_spawn_valid_type_simulated(self):
        svc = self._make()
        result = svc.spawn_agent("recon", {"id": "t1"})
        assert result["status"] == "spawned"
        assert result["agent_type"] == "recon"

    def test_execute_task_simulated(self):
        svc = self._make()
        result = svc.execute_task("vuln_research", {"target": "x.com"})
        assert result["status"] == "completed"
        assert result["agent_type"] == "vuln_research"

    def test_detect_target_web(self):
        svc = self._make()
        result = svc.detect_target_type("https://example.com")
        assert result["target_type"] == "web"
        assert "recon" in result["suggested_agents"]

    def test_detect_target_api(self):
        svc = self._make()
        result = svc.detect_target_type("https://api.example.com/v1/users")
        assert result["target_type"] == "api"
        assert "api_analyzer" in result["suggested_agents"]

    def test_detect_target_cloud(self):
        svc = self._make()
        result = svc.detect_target_type("aws.example.com")
        assert result["target_type"] == "cloud"

    def test_coordinator_status(self):
        svc = self._make()
        status = svc.get_coordinator_status()
        assert "status" in status

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["type_count"] == 10
        assert "recon" in stats["available_types"]

    def test_spawn_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.agents import AgentService
        bus = EventBus()
        events = []
        bus.subscribe("agent.spawned", lambda e: events.append(e))
        svc = AgentService(bus)
        svc.spawn_agent("recon", {"id": "t1"})
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — WorkflowService
# ══════════════════════════════════════════════════════════════════════

class TestWorkflowService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.workflows import WorkflowService
        return WorkflowService(EventBus())

    def test_list_templates(self):
        svc = self._make()
        templates = svc.list_templates()
        assert len(templates) >= 9
        ids = {t["id"] for t in templates}
        assert "full_bounty" in ids
        assert "bounty_hunt" in ids

    def test_create_workflow_valid(self):
        svc = self._make()
        result = svc.create_workflow("example.com", template="full_bounty")
        assert result["status"] == "created"
        assert result["target"] == "example.com"
        assert result["state"] == "scope"

    def test_create_workflow_bad_template(self):
        svc = self._make()
        result = svc.create_workflow("x.com", template="nonexistent")
        assert result["status"] == "error"

    def test_advance_valid(self):
        svc = self._make()
        result = svc.advance("wf-1", "recon")
        assert result["status"] == "advanced"
        assert result["state"] == "recon"

    def test_advance_invalid_state(self):
        svc = self._make()
        result = svc.advance("wf-1", "invalid_state")
        assert result["status"] == "error"

    def test_advance_gated_without_approval(self):
        svc = self._make()
        result = svc.advance("wf-1", "exploitation", approve=False)
        assert result["status"] == "blocked"

    def test_advance_gated_with_approval(self):
        svc = self._make()
        result = svc.advance("wf-1", "exploitation", approve=True)
        assert result["status"] == "advanced"

    def test_execute_step(self):
        svc = self._make()
        result = svc.execute_step("wf-1", "subfinder", {"domain": "x.com"})
        assert result["status"] == "executed"
        assert result["step"] == "subfinder"

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["template_count"] >= 9
        assert "scope" in stats["states"]

    def test_list_runs_empty(self):
        svc = self._make()
        runs = svc.list_runs()
        assert isinstance(runs, list)

    def test_create_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.workflows import WorkflowService
        bus = EventBus()
        events = []
        bus.subscribe("workflow.created", lambda e: events.append(e))
        svc = WorkflowService(bus)
        svc.create_workflow("x.com")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — RouterService
# ══════════════════════════════════════════════════════════════════════

class TestRouterService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.router import RouterService
        return RouterService(EventBus())

    def test_list_task_types(self):
        svc = self._make()
        tasks = svc.list_task_types()
        assert len(tasks) >= 11
        types = {t["type"] for t in tasks}
        assert "reasoning" in types
        assert "exploit_hypothesis" in types

    def test_list_model_tiers(self):
        svc = self._make()
        tiers = svc.list_model_tiers()
        assert len(tiers) == 3
        tier_names = {t["tier"] for t in tiers}
        assert tier_names == {"fast", "balanced", "deep"}

    def test_select_model_deep(self):
        svc = self._make()
        result = svc.select_model("exploit_hypothesis")
        assert result["tier"] == "deep"

    def test_select_model_fast(self):
        svc = self._make()
        result = svc.select_model("classification")
        assert result["tier"] == "fast"

    def test_select_model_balanced(self):
        svc = self._make()
        result = svc.select_model("reasoning")
        assert result["tier"] == "balanced"

    def test_query_fallback(self):
        svc = self._make()
        result = svc.query("test prompt")
        assert result["status"] == "fallback"
        assert result["task_type"] == "reasoning"

    def test_query_bad_task_type_defaults_to_reasoning(self):
        svc = self._make()
        result = svc.query("test", task_type="nonexistent")
        assert result["task_type"] == "reasoning"

    def test_list_providers_fallback(self):
        svc = self._make()
        providers = svc.list_providers()
        assert len(providers) >= 3
        ids = {p["id"] for p in providers}
        assert "anthropic" in ids

    def test_get_provider_health(self):
        svc = self._make()
        health = svc.get_provider_health()
        assert "status" in health

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["task_type_count"] >= 11
        assert stats["tier_count"] == 3

    def test_query_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.router import RouterService
        bus = EventBus()
        events = []
        bus.subscribe("router.query_completed", lambda e: events.append(e))
        svc = RouterService(bus)
        svc.query("test")
        assert len(events) == 1


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch3Commands:

    def _run(self, handler, args=None, kwargs=None):
        svc = make_services()
        ctx = MagicMock()
        ctx.services = svc
        from hydra.commands.builtins.agent_cmds import _agents, _workflow, _router
        handlers = {"agents": _agents, "workflows": _workflow, "router": _router}
        return handlers[handler](args or [], kwargs or {}, ctx)

    def test_agents_default_stats(self):
        r = self._run("agents")
        assert r.ok
        assert r.output["type"] == "agent_stats"

    def test_agents_list(self):
        r = self._run("agents", ["list"])
        assert r.ok
        assert r.output["type"] == "agent_list"
        assert len(r.output["agents"]) == 10

    def test_agents_detect(self):
        r = self._run("agents", ["detect", "https://api.x.com/v1"])
        assert r.ok
        assert r.output["target_type"] == "api"

    def test_agents_spawn(self):
        r = self._run("agents", ["spawn", "recon"])
        assert r.ok
        assert r.output["agent_type"] == "recon"

    def test_agents_status(self):
        r = self._run("agents", ["status"])
        assert r.ok

    def test_agents_bad_subcommand(self):
        r = self._run("agents", ["bad"])
        assert not r.ok

    def test_workflow_default_stats(self):
        r = self._run("workflows")
        assert r.ok
        assert r.output["type"] == "workflow_stats"

    def test_workflow_templates(self):
        r = self._run("workflows", ["templates"])
        assert r.ok
        assert len(r.output["templates"]) >= 9

    def test_workflow_create(self):
        r = self._run("workflows", ["create", "x.com"])
        assert r.ok
        assert r.output["type"] == "workflow_created"

    def test_workflow_advance(self):
        r = self._run("workflows", ["advance", "wf-1", "recon"])
        assert r.ok
        assert r.output["state"] == "recon"

    def test_workflow_runs(self):
        r = self._run("workflows", ["runs"])
        assert r.ok

    def test_workflow_bad_subcommand(self):
        r = self._run("workflows", ["bad"])
        assert not r.ok

    def test_router_default_stats(self):
        r = self._run("router")
        assert r.ok
        assert r.output["type"] == "router_stats"

    def test_router_providers(self):
        r = self._run("router", ["providers"])
        assert r.ok
        assert len(r.output["providers"]) >= 3

    def test_router_tasks(self):
        r = self._run("router", ["tasks"])
        assert r.ok
        assert len(r.output["tasks"]) >= 11

    def test_router_tiers(self):
        r = self._run("router", ["tiers"])
        assert r.ok
        assert len(r.output["tiers"]) == 3

    def test_router_select(self):
        r = self._run("router", ["select", "code_analysis"])
        assert r.ok
        assert r.output["tier"] == "deep"

    def test_router_health(self):
        r = self._run("router", ["health"])
        assert r.ok

    def test_router_bad_subcommand(self):
        r = self._run("router", ["bad"])
        assert not r.ok


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — ServiceContainer wiring
# ══════════════════════════════════════════════════════════════════════

class TestBatch3ServiceWiring:

    def test_agents_service_wired(self):
        svc = make_services()
        from hydra.services.agents import AgentService
        assert isinstance(svc.agents, AgentService)

    def test_workflows_service_wired(self):
        svc = make_services()
        from hydra.services.workflows import WorkflowService
        assert isinstance(svc.workflows, WorkflowService)

    def test_router_service_wired(self):
        svc = make_services()
        from hydra.services.router import RouterService
        assert isinstance(svc.router, RouterService)

    def test_all_20_services_accessible(self):
        svc = make_services()
        names = [
            "system", "engagement", "findings", "knowledge", "coverage",
            "session", "scan", "learning", "monitor", "updates",
            "ingest", "extraction", "report_store", "graph", "ttp", "memory",
            "agents", "workflows", "router", "search",
        ]
        for name in names:
            assert hasattr(svc, name), f"Missing service: {name}"
            obj = getattr(svc, name)
            assert obj is not None, f"Service {name} returned None"


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — Builtin registration includes agent commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch3BuiltinRegistration:

    def test_agent_commands_registered(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        assert "agents" in names
        assert "workflows" in names
        assert "router" in names


# ══════════════════════════════════════════════════════════════════════
# Batch 3 — Facade delegation
# ══════════════════════════════════════════════════════════════════════

class TestFacadeBatch3:

    def _make_facade(self):
        from hydra.services.event_bus import EventBus
        from hydra.services import ServiceContainer
        from hydra.commands.registry import CommandRegistry
        from hydra.registry.capability import CapabilityRegistry
        from hydra.facade import HydraFacade
        bus = EventBus()
        svc = ServiceContainer(event_bus=bus, data_dir=tempfile.mkdtemp())
        cmd = CommandRegistry()
        cap = CapabilityRegistry()
        return HydraFacade(svc, cap, bus, cmd)

    def test_list_agents(self):
        facade = self._make_facade()
        with patch.object(facade._svc.agents, "list_agents") as mock:
            mock.return_value = []
            facade.list_agents()
            mock.assert_called_once()

    def test_spawn_agent(self):
        facade = self._make_facade()
        with patch.object(facade._svc.agents, "spawn_agent") as mock:
            mock.return_value = {"status": "spawned"}
            facade.spawn_agent("recon", {"id": "t1"})
            mock.assert_called_once()

    def test_detect_target_type(self):
        facade = self._make_facade()
        with patch.object(facade._svc.agents, "detect_target_type") as mock:
            mock.return_value = {"target_type": "web"}
            facade.detect_target_type("x.com")
            mock.assert_called_once()

    def test_list_workflow_templates(self):
        facade = self._make_facade()
        with patch.object(facade._svc.workflows, "list_templates") as mock:
            mock.return_value = []
            facade.list_workflow_templates()
            mock.assert_called_once()

    def test_create_workflow(self):
        facade = self._make_facade()
        with patch.object(facade._svc.workflows, "create_workflow") as mock:
            mock.return_value = {"status": "created"}
            facade.create_workflow("x.com")
            mock.assert_called_once()

    def test_advance_workflow(self):
        facade = self._make_facade()
        with patch.object(facade._svc.workflows, "advance") as mock:
            mock.return_value = {"status": "advanced"}
            facade.advance_workflow("wf-1", "recon")
            mock.assert_called_once()

    def test_router_query(self):
        facade = self._make_facade()
        with patch.object(facade._svc.router, "query") as mock:
            mock.return_value = {"status": "ok"}
            facade.router_query("test prompt")
            mock.assert_called_once()

    def test_router_select_model(self):
        facade = self._make_facade()
        with patch.object(facade._svc.router, "select_model") as mock:
            mock.return_value = {"tier": "balanced"}
            facade.router_select_model("reasoning")
            mock.assert_called_once()

    def test_list_router_providers(self):
        facade = self._make_facade()
        with patch.object(facade._svc.router, "list_providers") as mock:
            mock.return_value = []
            facade.list_router_providers()
            mock.assert_called_once()


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — SearchService
# ══════════════════════════════════════════════════════════════════════

class TestSearchService:

    def _make(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.search import SearchService
        return SearchService(EventBus(), Path(tempfile.mkdtemp()))

    def test_search_returns_list(self):
        svc = self._make()
        results = svc.search("xss bypass")
        assert isinstance(results, list)

    def test_search_keyword_mode(self):
        svc = self._make()
        results = svc.search("sqli", mode="keyword")
        assert isinstance(results, list)

    def test_search_graph_mode(self):
        svc = self._make()
        results = svc.search("ssrf", mode="graph")
        assert isinstance(results, list)

    def test_search_hybrid_mode(self):
        svc = self._make()
        results = svc.search("cors", mode="hybrid")
        assert isinstance(results, list)

    def test_search_bad_mode_defaults_hybrid(self):
        svc = self._make()
        results = svc.search("test", mode="nonexistent")
        assert isinstance(results, list)

    def test_search_with_node_type_filter(self):
        svc = self._make()
        results = svc.search("xss", node_type="report")
        assert isinstance(results, list)

    def test_search_by_type(self):
        svc = self._make()
        results = svc.search_by_type("report", "xss")
        assert isinstance(results, list)

    def test_search_by_type_invalid(self):
        svc = self._make()
        results = svc.search_by_type("nonexistent")
        assert results == []

    def test_suggest(self):
        svc = self._make()
        results = svc.suggest("xss")
        assert isinstance(results, list)

    def test_get_facets(self):
        svc = self._make()
        facets = svc.get_facets()
        assert "by_type" in facets
        assert "by_target" in facets

    def test_get_stats(self):
        svc = self._make()
        stats = svc.get_stats()
        assert stats["mode_count"] == 4
        assert "hybrid" in stats["modes"]
        assert "report" in stats["entity_types"]

    def test_search_emits_event(self):
        from hydra.services.event_bus import EventBus
        from hydra.services.search import SearchService
        bus = EventBus()
        events = []
        bus.subscribe("search.completed", lambda e: events.append(e))
        svc = SearchService(bus, Path(tempfile.mkdtemp()))
        svc.search("test")
        assert len(events) == 1

    def test_rrf_fusion_deduplicates(self):
        from hydra.services.search import SearchService, SearchResult
        from hydra.services.event_bus import EventBus
        svc = SearchService(EventBus())
        r1 = SearchResult("page-a", score=0.9, source="keyword")
        r2 = SearchResult("page-a", score=0.7, source="graph")
        r3 = SearchResult("page-b", score=0.8, source="keyword")
        fused = svc._rrf_fuse([r1, r2, r3], limit=10)
        slugs = [r.slug for r in fused]
        assert slugs.count("page-a") == 1
        assert "page-b" in slugs
        # page-a should rank higher (appears in two sources)
        assert fused[0].slug == "page-a"

    def test_search_result_to_dict(self):
        from hydra.services.search import SearchResult
        r = SearchResult("slug-1", title="Test", score=0.75, source="keyword")
        d = r.to_dict()
        assert d["slug"] == "slug-1"
        assert d["title"] == "Test"
        assert d["score"] == 0.75


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — Search Commands
# ══════════════════════════════════════════════════════════════════════

class TestBatch4Commands:

    def _run(self, handler, args=None, kwargs=None):
        svc = make_services()
        ctx = MagicMock()
        ctx.services = svc
        from hydra.commands.builtins.search_cmds import _search, _suggest, _facets
        handlers = {"hsearch": _search, "suggest": _suggest, "facets": _facets}
        return handlers[handler](args or [], kwargs or {}, ctx)

    def test_hsearch_default_stats(self):
        r = self._run("hsearch")
        assert r.ok
        assert r.output["type"] == "search_stats"

    def test_hsearch_query(self):
        r = self._run("hsearch", ["xss", "bypass"])
        assert r.ok
        assert r.output["type"] == "search_results"
        assert r.output["query"] == "xss bypass"

    def test_hsearch_with_mode(self):
        r = self._run("hsearch", ["sqli"], {"mode": "keyword"})
        assert r.ok
        assert r.output["mode"] == "keyword"

    def test_suggest_no_args(self):
        r = self._run("suggest")
        assert not r.ok

    def test_suggest_with_partial(self):
        r = self._run("suggest", ["cors"])
        assert r.ok
        assert r.output["type"] == "search_suggestions"

    def test_facets(self):
        r = self._run("facets")
        assert r.ok
        assert r.output["type"] == "search_facets"


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — Service wiring + registration
# ══════════════════════════════════════════════════════════════════════

class TestBatch4Wiring:

    def test_search_service_wired(self):
        svc = make_services()
        from hydra.services.search import SearchService
        assert isinstance(svc.search, SearchService)

    def test_search_commands_registered(self):
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        assert "hsearch" in names
        assert "suggest" in names
        assert "facets" in names


# ══════════════════════════════════════════════════════════════════════
# Batch 4 — Facade delegation
# ══════════════════════════════════════════════════════════════════════

class TestFacadeBatch4:

    def _make_facade(self):
        from hydra.services.event_bus import EventBus
        from hydra.services import ServiceContainer
        from hydra.commands.registry import CommandRegistry
        from hydra.registry.capability import CapabilityRegistry
        from hydra.facade import HydraFacade
        bus = EventBus()
        svc = ServiceContainer(event_bus=bus, data_dir=tempfile.mkdtemp())
        cmd = CommandRegistry()
        cap = CapabilityRegistry()
        return HydraFacade(svc, cap, bus, cmd)

    def test_hybrid_search(self):
        facade = self._make_facade()
        with patch.object(facade._svc.search, "search") as mock:
            mock.return_value = []
            facade.hybrid_search("xss")
            mock.assert_called_once()

    def test_search_suggest(self):
        facade = self._make_facade()
        with patch.object(facade._svc.search, "suggest") as mock:
            mock.return_value = []
            facade.search_suggest("cor")
            mock.assert_called_once()

    def test_search_facets(self):
        facade = self._make_facade()
        with patch.object(facade._svc.search, "get_facets") as mock:
            mock.return_value = {"by_type": {}, "by_target": {}}
            facade.search_facets()
            mock.assert_called_once()

    def test_get_search_stats(self):
        facade = self._make_facade()
        with patch.object(facade._svc.search, "get_stats") as mock:
            mock.return_value = {"modes": [], "entity_types": []}
            facade.get_search_stats()
            mock.assert_called_once()


# ══════════════════════════════════════════════════════════════════════
# Cross-Batch Integration Tests
# ══════════════════════════════════════════════════════════════════════

class TestPhase9Integration:

    def test_all_10_services_loadable(self):
        """All Phase 9 services (10 new) instantiate without error."""
        svc = make_services()
        phase9 = [
            "ingest", "extraction", "report_store",
            "graph", "ttp", "memory",
            "agents", "workflows", "router", "search",
        ]
        for name in phase9:
            obj = getattr(svc, name)
            assert obj is not None, f"Phase 9 service {name} failed to load"

    def test_all_phase9_commands_registered(self):
        """All 13 Phase 9 commands register without collision."""
        from hydra.commands.registry import CommandRegistry
        from hydra.commands.builtins import register_all_builtins
        reg = CommandRegistry()
        register_all_builtins(reg)
        names = {c.name for c in reg.list_commands(include_hidden=True)}
        phase9_cmds = [
            "ingest", "reports", "extract", "intel-stats",
            "graph", "ttp", "memory",
            "agents", "workflows", "router",
            "hsearch", "suggest", "facets",
        ]
        for cmd in phase9_cmds:
            assert cmd in names, f"Phase 9 command /{cmd} not registered"

    def test_all_phase9_facade_methods_exist(self):
        """All Phase 9 facade methods are callable."""
        from hydra.facade import HydraFacade
        methods = [
            "ingest_text", "ingest_file", "ingest_batch", "get_ingest_stats",
            "list_reports", "get_report", "get_report_stats", "aggregate_reports",
            "extract_field", "extract_all",
            "graph_neighbors", "graph_path", "graph_subgraph", "graph_stats",
            "extract_ttps", "ttp_coverage", "generate_playbook",
            "memory_recall", "memory_record",
            "list_agents", "spawn_agent", "detect_target_type", "get_agent_stats",
            "list_workflow_templates", "create_workflow", "advance_workflow", "get_workflow_stats",
            "router_query", "router_select_model", "list_router_providers", "get_router_stats",
            "hybrid_search", "search_suggest", "search_facets", "get_search_stats",
        ]
        for m in methods:
            assert hasattr(HydraFacade, m), f"Facade missing method: {m}"

    def test_service_container_total_count(self):
        """ServiceContainer has 20 services total (10 original + 10 Phase 9)."""
        svc = make_services()
        all_services = [
            "system", "engagement", "findings", "knowledge", "coverage",
            "session", "scan", "learning", "monitor", "updates",
            "ingest", "extraction", "report_store", "graph", "ttp", "memory",
            "agents", "workflows", "router", "search",
        ]
        assert len(all_services) == 20
        for name in all_services:
            assert getattr(svc, name) is not None
