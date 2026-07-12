"""Phase 6 integration test — knowledge + coverage wiring.

Validates:
1. /search returns search_results type
2. /recall returns recall_results type
3. /learn records a lesson
4. /wiki looks up a page (returns error for missing pages)
5. /next returns coverage targets
6. /lint returns kb health
7. /coverage returns coverage summary
8. /findings returns findings list
9. /workflow returns workflow status
10. /engage lists engagements
11. Conversation renderers handle all new types
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from hydra.services.event_bus import EventBus
from hydra.services import ServiceContainer
from hydra.commands.registry import CommandRegistry
from hydra.commands.builtins import register_all_builtins
from hydra.facade import HydraFacade
from hydra.registry.capability import CapabilityRegistry


def make_stack():
    bus = EventBus()
    reg = CapabilityRegistry()
    svc = ServiceContainer(event_bus=bus)
    cmd = CommandRegistry()
    register_all_builtins(cmd, reg)
    facade = HydraFacade(svc, reg, bus, cmd)
    return facade, svc, bus


def test_search():
    facade, _, _ = make_stack()
    r = facade.execute_command("/search waf bypass")
    assert r.ok
    assert r.output["type"] == "search_results"
    assert r.output["query"] == "waf bypass"
    assert isinstance(r.output["results"], list)
    print("  [PASS] /search returns search_results")


def test_recall():
    facade, _, _ = make_stack()
    r = facade.execute_command("/recall idor auth")
    assert r.ok
    assert r.output["type"] == "recall_results"
    assert r.output["query"] == "idor auth"
    print("  [PASS] /recall returns recall_results")


def test_learn():
    facade, _, _ = make_stack()
    r = facade.execute_command("/learn always check for CORS misconfig --tier=project --category=recon-gap")
    assert r.ok
    assert r.output["type"] == "learn_recorded"
    print("  [PASS] /learn records lesson")


def test_wiki_missing():
    facade, _, _ = make_stack()
    r = facade.execute_command("/wiki nonexistent-page-xyz")
    assert r.status == "error"
    assert "not found" in r.errors[0].lower() or "not found" in str(r.errors).lower()
    print("  [PASS] /wiki returns error for missing page")


def test_wiki_no_args():
    facade, _, _ = make_stack()
    r = facade.execute_command("/wiki")
    assert r.status == "error"
    print("  [PASS] /wiki with no args returns usage error")


def test_next():
    facade, _, _ = make_stack()
    r = facade.execute_command("/next")
    assert r.ok
    assert r.output["type"] == "coverage_next"
    assert isinstance(r.output["targets"], list)
    print("  [PASS] /next returns coverage_next targets")


def test_lint():
    facade, _, _ = make_stack()
    r = facade.execute_command("/lint")
    assert r.ok
    assert r.output["type"] == "kb_lint"
    print("  [PASS] /lint returns kb health")


def test_coverage():
    facade, _, _ = make_stack()
    r = facade.execute_command("/coverage")
    assert r.ok
    assert r.output["type"] == "coverage"
    print("  [PASS] /coverage returns coverage summary")


def test_findings():
    facade, _, _ = make_stack()
    r = facade.execute_command("/findings")
    assert r.ok
    assert r.output["type"] == "findings_list"
    print("  [PASS] /findings returns findings list")


def test_workflow():
    facade, _, _ = make_stack()
    r = facade.execute_command("/workflow")
    assert r.ok
    assert r.output["type"] == "workflow_status"
    print("  [PASS] /workflow returns status")


def test_engage():
    facade, _, _ = make_stack()
    r = facade.execute_command("/engage")
    assert r.ok
    assert r.output["type"] == "engage_list"
    print("  [PASS] /engage lists engagements")


def test_conversation_renderers():
    """Verify ConversationLog can render all new result types without crashing."""
    pytest.importorskip("textual")
    from control_center.tui.widgets.conversation import ConversationLog
    from unittest.mock import MagicMock

    log = ConversationLog()
    log.write = MagicMock()

    test_cases = [
        {"type": "search_results", "query": "test", "results": []},
        {"type": "recall_results", "query": "test", "results": [{"slug": "p1", "score": 0.9}]},
        {"type": "learn_recorded"},
        {"type": "scope_register", "program": "acme", "platform": "h1", "in_scope": "*.acme.com"},
        {"type": "scope_load", "url": "https://hackerone.com/acme"},
        {"type": "workflow_status", "workflow": None},
        {"type": "workflow_status", "workflow": {"state": "recon", "run_id": "wf1", "target": "t.com"}},
        {"type": "engage_list", "engagements": []},
        {"type": "engage_list", "engagements": [{"id": "e1", "name": "Test", "client": "Acme"}]},
        {"type": "engage_switch", "engagement_id": "e1"},
        {"type": "coverage_next", "targets": []},
        {"type": "coverage_next", "targets": [{"endpoint": "/api", "vuln_class": "sqli", "priority": 8.5}]},
        {"type": "kb_lint", "result": {"total_pages": 100, "orphans": ["p1"], "dangling_links": []}},
        {"type": "wiki_page", "slug": "test-page", "page": {"title": "Test", "type": "finding", "stage": "validated"}},
        {"type": "findings_list", "findings": [
            {"id": "f1", "title": "XSS in /search", "severity": "high"},
        ]},
        {"type": "finding_detail", "finding": {"id": "f1", "title": "XSS", "severity": "high", "state": "draft"}},
    ]

    for case in test_cases:
        try:
            log.add_result(case)
        except Exception as exc:
            raise AssertionError(f"Failed to render {case['type']}: {exc}")

    print(f"  [PASS] Conversation log rendered {len(test_cases)} result types without errors")


def test_command_count():
    bus = EventBus()
    reg = CapabilityRegistry()
    svc = ServiceContainer(event_bus=bus)
    cmd = CommandRegistry()
    register_all_builtins(cmd, reg)
    facade = HydraFacade(svc, reg, bus, cmd)
    from hydra.presentation.api import PresentationAPI
    api = PresentationAPI(facade, reg, bus)

    cmds = api.list_commands()
    names = [c.name for c in cmds]
    required = ["search", "recall", "learn", "wiki", "next", "lint",
                 "findings", "coverage", "workflow", "engage",
                 "recon", "scan", "scope", "attack",
                 "help", "status", "clear", "tools", "session"]
    for name in required:
        assert name in names, f"Missing command: {name}"
    print(f"  [PASS] All {len(required)} required commands registered (total: {len(cmds)})")


if __name__ == "__main__":
    print("\n=== Phase 6: Knowledge + Coverage Integration Tests ===\n")
    test_search()
    test_recall()
    test_learn()
    test_wiki_missing()
    test_wiki_no_args()
    test_next()
    test_lint()
    test_coverage()
    test_findings()
    test_workflow()
    test_engage()
    test_conversation_renderers()
    test_command_count()
    print("\n=== ALL PHASE 6 TESTS PASSED ===\n")
