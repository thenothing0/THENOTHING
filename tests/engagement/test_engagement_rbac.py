"""Engagement management + RBAC + report export."""

import json

import pytest

from hydra.engagement import EngagementStore, Role, can
from hydra.reporting.export import to_json, to_markdown, to_sarif


# ── RBAC matrix ──
def test_role_permissions():
    assert can(Role.VIEWER, "read") and not can(Role.VIEWER, "create_finding")
    assert can(Role.OPERATOR, "create_finding") and not can(Role.OPERATOR, "confirm_finding")
    assert can(Role.LEAD, "confirm_finding") and not can(Role.LEAD, "manage_team")
    assert can(Role.ADMIN, "manage_team")          # admin ⊇ everything
    assert not can(Role.OPERATOR, "unknown_action")


# ── engagement store ──
def test_create_with_owner_and_team(tmp_path):
    s = EngagementStore(db_path=str(tmp_path / "e.db"))
    eid = s.create("Acme", "Q2 Pentest", scope=["*.acme.com"], owner="alice")
    eng = s.get(eid)
    assert eng["client"] == "Acme" and eng["scope"] == ["*.acme.com"]
    assert eng["team"][0]["role"] == Role.ADMIN     # owner is admin


def test_authorize_enforces_rbac(tmp_path):
    s = EngagementStore(db_path=str(tmp_path / "e.db"))
    eid = s.create("Acme", "Job", owner="alice")
    s.add_member(eid, "bob", Role.OPERATOR)
    assert s.authorize(eid, "bob", "create_finding")["allowed"] is True
    assert s.authorize(eid, "bob", "confirm_finding")["allowed"] is False  # needs lead
    assert s.authorize(eid, "alice", "manage_team")["allowed"] is True     # admin
    assert s.authorize(eid, "carol", "read")["allowed"] is False           # non-member


def test_bad_role_rejected(tmp_path):
    s = EngagementStore(db_path=str(tmp_path / "e.db"))
    eid = s.create("Acme", "Job")
    with pytest.raises(ValueError):
        s.add_member(eid, "x", "superuser")


# ── report export ──
_FINDINGS = [
    {"title": "IDOR on orders", "vuln_class": "idor", "severity": "high", "state": "confirmed",
     "endpoint": "/api/orders/{id}", "cwe": "CWE-639", "owasp": "A01:2021", "cvss_score": 8.1,
     "impact": "cross-account read", "remediation": "enforce object-level authz"},
    {"title": "Reflected XSS", "vuln_class": "xss", "severity": "medium", "state": "validated",
     "endpoint": "/search", "parameter": "q"},
]


def test_sarif_export_shape():
    doc = json.loads(to_sarif(_FINDINGS))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"idor", "xss"}
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels and "warning" in levels     # high->error, medium->warning


def test_markdown_export_orders_by_severity():
    md = to_markdown(_FINDINGS, engagement={"name": "Q2", "client": "Acme"})
    assert "Client:** Acme" in md
    assert md.index("IDOR on orders") < md.index("Reflected XSS")   # high before medium


def test_json_export_roundtrips():
    out = json.loads(to_json(_FINDINGS, engagement={"id": "ENG-1"}))
    assert out["count"] == 2 and out["engagement"]["id"] == "ENG-1"
