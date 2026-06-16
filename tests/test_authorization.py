"""
Bug-Bounty Authorization Gate tests.

The gate is the safety keystone that constrains all active / exploitation actions to targets covered
by a registered bug bounty program. Core property: **deny-by-default** — with no covering program,
every active action is denied. Absolute prohibitions (DoS / destructive / exfil / social) are never
allowed, even in-scope; exploitation is PoC-only.
"""

import json

import pytest

from hydra.authorization import (
    AuthorizationError,
    BugBountyAuthorizationGate,
    KNOWN_PLATFORMS,
)


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_AUTHORIZED_PROGRAMS", str(tmp_path / "programs.json"))
    return BugBountyAuthorizationGate()


@pytest.fixture
def acme(gate):
    gate.register_program("acme", "hackerone",
                          in_scope=["*.acme.com", "app.acme.io"],
                          out_of_scope=["admin.acme.com"])
    return gate


# ── deny-by-default (the core invariant) ─────────────────────────────────────────
def test_deny_by_default_when_no_program(gate):
    for action in ("exploitation", "vulnerability_scan", "active_recon", "data_access"):
        d = gate.authorize("https://example.com", action)
        assert d.authorized is False
        assert d.scope_violation is True
        assert "deny-by-default" in d.reason


def test_unrelated_domain_denied(acme):
    assert acme.authorize("https://google.com", "exploitation").authorized is False
    assert acme.authorize("notacme.com", "vulnerability_scan").authorized is False


# ── in-scope authorization ───────────────────────────────────────────────────────
def test_in_scope_wildcard_authorized(acme):
    d = acme.authorize("https://api.acme.com/v1", "exploitation")
    assert d.authorized is True
    assert d.program == "acme" and d.platform == "hackerone"
    assert d.matched_asset == "*.acme.com"


def test_exploitation_is_poc_only(acme):
    d = acme.authorize("https://api.acme.com", "exploitation")
    assert d.authorized and d.poc_only is True
    assert any("proof-of-concept only" in m for m in d.mitigations)
    assert d.risk_level == "high"


def test_passive_recon_not_poc_gated(acme):
    d = acme.authorize("https://api.acme.com", "active_recon")
    assert d.authorized and d.poc_only is False


# ── scope boundaries ─────────────────────────────────────────────────────────────
def test_explicit_out_of_scope_denied(acme):
    d = acme.authorize("https://admin.acme.com", "exploitation")
    assert d.authorized is False and d.scope_violation is True
    assert "OUT OF SCOPE" in d.reason


def test_bare_apex_does_not_cover_subdomains(acme):
    # app.acme.io is registered as a bare host → matches exactly, not its subdomains (conservative)
    assert acme.authorize("https://app.acme.io", "active_recon").authorized is True
    assert acme.authorize("https://sub.app.acme.io", "active_recon").authorized is False


def test_wildcard_covers_apex_and_subdomains(acme):
    assert acme.authorize("https://acme.com", "vulnerability_scan").authorized is True
    assert acme.authorize("https://deep.sub.acme.com", "vulnerability_scan").authorized is True


# ── absolute prohibitions (never allowed, even in-scope) ─────────────────────────
@pytest.mark.parametrize("action", ["dos_testing", "destructive"])
def test_absolute_prohibitions_denied_even_in_scope(acme, action):
    d = acme.authorize("https://api.acme.com", action)
    assert d.authorized is False
    assert d.prohibited is True
    assert d.risk_level == "prohibited"


def test_absolute_prohibition_list_present(gate):
    assert any("denial of service" in p.lower() for p in gate.absolute_prohibitions)


# ── require() hard gate ──────────────────────────────────────────────────────────
def test_require_raises_on_deny(acme):
    with pytest.raises(AuthorizationError):
        acme.require("https://evil.example", "exploitation")
    # in-scope does not raise
    assert acme.require("https://api.acme.com", "exploitation").authorized is True


# ── registration validation ──────────────────────────────────────────────────────
def test_register_rejects_unknown_platform(gate):
    with pytest.raises(ValueError):
        gate.register_program("x", "definitely_not_a_platform", in_scope=["x.com"])


def test_register_requires_in_scope(gate):
    with pytest.raises(ValueError):
        gate.register_program("x", "custom", in_scope=[])


def test_known_platforms_cover_majors():
    assert {"hackerone", "bugcrowd", "intigriti", "yeswehack"} <= KNOWN_PLATFORMS


# ── persistence + provenance + determinism ───────────────────────────────────────
def test_registry_persists_across_instances(acme, tmp_path):
    g2 = BugBountyAuthorizationGate()
    assert [p["program"] for p in g2.programs()] == ["acme"]
    assert g2.authorize("https://api.acme.com", "exploitation").authorized is True
    saved = json.loads((tmp_path / "programs.json").read_text())
    assert saved["programs"][0]["program"] == "acme"


def test_register_from_scope_object(gate):
    # emulate a hydra.scope.ProgramScope shape (as fetched live from a platform)
    class S:
        program_name = "vk"
        platform = "custom"
        in_scope = [{"asset": "*.vk.com"}]
        out_of_scope = [{"asset": "legal.vk.com"}]
        program_url = "https://standoff365.com/vk"
    gate.register_scope(S())
    assert gate.authorize("https://api.vk.com", "exploitation").authorized is True
    assert gate.authorize("https://legal.vk.com", "exploitation").authorized is False


def test_decision_is_audited(acme):
    acme.authorize("https://api.acme.com", "exploitation")
    acme.authorize("https://evil.com", "exploitation")
    log = acme.audit_log()
    assert len(log) == 2
    assert {e["authorized"] for e in log} == {True, False}
    assert all(e["audit_id"] and e["timestamp"] for e in log)


def test_decision_to_dict_serializable(acme):
    d = acme.authorize("https://api.acme.com", "exploitation")
    json.dumps(d.to_dict())          # must be JSON-serializable for MCP/audit
