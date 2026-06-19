"""HITL: risk classification + tiered approval policy + emergency stop."""

from hydra.hitl import ApprovalPolicy, Decision, RiskLevel, classify_risk


# ── classification ──
def test_classify_tiers():
    assert classify_risk("finding_list") == RiskLevel.LOW
    assert classify_risk("nuclei_scan") == RiskLevel.MEDIUM
    assert classify_risk("shell_exec", {"command": "curl https://t"}) == RiskLevel.HIGH
    assert classify_risk("secretsdump_run") == RiskLevel.CRITICAL


def test_shell_arg_heuristics_elevate():
    assert classify_risk("shell_exec", {"command": "nuclei -u https://t"}) == RiskLevel.HIGH
    assert classify_risk("shell_exec", {"command": "slowloris -d t"}) == RiskLevel.PROHIBITED


def test_unknown_tool_defaults_medium():
    assert classify_risk("some_new_tool") == RiskLevel.MEDIUM


# ── policy: interactive tiers ──
def test_low_auto_allows():
    d = ApprovalPolicy().evaluate("finding_list")
    assert d["auto"] and d["decision"] == Decision.ALLOW_ONCE


def test_medium_offers_session():
    d = ApprovalPolicy().evaluate("nuclei_scan")
    assert not d["auto"] and Decision.ALLOW_SESSION in d["options"]


def test_high_disables_session_offers_workflow():
    d = ApprovalPolicy().evaluate("shell_exec", {"command": "id"})
    assert Decision.ALLOW_SESSION not in d["options"]
    assert Decision.ALLOW_WORKFLOW in d["options"]


def test_critical_offers_emergency_stop_no_caching():
    d = ApprovalPolicy().evaluate("secretsdump_run")
    assert Decision.EMERGENCY_STOP in d["options"]
    assert Decision.ALLOW_SESSION not in d["options"]


def test_prohibited_hard_denies_even_in_operator_mode():
    p = ApprovalPolicy(operator_mode=True)
    d = p.evaluate("shell_exec", {"command": ":(){ :|:& };:"})
    assert d["hard_deny"] and d["decision"] == Decision.DENY


# ── operator mode ──
def test_operator_mode_auto_approves_up_to_critical():
    p = ApprovalPolicy(operator_mode=True)
    assert p.evaluate("secretsdump_run")["decision"] == Decision.ALWAYS_ALLOW
    # but never a prohibition
    assert p.evaluate("shell_exec", {"command": "mkfs.ext4 /dev/sda"})["hard_deny"]


# ── workflow grant + emergency stop ──
def test_workflow_grant_auto_allows_high():
    p = ApprovalPolicy()
    p.grant_workflow("W1", "shell_exec")
    d = p.evaluate("shell_exec", {"command": "id"}, workflow_run_id="W1")
    assert d["auto"] and d["decision"] == Decision.ALLOW_WORKFLOW


def test_emergency_stop_denies_everything():
    p = ApprovalPolicy()
    p.emergency_stop()
    assert p.evaluate("finding_list")["decision"] == Decision.DENY
    p.reset_emergency()
    assert p.evaluate("finding_list")["decision"] == Decision.ALLOW_ONCE
