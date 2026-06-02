"""
Phase-B learning_score tests — the 1-10 scorer is deterministic, explainable,
and LLM-free. Bands are pinned: a chained authz-bypass scores high (>=7); a
trivial/duplicate misconfig scores low (<=3).
"""

from types import SimpleNamespace

from hydra.knowledge.learning_score import score_report


def _extracted(vuln_class, signals):
    return SimpleNamespace(vuln_class=SimpleNamespace(value=vuln_class), signals=signals)


def test_chained_authz_bypass_scores_high():
    score, rationale = score_report(_extracted("authz_bypass", ["chain", "escalation"]))
    assert score >= 7
    assert rationale  # non-empty rationale
    assert "chain" in rationale and "escalation" in rationale


def test_trivial_duplicate_misconfig_scores_low():
    score, rationale = score_report(_extracted("misconfig", ["trivial", "duplicate"]))
    assert score <= 3
    assert rationale


def test_score_is_clamped_1_to_10():
    # Maximal penalties cannot drop below 1.
    low, _ = score_report(_extracted("unknown", ["duplicate", "trivial"]))
    assert low == 1
    # Maximal bonuses cannot exceed 10.
    high, _ = score_report(_extracted("rce", ["chain", "escalation", "pivot"]))
    assert high == 10


def test_unknown_class_is_low_band():
    score, _ = score_report(_extracted("unknown", []))
    assert score <= 3


def test_hyphenated_and_underscored_classes_normalize():
    a, _ = score_report(_extracted("authz-bypass", ["chain"]))
    b, _ = score_report(_extracted("authz_bypass", ["chain"]))
    assert a == b


def test_deterministic_no_hidden_state():
    # Same input → identical output across repeated calls (no LLM, no randomness).
    inp = _extracted("ssrf", ["escalation"])
    first = score_report(inp)
    for _ in range(5):
        assert score_report(inp) == first


def test_rationale_lists_contributing_signals():
    _, rationale = score_report(_extracted("idor", ["chain"]))
    assert "base" in rationale            # base band reported
    assert "+2 chain" in rationale        # the exact signal that moved the score
