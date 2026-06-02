"""Confidence scoring + promotion guardrail tests (Phase A)."""

import time

import pytest

from hydra.knowledge.confidence import (
    apply_contradiction,
    apply_decay,
    meets_two_signal,
    score_from_sources,
)
from hydra.knowledge.promotion import PromotionError, promote, validate_promotion
from hydra.knowledge.schema import Confidence, Stage


# ── confidence (Two-Signal) ──────────────────────────────────────────────

def test_single_source_is_low():
    assert score_from_sources(["source.crt_sh"]) == Confidence.LOW


def test_two_sources_is_medium():
    assert score_from_sources(["source.crt_sh", "source.subfinder"]) == Confidence.MEDIUM


def test_three_sources_is_high():
    assert score_from_sources(["source.crt_sh", "source.subfinder", "source.amass"]) == Confidence.HIGH


def test_strong_weights_lift_two_to_high():
    assert score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}) == Confidence.HIGH


def test_duplicate_sources_collapse():
    # same source twice is still one signal -> low
    assert score_from_sources(["source.crt_sh", "source.crt_sh"]) == Confidence.LOW


def test_two_signal_helper():
    assert not meets_two_signal(["x"])
    assert meets_two_signal(["x", "y"])


def test_decay_reduces_old_confidence():
    old = time.time() - 200 * 24 * 3600
    assert apply_decay(Confidence.HIGH, old).rank < Confidence.HIGH.rank
    # fresh confidence is unchanged
    assert apply_decay(Confidence.HIGH, time.time()) == Confidence.HIGH


def test_contradiction_drops_one_notch():
    assert apply_contradiction(Confidence.HIGH) == Confidence.MEDIUM
    assert apply_contradiction(Confidence.LOW) == Confidence.LOW


# ── promotion guardrails ─────────────────────────────────────────────────

def test_valid_finding_to_pattern():
    d = validate_promotion(Stage.FINDING, Stage.PATTERN, sources=["f1", "f2"])
    assert d.allowed


def test_valid_hypothesis_to_finding_in_scope():
    d = validate_promotion(Stage.HYPOTHESIS, Stage.FINDING, sources=["s1", "s2"], scope_ok=True)
    assert d.allowed


@pytest.mark.parametrize("frm,to", [
    (Stage.HYPOTHESIS, Stage.PATTERN),
    (Stage.HYPOTHESIS, Stage.CHAIN),
    (Stage.OBSERVATION, Stage.FINDING),
    (Stage.INTEL, Stage.FINDING),
])
def test_forbidden_transitions_rejected(frm, to):
    d = validate_promotion(frm, to, sources=["a", "b", "c"])
    assert not d.allowed
    with pytest.raises(PromotionError):
        promote(frm, to, sources=["a", "b", "c"])


def test_missing_evidence_rejected():
    assert not validate_promotion(Stage.INTEL, Stage.HYPOTHESIS, sources=[], evidence_count=0).allowed


def test_two_signal_required_for_finding():
    assert not validate_promotion(Stage.HYPOTHESIS, Stage.FINDING, sources=["only-one"]).allowed


def test_out_of_scope_cannot_become_finding():
    assert not validate_promotion(Stage.HYPOTHESIS, Stage.FINDING,
                                  sources=["a", "b"], scope_ok=False).allowed


def test_stage_skip_rejected():
    # intel -> hypothesis is the only legal next step; intel -> finding skips a stage
    assert not validate_promotion(Stage.INTEL, Stage.FINDING, sources=["a", "b"]).allowed
    assert validate_promotion(Stage.INTEL, Stage.HYPOTHESIS, evidence_count=1).allowed
