"""Signature provider + evidence_policy (config-only) tests (Phase C)."""

import inspect

import hydra.knowledge.evidence_policy as ep
from hydra.knowledge.schema import NodeType
from hydra.knowledge.signatures import (
    DEFAULT_PROVIDER,
    SignatureProvider,
    TagTechniqueVocabProvider,
)
from hydra.knowledge.wiki_store import WikiStore


def test_default_provider_derives_vuln_class(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    p = ws.upsert(NodeType.FINDING, "f1", {"tags": ["idor", "api"]},
                  "# f\ninsecure direct object reference\n")
    assert DEFAULT_PROVIDER.signature(p) == "idor"


def test_explicit_vuln_class_wins(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    p = ws.upsert(NodeType.REPORT, "r1", {"vuln_class": "ssrf", "tags": ["misc"]}, "# r\n")
    assert DEFAULT_PROVIDER.signature(p) == "ssrf"


def test_unknown_signature_is_empty(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    p = ws.upsert(NodeType.FINDING, "f2", {"tags": ["misc"]}, "# nothing vuln-ish here\n")
    assert DEFAULT_PROVIDER.signature(p) == ""


def test_signature_is_deterministic(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    p = ws.upsert(NodeType.FINDING, "f3", {"tags": ["idor", "ssrf"]},
                  "# both\nidor and server side request forgery\n")
    assert DEFAULT_PROVIDER.signature(p) == DEFAULT_PROVIDER.signature(p)  # stable


def test_provider_is_pluggable(tmp_path):
    """A custom provider satisfies the protocol and swaps in without touching discovery."""
    class FixedProvider:
        name = "fixed/test"

        def signature(self, page):
            return "constant"

    prov = FixedProvider()
    assert isinstance(prov, SignatureProvider)  # runtime_checkable protocol
    ws = WikiStore(tmp_path / "wiki")
    p = ws.upsert(NodeType.FINDING, "f4", {"tags": ["x"]}, "# x\n")
    assert prov.signature(p) == "constant"
    assert isinstance(DEFAULT_PROVIDER, TagTechniqueVocabProvider)


# ── evidence_policy is CONFIGURATION ONLY ─────────────────────────────────────
def test_evidence_policy_weights():
    assert ep.weight_for(ep.CLASS_VALIDATED_FINDING) > ep.weight_for(ep.CLASS_REPORT_INTEL)
    assert ep.weight_for(ep.CLASS_HYPOTHESIS) == 0.0
    assert ep.is_excluded(ep.CLASS_HYPOTHESIS)
    assert ep.weight_for("anything-unknown") == 0.0  # never inflated


def test_evidence_policy_is_config_only_not_a_second_engine():
    """The policy module must expose only data + trivial lookups — no scoring/banding/decay."""
    # 1. Only the two trivial lookups exist (no scoring functions).
    funcs = {n for n, o in inspect.getmembers(ep, inspect.isfunction)
             if o.__module__ == ep.__name__}
    assert funcs <= {"weight_for", "is_excluded"}, f"unexpected logic in evidence_policy: {funcs}"

    # 2. It must not wire in / re-implement the confidence engine.
    assert not hasattr(ep, "score_from_sources") and not hasattr(ep, "meets_two_signal")
    assert "confidence" not in {n for n in dir(ep) if not n.startswith("__")}

    # 3. EVIDENCE_WEIGHTS is plain data (a float-valued mapping); the two lookups are the
    #    only logic. Together (1)+(2)+(3) prove the module is configuration, not an engine.
    assert isinstance(ep.EVIDENCE_WEIGHTS, dict)
    assert all(isinstance(v, (int, float)) for v in ep.EVIDENCE_WEIGHTS.values())
