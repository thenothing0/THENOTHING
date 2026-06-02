"""Phase-C discovery tests: dry-run, evidence weighting, boundaries, strengthen, provenance, determinism."""

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.evidence_policy as policy
import hydra.knowledge.promotion as promotion_mod
from hydra.knowledge.discovery import (
    ChainDiscovery,
    DiscoveryError,
    PatternDiscovery,
    confirm_candidate,
)
from hydra.knowledge.graph_index import KnowledgeGraphIndex
from hydra.knowledge.schema import NodeType

import pytest


def _by_type_counts(ws):
    return {k: len(v) for k, v in KnowledgeGraphIndex.build(ws).by_type().items()}


# ── pattern discovery + weighting ─────────────────────────────────────────────
def test_two_validated_findings_make_high_pattern(seed_wiki):
    cands = PatternDiscovery(seed_wiki).discover()
    idor = next(c for c in cands if c.signature == "idor")
    assert idor.confidence.value == "high"
    assert set(idor.source_refs) == {"acme-idor-a", "acme-idor-b"}
    assert idor.recommendation == "create_new"
    assert len(idor.explain["matched_signals"]) >= 2


def test_finding_plus_report_intel_is_medium(seed_wiki):
    cands = PatternDiscovery(seed_wiki).discover()
    ssrf = next((c for c in cands if c.signature == "ssrf"), None)
    assert ssrf is not None, "finding + report-intel should form a candidate"
    assert ssrf.confidence.value == "medium"   # 0.7 + 0.4 = 1.1 < 1.2
    counts = ssrf.explain["evidence_counts"]
    assert counts.get("validated_finding") == 1 and counts.get("report_intel") == 1


def test_single_source_makes_no_pattern(seed_wiki):
    cands = PatternDiscovery(seed_wiki).discover()
    assert not any(c.signature == "xss" for c in cands)  # only one xss finding


def test_hypothesis_excluded_from_evidence(seed_wiki):
    cands = PatternDiscovery(seed_wiki).discover()
    idor = next(c for c in cands if c.signature == "idor")
    refs = {e.ref for e in idor.supporting_evidence}
    assert "acme-idor-hyp" not in refs
    assert all(e.evidence_class != policy.CLASS_HYPOTHESIS for e in idor.supporting_evidence)


def test_conflicting_evidence_surfaced(seed_wiki):
    cands = PatternDiscovery(seed_wiki).discover()
    idor = next(c for c in cands if c.signature == "idor")
    assert "acme-idor-rejected" in idor.conflicting_evidence


def test_dedup_by_root_source(seed_wiki):
    # add a second report-intel from the SAME root report → still one ssrf source
    seed_wiki.upsert(NodeType.INTEL, "ssrf-writeup-intel-2",
                     {"tags": ["intel", "report-derived"]},
                     "# more ssrf\nserver side request forgery again. From [[ssrf-writeup]].\n")
    cands = PatternDiscovery(seed_wiki).discover()
    ssrf = next(c for c in cands if c.signature == "ssrf")
    # two intel pages share root 'ssrf-writeup' → counts once; with the finding = 2 sources
    assert ssrf.explain["deduped_source_count"] == 2


# ── propose-only invariant ────────────────────────────────────────────────────
def test_discovery_is_dry_run(seed_wiki):
    before = _by_type_counts(seed_wiki)
    PatternDiscovery(seed_wiki).discover()
    ChainDiscovery(seed_wiki).discover()
    assert _by_type_counts(seed_wiki) == before  # nothing written


# ── boundary: promotion/confidence untouched + no finding/report created ──────
def test_no_finding_or_report_created_on_any_path(seed_wiki):
    before = _by_type_counts(seed_wiki)
    pats = PatternDiscovery(seed_wiki).discover()
    confirm_candidate("pattern", pats[0].id, seed_wiki)
    after = _by_type_counts(seed_wiki)
    for t in ("finding", "observation", "report"):
        assert after.get(t, 0) == before.get(t, 0), f"{t} count changed"


def test_promotion_and_confidence_modules_unchanged():
    # discovery must not monkeypatch the shared engines
    assert hasattr(promotion_mod, "validate_promotion")
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"


# ── confirm / materialize / strengthen / idempotency ──────────────────────────
def test_confirm_materializes_with_provenance_and_backlink(seed_wiki):
    pats = PatternDiscovery(seed_wiki).discover()
    idor = next(c for c in pats if c.signature == "idor")
    res = confirm_candidate("pattern", idor.id, seed_wiki)
    assert res["confirmed"]
    page = seed_wiki.get("idor-pattern", NodeType.PATTERN)
    assert page.meta["status"] == "candidate"
    assert page.meta["discovered_by"] == "phase_c"
    assert page.meta["candidate_id"] == idor.id
    assert page.meta["confidence"] == "high"
    assert page.meta["source_refs"] and page.meta.get("confirmed_at")
    # symmetric backlink + no orphan
    assert "[[idor-pattern]]" in seed_wiki.get("acme-idor-b").body
    idx = KnowledgeGraphIndex.build(seed_wiki)
    assert "idor-pattern" not in idx.orphans()


def test_confirm_idempotent(seed_wiki):
    pats = PatternDiscovery(seed_wiki).discover()
    cid = next(c for c in pats if c.signature == "idor").id
    confirm_candidate("pattern", cid, seed_wiki)
    confirm_candidate("pattern", cid, seed_wiki)
    patterns = KnowledgeGraphIndex.build(seed_wiki).by_type().get("pattern", [])
    assert patterns.count("idor-pattern") == 1


def test_confirm_unknown_id_raises(seed_wiki):
    with pytest.raises(DiscoveryError):
        confirm_candidate("pattern", "patt-deadbeef0000", seed_wiki)


def test_strengthen_existing_no_duplicate(seed_wiki):
    # first confirm creates idor-pattern; re-discovery now recommends strengthen
    pats = PatternDiscovery(seed_wiki).discover()
    confirm_candidate("pattern", next(c for c in pats if c.signature == "idor").id, seed_wiki)
    pats2 = PatternDiscovery(seed_wiki).discover()
    idor2 = next(c for c in pats2 if c.signature == "idor")
    assert idor2.recommendation == "strengthen_existing"
    assert idor2.existing_slug == "idor-pattern"
    confirm_candidate("pattern", idor2.id, seed_wiki)
    assert KnowledgeGraphIndex.build(seed_wiki).by_type().get("pattern", []).count("idor-pattern") == 1


# ── chains (conservative) ─────────────────────────────────────────────────────
def test_chain_from_shared_target(seed_wiki):
    chains = ChainDiscovery(seed_wiki).discover()
    shared = next((c for c in chains if c.link_basis == "shared_target"), None)
    assert shared is not None
    # only validated findings are steps; hypothesis never appears
    assert "acme-idor-hyp" not in shared.steps
    assert all(seed_wiki.get(s, NodeType.FINDING) is not None for s in shared.steps)


def test_chain_confirm_writes_nodes_frontmatter(seed_wiki):
    chains = ChainDiscovery(seed_wiki).discover()
    cid = chains[0].id
    confirm_candidate("chain", cid, seed_wiki)
    page = next(iter(seed_wiki.list_pages(NodeType.CHAIN)))
    assert page.meta.get("nodes")
    assert page.meta["discovered_by"] == "phase_c"


# ── determinism ───────────────────────────────────────────────────────────────
def test_determinism_ids_order_bands(seed_wiki):
    a = PatternDiscovery(seed_wiki).discover()
    b = PatternDiscovery(seed_wiki).discover()
    assert [c.id for c in a] == [c.id for c in b]
    assert [c.confidence.value for c in a] == [c.confidence.value for c in b]
    assert [c.proposed_slug for c in a] == [c.proposed_slug for c in b]


# ── machine-readable explainability ───────────────────────────────────────────
def test_explain_block_is_machine_readable(seed_wiki):
    c = next(x for x in PatternDiscovery(seed_wiki).discover() if x.signature == "idor")
    ex = c.explain
    assert set(ex) >= {"matched_signals", "evidence_counts", "deduped_source_count", "confidence_inputs"}
    assert isinstance(ex["evidence_counts"], dict)
    assert ex["confidence_inputs"]["two_signal"] is True
    assert set(ex["confidence_inputs"]) >= {"refs", "weights", "two_signal"}
