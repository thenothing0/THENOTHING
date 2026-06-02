"""
Phase-B Report Intelligence pipeline tests — all offline, fixture-driven, into a
throwaway wiki. They pin the hard guarantees:

  * extraction carries provenance and never fabricates;
  * report+intel pages are written with symmetric backlinks and no auto-stubs;
  * the Phase-C boundary holds (only report/intel types created, ever);
  * Phase-A promotion rules are unaffected;
  * ingestion is idempotent and preserves manual body edits;
  * a newly-created intel page is recallable with no code change.
"""

from pathlib import Path

import pytest

from hydra.knowledge.report_intel import ReportIntelligencePipeline, ReportSource
from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiStore

FIXTURES = Path(__file__).resolve().parents[1] / "_doubles" / "fixtures" / "reports"
CHAINED = FIXTURES / "chained_authz_takeover.md"
TRIVIAL = FIXTURES / "trivial_header_misconfig.md"

# Page types Phase B must NEVER create (the Phase-C boundary).
_FORBIDDEN_TYPES = (NodeType.FINDING, NodeType.PATTERN, NodeType.CHAIN,
                    NodeType.HYPOTHESIS)


@pytest.fixture
def store(tmp_path):
    return WikiStore(root=tmp_path / "wiki")


@pytest.fixture
def pipeline(store):
    return ReportIntelligencePipeline(store=store)


def _count_by_type(store):
    return {t: len(store.list_pages(t)) for t in NodeType}


def test_extraction_has_provenance_and_no_fabrication(pipeline):
    e = pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Authz chain ATO"))

    # Core fields extracted via the reused research_ingestion backbone.
    assert e.vuln_class.known and e.vuln_class.value == "idor"
    assert e.vuln_class.inferred is True  # pattern-matched, not quoted
    assert isinstance(e.exploitation_sequence.value, list) and len(e.exploitation_sequence.value) >= 3
    assert e.severity.known

    # Section extractors lift verbatim text WITH provenance.
    assert e.root_cause.known and e.root_cause.evidence != "not found"
    assert e.root_cause.inferred is False
    assert e.impact.known

    # learning_score is in range and a chained authz/idor report scores high.
    assert 1 <= e.learning_score <= 10
    assert e.learning_score >= 7
    assert e.learning_score_rationale


def test_unknown_fields_stay_unknown(pipeline):
    e = pipeline.ingest(ReportSource(path=str(TRIVIAL), target="acme", title="Trivial header"))
    # The trivial report has no "trust boundary" / "assumptions" sections.
    assert not e.trust_boundary_failure.known
    assert e.trust_boundary_failure.evidence == "not found"
    assert e.trust_boundary_failure.inferred is False  # honest unknown, not a guess


def test_materialization_and_symmetric_crosslinks(store, pipeline):
    # Pre-create an EXISTING technique page so it is linked (not unresolved).
    store.upsert(NodeType.TECHNIQUE, "idor", meta={"tags": ["technique"]}, body="# idor\n")

    e = pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Authz chain ATO"))

    report = store.get(e.slug, NodeType.REPORT)
    intel = store.get(e.slug + "-intel", NodeType.INTEL)
    assert report is not None and intel is not None

    # Symmetric backlinks: report<->intel, and both link the target.
    assert (e.slug + "-intel") in report.links
    assert e.slug in intel.links
    assert "acme" in report.links and "acme" in intel.links

    # Only EXISTING technique/pattern pages are linked.
    assert e.related_techniques == ["idor"]
    # The missing reference is recorded, never created.
    assert "ghost-technique" in e.unresolved_references
    assert store.get("ghost-technique", NodeType.TECHNIQUE) is None


def test_stage_boundary_only_report_and_intel_created(store, pipeline):
    before = _count_by_type(store)
    pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Chained"))
    pipeline.ingest(ReportSource(path=str(TRIVIAL), target="acme", title="Trivial"))
    after = _count_by_type(store)

    # No finding/pattern/chain/hypothesis page is ever created — Phase-C boundary.
    for t in _FORBIDDEN_TYPES:
        assert after[t] == before[t] == 0, f"Phase-C boundary violated: created {t}"
    # Exactly the report + intel pages grew.
    assert after[NodeType.REPORT] == before[NodeType.REPORT] + 2
    assert after[NodeType.INTEL] == before[NodeType.INTEL] + 2


def test_high_value_chained_report_stays_report_intel_only(store, pipeline):
    # Regression: a tempting high-value chained report must not auto-promote.
    e = pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Chained"))
    assert e.learning_score >= 7
    assert store.get(e.slug, NodeType.REPORT) is not None
    for t in _FORBIDDEN_TYPES:
        assert store.list_pages(t) == []


def test_promotion_rules_unaffected(pipeline):
    # Ingesting reports must not change Phase-A promotion behavior.
    from hydra.knowledge.promotion import validate_promotion
    from hydra.knowledge.schema import Stage
    pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Chained"))
    # intel->pattern is forbidden; intel->finding is forbidden; both still rejected.
    assert validate_promotion(Stage.INTEL, Stage.PATTERN, evidence_count=9).allowed is False
    assert validate_promotion(Stage.INTEL, Stage.FINDING, evidence_count=9).allowed is False
    # A legal one-step promotion with two signals is still allowed.
    assert validate_promotion(Stage.FINDING, Stage.PATTERN,
                              sources=["a", "b"], evidence_count=2).allowed is True


def test_idempotent_and_preserves_manual_body(store, pipeline):
    src = ReportSource(path=str(CHAINED), target="acme", title="Authz chain ATO")
    e1 = pipeline.ingest(src)
    n_reports = len(store.list_pages(NodeType.REPORT))
    n_intel = len(store.list_pages(NodeType.INTEL))

    # A researcher hand-edits the report page.
    page = store.get(e1.slug, NodeType.REPORT)
    page.body = page.body.rstrip() + "\n\n## Manual note\n- hand-added line that must survive\n"
    store.write_page(page)

    # Re-ingest the identical report.
    e2 = pipeline.ingest(src)
    assert e2.slug == e1.slug
    assert len(store.list_pages(NodeType.REPORT)) == n_reports  # no duplicate page
    assert len(store.list_pages(NodeType.INTEL)) == n_intel

    reloaded = store.get(e1.slug, NodeType.REPORT)
    assert "hand-added line that must survive" in reloaded.body   # manual edit preserved
    assert reloaded.meta.get("learning_score") == e2.learning_score  # frontmatter still merged


def test_no_orphans_after_ingest(store, pipeline):
    from hydra.knowledge.graph_index import KnowledgeGraphIndex
    e = pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Chained"))
    idx = KnowledgeGraphIndex.build(store)
    orphans = set(idx.orphans())
    assert e.slug not in orphans               # report has inbound link from intel
    assert (e.slug + "-intel") not in orphans  # intel has inbound link from report


def test_intel_recallable_with_no_code_change(store, pipeline):
    from hydra.knowledge.memory import OffensiveMemory
    pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Authz chain ATO"))
    hits = OffensiveMemory(store=store).recall("idor account takeover", limit=10)
    slugs = {h.slug for h in hits}
    assert any(s.endswith("-intel") for s in slugs)


def test_graph_index_rebuild_is_stable(store, pipeline):
    from hydra.knowledge.graph_index import KnowledgeGraphIndex
    pipeline.ingest(ReportSource(path=str(CHAINED), target="acme", title="Chained"))
    a = KnowledgeGraphIndex.build(store)
    b = KnowledgeGraphIndex.build(store)
    assert a.nodes == b.nodes
