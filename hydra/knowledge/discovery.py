"""
Pattern & Chain discovery (Phase C) — propose-only synthesis over the wiki.

Discovery reads the canonical knowledge already in the wiki (validated findings +
Phase-B report-intel + the link graph) and **proposes** higher-tier synthesis as
ranked candidates. It is the first phase allowed to create `pattern`/`chain`
knowledge — but only on an **explicit** confirm step (see `bridge.confirm_*`); by
default it is pure, read-only and side-effect-free.

Invariants (enforced here, asserted by tests):
  * **Propose-only** — `discover_*` never writes a page or mutates the graph.
  * **Two-Signal gate** — a candidate needs ≥2 *independent* evidence sources
    (deduped by root source) AND ≥2 contributing signals.
  * **Weighted, no magic constants** — evidence is *classified*
    (validated_finding / report_intel / hypothesis); weights come from the
    declarative `evidence_policy`; the band is computed by the existing
    `confidence.score_from_sources`. `confidence.py`/`promotion.py` untouched.
  * **Hypotheses excluded** — weight 0; dropped before scoring; can never tip a threshold.
  * **Conservative chains** — only shared-target / shared-asset / explicit graph-path;
    never semantic-similarity guesses.
  * **Single canonical node** — a candidate matching an existing pattern/chain is a
    `strengthen_existing` recommendation, not a new conflicting slug.
  * **Explainable + deterministic** — every candidate carries a machine-readable
    `explain` block; ids/ordering/bands are reproducible across runs.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.knowledge import evidence_policy as policy
from hydra.knowledge.confidence import meets_two_signal, score_from_sources
from hydra.knowledge.graph_index import KnowledgeGraphIndex
from hydra.knowledge.schema import Confidence, NodeType, extract_wikilinks, slugify
from hydra.knowledge.signatures import DEFAULT_PROVIDER, SignatureProvider
from hydra.knowledge.wiki_store import WikiPage, WikiStore

# A finding only counts as validated evidence at these stages.
VALIDATED_STATUSES = frozenset({"confirmed", "submitted", "accepted", "resolved"})
# Findings whose status marks them as non-evidence but worth surfacing as conflicts.
CONFLICTING_STATUSES = frozenset({"na", "rejected", "duplicate"})

_MIN_SUPPORT = 2
_MIN_SIGNALS = 2
# Bounded chain size — a target with many findings yields a readable chain, not a bag.
_MAX_CHAIN_STEPS = 12


@dataclass(frozen=True)
class DiscoveryLimits:
    """Operational guardrails for discovery (Phase C.5).

    `max_groups`/`max_candidates` are **deterministic** caps applied after a stable
    sort, so truncation is reproducible. `timeout_seconds` is a best-effort wall-clock
    safety valve (non-deterministic; generous default so it rarely fires) that stops
    adding groups if a run runs long on a very large corpus.
    """
    max_groups: int = 5000
    max_candidates: int = 1000
    timeout_seconds: float = 30.0


DEFAULT_LIMITS = DiscoveryLimits()


class DiscoveryError(Exception):
    """Raised when a confirm target fails re-validation (e.g. guard no longer holds)."""


# ── Evidence + candidates ─────────────────────────────────────────────────────
@dataclass
class Evidence:
    ref: str                 # page slug
    evidence_class: str      # validated_finding | report_intel | hypothesis(excluded)
    root_source: str         # dedup key — same root counts once
    signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"ref": self.ref, "evidence_class": self.evidence_class,
                "root_source": self.root_source, "signals": sorted(self.signals)}


@dataclass
class Candidate:
    id: str
    candidate_type: str            # "pattern" | "chain"
    confidence: Confidence
    supporting_evidence: List[Evidence] = field(default_factory=list)
    recommendation: str = "create_new"     # create_new | strengthen_existing
    existing_slug: str = ""
    rationale: str = ""
    explain: Dict = field(default_factory=dict)
    source_refs: List[str] = field(default_factory=list)
    conflicting_evidence: List[str] = field(default_factory=list)
    proposed_slug: str = ""
    proposed_links: List[str] = field(default_factory=list)
    signature_provider: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "candidate_type": self.candidate_type,
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence,
            "recommendation": self.recommendation, "existing_slug": self.existing_slug,
            "rationale": self.rationale, "explain": self.explain,
            "source_refs": self.source_refs, "conflicting_evidence": self.conflicting_evidence,
            "proposed_slug": self.proposed_slug, "proposed_links": self.proposed_links,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "signature_provider": self.signature_provider,
        }


@dataclass
class PatternCandidate(Candidate):
    signature: str = ""
    vuln_class: str = ""

    def to_dict(self) -> Dict:
        return {**super().to_dict(), "signature": self.signature, "vuln_class": self.vuln_class}


@dataclass
class ChainCandidate(Candidate):
    steps: List[str] = field(default_factory=list)
    link_basis: str = ""          # shared_target | shared_asset | graph_path

    def to_dict(self) -> Dict:
        return {**super().to_dict(), "steps": self.steps, "link_basis": self.link_basis}


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _candidate_id(kind: str, key: str, refs: List[str]) -> str:
    payload = f"{kind}|{key}|{'|'.join(sorted(refs))}"
    return f"{kind[:4]}-{hashlib.sha1(payload.encode()).hexdigest()[:12]}"


def _confidence_from_evidence(evidence: List[Evidence]) -> (Confidence, Dict):
    """Delegate banding to the existing confidence engine; weights from evidence_policy.

    Hypothesis-class evidence (weight 0) is dropped before scoring. Returns the
    band plus the machine-readable confidence inputs.
    """
    refs: List[str] = []
    weights: Dict[str, float] = {}
    for e in evidence:
        if policy.is_excluded(e.evidence_class):
            continue
        refs.append(e.root_source)
        weights[e.root_source] = policy.weight_for(e.evidence_class)
    band = score_from_sources(refs, weights)
    inputs = {"refs": sorted(set(refs)), "weights": weights,
              "two_signal": meets_two_signal(refs)}
    return band, inputs


def _target_slug(page: WikiPage) -> str:
    raw = page.meta.get("target") or ""
    links = extract_wikilinks(str(raw))
    return links[0] if links else ""


def _shared_tags(pages: List[WikiPage]) -> List[str]:
    """Tags appearing in ≥2 of the pages (a corroborating signal across evidence)."""
    counts: Dict[str, int] = {}
    for p in pages:
        for t in {slugify(str(x)) for x in (p.meta.get("tags") or [])}:
            counts[t] = counts.get(t, 0) + 1
    return sorted(t for t, c in counts.items() if c >= 2 and t)


# Cross-evidence signal keywords — a recurring lesson is stronger when its examples
# share an escalation / chaining / trust-boundary characteristic, not just a class.
_SIGNAL_KEYWORDS = {
    "escalation": ("escalat", "privilege", "account takeover", "ato ", "admin access"),
    "chain": ("chain", "multi-step", "pivot", "combined"),
    "trust_boundary": ("trust boundary", "trust-boundary", "boundary"),
    "auth_bypass": ("auth bypass", "authorization bypass", "broken access", "bypass auth"),
}


def _keyword_signals(pages: List[WikiPage]) -> List[str]:
    """Signal keywords detected across the evidence bodies/tags (deterministic)."""
    blob = "\n".join((p.body or "") + " " + " ".join(map(str, p.meta.get("tags") or []))
                     for p in pages).lower()
    return sorted(name for name, kws in _SIGNAL_KEYWORDS.items() if any(k in blob for k in kws))


# ── Pattern discovery ─────────────────────────────────────────────────────────────
class PatternDiscovery:
    def __init__(self, store: Optional[WikiStore] = None,
                 index: Optional[KnowledgeGraphIndex] = None,
                 provider: Optional[SignatureProvider] = None):
        self.store = store or WikiStore()
        self.index = index or KnowledgeGraphIndex.build(self.store)
        self.provider = provider or DEFAULT_PROVIDER

    def discover(self, min_support: int = _MIN_SUPPORT,
                 limits: DiscoveryLimits = DEFAULT_LIMITS) -> List[PatternCandidate]:
        start = time.perf_counter()
        # Collect evidence pages grouped by signature (read-only).
        groups: Dict[str, List[tuple]] = {}     # signature -> [(page, Evidence)]
        conflicts: Dict[str, List[str]] = {}
        for page in self.store.iter_pages():
            ev = self._classify(page)
            sig = self.provider.signature(page)
            if not sig:
                continue
            if ev is None:
                # Surface non-evidence findings (na/rejected/duplicate) as conflicts.
                if page.type == NodeType.FINDING and \
                        str(page.meta.get("status", "")).lower() in CONFLICTING_STATUSES:
                    conflicts.setdefault(sig, []).append(page.slug)
                continue
            groups.setdefault(sig, []).append((page, ev))

        existing_pattern_sigs = self._existing_signatures(NodeType.PATTERN)

        candidates: List[PatternCandidate] = []
        # Deterministic, bounded iteration: signatures sorted, capped by max_groups.
        for gi, sig in enumerate(sorted(groups)):
            if gi >= limits.max_groups:
                break
            if limits.timeout_seconds and (time.perf_counter() - start) > limits.timeout_seconds:
                break
            items = groups[sig]
            evidence = self._dedup_by_root([e for _, e in items])
            if len(evidence) < min_support or not meets_two_signal([e.root_source for e in evidence]):
                continue
            pages = [p for p, _ in items]
            signals = sorted(set([sig] + _shared_tags(pages) + _keyword_signals(pages)))
            if len(signals) < _MIN_SIGNALS:
                continue

            band, conf_inputs = _confidence_from_evidence(evidence)
            refs = sorted({e.ref for e in evidence})
            cid = _candidate_id("pattern", sig, refs)
            proposed_slug = f"{sig}-pattern"

            cand = PatternCandidate(
                id=cid, candidate_type="pattern", confidence=band,
                supporting_evidence=evidence, signature=sig, vuln_class=sig,
                source_refs=refs, proposed_slug=proposed_slug, proposed_links=refs,
                conflicting_evidence=sorted(conflicts.get(sig, [])),
                signature_provider=self.provider.name,
                explain={
                    "matched_signals": signals,
                    "evidence_counts": self._counts(evidence),
                    "deduped_source_count": len({e.root_source for e in evidence}),
                    "confidence_inputs": conf_inputs,
                },
            )
            # Single canonical node: strengthen if a matching pattern already exists.
            existing = existing_pattern_sigs.get(sig) or (
                proposed_slug if self.store.exists(proposed_slug, NodeType.PATTERN) else "")
            if existing:
                cand.recommendation = "strengthen_existing"
                cand.existing_slug = existing
            cand.rationale = self._rationale(cand)
            candidates.append(cand)

        return _apply_limits(candidates, limits)

    def _classify(self, page: WikiPage) -> Optional[Evidence]:
        """Map a page to discovery Evidence, or None if it isn't pattern evidence."""
        if page.type == NodeType.FINDING:
            status = str(page.meta.get("status", "")).lower()
            if status not in VALIDATED_STATUSES:
                return None  # unvalidated finding: not evidence (surfaced as conflict if na/rejected)
            return Evidence(ref=page.slug, evidence_class=policy.CLASS_VALIDATED_FINDING,
                            root_source=page.slug)
        if page.type == NodeType.INTEL and "report-derived" in (page.meta.get("tags") or []):
            return Evidence(ref=page.slug, evidence_class=policy.CLASS_REPORT_INTEL,
                            root_source=_report_root(page))
        if page.type == NodeType.HYPOTHESIS:
            # classified but excluded (weight 0) — never contributes
            return Evidence(ref=page.slug, evidence_class=policy.CLASS_HYPOTHESIS,
                            root_source=page.slug)
        return None

    @staticmethod
    def _dedup_by_root(evidence: List[Evidence]) -> List[Evidence]:
        """Keep one (highest-weight) evidence item per root source; drop excluded classes."""
        best: Dict[str, Evidence] = {}
        for e in evidence:
            if policy.is_excluded(e.evidence_class):
                continue
            cur = best.get(e.root_source)
            if cur is None or policy.weight_for(e.evidence_class) > policy.weight_for(cur.evidence_class):
                best[e.root_source] = e
        return [best[k] for k in sorted(best)]

    @staticmethod
    def _counts(evidence: List[Evidence]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in evidence:
            out[e.evidence_class] = out.get(e.evidence_class, 0) + 1
        return out

    def _existing_signatures(self, ntype: NodeType) -> Dict[str, str]:
        sigs: Dict[str, str] = {}
        for page in self.store.iter_pages(ntype):
            s = self.provider.signature(page)
            if s and s not in sigs:
                sigs[s] = page.slug
        return sigs

    @staticmethod
    def _rationale(c: PatternCandidate) -> str:
        n = c.explain["deduped_source_count"]
        counts = c.explain["evidence_counts"]
        rec = "strengthen existing" if c.recommendation == "strengthen_existing" else "new pattern"
        return (f"{rec}: signature '{c.signature}' seen across {n} independent sources "
                f"({counts}); signals={c.explain['matched_signals']}; "
                f"confidence={c.confidence.value}")


# ── Chain discovery (conservative) ────────────────────────────────────────────────
class ChainDiscovery:
    def __init__(self, store: Optional[WikiStore] = None,
                 index: Optional[KnowledgeGraphIndex] = None):
        self.store = store or WikiStore()
        self.index = index or KnowledgeGraphIndex.build(self.store)

    # Bases are STRUCTURED and bounded — every chain comes from a group keyed by a
    # concrete shared attribute. There is NO pairwise path scan (the old O(F²) cliff).
    _BASES = ("shared_target", "shared_asset", "shared_program", "shared_root_report")

    def discover(self, min_support: int = _MIN_SUPPORT,
                 limits: DiscoveryLimits = DEFAULT_LIMITS) -> List[ChainCandidate]:
        start = time.perf_counter()
        findings = [p for p in self.store.iter_pages(NodeType.FINDING)
                    if str(p.meta.get("status", "")).lower() in VALIDATED_STATUSES]
        existing = self._existing_chain_nodes()

        # Build every grouping in single linear passes — total O(F · avg_degree).
        buckets: Dict[str, Dict[str, List[WikiPage]]] = {
            "shared_target": _bucket_by(findings, _target_slug),
            "shared_program": _bucket_by(findings, self._program_key),
            "shared_asset": self._group_by_shared_asset(findings),
            "shared_root_report": self._bucket_by_linked_type(findings, NodeType.REPORT),
        }

        # Deterministic, bounded iteration order: fixed basis order, sorted keys.
        ordered: List[tuple] = []
        for basis in self._BASES:
            for key in sorted(buckets[basis]):
                ordered.append((basis, key, buckets[basis][key]))

        candidates: List[ChainCandidate] = []
        for idx, (basis, key, group) in enumerate(ordered):
            if idx >= limits.max_groups:
                break
            if limits.timeout_seconds and (time.perf_counter() - start) > limits.timeout_seconds:
                break
            if len(group) >= min_support:
                candidates.append(self._build(group, basis, key, existing))

        # De-duplicate identical step sets (first basis in priority order wins) — deterministic.
        seen_steps: Dict[frozenset, ChainCandidate] = {}
        for c in candidates:
            seen_steps.setdefault(frozenset(c.steps), c)
        return _apply_limits(list(seen_steps.values()), limits)

    @staticmethod
    def _program_key(page: WikiPage) -> str:
        return slugify(str(page.meta.get("program") or page.meta.get("platform") or ""))

    def _build(self, group: List[WikiPage], basis: str, key: str,
               existing: Dict[frozenset, str]) -> ChainCandidate:
        # Cap steps deterministically (highest-severity first) so a target with many
        # findings yields a bounded, readable chain rather than an unbounded bag.
        ordered = sorted(group, key=lambda p: (_severity_rank(p), p.slug))[:_MAX_CHAIN_STEPS]
        steps = [p.slug for p in ordered]
        evidence = [Evidence(ref=p.slug, evidence_class=policy.CLASS_VALIDATED_FINDING,
                             root_source=p.slug) for p in ordered]
        band, conf_inputs = _confidence_from_evidence(evidence)
        cid = _candidate_id("chain", f"{basis}:{key}", steps)
        cand = ChainCandidate(
            id=cid, candidate_type="chain", confidence=band, supporting_evidence=evidence,
            steps=steps, link_basis=basis, source_refs=steps, proposed_links=steps,
            proposed_slug=f"{slugify(key)}-chain"[:60],
            explain={"matched_signals": [basis], "evidence_counts": {policy.CLASS_VALIDATED_FINDING: len(steps)},
                     "deduped_source_count": len(set(steps)), "confidence_inputs": conf_inputs},
        )
        node_key = frozenset(steps)
        if node_key in existing:
            cand.recommendation = "strengthen_existing"
            cand.existing_slug = existing[node_key]
        cand.rationale = (f"chain via {basis} '{key}': {' → '.join(steps)}; "
                          f"confidence={band.value}")
        return cand

    def _group_by_shared_asset(self, findings: List[WikiPage]) -> Dict[str, List[WikiPage]]:
        asset_to_findings: Dict[str, List[WikiPage]] = {}
        asset_nodes = {n for n, t in self.index.nodes.items() if t == NodeType.ASSET.value}
        for f in findings:
            for nb in self.index.neighbors(f.slug):
                if nb in asset_nodes:
                    asset_to_findings.setdefault(nb, []).append(f)
        return asset_to_findings

    def _bucket_by_linked_type(self, findings: List[WikiPage],
                               ntype: NodeType) -> Dict[str, List[WikiPage]]:
        """Group findings by a linked page of `ntype` (e.g. the same root report).

        O(F · avg_degree) via the prebuilt graph index — no pairwise traversal."""
        type_nodes = {n for n, t in self.index.nodes.items() if t == ntype.value}
        out: Dict[str, List[WikiPage]] = {}
        for f in findings:
            for nb in self.index.neighbors(f.slug):
                if nb in type_nodes:
                    out.setdefault(nb, []).append(f)
        return out

    def _existing_chain_nodes(self) -> Dict[frozenset, str]:
        out: Dict[frozenset, str] = {}
        for page in self.store.iter_pages(NodeType.CHAIN):
            nodes = frozenset(slugify(str(n)) for n in (page.meta.get("nodes") or []))
            if nodes:
                out[nodes] = page.slug
        return out


def _report_root(intel_page: WikiPage) -> str:
    """Root source of a report-derived intel page (the originating report slug)."""
    for link in extract_wikilinks(intel_page.body):
        if not link.endswith("-intel"):
            return link
    return intel_page.slug


def _severity_rank(page: WikiPage) -> int:
    sev = str(page.meta.get("severity", "")).lower()
    order = {"critical": 0, "p1": 0, "high": 1, "p2": 1, "medium": 2, "p3": 2,
             "low": 3, "p4": 3, "info": 4, "p5": 4}
    return order.get(sev, 5)


def _rank(candidates: List[Candidate]) -> List[Candidate]:
    """Deterministic ranking: confidence desc, then candidate id asc."""
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(candidates, key=lambda c: (
        rank.get(c.confidence.value if isinstance(c.confidence, Confidence) else c.confidence, 3),
        c.id))


def _apply_limits(candidates: List[Candidate], limits: DiscoveryLimits) -> List[Candidate]:
    """Rank deterministically, then truncate to max_candidates (deterministic truncation)."""
    return _rank(candidates)[:limits.max_candidates]


def _bucket_by(findings: List[WikiPage], key_fn) -> Dict[str, List[WikiPage]]:
    """Single-pass O(F) bucketing of findings by a structured key (empty keys dropped)."""
    out: Dict[str, List[WikiPage]] = {}
    for f in findings:
        k = key_fn(f)
        if k:
            out.setdefault(k, []).append(f)
    return out


def _resolve_and_validate(ctype: str, candidate_id: str, store: WikiStore):
    """Re-run discovery, find the candidate by id, re-validate the two-signal guard.
    Returns (match, materialize_fn_name). Raises DiscoveryError on miss/invalid."""
    if ctype == "pattern":
        candidates = PatternDiscovery(store).discover()
        materialize = "materialize_pattern"
    elif ctype == "chain":
        candidates = ChainDiscovery(store).discover()
        materialize = "materialize_chain"
    else:
        raise DiscoveryError(f"unknown candidate_type: {ctype}")

    match = next((c for c in candidates if c.id == candidate_id), None)
    if match is None:
        raise DiscoveryError(
            f"candidate id '{candidate_id}' not found among current {ctype} candidates "
            "(it may have been superseded by newer evidence — re-run discovery)")
    refs = [e.root_source for e in match.supporting_evidence
            if not policy.is_excluded(e.evidence_class)]
    if not meets_two_signal(refs):
        raise DiscoveryError(f"candidate '{candidate_id}' no longer meets the two-signal gate")
    return match, materialize


def confirm_candidate(candidate_type: str, candidate_id: str,
                      store: Optional[WikiStore] = None, rebuild: bool = False) -> Dict:
    """The explicit materialization step. Single-writer.

    Re-runs discovery deterministically, re-validates the candidate by id (the guard
    must still hold), and materializes the canonical page. Duplicate canonical pages
    are prevented by the deterministic slug → identical path (the pre-write existence
    check in `bridge.materialize_*` decides create-vs-merge); this is NOT locking, so
    confirms must run single-threaded.

    Phase C.5: `rebuild` defaults to **False** — a single confirm no longer triggers a
    full graph-index rebuild (the index is rebuilt fresh from the canonical wiki on the
    next read, so per-write rebuilds were pure amplification). For many confirms use
    `confirm_candidates(...)`, which rebuilds the persisted index **once** at the end.
    """
    store = store or WikiStore()
    ctype = candidate_type.strip().lower()
    match, materialize = _resolve_and_validate(ctype, candidate_id, store)

    from hydra.knowledge import bridge  # lazy: discovery stays import-cycle-free
    path = getattr(bridge, materialize)(match, store=store, rebuild=rebuild)
    return {
        "confirmed": True, "candidate_type": ctype, "candidate_id": candidate_id,
        "recommendation": match.recommendation,
        "page": path, "confidence": match.confidence.value,
    }


def confirm_candidates(pairs, store: Optional[WikiStore] = None) -> Dict:
    """Batch confirm. Materializes each (candidate_type, candidate_id) with the
    per-write index rebuild **deferred**, then rebuilds the persisted index **once**.

    Turns N full rebuilds into 1 (eliminates write amplification). Skips ids that no
    longer resolve/validate and reports them rather than aborting the batch.
    """
    store = store or WikiStore()
    confirmed, skipped = [], []
    for candidate_type, candidate_id in pairs:
        try:
            res = confirm_candidate(candidate_type, candidate_id, store=store, rebuild=False)
            confirmed.append(res)
        except DiscoveryError as e:
            skipped.append({"candidate_id": candidate_id, "reason": str(e)})

    from hydra.knowledge import bridge
    stats = bridge.rebuild_index(store)  # single rebuild for the whole batch
    return {"confirmed": confirmed, "skipped": skipped,
            "count": len(confirmed), "index": stats}
