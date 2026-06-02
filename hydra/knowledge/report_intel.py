"""
Report Intelligence (Phase B) — turn disclosed bug-bounty reports / writeups into
reusable attacker knowledge in the canonical wiki.

A disclosed report is a *learning asset*, not an archive entry. This pipeline
extracts the distilled, reusable lesson (root cause, trust-boundary failure,
exploitation sequence, escalation/impact, attacker assumptions), assigns a
transparent `learning_score`, and materializes two cross-linked canonical wiki
pages — a `report` page (the source + score rationale + provenance) and an
`intel` page (the actionable, distilled intelligence). It reuses the existing
extraction backbone (`hydra.research_ingestion.ResearchIngestionEngine`) and the
canonical wiki writer (`hydra.knowledge.wiki_store` / `bridge`); it never
duplicates parsing, scoring, or wiki-writing logic.

Guarantees (Phase-A invariants preserved):
  * **Wiki canonical** — pages are written through `WikiStore`; the graph index
    is only rebuilt, never written as a source of truth.
  * **Offline-first** — content is read from a local path or passed as text; the
    optional RAG index is behind `rag_adapter` and degrades to a no-op.
  * **Phase-C boundary (hard)** — only `report` and `intel` pages are ever
    created. No finding / pattern / chain / promotion artifact is produced under
    any ingestion path. The promotion library is untouched.
  * **No auto-stubs** — links are emitted only to *existing* technique/pattern
    pages; a referenced page that does not exist is recorded in
    `unresolved_references`, never created.
  * **Evidence discipline** — every populated field carries provenance and is
    never fabricated; fields that cannot be extracted stay `"unknown"`/`[]`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from hydra.knowledge import bridge
from hydra.knowledge.learning_score import score_report
from hydra.knowledge.rag_adapter import NoOpRagAdapter, RagIndexAdapter
from hydra.knowledge.schema import NodeType, extract_wikilinks, slugify
from hydra.knowledge.wiki_store import WikiStore
from hydra.research_ingestion import ResearchIngestionEngine, ResearchSource


# ── Provenance-carrying field ─────────────────────────────────────────────────
@dataclass
class ExtractedField:
    """A single extracted attacker-knowledge field with provenance.

    `value` is honest: `"unknown"` / `[]` when the field could not be extracted.
    `evidence` cites where it came from (a section heading, a line, or the
    extractor that produced it). `inferred` is True when the pipeline *derived*
    the value rather than quoting it verbatim from the report.
    """
    value: Any = "unknown"
    evidence: str = "not found"
    inferred: bool = False

    @property
    def known(self) -> bool:
        return self.value not in ("unknown", "", None, [], {})

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "evidence": self.evidence, "inferred": self.inferred}


@dataclass
class ExtractedReport:
    """The distilled, reusable knowledge extracted from one disclosed report."""
    slug: str = ""
    title: str = ""
    source: str = ""
    target: str = ""

    target_type: ExtractedField = field(default_factory=ExtractedField)
    asset_type: ExtractedField = field(default_factory=ExtractedField)
    vuln_class: ExtractedField = field(default_factory=ExtractedField)
    root_cause: ExtractedField = field(default_factory=ExtractedField)
    trust_boundary_failure: ExtractedField = field(default_factory=ExtractedField)
    exploitation_sequence: ExtractedField = field(default_factory=lambda: ExtractedField(value=[]))
    escalation_path: ExtractedField = field(default_factory=ExtractedField)
    impact: ExtractedField = field(default_factory=ExtractedField)
    severity: ExtractedField = field(default_factory=ExtractedField)
    severity_reasoning: ExtractedField = field(default_factory=ExtractedField)
    attacker_assumptions: ExtractedField = field(default_factory=ExtractedField)

    signals: List[str] = field(default_factory=list)
    learning_score: int = 1
    learning_score_rationale: str = ""

    related_techniques: List[str] = field(default_factory=list)
    related_patterns: List[str] = field(default_factory=list)
    unresolved_references: List[str] = field(default_factory=list)

    report_path: str = ""
    intel_path: str = ""

    _FIELD_NAMES = (
        "target_type", "asset_type", "vuln_class", "root_cause",
        "trust_boundary_failure", "exploitation_sequence", "escalation_path",
        "impact", "severity", "severity_reasoning", "attacker_assumptions",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slug": self.slug,
            "title": self.title,
            "source": self.source,
            "target": self.target,
            "fields": {name: getattr(self, name).to_dict() for name in self._FIELD_NAMES},
            "signals": sorted(self.signals),
            "learning_score": self.learning_score,
            "learning_score_rationale": self.learning_score_rationale,
            "related_techniques": self.related_techniques,
            "related_patterns": self.related_patterns,
            "unresolved_references": self.unresolved_references,
            "report_path": self.report_path,
            "intel_path": self.intel_path,
        }


# ── Source ────────────────────────────────────────────────────────────────────
@dataclass
class ReportSource:
    """A disclosed report to ingest. Content is read **offline** from `path` or
    taken directly from `text`. `target` is the program/asset slug it concerns."""
    path: str = ""
    text: str = ""
    source_url: str = ""
    target: str = ""
    title: str = ""
    source_type: str = "writeup"

    def read_content(self) -> str:
        if self.text:
            return self.text
        if self.path:
            return Path(self.path).read_text(encoding="utf-8")
        return ""

    def identity(self) -> str:
        """Deterministic identity for idempotent slugging."""
        return self.title or self.source_url or self.path or "untitled-report"


# ── Signal / section extraction ────────────────────────────────────────────────
# Bonus/penalty signal keyword sets (the scorer reads the resulting tokens).
_SIGNAL_PATTERNS: Dict[str, List[str]] = {
    "chain": [r"\bchain", r"\bchained\b", r"multi-?step", r"combin(e|ed|ing)",
              r"stitch", r"pivot(ed|ing)? (in)?to"],
    "escalation": [r"escalat", r"privilege", r"account ?takeover", r"\bato\b",
                   r"admin (access|panel)", r"elevat"],
    "pivot": [r"\bpivot\b", r"uncommon", r"novel", r"creative", r"unusual"],
    "duplicate": [r"duplicate", r"\bdupe\b", r"already (known|reported|disclosed)"],
    "trivial": [r"trivial", r"\bminor\b", r"informational", r"low.?impact"],
}

# Section headings (markdown or "Label:") we try to lift verbatim.
_SECTION_ALIASES: Dict[str, List[str]] = {
    "root_cause": ["root cause", "underlying cause", "why it happened"],
    "trust_boundary_failure": ["trust boundary", "trust-boundary", "boundary failure"],
    "escalation_path": ["escalation", "privilege escalation", "impact escalation"],
    "impact": ["impact", "business impact", "consequence"],
    "attacker_assumptions": ["assumption", "attacker assumption", "preconditions"],
}

# Target/asset-type inference keywords.
_TARGET_TYPE_HINTS = [
    ("api", [r"\bapi\b", r"\bendpoint", r"\brest\b", r"\bgraphql\b"]),
    ("mobile", [r"\bandroid\b", r"\bios\b", r"\bapk\b", r"\bmobile\b"]),
    ("cloud", [r"\baws\b", r"\bgcp\b", r"\bazure\b", r"\bs3\b", r"\bkubernetes\b", r"\bk8s\b"]),
    ("web", [r"\bweb\b", r"\bbrowser\b", r"\bcookie\b", r"\bdom\b"]),
]
_ASSET_TYPE_HINTS = _TARGET_TYPE_HINTS  # same vocabulary; asset_type mirrors target_type


def _detect_signals(content: str, step_count: int) -> List[str]:
    low = content.lower()
    found: List[str] = []
    for sig, patterns in _SIGNAL_PATTERNS.items():
        if any(re.search(p, low) for p in patterns):
            found.append(sig)
    # A genuine multi-step exploitation sequence is itself a chain signal.
    if step_count >= 3 and "chain" not in found:
        found.append("chain")
    return found


def _extract_section(content: str, aliases: List[str]) -> ExtractedField:
    """Lift the text under a matching markdown heading or an inline `Label:` line.

    Verbatim extraction → `inferred=False`. Returns an honest `unknown` field
    (inferred=False, evidence='not found') when nothing matches.
    """
    lines = content.splitlines()
    alias_re = re.compile(r"^\s*#{1,6}\s*(" + "|".join(re.escape(a) for a in aliases) + r")\b",
                          re.IGNORECASE)
    for i, line in enumerate(lines):
        if alias_re.search(line):
            # Collect following non-empty lines until the next heading.
            buf: List[str] = []
            for j in range(i + 1, len(lines)):
                if re.match(r"^\s*#{1,6}\s", lines[j]):
                    break
                if lines[j].strip():
                    buf.append(lines[j].strip())
            value = " ".join(buf).strip()
            if value:
                return ExtractedField(value=value, evidence=f"section '{line.strip()}' (line {i+1})",
                                      inferred=False)
    # Inline "Label: value" form.
    inline_re = re.compile(r"^\s*[*-]?\s*(?:\*\*)?(" + "|".join(re.escape(a) for a in aliases)
                           + r")(?:\*\*)?\s*[:：]\s*(.+)$", re.IGNORECASE)
    for i, line in enumerate(lines):
        m = inline_re.search(line)
        if m and m.group(2).strip():
            return ExtractedField(value=m.group(2).strip(),
                                  evidence=f"line {i+1} ('{m.group(1)}:')", inferred=False)
    return ExtractedField()  # honest unknown


def _infer_type(content: str, hints) -> ExtractedField:
    low = content.lower()
    for label, patterns in hints:
        if any(re.search(p, low) for p in patterns):
            return ExtractedField(value=label, evidence="inferred from content keywords",
                                  inferred=True)
    return ExtractedField()


# ── Pipeline ────────────────────────────────────────────────────────────────────
class ReportIntelligencePipeline:
    """Ingest disclosed reports into cross-linked `report` + `intel` wiki pages."""

    def __init__(self, store: Optional[WikiStore] = None,
                 engine: Optional[ResearchIngestionEngine] = None,
                 rag: Optional[RagIndexAdapter] = None):
        self.store = store or WikiStore()
        self.engine = engine or ResearchIngestionEngine()
        self.rag = rag or NoOpRagAdapter()

    def ingest(self, source: ReportSource) -> ExtractedReport:
        content = source.read_content()
        slug = slugify(source.identity())
        target_slug = slugify(source.target) if source.target else ""

        extracted = ExtractedReport(
            slug=slug, title=source.title or source.identity(),
            source=source.source_url or source.path, target=target_slug,
        )

        # 1+2. Reuse the research_ingestion extraction backbone for vuln types,
        # methodology steps (→ exploitation_sequence), payloads and severity.
        rs = ResearchSource(source_type=source.source_type, url=source.source_url,
                            title=extracted.title, content=content)
        results = self.engine.ingest(rs)
        vuln_types: List[str] = results.get("patterns") or []
        meth = self.engine._methodologies[-1] if self.engine._methodologies else None
        steps: List[str] = list(meth.steps) if meth else []
        severity_word = meth.severity if meth else self.engine._detect_severity(content)

        if vuln_types:
            extracted.vuln_class = ExtractedField(
                value=vuln_types[0], evidence="research_ingestion VULN_TYPE_PATTERNS",
                inferred=True)
        if steps:
            extracted.exploitation_sequence = ExtractedField(
                value=steps, evidence="research_ingestion methodology steps", inferred=False)
        extracted.severity = ExtractedField(
            value=severity_word, evidence="research_ingestion SEVERITY_PATTERNS", inferred=True)

        # 3. Section/regex extractors for the remaining attacker-knowledge fields.
        extracted.target_type = _infer_type(content, _TARGET_TYPE_HINTS)
        extracted.asset_type = _infer_type(content, _ASSET_TYPE_HINTS)
        extracted.root_cause = _extract_section(content, _SECTION_ALIASES["root_cause"])
        extracted.trust_boundary_failure = _extract_section(
            content, _SECTION_ALIASES["trust_boundary_failure"])
        extracted.escalation_path = _extract_section(content, _SECTION_ALIASES["escalation_path"])
        extracted.impact = _extract_section(content, _SECTION_ALIASES["impact"])
        extracted.attacker_assumptions = _extract_section(
            content, _SECTION_ALIASES["attacker_assumptions"])
        extracted.severity_reasoning = self._severity_reasoning(content)

        # 4. Deterministic, explainable learning_score.
        extracted.signals = _detect_signals(content, len(steps))
        extracted.learning_score, extracted.learning_score_rationale = score_report(extracted)

        # 5. Resolve related technique/pattern links — existing pages only.
        self._resolve_links(content, extracted, slug, target_slug)

        # 6. Materialize canonical wiki pages (idempotent) + rebuild index.
        self._materialize(extracted, target_slug)

        # 7. Optional RAG index (offline no-op by default).
        try:
            self.rag.index(slug=slug, title=extracted.title, text=content,
                           metadata={"category": extracted.vuln_class.value,
                                     "severity": severity_word, "target": target_slug})
        except Exception:
            pass

        return extracted

    # ── helpers ──────────────────────────────────────────────────────────────
    def _severity_reasoning(self, content: str) -> ExtractedField:
        m = re.search(r"(cvss[^\n]*|severity[^\n]*)", content, re.IGNORECASE)
        if m:
            return ExtractedField(value=m.group(1).strip(), evidence="severity/CVSS line",
                                  inferred=False)
        return ExtractedField(value="unknown", evidence="no explicit severity statement",
                              inferred=True)

    def _resolve_links(self, content: str, extracted: ExtractedReport,
                       slug: str, target_slug: str) -> None:
        """Partition referenced links into existing techniques/patterns vs unresolved.

        Candidates come from explicit `[[wikilinks]]` in the report body plus the
        normalized vuln_class. Self / target / the paired report-intel slugs are
        excluded. No page is ever created here (no auto-stubs)."""
        own = {slug, target_slug, _intel_slug(slug)}
        candidates: List[str] = [c for c in extract_wikilinks(content) if c]
        if extracted.vuln_class.known:
            candidates.append(slugify(extracted.vuln_class.value))

        seen: set = set()
        for cand in candidates:
            cand = slugify(cand)
            if not cand or cand in own or cand in seen:
                continue
            seen.add(cand)
            if self.store.exists(cand, NodeType.TECHNIQUE):
                extracted.related_techniques.append(cand)
            elif self.store.exists(cand, NodeType.PATTERN):
                extracted.related_patterns.append(cand)
            else:
                extracted.unresolved_references.append(cand)

    def _materialize(self, extracted: ExtractedReport, target_slug: str) -> None:
        slug = extracted.slug
        intel = _intel_slug(slug)

        report_meta = {
            "tags": ["report", "auto"],
            "source": extracted.source or "",
            "vuln_class": extracted.vuln_class.value,
            "asset_type": extracted.asset_type.value,
            "severity": extracted.severity.value,
            "learning_score": extracted.learning_score,
            "learning_score_rationale": extracted.learning_score_rationale,
            "unresolved_references": list(extracted.unresolved_references),
        }
        if target_slug:
            report_meta["target"] = f"[[{target_slug}]]"

        report_body = self._render_report_body(extracted, intel, target_slug)
        report_page = self._upsert_preserving(NodeType.REPORT, slug, report_meta, report_body)
        extracted.report_path = str(report_page.path)

        intel_meta = {
            "tags": ["intel", "auto", "report-derived"],
            "sources": [extracted.source] if extracted.source else [],
            "learning_score": extracted.learning_score,
        }
        if target_slug:
            intel_meta["target"] = f"[[{target_slug}]]"
        intel_body = self._render_intel_body(extracted, slug, target_slug)
        intel_page = self._upsert_preserving(NodeType.INTEL, intel, intel_meta, intel_body)
        extracted.intel_path = str(intel_page.path)

        self.store.append_log(
            "report-intel",
            f"ingested '{extracted.title}' → report/{slug} + intel/{intel} "
            f"(learning_score={extracted.learning_score})")
        bridge.rebuild_index(self.store)

    def _upsert_preserving(self, ntype: NodeType, slug: str, meta: Dict, body: str):
        """Create with body when absent; on re-ingest, merge frontmatter only and
        leave the existing body untouched (manual edits survive). Idempotent."""
        existing = self.store.get(slug, ntype)
        if existing is None:
            return self.store.upsert(ntype, slug, meta=meta, body=body)
        return self.store.upsert(ntype, slug, meta=meta, body="")  # body="" → preserved

    def _render_report_body(self, e: ExtractedReport, intel_slug: str, target_slug: str) -> str:
        def line(label: str, f: ExtractedField) -> str:
            tag = " _(inferred)_" if (f.inferred and f.known) else ""
            val = ", ".join(f.value) if isinstance(f.value, list) else f.value
            return f"- **{label}:** {val}{tag}  \n  <sub>provenance: {f.evidence}</sub>"

        related_bits = []
        if e.related_techniques:
            related_bits.append("Techniques: " + " ".join(f"[[{t}]]" for t in e.related_techniques))
        if e.related_patterns:
            related_bits.append("Patterns: " + " ".join(f"[[{p}]]" for p in e.related_patterns))
        related_bits.append(f"Intel: [[{intel_slug}]]")
        if target_slug:
            related_bits.append(f"Target: [[{target_slug}]]")

        unresolved = ""
        if e.unresolved_references:
            unresolved = ("\n## Unresolved references (recorded, not created)\n"
                          + "\n".join(f"- `{r}` — no page exists (Phase C may create it)"
                                      for r in e.unresolved_references) + "\n")

        return (
            f"# {e.title}\n\n"
            f"> Reusable lesson distilled from a disclosed report — see the intel page [[{intel_slug}]].\n\n"
            "## Distilled intelligence\n"
            f"{line('Root cause', e.root_cause)}\n"
            f"{line('Trust-boundary failure', e.trust_boundary_failure)}\n"
            f"{line('Exploitation sequence', e.exploitation_sequence)}\n"
            f"{line('Escalation / impact', e.escalation_path)}\n"
            f"{line('Impact', e.impact)}\n"
            f"{line('Severity reasoning', e.severity_reasoning)}\n"
            f"{line('Attacker assumptions', e.attacker_assumptions)}\n\n"
            "## Why the learning_score\n"
            f"- **{e.learning_score}/10** — {e.learning_score_rationale}\n"
            f"- signals: {', '.join(sorted(e.signals)) or 'none'}\n"
            f"{unresolved}\n"
            "## Related\n"
            f"- {' · '.join(related_bits)}\n"
        )

    def _render_intel_body(self, e: ExtractedReport, report_slug: str, target_slug: str) -> str:
        steps = e.exploitation_sequence.value if isinstance(e.exploitation_sequence.value, list) else []
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) or "_not extracted_"
        target_link = f"\n- Target: [[{target_slug}]]" if target_slug else ""
        return (
            f"# {e.title} — actionable intelligence\n\n"
            f"> Distilled from report [[{report_slug}]]. What to *reuse*, not an archive copy.\n\n"
            f"- **Vuln class:** {e.vuln_class.value}\n"
            f"- **Target / asset type:** {e.target_type.value} / {e.asset_type.value}\n"
            f"- **Root cause to look for:** {e.root_cause.value}\n"
            f"- **Trust boundary to probe:** {e.trust_boundary_failure.value}\n"
            f"- **Learning score:** {e.learning_score}/10\n\n"
            "## Reusable exploitation sequence\n"
            f"{steps_md}\n\n"
            "## Provenance\n"
            f"- Source: {e.source or 'n/a'}\n"
            f"- Report page: [[{report_slug}]]{target_link}\n"
        )


def _intel_slug(report_slug: str) -> str:
    return slugify(f"{report_slug}-intel")
