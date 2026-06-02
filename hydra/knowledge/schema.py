"""
Knowledge schema — the typed page-type contract for the wiki.

This is the single parsing/serialization authority for wiki markdown pages
(mirrors how mcp_server pins its tool contract). Every other module —
wiki_store, promotion, graph_index, bridge, lint — depends on these types and
helpers, so the wiki format has exactly one definition.

Wiki page format (matches wiki/SCHEMA.md):

    ---
    type: finding
    tags: [...]
    target: "[[tripadvisor]]"
    ...
    ---
    # Title
    body with [[wikilinks]] ...
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Tuple

try:  # pyyaml is a declared runtime dependency
    import yaml
except Exception:  # pragma: no cover - yaml is in requirements.txt
    yaml = None


class NodeType(str, Enum):
    """The page/node types. 8 from wiki/SCHEMA.md + observation/report (Phase A additions)."""
    TARGET = "target"
    TECHNIQUE = "technique"
    ASSET = "asset"
    PATTERN = "pattern"
    FINDING = "finding"
    INTEL = "intel"
    CHAIN = "chain"
    HYPOTHESIS = "hypothesis"
    OBSERVATION = "observation"
    REPORT = "report"

    @classmethod
    def from_str(cls, raw: Any) -> "NodeType":
        return cls(str(raw or "").strip().lower())


class Stage(str, Enum):
    """The knowledge hierarchy. Higher index = more valuable / more validated."""
    OBSERVATION = "observation"
    INTEL = "intel"
    HYPOTHESIS = "hypothesis"
    FINDING = "finding"
    PATTERN = "pattern"
    CHAIN = "chain"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


# Promotion order: Observation -> Intel -> Hypothesis -> Finding -> Pattern -> Chain
STAGE_ORDER: List[Stage] = [
    Stage.OBSERVATION, Stage.INTEL, Stage.HYPOTHESIS,
    Stage.FINDING, Stage.PATTERN, Stage.CHAIN,
]

# Transitions that are NEVER allowed even with evidence (spec: validation is mandatory;
# a hypothesis must become a finding before it can ever inform a pattern/chain).
FORBIDDEN_PROMOTIONS: set[Tuple[Stage, Stage]] = {
    (Stage.HYPOTHESIS, Stage.PATTERN),
    (Stage.HYPOTHESIS, Stage.CHAIN),
    (Stage.OBSERVATION, Stage.FINDING),
    (Stage.OBSERVATION, Stage.PATTERN),
    (Stage.OBSERVATION, Stage.CHAIN),
    (Stage.INTEL, Stage.PATTERN),
    (Stage.INTEL, Stage.CHAIN),
    (Stage.INTEL, Stage.FINDING),
}

# Which NodeType corresponds to each promotion Stage (for type<->stage reasoning).
NODE_TYPE_FOR_STAGE: Dict[Stage, NodeType] = {
    Stage.OBSERVATION: NodeType.OBSERVATION,
    Stage.INTEL: NodeType.INTEL,
    Stage.HYPOTHESIS: NodeType.HYPOTHESIS,
    Stage.FINDING: NodeType.FINDING,
    Stage.PATTERN: NodeType.PATTERN,
    Stage.CHAIN: NodeType.CHAIN,
}

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)
_WIKILINK_RE = re.compile(r"\[\[([^\]]+?)\]\]")


def split_page(text: str) -> Tuple[Dict[str, Any], str]:
    """Split a wiki page into (frontmatter dict, body). No frontmatter → ({}, text)."""
    m = _FRONTMATTER_RE.match(text or "")
    if not m:
        return {}, (text or "")
    return parse_frontmatter(m.group(1)), m.group(2)


def parse_frontmatter(block: str) -> Dict[str, Any]:
    """Parse a YAML frontmatter block into a dict (empty dict on failure)."""
    if yaml is None:
        return {}
    try:
        data = yaml.safe_load(block) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def dump_frontmatter(meta: Dict[str, Any]) -> str:
    """Serialize a frontmatter dict back to a `---`-delimited YAML block.

    Preserves unknown keys (we never silently drop hand-authored metadata) and
    keeps a stable, human-friendly key order with `type` first.
    """
    if yaml is None:  # pragma: no cover
        return "---\n---\n"
    ordered: Dict[str, Any] = {}
    for key in ("type", "aliases", "tags", "target", "host", "scope_status",
                "platform", "status", "severity", "confidence", "created", "updated"):
        if key in meta:
            ordered[key] = meta[key]
    for key, val in meta.items():
        if key not in ordered:
            ordered[key] = val
    body = yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, default_flow_style=False)
    return f"---\n{body}---\n"


def extract_wikilinks(text: str) -> List[str]:
    """Return the de-duplicated list of [[wikilink]] targets in a page (frontmatter + body).

    A link target may carry an alias/section (`[[page|alias]]`, `[[page#sec]]`) — we keep
    only the page slug, normalized to lowercase-kebab for graph node identity.
    """
    seen: Dict[str, None] = {}
    for raw in _WIKILINK_RE.findall(text or ""):
        slug = raw.split("|")[0].split("#")[0].strip()
        slug = slugify(slug)
        if slug and slug not in seen:
            seen[slug] = None
    return list(seen)


def slugify(name: str) -> str:
    """lowercase-kebab-case slug used for filenames and graph node ids."""
    s = str(name or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")
