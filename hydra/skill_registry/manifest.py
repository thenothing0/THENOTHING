"""Canonical skill manifest + multi-format (Markdown / YAML / JSON) loading."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class SkillManifest:
    """Normalized, format-independent skill definition (the trust unit)."""
    id: str
    name: str
    category: str
    version: str = "1.0.0"
    body: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    requires: List[Dict[str, str]] = field(default_factory=list)  # [{skill, range}]
    triggers: List[str] = field(default_factory=list)
    signature: str = ""          # detached hex HMAC (set by sign_skill)
    signer: str = ""             # key id that produced the signature
    source: str = "inline"       # builtin|project|personal|extra|marketplace|inline

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items()}


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.S)


def parse_manifest(text: str, fmt: str, source: str = "inline") -> SkillManifest:
    """Parse skill `text` of the given format ('md'|'yaml'|'json') into a manifest."""
    fmt = fmt.lower()
    if fmt in ("md", "markdown"):
        meta, body = _parse_markdown(text)
    elif fmt in ("yaml", "yml"):
        import yaml
        meta = yaml.safe_load(text) or {}
        body = meta.pop("body", "") if isinstance(meta, dict) else ""
    elif fmt == "json":
        meta = json.loads(text)
        body = meta.pop("body", "") if isinstance(meta, dict) else ""
    else:
        raise ValueError(f"unknown skill format '{fmt}'")
    if not isinstance(meta, dict):
        raise ValueError("skill metadata must be a mapping")
    return _from_meta(meta, body, source)


def load_manifest(path: str, source: str = "") -> SkillManifest:
    """Load a manifest from a file, inferring format from the extension."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    ext = p.suffix.lower().lstrip(".")
    fmt = {"md": "md", "markdown": "md", "yaml": "yaml", "yml": "yaml", "json": "json"}.get(ext)
    if not fmt:
        # SKILL.md / SKILL.yaml / skill.json by name
        name = p.name.lower()
        fmt = "md" if name.endswith(".md") else "yaml" if "yaml" in name or "yml" in name else "json"
    return parse_manifest(text, fmt, source=source or _infer_source(p))


def _parse_markdown(text: str):
    m = _FRONTMATTER_RE.match(text.strip())
    if not m:
        # No frontmatter: treat first '# Heading' as name, rest as body.
        body = text.strip()
        first = next((ln[1:].strip() for ln in body.splitlines() if ln.startswith("# ")), "")
        return ({"name": first}, body)
    import yaml
    meta = yaml.safe_load(m.group(1)) or {}
    return (meta, m.group(2).strip())


def _from_meta(meta: Dict, body: str, source: str) -> SkillManifest:
    # Accept both `allowed-tools` (PentesterFlow/MD convention) and `allowed_tools`.
    allowed = meta.get("allowed_tools") or meta.get("allowed-tools") or meta.get("tools") or []
    requires = _normalize_requires(meta.get("requires") or [])
    sid = str(meta.get("id") or _slug(meta.get("name", "")))
    return SkillManifest(
        id=sid,
        name=str(meta.get("name") or sid),
        category=str(meta.get("category") or "uncategorized"),
        version=str(meta.get("version") or "1.0.0"),
        body=body or str(meta.get("body") or ""),
        allowed_tools=[str(t) for t in allowed],
        requires=requires,
        triggers=[str(t) for t in (meta.get("triggers") or [])],
        signature=str(meta.get("signature") or ""),
        signer=str(meta.get("signer") or ""),
        source=source,
    )


def _normalize_requires(req) -> List[Dict[str, str]]:
    out = []
    for r in req:
        if isinstance(r, str):
            out.append({"skill": r, "range": "*"})
        elif isinstance(r, dict) and r.get("skill"):
            out.append({"skill": str(r["skill"]), "range": str(r.get("range", "*"))})
    return out


def canonical_bytes(m: SkillManifest) -> bytes:
    """Deterministic byte representation signed/verified over. Excludes the
    signature/signer/source fields (which are *about* the signature, not signed)."""
    payload = {
        "id": m.id, "name": m.name, "category": m.category, "version": m.version,
        "body": m.body, "allowed_tools": sorted(m.allowed_tools),
        "requires": sorted([f"{r['skill']}{r['range']}" for r in m.requires]),
        "triggers": sorted(m.triggers),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "skill"


def _infer_source(p: Path) -> str:
    s = str(p).lower()
    if ".thenothing/skills" in s:
        return "project"
    if "marketplace" in s:
        return "marketplace"
    if str(Path.home()).lower() in s:
        return "personal"
    return "builtin"
