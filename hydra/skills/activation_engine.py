"""
Dynamic skill activation from fingerprints (stack, headers, infra, OSINT).

Produces a reasoning trace and ordered skill IDs for planner / Claude Code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from hydra.skills import Skill, SkillRegistry


@dataclass
class TechnologyFingerprint:
    """Signals used to rank skills. All optional."""

    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    infrastructure: List[str] = field(default_factory=list)
    osint_hints: List[str] = field(default_factory=list)
    historical_findings: List[str] = field(default_factory=list)
    attack_surface_tags: List[str] = field(default_factory=list)


@dataclass
class ActivationResult:
    """Output of dynamic activation."""

    activated_skill_ids: List[str]
    reasoning_trace: List[str]
    suggested_mcp_sequence: List[str]
    confidence_by_skill: Dict[str, float]


def _norm_tokens(items: List[str]) -> Set[str]:
    return {str(x).lower().strip() for x in items if x}


def _score_skill(skill: Skill, tokens: Set[str], fp: TechnologyFingerprint) -> float:
    score = skill.confidence_score * 0.35
    assoc = {a.lower() for a in skill.framework_associations}
    hit = assoc & tokens
    if hit:
        score += 0.18 * min(3, len(hit))
    for tag in skill.tags:
        tl = tag.lower()
        if tl in tokens or any(t in tl for t in tokens if len(t) > 3):
            score += 0.04
    for h in fp.attack_surface_tags:
        if h.lower() in " ".join(skill.tags).lower():
            score += 0.06
    for finding in fp.historical_findings:
        if finding.lower() in skill.id.lower() or finding.lower() in skill.name.lower():
            score += 0.08
    # Header-based nudges (conservative)
    server = fp.headers.get("server", "").lower()
    if "vercel" in server and "edge" in " ".join(skill.tags).lower():
        score += 0.02
    if "cloudflare" in server:
        score += 0.02
    return min(1.0, score)


class DynamicSkillActivator:
    """
    Ranks registry skills given a fingerprint; explains decisions in `reasoning_trace`.
    """

    def __init__(self, registry: SkillRegistry):
        self._registry = registry

    def activate(
        self,
        fingerprint: TechnologyFingerprint,
        max_skills: int = 24,
        min_score: float = 0.22,
    ) -> ActivationResult:
        tokens: Set[str] = set()
        tokens |= _norm_tokens(fingerprint.technologies)
        tokens |= _norm_tokens(fingerprint.infrastructure)
        tokens |= _norm_tokens(fingerprint.osint_hints)
        tokens |= _norm_tokens(fingerprint.attack_surface_tags)

        reasoning: List[str] = []
        reasoning.append(f"Token universe size={len(tokens)} from fingerprint.")

        scored: List[tuple[float, Skill]] = []
        for skill in self._registry.all_skills():
            s = _score_skill(skill, tokens, fingerprint)
            if s >= min_score:
                scored.append((s, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:max_skills]

        for rank, (s, sk) in enumerate(top[:8], start=1):
            overlap = {a.lower() for a in sk.framework_associations} & tokens
            reasoning.append(
                f"#{rank} {sk.id} score={s:.2f} category={sk.category.value} "
                f"tech_overlap={sorted(overlap) or 'heuristic/tags'}"
            )

        if not top:
            reasoning.append("No skills above threshold; falling back to broad recon + validation.")
            all_ids = [s.id for s in self._registry.all_skills()]
            fallback = [
                sid
                for sid in all_ids
                if any(
                    k in sid
                    for k in ("subdomain", "github", "recon", "osint", "report", "validation")
                )
            ][:12]
            if not fallback:
                fallback = all_ids[:12]
            return ActivationResult(
                activated_skill_ids=fallback,
                reasoning_trace=reasoning,
                suggested_mcp_sequence=_default_mcp_chain(),
                confidence_by_skill={sid: 0.25 for sid in fallback},
            )

        ids = [sk.id for _, sk in top]
        conf = {sk.id: round(s, 3) for s, sk in top}
        mcp = _collect_mcp_sequence([sk for _, sk in top])
        return ActivationResult(
            activated_skill_ids=ids,
            reasoning_trace=reasoning,
            suggested_mcp_sequence=mcp,
            confidence_by_skill=conf,
        )


def _collect_mcp_sequence(skills: List[Skill]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for sk in skills:
        for step in sk.recon_steps:
            t = (step.tool or "").strip()
            if t and t not in seen:
                seen.add(t)
                out.append(t)
    if not out:
        return _default_mcp_chain()
    return out


def _default_mcp_chain() -> List[str]:
    return [
        "check_tools",
        "subfinder_scan",
        "amass_enum",
        "httpx_probe",
        "whatweb_detect",
        "wafw00f_detect",
        "katana_crawl",
        "nuclei_scan",
    ]


def fingerprint_from_dict(data: Dict[str, Any]) -> TechnologyFingerprint:
    """Build fingerprint from JSON-like dict (API / agent payloads)."""
    return TechnologyFingerprint(
        technologies=list(data.get("technologies") or []),
        headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
        infrastructure=list(data.get("infrastructure") or []),
        osint_hints=list(data.get("osint_hints") or []),
        historical_findings=list(data.get("historical_findings") or []),
        attack_surface_tags=list(data.get("attack_surface_tags") or []),
    )


def exploit_probability_estimate(result: ActivationResult) -> float:
    """Heuristic 0..1 from top confidence scores (not a guarantee)."""
    if not result.confidence_by_skill:
        return 0.0
    vals = sorted(result.confidence_by_skill.values(), reverse=True)[:5]
    return min(1.0, sum(vals) / max(1, len(vals)) * 1.1)
