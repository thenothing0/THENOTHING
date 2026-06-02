"""
Load modular YAML skills from repository `skills/<category>/SKILL.yaml`.

Claude Code / THENOTHING: skills are data-first; execution is MCP-only at runtime.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from hydra.skills import (
    ExploitHypothesis,
    ReconStep,
    Skill,
    SkillCategory,
    SkillRegistry,
    Severity,
    ValidationRule,
)

logger = logging.getLogger("hydra.skills.yaml_loader")

# skills/<folder>/SKILL.yaml → canonical SkillCategory
_FOLDER_TO_CATEGORY: Dict[str, SkillCategory] = {
    "recon": SkillCategory.RECON,
    "web": SkillCategory.WEB,
    "api": SkillCategory.API,
    "graphql": SkillCategory.GRAPHQL,
    "oauth": SkillCategory.AUTH,
    "business_logic": SkillCategory.BUSINESS_LOGIC,
    "cloud": SkillCategory.CLOUD,
    "kubernetes": SkillCategory.KUBERNETES,
    "osint": SkillCategory.OSINT,
    "xss": SkillCategory.WEB,
    "sqli": SkillCategory.WEB,
    "ssrf": SkillCategory.WEB,
    "ssti": SkillCategory.WEB,
    "deserialization": SkillCategory.WEB,
    "auth": SkillCategory.AUTH,
    "race_conditions": SkillCategory.WEB,
    "ai_security": SkillCategory.AI_SECURITY,
    "mobile": SkillCategory.MOBILE,
    "browser": SkillCategory.FRONTEND,
    "javascript": SkillCategory.FRONTEND,
    "websocket": SkillCategory.FRONTEND,
    "cicd": SkillCategory.CICD,
    "containers": SkillCategory.KUBERNETES,
    "aws": SkillCategory.CLOUD,
    "azure": SkillCategory.CLOUD,
    "gcp": SkillCategory.CLOUD,
    "reporting": SkillCategory.REPORTING,
    "exploit_chains": SkillCategory.EXPLOIT_CHAINS,
    "validation": SkillCategory.VALIDATION,
    "stealth": SkillCategory.STEALTH,
    "opsec": SkillCategory.OPSEC,
}


def _skills_root() -> Path:
    return Path(__file__).resolve().parents[2] / "skills"


def _parse_severity(raw: Any) -> Severity:
    if isinstance(raw, Severity):
        return raw
    s = str(raw or "medium").lower()
    for sev in Severity:
        if sev.value == s:
            return sev
    return Severity.MEDIUM


def _parse_category(folder: str, yaml_cat: Any) -> SkillCategory:
    if yaml_cat:
        c = str(yaml_cat).lower()
        for member in SkillCategory:
            if member.value == c:
                return member
    return _FOLDER_TO_CATEGORY.get(folder.lower(), SkillCategory.WEB)


def _hypotheses(raw: Any) -> List[ExploitHypothesis]:
    out: List[ExploitHypothesis] = []
    if not raw:
        return out
    for i, h in enumerate(raw):
        if not isinstance(h, dict):
            continue
        hid = str(h.get("id") or f"h{i}")
        out.append(
            ExploitHypothesis(
                id=hid,
                title=str(h.get("title") or hid),
                description=str(h.get("description") or ""),
                preconditions=list(h.get("preconditions") or []),
                test_steps=list(h.get("test_steps") or h.get("steps") or []),
                payloads=list(h.get("payloads") or []),
                indicators=list(h.get("indicators") or []),
                severity=_parse_severity(h.get("severity")),
                confidence=float(h.get("confidence") or 0.5),
                cwe=str(h.get("cwe") or ""),
                owasp=str(h.get("owasp") or ""),
                chain_next=list(h.get("chain_next") or []),
            )
        )
    return out


def _validation_rules(raw: Any) -> List[ValidationRule]:
    out: List[ValidationRule] = []
    if not raw:
        return out
    if isinstance(raw, dict):
        # shorthand block from YAML `validation:`
        if raw.get("require_replay"):
            out.append(
                ValidationRule(
                    name="replay_required",
                    check_type="manual_replay",
                    expected=True,
                    confidence_boost=0.25,
                )
            )
        if raw.get("require_screenshot"):
            out.append(
                ValidationRule(
                    name="screenshot_evidence",
                    check_type="evidence_attachment",
                    expected="screenshot",
                    confidence_boost=0.15,
                )
            )
        for item in raw.get("rules") or []:
            if isinstance(item, dict):
                out.append(
                    ValidationRule(
                        name=str(item.get("name") or "rule"),
                        check_type=str(item.get("check_type") or "body_contains"),
                        expected=item.get("expected"),
                        confidence_boost=float(item.get("confidence_boost") or 0.1),
                        false_positive_indicators=list(item.get("false_positive_indicators") or []),
                    )
                )
        return out
    for i, item in enumerate(raw):
        if isinstance(item, dict):
            out.append(
                ValidationRule(
                    name=str(item.get("name") or f"rule_{i}"),
                    check_type=str(item.get("check_type") or "body_contains"),
                    expected=item.get("expected"),
                    confidence_boost=float(item.get("confidence_boost") or 0.1),
                    false_positive_indicators=list(item.get("false_positive_indicators") or []),
                )
            )
    return out


def _recon_from_mcp(mcp_tools: Any, objectives: Any) -> List[ReconStep]:
    steps: List[ReconStep] = []
    if not mcp_tools:
        return steps
    for i, tool in enumerate(mcp_tools):
        name = str(tool)
        steps.append(
            ReconStep(
                name=f"mcp_{name}_{i}",
                tool=name,
                command_template=name,
                parse_logic="parse_mcp_json_output",
                condition="",
                priority=min(1 + i // 2, 3),
            )
        )
    if objectives:
        for j, obj in enumerate(objectives):
            steps.append(
                ReconStep(
                    name=f"objective_{j}",
                    tool="",
                    parse_logic=str(obj),
                    condition="after_fingerprint",
                    priority=2,
                )
            )
    return steps


def yaml_document_to_skill(folder: str, data: Dict[str, Any]) -> Skill:
    """Map one YAML document to a hydra Skill."""
    sid = str(data.get("id") or data.get("name") or folder).replace(" ", "_").lower()
    name = str(data.get("name") or sid)
    category = _parse_category(folder, data.get("category"))
    desc = str(data.get("description") or data.get("summary") or "")

    objectives = list(data.get("objectives") or [])
    heuristics = list(data.get("reasoning_heuristics") or data.get("methodology") or [])
    if isinstance(data.get("methodology"), str):
        heuristics.insert(0, data["methodology"])

    tags = list(data.get("tags") or [])
    tags.append(folder)
    triggers = list(data.get("triggers") or [])
    for t in triggers:
        tags.append(f"trigger:{t}")

    technologies = list(data.get("technologies") or data.get("technology_fingerprints") or [])
    fp_list: List[Dict[str, str]] = []
    for tech in technologies:
        fp_list.append({"type": "technology", "value": str(tech)})

    conf_rules = data.get("confidence_rules") or {}
    min_conf = float(conf_rules.get("minimum_score") or 0.0)

    stealth = str(data.get("stealth_mode") or "")
    remediation = list(data.get("remediation") or [])
    if stealth:
        remediation.append(f"stealth_mode:{stealth}")

    report_bits = []
    rg = data.get("reporting_guidance")
    if isinstance(rg, list):
        report_bits.extend(str(x) for x in rg)
    elif isinstance(rg, str):
        report_bits.append(rg)
    evidence = list(data.get("evidence_requirements") or ["http_response", "reproduction_steps"])
    if conf_rules.get("minimum_score"):
        evidence.append(f"min_confidence:{min_conf}")

    branches = data.get("adaptive_branches") or {}
    false_positive = list(data.get("false_positive_reduction") or data.get("false_positives") or [])

    skill = Skill(
        id=sid,
        name=name,
        category=category,
        description=desc,
        version=str(data.get("version") or "1.0"),
        severity=_parse_severity(data.get("severity")),
        tags=list(dict.fromkeys(tags)),
        reasoning_heuristics=heuristics,
        fingerprints=fp_list,
        exploit_hypotheses=_hypotheses(data.get("exploit_hypotheses")),
        recon_steps=_recon_from_mcp(data.get("mcp_tools"), objectives),
        payloads=list(data.get("payload_strategies") or data.get("payloads") or []),
        payload_mutations=list(data.get("payload_mutations") or []),
        validation_rules=_validation_rules(data.get("validation")),
        evidence_requirements=evidence,
        false_positive_patterns=false_positive,
        chain_from=list(data.get("chain_from") or []),
        chain_to=list(data.get("chain_to") or []),
        framework_associations=technologies,
        report_template="\n".join(report_bits),
        remediation=remediation,
        references=list(data.get("references") or []),
        confidence_score=max(0.1, min(1.0, 0.5 + min_conf / 2)),
    )
    return skill


def iter_skill_yaml_files(root: Optional[Path] = None) -> Iterable[tuple[str, Path]]:
    base = root or _skills_root()
    if not base.is_dir():
        return
    for path in sorted(base.glob("*/SKILL.yaml")):
        folder = path.parent.name.lower()
        if folder.startswith("_") or folder == "archive":
            continue
        yield folder, path


def load_yaml_skills(root: Optional[Path] = None) -> List[Skill]:
    skills: List[Skill] = []
    base = root or _skills_root()
    if not base.is_dir():
        logger.warning("YAML skills root missing: %s", base)
        return skills
    for folder, path in iter_skill_yaml_files(base):
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) or {}
            if not isinstance(data, dict):
                logger.warning("Skip non-dict YAML: %s", path)
                continue
            skills.append(yaml_document_to_skill(folder, data))
        except Exception as exc:  # noqa: BLE001 — loader must not crash registry build
            logger.error("Failed to load skill YAML %s: %s", path, exc)
    return skills


def register_yaml_skills(registry: SkillRegistry, root: Optional[Path] = None) -> int:
    """Register all YAML skills onto an existing registry. Returns count added."""
    n = 0
    for skill in load_yaml_skills(root):
        if registry.get(skill.id):
            sid = skill.id
            skill.id = f"{sid}__yaml"
        registry.register(skill)
        n += 1
    logger.info("Registered %s YAML modular skills", n)
    return n
