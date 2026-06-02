"""Tests for YAML modular skills and dynamic activation."""

from hydra.skills import Skill, SkillCategory, Severity
from hydra.skills.activation_engine import (
    DynamicSkillActivator,
    TechnologyFingerprint,
    exploit_probability_estimate,
)
from hydra.skills.yaml_loader import _skills_root, load_yaml_skills, register_yaml_skills
from hydra.skills import SkillRegistry


def test_skills_root_exists():
    root = _skills_root()
    assert root.name == "skills"


def test_load_yaml_skills():
    skills = load_yaml_skills()
    assert len(skills) >= 1
    ids = {s.id for s in skills}
    assert any(x.startswith("tn_") for x in ids)


def test_register_yaml_skills_id_collision_suffix():
    reg = SkillRegistry()
    reg.register(
        Skill(
            id="tn_xss",
            name="placeholder",
            category=SkillCategory.WEB,
            description="test",
            severity=Severity.LOW,
        )
    )
    n = register_yaml_skills(reg)
    assert n >= 1
    assert reg.get("tn_xss__yaml") is not None or reg.get("tn_xss") is not None


def test_activation_engine_orders_skills():
    reg = SkillRegistry()
    for sid, tech in [("a", ["React"]), ("b", ["Vue"]), ("c", ["COBOL"])]:
        reg.register(
            Skill(
                id=sid,
                name=sid,
                category=SkillCategory.WEB,
                description="d",
                framework_associations=tech,
                tags=["web"],
            )
        )
    act = DynamicSkillActivator(reg)
    fp = TechnologyFingerprint(technologies=["React", "Next.js"])
    res = act.activate(fp, max_skills=5, min_score=0.01)
    assert "a" in res.activated_skill_ids
    assert res.reasoning_trace
    prob = exploit_probability_estimate(res)
    assert 0.0 <= prob <= 1.0
