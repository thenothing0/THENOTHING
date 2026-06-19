"""Signed Skills 2.0: multi-format, signing/trust, overrides, SemVer deps."""

import pytest

from hydra.skill_registry import (
    DependencyError,
    SignedSkillRegistry,
    TrustLevel,
    parse_manifest,
    sign_skill,
    verify_skill,
)
from hydra.skill_registry.manifest import SkillManifest

MD = """---
id: jwt
name: JWT Testing
category: auth
version: 2.1.0
allowed-tools: [http, shell]
requires:
  - skill: recon
    range: ">=1.0.0"
---
# JWT Testing
Algorithm confusion, kid abuse, weak secrets.
"""

JSON = '{"id":"recon","name":"Recon","category":"recon","version":"1.2.0","body":"map surface"}'
YAML = "id: ssrf\nname: SSRF\ncategory: web\nversion: 1.0.0\nallowed_tools: [http]\n"


# ── multi-format ──
def test_parse_markdown_frontmatter():
    m = parse_manifest(MD, "md")
    assert m.id == "jwt" and m.version == "2.1.0"
    assert m.allowed_tools == ["http", "shell"]
    assert m.requires == [{"skill": "recon", "range": ">=1.0.0"}]
    assert "Algorithm confusion" in m.body


def test_parse_json_and_yaml():
    assert parse_manifest(JSON, "json").id == "recon"
    assert parse_manifest(YAML, "yaml").allowed_tools == ["http"]


# ── signing / trust ──
def test_sign_and_verify_trusted():
    m = parse_manifest(YAML, "yaml", source="marketplace")
    m.signature = sign_skill(m, "alice", "s3cret")
    m.signer = "alice"
    assert verify_skill(m, keyring={"alice": "s3cret"}) == TrustLevel.SIGNED_TRUSTED


def test_tampered_body_invalidates_signature():
    m = parse_manifest(YAML, "yaml", source="marketplace")
    m.signature = sign_skill(m, "alice", "s3cret")
    m.body = "evil injected methodology"          # tamper after signing
    assert verify_skill(m, keyring={"alice": "s3cret"}) == TrustLevel.INVALID


def test_unknown_signer_and_unsigned_sources():
    m = parse_manifest(YAML, "yaml", source="marketplace")
    m.signature = sign_skill(m, "bob", "k")
    assert verify_skill(m, keyring={"alice": "s3cret"}) == TrustLevel.SIGNED_UNKNOWN
    assert verify_skill(SkillManifest("a", "A", "web", source="builtin")) == TrustLevel.UNSIGNED_BUILTIN
    assert verify_skill(SkillManifest("a", "A", "web", source="project")) == TrustLevel.UNSIGNED_LOCAL


# ── overrides / shadow warning ──
def test_local_shadows_signed_builtin_warns():
    reg = SignedSkillRegistry(keyring={"core": "key"})
    builtin = parse_manifest(YAML, "yaml", source="builtin")
    builtin.signature = sign_skill(builtin, "core", "key")
    reg.add(builtin)
    local = parse_manifest(YAML, "yaml", source="project")   # same id, no sig
    reg.add(local)
    assert any("shadows a SIGNED builtin" in w for w in reg.warnings)
    assert reg.get("ssrf").source == "project"               # project wins precedence


def test_lower_precedence_ignored():
    reg = SignedSkillRegistry()
    reg.add(parse_manifest(YAML, "yaml", source="project"))
    res = reg.add(parse_manifest(YAML, "yaml", source="builtin"))  # lower precedence
    assert "ignored" in res["action"] and reg.get("ssrf").source == "project"


# ── dependencies ──
def test_dependency_resolution_order():
    reg = SignedSkillRegistry()
    reg.add(parse_manifest(JSON, "json"))   # recon 1.2.0
    reg.add(parse_manifest(MD, "md"))       # jwt requires recon >=1.0.0
    assert reg.resolve("jwt") == ["recon", "jwt"]


def test_version_mismatch_raises():
    reg = SignedSkillRegistry()
    recon = parse_manifest('{"id":"recon","name":"R","category":"recon","version":"0.9.0"}', "json")
    reg.add(recon)
    reg.add(parse_manifest(MD, "md"))       # needs recon >=1.0.0
    with pytest.raises(DependencyError):
        reg.resolve("jwt")


def test_cycle_detected():
    reg = SignedSkillRegistry()
    a = SkillManifest("a", "A", "web", requires=[{"skill": "b", "range": "*"}])
    b = SkillManifest("b", "B", "web", requires=[{"skill": "a", "range": "*"}])
    reg.add(a)
    reg.add(b)
    with pytest.raises(DependencyError):
        reg.resolve("a")


# ── trust-gated install ──
def test_marketplace_install_requires_signature():
    reg = SignedSkillRegistry(keyring={"alice": "s3cret"})
    m = parse_manifest(YAML, "yaml", source="marketplace")
    with pytest.raises(PermissionError):
        reg.install(m, require_signature=True)        # unsigned -> refused
    m.signature = sign_skill(m, "alice", "s3cret")
    assert reg.install(m, require_signature=True)["trust"] == TrustLevel.SIGNED_TRUSTED
