"""
Signed Skill Framework 2.0 (architecture spec Part 3).

Adds the trust layer PentesterFlow's skill system lacks, on top of THENOTHING's
existing YAML skills (`hydra/skills`):

  * **Multi-format load** — Markdown (frontmatter), YAML, JSON normalize to one
    canonical `SkillManifest`.
  * **Versioning + dependencies** — SemVer + `requires: [{skill, ">=1.2"}]`, with
    acyclic dependency resolution.
  * **Overrides** — discovery-order precedence (builtin < project < personal <
    extra), with a shadow WARNING when a local skill shadows a signed builtin
    (PF-3 mitigation).
  * **Signing + trust verification** — detached HMAC signature over the canonical
    manifest bytes; trust tiers (signed-trusted > signed-unknown > unsigned-builtin
    > unsigned-local). Marketplace installs MUST verify.

Deterministic, stdlib-only (hashlib/hmac), no execution — skills are data.
"""

from .manifest import (
    SkillManifest,
    canonical_bytes,
    load_manifest,
    parse_manifest,
)
from .registry import (
    DependencyError,
    SignedSkillRegistry,
    TrustLevel,
)
from .signing import sign_skill, trust_level, verify_skill

__all__ = [
    "SkillManifest",
    "parse_manifest",
    "load_manifest",
    "canonical_bytes",
    "SignedSkillRegistry",
    "TrustLevel",
    "DependencyError",
    "sign_skill",
    "verify_skill",
    "trust_level",
]
