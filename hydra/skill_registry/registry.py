"""Signed skill registry: overrides, SemVer deps, trust-gated install."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .manifest import SkillManifest
from .signing import TrustLevel, trust_rank, verify_skill

# Discovery precedence: later sources override earlier on id collision.
SOURCE_ORDER = ("builtin", "marketplace", "personal", "project", "extra", "inline")


class DependencyError(RuntimeError):
    """Unsatisfied or cyclic skill dependency."""


class TrustLevelAlias:  # re-export for package __init__
    pass


class SignedSkillRegistry:
    def __init__(self, keyring: Optional[Dict[str, str]] = None,
                 min_trust: str = TrustLevel.UNSIGNED_LOCAL):
        self._skills: Dict[str, SkillManifest] = {}
        self._keyring = keyring
        self._min_trust = min_trust
        self.warnings: List[str] = []

    # ── registration with override semantics ─────────────────────────────────────
    def add(self, manifest: SkillManifest) -> Dict:
        """Register a manifest. Higher-precedence source overrides a lower one; a
        local skill shadowing a SIGNED builtin raises a warning (PF-3 mitigation)."""
        existing = self._skills.get(manifest.id)
        if existing is not None:
            new_rank = SOURCE_ORDER.index(_src(manifest.source))
            old_rank = SOURCE_ORDER.index(_src(existing.source))
            if new_rank < old_rank:
                return {"id": manifest.id, "action": "ignored (lower precedence)"}
            # Shadow warning: a local override of a signed builtin is suspicious.
            if (existing.source == "builtin"
                    and verify_skill(existing, self._keyring) == TrustLevel.SIGNED_TRUSTED
                    and manifest.source in ("project", "personal", "extra")):
                self.warnings.append(
                    f"skill '{manifest.id}' from {manifest.source} shadows a SIGNED builtin "
                    "— verify this override is intentional")
        self._skills[manifest.id] = manifest
        return {"id": manifest.id, "action": "registered", "source": manifest.source}

    def get(self, skill_id: str) -> Optional[SkillManifest]:
        return self._skills.get(skill_id)

    def names(self) -> List[str]:
        return sorted(self._skills)

    # ── trust ────────────────────────────────────────────────────────────────────
    def trust_of(self, skill_id: str) -> str:
        m = self._skills.get(skill_id)
        if not m:
            return TrustLevel.INVALID
        return verify_skill(m, self._keyring)

    def install(self, manifest: SkillManifest, require_signature: bool = False) -> Dict:
        """Trust-gated install. A marketplace install (require_signature=True) must
        be SIGNED_TRUSTED; otherwise the registry's min_trust floor applies."""
        level = verify_skill(manifest, self._keyring)
        if require_signature and level != TrustLevel.SIGNED_TRUSTED:
            raise PermissionError(
                f"refusing to install '{manifest.id}': trust={level}, signed-trusted required")
        if trust_rank(level) < trust_rank(self._min_trust):
            raise PermissionError(
                f"refusing to install '{manifest.id}': trust={level} below floor {self._min_trust}")
        res = self.add(manifest)
        res["trust"] = level
        return res

    # ── dependency resolution (SemVer) ───────────────────────────────────────────
    def resolve(self, skill_id: str) -> List[str]:
        """Topologically ordered dependency closure for `skill_id` (deps first).
        Raises DependencyError on a missing dep, version mismatch, or a cycle."""
        order: List[str] = []
        visiting: set = set()
        done: set = set()

        def visit(sid: str, chain: List[str]):
            if sid in done:
                return
            if sid in visiting:
                raise DependencyError(f"cyclic dependency: {' -> '.join(chain + [sid])}")
            m = self._skills.get(sid)
            if not m:
                raise DependencyError(f"missing skill '{sid}' (required by {chain[-1] if chain else '?'})")
            visiting.add(sid)
            for req in m.requires:
                dep = self._skills.get(req["skill"])
                if not dep:
                    raise DependencyError(f"'{sid}' requires missing skill '{req['skill']}'")
                if not _satisfies(dep.version, req["range"]):
                    raise DependencyError(
                        f"'{sid}' requires {req['skill']} {req['range']}, "
                        f"have {dep.version}")
                visit(req["skill"], chain + [sid])
            visiting.discard(sid)
            done.add(sid)
            order.append(sid)

        visit(skill_id, [])
        return order


def _src(source: str) -> str:
    return source if source in SOURCE_ORDER else "inline"


# ── minimal SemVer range satisfaction (>=, >, <=, <, ==, ^, ~, *) ─────────────────
_VER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def _parse_ver(v: str):
    m = _VER_RE.match(v.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)


def _satisfies(version: str, rng: str) -> bool:
    rng = (rng or "*").strip()
    if rng in ("*", "", "any"):
        return True
    ver = _parse_ver(version)
    for op in (">=", "<=", "==", ">", "<", "^", "~"):
        if rng.startswith(op):
            target = _parse_ver(rng[len(op):])
            if op == ">=":
                return ver >= target
            if op == "<=":
                return ver <= target
            if op == ">":
                return ver > target
            if op == "<":
                return ver < target
            if op == "==":
                return ver == target
            if op == "^":  # compatible: same major, >= target
                return ver[0] == target[0] and ver >= target
            if op == "~":  # same major.minor, >= target
                return ver[0] == target[0] and ver[1] == target[1] and ver >= target
    return _parse_ver(rng) == ver  # bare version == exact
