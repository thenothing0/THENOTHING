"""Detached skill signatures + trust-level computation.

Uses HMAC-SHA256 over the canonical manifest bytes (stdlib, deterministic, no new
deps). A keyring maps key-id → secret; a signature is `<key_id>:<hex_hmac>`. This
is a symmetric-key trust model suited to an operator/team marketplace; the design
isolates the crypto so it can later be swapped for asymmetric (minisign/cosign)
without touching the registry.
"""

from __future__ import annotations

import hmac
import os
from hashlib import sha256
from typing import Dict, Optional

from .manifest import SkillManifest, canonical_bytes


class TrustLevel:
    SIGNED_TRUSTED = "signed-trusted"      # valid signature by a trusted key
    SIGNED_UNKNOWN = "signed-unknown"      # valid-format sig, signer not in keyring
    UNSIGNED_BUILTIN = "unsigned-builtin"  # shipped with the platform
    UNSIGNED_LOCAL = "unsigned-local"      # operator/project authored, no sig
    INVALID = "invalid"                    # signature present but does NOT verify

# Ordering for "is at least as trusted as" comparisons.
_RANK = {
    TrustLevel.INVALID: 0,
    TrustLevel.UNSIGNED_LOCAL: 1,
    TrustLevel.UNSIGNED_BUILTIN: 2,
    TrustLevel.SIGNED_UNKNOWN: 3,
    TrustLevel.SIGNED_TRUSTED: 4,
}


def trust_rank(level: str) -> int:
    return _RANK.get(level, 0)


def _keyring(keyring: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Resolve the keyring. Env var HYDRA_SKILL_KEYS holds 'id1=secret1,id2=secret2'."""
    if keyring is not None:
        return keyring
    out: Dict[str, str] = {}
    raw = os.environ.get("HYDRA_SKILL_KEYS", "")
    for pair in raw.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def sign_skill(manifest: SkillManifest, key_id: str, secret: str) -> str:
    """Return a detached signature string `<key_id>:<hex>` for the manifest."""
    mac = hmac.new(secret.encode(), canonical_bytes(manifest), sha256).hexdigest()
    return f"{key_id}:{mac}"


def verify_skill(manifest: SkillManifest, keyring: Optional[Dict[str, str]] = None) -> str:
    """Compute the TrustLevel of `manifest` against a keyring.

    A present signature is verified (constant-time) against the named key. Unknown
    signer (valid format, key not held) is SIGNED_UNKNOWN; a non-verifying sig is
    INVALID. No signature → builtin/local by source.
    """
    sig = manifest.signature.strip()
    if not sig:
        return (TrustLevel.UNSIGNED_BUILTIN if manifest.source == "builtin"
                else TrustLevel.UNSIGNED_LOCAL)
    if ":" not in sig:
        return TrustLevel.INVALID
    key_id, mac = sig.split(":", 1)
    ring = _keyring(keyring)
    secret = ring.get(key_id)
    if secret is None:
        return TrustLevel.SIGNED_UNKNOWN          # well-formed sig, signer not trusted here
    expected = hmac.new(secret.encode(), canonical_bytes(manifest), sha256).hexdigest()
    return TrustLevel.SIGNED_TRUSTED if hmac.compare_digest(expected, mac) else TrustLevel.INVALID


def trust_level(manifest: SkillManifest, keyring: Optional[Dict[str, str]] = None) -> str:
    """Alias for verify_skill (reads better at call sites)."""
    return verify_skill(manifest, keyring)
