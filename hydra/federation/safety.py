"""
Federation safety & protocol primitives (Phase N).

Centralizes the rules that make federation *metadata only*:

  * a deterministic id / canonical-JSON helper (rebuild-identical, idempotent ids),
  * semantic-version compatibility, and
  * `assert_safe()` — a recursive guard that REJECTS any payload carrying raw
    knowledge (wiki pages, evidence, findings, targets, source identities,
    secrets, exploit payloads). Enforced on BOTH export (generation) and import,
    so no canonical knowledge can ever cross the federation boundary.

Pure-python, offline, deterministic. Touches nothing canonical.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, List, Tuple

# Protocol the local node speaks; peers are compatible iff the MAJOR matches.
FEDERATION_PROTOCOL_VERSION = "1.0.0"
# Schema version stamped into every exported digest envelope.
DIGEST_SCHEMA_VERSION = "1.0.0"


class FederationSafetyError(ValueError):
    """Raised when a payload would leak raw/canonical knowledge across federation."""


# Exact keys that must never appear in any exchanged payload. These carry raw
# knowledge or source-sensitive identity — federation exchanges aggregates only.
_FORBIDDEN_EXACT = frozenset({
    "wiki", "wiki_page", "page", "page_id", "page_body", "body",
    "evidence", "evidence_content", "evidence_body", "proof",
    "finding", "finding_id", "findings",
    "target", "targets", "host", "hostname", "url", "uri", "domain",
    "ip", "ip_address", "ipaddr",
    "vulnerability", "vuln", "vuln_detail",
    "report", "report_body", "writeup", "poc",
    "source_id", "source_ids",          # source identity disclosure is forbidden
    "secret", "credential", "credentials", "password", "token",
    "api_key", "apikey", "cookie", "email", "asset", "asset_id",
})

# Substrings that are forbidden anywhere in a key (catches *_secret, raw_*, …).
# NB: deliberately NOT "evidence" — `evidence_class`/`evidence_type` are abstract
# aggregate labels (no content), which federation is allowed to exchange.
_FORBIDDEN_SUBSTR: Tuple[str, ...] = (
    "secret", "credential", "password", "apikey", "api_key",
    "exploit_payload", "raw_", "_raw", "private_key",
)


def canonical_json(obj: Any) -> str:
    """Stable JSON (sorted keys, compact) → deterministic ids & rebuild-identical."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def deterministic_id(prefix: str, *parts: str) -> str:
    """A stable, collision-resistant id derived only from its inputs (no clock)."""
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:16]}"


def _key_is_forbidden(key: str) -> bool:
    k = str(key).strip().lower()
    if k in _FORBIDDEN_EXACT:
        return True
    return any(sub in k for sub in _FORBIDDEN_SUBSTR)


def scan_forbidden(payload: Any, path: str = "") -> List[str]:
    """Return the dotted paths of every forbidden key found (recursively)."""
    bad: List[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            here = f"{path}.{key}" if path else str(key)
            if _key_is_forbidden(key):
                bad.append(here)
            bad.extend(scan_forbidden(value, here))
    elif isinstance(payload, (list, tuple)):
        for i, value in enumerate(payload):
            bad.extend(scan_forbidden(value, f"{path}[{i}]"))
    return bad


def assert_safe(payload: Any, where: str = "payload") -> None:
    """Raise FederationSafetyError if `payload` carries any raw/canonical knowledge."""
    bad = scan_forbidden(payload)
    if bad:
        raise FederationSafetyError(
            f"{where} contains forbidden (non-metadata) keys: {sorted(bad)}")


def parse_semver(version: str) -> Tuple[int, int, int]:
    """Parse 'MAJOR.MINOR.PATCH' → (M,m,p). Raises ValueError on a non-semver string."""
    parts = str(version).strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"not a semantic version: {version!r}")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def semver_compatible(a: str, b: str = FEDERATION_PROTOCOL_VERSION) -> bool:
    """Two versions are federation-compatible iff their MAJOR component matches."""
    try:
        return parse_semver(a)[0] == parse_semver(b)[0]
    except ValueError:
        return False
