"""
Cached/fixture source adapter — the offline backbone.

Reads previously-captured ("cached evidence") source output from disk so the
fusion pipeline runs with no network. Layout (one asset value per line):

    <base>/<source-key>/<domain>.txt

where <source-key> is tried as the source id-slug, then the display name, then
the raw id. <base> defaults to `output/recon_cache/` and
`tests/_doubles/fixtures/recon/` (so both real cached evidence and test
fixtures work without configuration).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence

from hydra.capabilities.sources import Source

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _default_dirs() -> List[Path]:
    dirs: List[Path] = []
    env = os.environ.get("HYDRA_RECON_FIXTURES")
    if env:
        dirs.append(Path(env))
    dirs.append(_REPO_ROOT / "output" / "recon_cache")
    dirs.append(_REPO_ROOT / "tests" / "_doubles" / "fixtures" / "recon")
    return dirs


def collect(source: Source, domain: str,
            fixtures_dirs: Optional[Sequence[Path]] = None) -> List[str]:
    if not domain:
        return []
    bases = [Path(d) for d in fixtures_dirs] if fixtures_dirs else _default_dirs()
    keys = [source.id.replace("source.", ""), source.name, source.id]
    for base in bases:
        for key in keys:
            f = base / key / f"{domain}.txt"
            if f.exists():
                return [ln.strip() for ln in f.read_text(encoding="utf-8").splitlines()
                        if ln.strip() and not ln.startswith("#")]
    return []
