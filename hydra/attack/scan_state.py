"""
Scan state / cross-run dedup (audit improvement #4 — derived, disposable).

At scale you re-run scans; without state you re-hit every endpoint every time. `ScanState` persists a
content-addressed key per scanned `(target, vuln_class, point)` to an append-only journal under
`output/` (rebuildable, disposable — never canonical knowledge). `seen()` lets `scan_many` SKIP
endpoints already scanned in a prior run (resume), and `mark()` records progress as it goes.

Opt-in (the workflow passes a `ScanState` only when `resume=True`), so default scans stay deterministic
and self-contained. Defensive: any I/O error degrades to "nothing seen" rather than failing the scan.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional, Set


def _key(target: str, vuln_class: str, point: str) -> str:
    raw = f"{(target or '').strip().lower()}|{(vuln_class or '').lower()}|{point or ''}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


class ScanState:
    def __init__(self, path: Optional[Path] = None, filename: str = "scan_state.jsonl"):
        if path is None:
            base = Path(__file__).resolve().parents[2] / "output"
            base.mkdir(parents=True, exist_ok=True)
            path = base / filename
        self.path = Path(path)
        self._seen: Set[str] = self._load()

    def _load(self) -> Set[str]:
        seen: Set[str] = set()
        try:
            if self.path.is_file():
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    try:
                        k = json.loads(line).get("key")
                        if k:
                            seen.add(k)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return seen

    def seen(self, target: str, vuln_class: str, point: str = "*") -> bool:
        return _key(target, vuln_class, point) in self._seen

    def mark(self, target: str, vuln_class: str, point: str = "*", verdict: str = "") -> None:
        k = _key(target, vuln_class, point)
        if k in self._seen:
            return
        self._seen.add(k)
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"key": k, "target": target, "vuln_class": vuln_class,
                                     "point": point, "verdict": verdict}) + "\n")
        except OSError:
            pass

    def __len__(self) -> int:
        return len(self._seen)
