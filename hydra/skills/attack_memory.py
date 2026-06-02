"""
Append-only attack memory + reasoning traces under `output/` for THENOTHING runs.

Persists lightweight JSONL for collaboration and post-run analysis. No secrets.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _output_dir(root: Optional[Path] = None) -> Path:
    base = root or Path(__file__).resolve().parents[2]
    out = base / "output"
    out.mkdir(parents=True, exist_ok=True)
    return out


def append_event(
    kind: str,
    payload: Dict[str, Any],
    *,
    root: Optional[Path] = None,
    filename: str = "attack_memory.jsonl",
) -> Path:
    """Append one JSON object line. Returns path written."""
    out = _output_dir(root)
    path = out / filename
    record = {"ts": time.time(), "kind": kind, **payload}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def append_reasoning_trace(
    target: str,
    trace: List[str],
    activated_skills: List[str],
    *,
    root: Optional[Path] = None,
) -> Path:
    return append_event(
        "reasoning_trace",
        {"target": target, "trace": trace, "activated_skills": activated_skills},
        root=root,
    )


def tail_events(max_lines: int = 50, *, root: Optional[Path] = None, filename: str = "attack_memory.jsonl") -> List[Dict[str, Any]]:
    path = _output_dir(root) / filename
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    rows: List[Dict[str, Any]] = []
    for line in lines[-max_lines:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
