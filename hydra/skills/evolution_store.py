"""
Persist per-skill evolution metrics to `output/skill_evolution.json`.

Pairs with SkillEvolver + YAML/code skills for long-run calibration.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from hydra.skills import SkillRegistry


def dump_registry_metrics(registry: SkillRegistry, *, root: Optional[Path] = None) -> Path:
    base = root or Path(__file__).resolve().parents[2]
    out = base / "output"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "skill_evolution.json"
    payload: Dict[str, Any] = {
        "updated": time.time(),
        "skills": {},
    }
    for sk in registry.all_skills():
        payload["skills"][sk.id] = {
            "success_count": sk.success_count,
            "failure_count": sk.failure_count,
            "false_positive_count": sk.false_positive_count,
            "confidence_score": sk.confidence_score,
            "success_rate": sk.success_rate,
            "category": sk.category.value,
        }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_registry_metrics(registry: SkillRegistry, *, root: Optional[Path] = None) -> int:
    """Restore counters from disk. Returns number of skills updated."""
    base = root or Path(__file__).resolve().parents[2]
    path = base / "output" / "skill_evolution.json"
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return 0
    n = 0
    for sid, stats in (data.get("skills") or {}).items():
        sk = registry.get(sid)
        if not sk or not isinstance(stats, dict):
            continue
        sk.success_count = int(stats.get("success_count") or 0)
        sk.failure_count = int(stats.get("failure_count") or 0)
        sk.false_positive_count = int(stats.get("false_positive_count") or 0)
        sk.confidence_score = float(stats.get("confidence_score") or 0.5)
        n += 1
    return n
