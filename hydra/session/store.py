"""Session persistence, compaction, and resume-recap."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# The 11 structured sections a compaction summary fills (PentesterFlow parity).
MEMORY_SECTIONS = (
    "objectives", "plan", "completed", "target_scope", "decisions", "tested",
    "findings", "files", "commands", "credentials", "todos",
)
# Upper bound per list so a long engagement can't grow the checkpoint without
# limit; findings/credentials get a larger cap (losing an early finding is worse).
_LIST_CAP = 40
_BIG_LIST_CAP = 200
_BIG_LISTS = {"findings", "credentials"}


@dataclass
class SessionMemory:
    """Structured, compaction-built persistent memory for an engagement."""
    objectives: List[str] = field(default_factory=list)
    plan: List[str] = field(default_factory=list)
    completed: List[str] = field(default_factory=list)
    target_scope: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    tested: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    credentials: List[str] = field(default_factory=list)
    todos: List[str] = field(default_factory=list)
    compactions: int = 0
    last_compacted_at: str = ""

    def item_count(self) -> int:
        return sum(len(getattr(self, s)) for s in MEMORY_SECTIONS)


def _cap(section: str) -> int:
    return _BIG_LIST_CAP if section in _BIG_LISTS else _LIST_CAP


def _dedup_keep_recent(items: List[str], cap: int) -> List[str]:
    seen, out = set(), []
    for it in items:
        k = it.strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(it.strip())
    return out[-cap:]  # most-recent wins


def merge_memory(memory: Optional[SessionMemory], summary: str) -> SessionMemory:
    """Fold a freshly-produced compaction `summary` (Markdown with the standard
    headings) into the running memory, deduped + capped + redacted."""
    from hydra.safety import redact

    mem = memory or SessionMemory()
    parsed = _parse_sections(redact(summary))
    for section in MEMORY_SECTIONS:
        merged = getattr(mem, section) + parsed.get(section, [])
        setattr(mem, section, _dedup_keep_recent(merged, _cap(section)))
    mem.compactions += 1
    mem.last_compacted_at = _now()
    return mem


def _parse_sections(summary: str) -> Dict[str, List[str]]:
    """Parse a Markdown compaction summary into the section lists. Headings are
    matched loosely (case/punct-insensitive) to the canonical section names."""
    alias = {
        "current objective": "objectives", "objective": "objectives", "objectives": "objectives",
        "plan": "plan",
        "completed tasks": "completed", "completed": "completed",
        "target and scope": "target_scope", "target": "target_scope", "scope": "target_scope",
        "decisions and assumptions": "decisions", "decisions": "decisions",
        "tested surface": "tested", "tested": "tested",
        "findings and evidence": "findings", "findings": "findings",
        "files and commands": "files", "files": "files",
        "commands": "commands",
        "credentials and placeholders": "credentials", "credentials": "credentials",
        "open todos": "todos", "todos": "todos", "next best actions": "todos",
    }
    out: Dict[str, List[str]] = {s: [] for s in MEMORY_SECTIONS}
    current: Optional[str] = None
    for raw in summary.splitlines():
        line = raw.strip()
        if not line:
            continue
        heading = line.lstrip("#").strip().rstrip(":").lower()
        if line.startswith("#") or heading in alias:
            current = alias.get(heading)
            continue
        if current:
            out[current].append(line.lstrip("-*0123456789. ").strip())
    return out


def compact_messages(messages: List[Dict[str, str]], max_chars: int = 22_000) -> str:
    """Build the bounded user-content blob handed to the model for compaction.
    Keeps the tail (freshest work) when over budget; redacts secrets."""
    from hydra.safety import redact

    parts = [f"{m.get('role', '?')}: {m.get('content', '')}" for m in messages]
    blob = redact("\n".join(parts))
    return blob[-max_chars:] if len(blob) > max_chars else blob


def format_recap(memory: Optional[SessionMemory]) -> str:
    """Human-readable resume recap of persistent memory."""
    if not memory or memory.item_count() == 0:
        return "session memory is empty — nothing to recap."
    out = [f"Resume recap · {memory.compactions} compaction(s)"]
    if memory.last_compacted_at:
        out.append(f"Last compacted: {memory.last_compacted_at}")
    labels = {"objectives": "Objectives", "plan": "Plan", "findings": "Findings",
              "tested": "Tested surface", "todos": "Next / TODOs",
              "target_scope": "Target & scope"}
    for section, label in labels.items():
        items = getattr(memory, section)
        if items:
            out.append(f"\n{label}:")
            out.extend(f"  - {it}" for it in items[:8])
    return "\n".join(out)


class SessionStore:
    """Crash-safe JSON session persistence under a sessions directory."""

    def __init__(self, session_id: str, base_dir: str = ".thenothing/sessions"):
        self.session_id = session_id
        self._dir = Path(base_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / f"{session_id}.json"

    def exists(self) -> bool:
        return self._path.is_file()

    def save(self, messages: List[Dict[str, str]], memory: Optional[SessionMemory],
             target: str = "") -> None:
        from hydra.safety import redact

        payload = {
            "session_id": self.session_id,
            "target": target,
            "updated_at": _now(),
            "memory": asdict(memory) if memory else None,
            # Redact persisted transcript content (operator-secret boundary).
            "messages": [{**m, "content": redact(m.get("content", ""))} for m in messages],
        }
        # tmp + fsync + atomic rename = crash-safe (no torn writes on power loss).
        fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def load(self) -> Dict:
        if not self.exists():
            return {"messages": [], "memory": None, "target": ""}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        mem = data.get("memory")
        if mem:
            data["memory"] = SessionMemory(**{k: v for k, v in mem.items()
                                              if k in SessionMemory().__dict__})
        return data

    def clear(self) -> None:
        if self._path.exists():
            self._path.unlink()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
