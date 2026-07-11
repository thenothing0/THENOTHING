from __future__ import annotations

import subprocess
from pathlib import Path

from ..core.config import get_settings


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            cwd=cwd or get_settings().hydra_root,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def git_branch() -> str:
    return _run(["git", "branch", "--show-current"])


def git_last_commit() -> str:
    return _run(["git", "log", "--oneline", "-1"])


def git_modified_count() -> int:
    out = _run(["git", "status", "--short"])
    modified = [l for l in out.splitlines() if l and l[0] in ("M", "A", "D", "R")]
    return len(modified)


def git_untracked_count() -> int:
    out = _run(["git", "status", "--short"])
    return sum(1 for l in out.splitlines() if l.startswith("??"))


def detect_tech_stack() -> list[str]:
    root = get_settings().hydra_root
    stack = []
    if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
        stack.append("Python")
    if (root / "package.json").exists():
        stack.append("Node.js")
    if (root / "Dockerfile").exists():
        stack.append("Docker")
    if (root / "docker-compose.yml").exists():
        stack.append("Docker Compose")
    if (root / "k8s").is_dir():
        stack.append("Kubernetes")
    if (root / "mcp_server.py").exists():
        stack.append("MCP")
    if (root / ".github" / "workflows").is_dir():
        stack.append("GitHub Actions")

    for name in ["FastAPI", "Pydantic", "aiohttp", "Redis", "PostgreSQL", "ChromaDB"]:
        req = root / "requirements.txt"
        if req.exists() and name.lower() in req.read_text().lower():
            stack.append(name)
    return stack


def count_hydra_subsystems() -> int:
    hydra = get_settings().hydra_root / "hydra"
    if not hydra.is_dir():
        return 0
    return sum(1 for d in hydra.iterdir() if d.is_dir() and not d.name.startswith("_"))


def count_mcp_tools() -> int:
    mcp = get_settings().hydra_root / "mcp_server.py"
    if not mcp.exists():
        return 0
    return mcp.read_text().count("@mcp.tool")


def get_dashboard_stats() -> dict:
    return {
        "repo_name": get_settings().hydra_root.name,
        "branch": git_branch(),
        "last_commit": git_last_commit(),
        "modified_files": git_modified_count(),
        "untracked_files": git_untracked_count(),
        "tech_stack": detect_tech_stack(),
        "mcp_tool_count": count_mcp_tools(),
        "hydra_subsystems": count_hydra_subsystems(),
        "runtime_status": "ready",
    }
