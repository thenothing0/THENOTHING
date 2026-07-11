import subprocess
from pathlib import Path

from fastapi import APIRouter

from ..core.config import get_settings
from ..models.schemas import DashboardStats
from ..services.repo_analyzer import get_dashboard_stats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def stats():
    return get_dashboard_stats()


@router.get("/health")
async def project_health():
    """Extended project health for Phase 2 dashboard panel."""
    root = get_settings().hydra_root

    # Git status
    git_info = {}
    try:
        for cmd, key in [
            (["git", "log", "--oneline", "-5"], "recent_commits"),
            (["git", "branch", "-a", "--no-color"], "branches"),
            (["git", "stash", "list"], "stashes"),
        ]:
            r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(root), timeout=5)
            git_info[key] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()][:10]
    except Exception:
        pass

    # Runtime health
    runtime = {"docker": "unknown", "mcp": "unknown"}
    try:
        r = subprocess.run(["docker", "compose", "ps", "--format", "json"], capture_output=True, text=True, cwd=str(root), timeout=5)
        runtime["docker"] = "running" if r.returncode == 0 and r.stdout.strip() else "stopped"
    except Exception:
        runtime["docker"] = "unavailable"

    mcp_server = root / "mcp_server.py"
    runtime["mcp"] = "available" if mcp_server.exists() else "missing"

    # Knowledge health
    wiki = root / "wiki"
    knowledge = {"status": "unavailable", "pages": 0}
    if wiki.is_dir():
        pages = list(wiki.rglob("*.md"))
        knowledge = {"status": "healthy", "pages": len(pages)}

    # Test discovery
    test_files = list(root.rglob("test_*.py")) + list(root.rglob("*_test.py"))
    test_files = [t for t in test_files if ".git" not in t.parts]

    return {
        "git": git_info,
        "runtime": runtime,
        "knowledge": knowledge,
        "tests": {"file_count": len(test_files)},
    }
