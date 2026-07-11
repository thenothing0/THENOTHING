"""Harness Engineering — unified engineering context builder."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.config import get_settings
from . import repo_analyzer, repo_memory, guard_pipeline


def activate(root: Path | None = None) -> dict[str, Any]:
    """Activate /harness — builds complete engineering context in one call."""
    if root is None:
        root = get_settings().hydra_root

    repo_stats = repo_analyzer.get_dashboard_stats(root)
    repo_summary = repo_memory.build_summary(root)
    arch = repo_memory.detect_architecture(root)
    apis = repo_memory.index_apis(root)
    deps = repo_memory.index_dependencies(root)
    guards = guard_pipeline.run_pipeline(root)

    tech_stack = repo_stats.get("tech_stack", [])
    active_task = _detect_active_task(root)

    return {
        "status": "active",
        "repository": {
            "name": repo_stats.get("repo_name", "unknown"),
            "branch": repo_stats.get("branch", "unknown"),
            "last_commit": repo_stats.get("last_commit", ""),
            "modified_files": repo_stats.get("modified_files", 0),
            "untracked_files": repo_stats.get("untracked_files", 0),
        },
        "tech_stack": tech_stack,
        "architecture": arch,
        "repo_memory": repo_summary,
        "apis": {
            "count": len(apis),
            "endpoints": apis[:20],
        },
        "dependencies": deps,
        "guards": guards,
        "active_task": active_task,
        "context_ready": True,
    }


def _detect_active_task(root: Path) -> dict[str, Any] | None:
    """Detect what the user is likely working on from git state."""
    import subprocess
    try:
        diff = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, cwd=str(root), timeout=5,
        )
        changed = [f for f in diff.stdout.strip().splitlines() if f]

        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True, cwd=str(root), timeout=5,
        )
        branch_name = branch.stdout.strip()

        if not changed and not branch_name:
            return None

        domains = set()
        for f in changed:
            parts = Path(f).parts
            if len(parts) > 1:
                domains.add(parts[0])

        return {
            "branch": branch_name,
            "changed_files": changed[:20],
            "changed_count": len(changed),
            "domains": sorted(domains),
            "inferred_task": _infer_task(branch_name, changed),
        }
    except Exception:
        return None


def _infer_task(branch: str, files: list[str]) -> str:
    if not branch:
        return "unknown"
    lower = branch.lower()
    if any(kw in lower for kw in ("fix", "bug", "hotfix", "patch")):
        return "bugfix"
    if any(kw in lower for kw in ("feat", "feature", "add")):
        return "feature"
    if any(kw in lower for kw in ("refactor", "cleanup", "clean")):
        return "refactor"
    if any(kw in lower for kw in ("test", "spec")):
        return "testing"
    if any(kw in lower for kw in ("doc", "readme")):
        return "documentation"
    if any(kw in lower for kw in ("ci", "cd", "deploy", "release")):
        return "devops"
    return "development"
