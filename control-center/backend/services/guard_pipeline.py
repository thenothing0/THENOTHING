"""Guard Skills — quality gate pipeline for engineering tasks."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from typing import Any

from ..core.config import get_settings


class GuardResult:
    def __init__(self, name: str, status: str, issues: list[dict], score: int = 100):
        self.name = name
        self.status = status  # pass | warn | fail
        self.issues = issues
        self.score = score

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "issues": self.issues,
            "score": self.score,
            "issue_count": len(self.issues),
        }


def _walk_py(root: Path, max_files: int = 200) -> list[Path]:
    files = []
    for p in root.rglob("*.py"):
        if any(s in p.parts for s in ("node_modules", ".git", "__pycache__", ".venv", "venv", ".next")):
            continue
        files.append(p)
        if len(files) >= max_files:
            break
    return files


def clean_code_guard(files: list[Path], root: Path) -> GuardResult:
    issues = []
    for path in files[:100]:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            if len(line) > 200:
                issues.append({"file": rel, "line": i, "msg": f"Line too long ({len(line)} chars)"})
            if "TODO" in line or "FIXME" in line or "HACK" in line:
                issues.append({"file": rel, "line": i, "msg": f"Marker: {line.strip()[:80]}"})
        if len(lines) > 500:
            issues.append({"file": rel, "line": 0, "msg": f"Large file ({len(lines)} lines)"})
    score = max(0, 100 - len(issues) * 2)
    return GuardResult("clean_code", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:30], score)


def security_guard(files: list[Path], root: Path) -> GuardResult:
    issues = []
    patterns = [
        (re.compile(r'exec\s*\('), "exec() usage"),
        (re.compile(r'eval\s*\('), "eval() usage"),
        (re.compile(r'subprocess\.call\s*\(.*shell\s*=\s*True'), "shell=True in subprocess"),
        (re.compile(r'pickle\.loads?\s*\('), "pickle deserialization"),
        (re.compile(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{4,}'), "hardcoded secret candidate"),
        (re.compile(r'verify\s*=\s*False'), "SSL verification disabled"),
        (re.compile(r'__import__\s*\('), "dynamic import"),
    ]
    for path in files[:100]:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for pat, msg in patterns:
            for match in pat.finditer(content):
                line = content[:match.start()].count("\n") + 1
                issues.append({"file": rel, "line": line, "msg": msg})
    score = max(0, 100 - len(issues) * 5)
    return GuardResult("security", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:30], score)


def architecture_guard(root: Path) -> GuardResult:
    issues = []
    from . import repo_memory
    modules = repo_memory.index_modules(root)
    import_map = repo_memory.index_imports(root)

    circular = set()
    for file_a, imports_a in import_map.items():
        mod_a = file_a.replace("/", ".").replace(".py", "")
        for file_b, imports_b in import_map.items():
            if file_a == file_b:
                continue
            mod_b = file_b.replace("/", ".").replace(".py", "")
            base_a = mod_a.split(".")[0]
            base_b = mod_b.split(".")[0]
            if base_a in imports_b and base_b in imports_a:
                pair = tuple(sorted([base_a, base_b]))
                if pair not in circular:
                    circular.add(pair)
                    issues.append({"file": "", "line": 0, "msg": f"Potential circular import: {pair[0]} <-> {pair[1]}"})

    for mod in modules:
        if mod["file_count"] > 30:
            issues.append({"file": mod["path"], "line": 0, "msg": f"Large package ({mod['file_count']} files)"})

    score = max(0, 100 - len(issues) * 3)
    return GuardResult("architecture", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:20], score)


def performance_guard(files: list[Path], root: Path) -> GuardResult:
    issues = []
    patterns = [
        (re.compile(r'time\.sleep\s*\(\s*(\d+)'), "sleep() call"),
        (re.compile(r'for .+ in .+:\s*\n\s+for .+ in'), "nested loop"),
        (re.compile(r'\.readlines\s*\(\s*\)'), "readlines() loads entire file"),
    ]
    for path in files[:100]:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for pat, msg in patterns:
            for match in pat.finditer(content):
                line = content[:match.start()].count("\n") + 1
                issues.append({"file": rel, "line": line, "msg": msg})
    score = max(0, 100 - len(issues) * 2)
    return GuardResult("performance", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:20], score)


def compatibility_guard(root: Path) -> GuardResult:
    issues = []
    req = root / "requirements.txt"
    if not req.exists():
        issues.append({"file": "", "line": 0, "msg": "No requirements.txt found"})

    setup = root / "setup.py"
    setup_cfg = root / "setup.cfg"
    pyproject = root / "pyproject.toml"
    if not (setup.exists() or setup_cfg.exists() or pyproject.exists()):
        issues.append({"file": "", "line": 0, "msg": "No package configuration (setup.py/pyproject.toml)"})

    score = max(0, 100 - len(issues) * 10)
    return GuardResult("compatibility", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:10], score)


def mcp_guard(root: Path) -> GuardResult:
    issues = []
    mcp_server = root / "mcp_server.py"
    if not mcp_server.exists():
        issues.append({"file": "", "line": 0, "msg": "No mcp_server.py found"})
    else:
        content = mcp_server.read_text(errors="replace")
        tool_count = content.count("@mcp.tool") + content.count("@server.tool") + content.count("def tool_")
        if tool_count == 0:
            issues.append({"file": "mcp_server.py", "line": 0, "msg": "No MCP tools detected"})

    mcp_json = root / ".mcp.json"
    if not mcp_json.exists():
        issues.append({"file": "", "line": 0, "msg": "No .mcp.json config found"})

    score = max(0, 100 - len(issues) * 15)
    return GuardResult("mcp", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:10], score)


def runtime_guard(root: Path) -> GuardResult:
    issues = []
    dc = root / "docker-compose.yml"
    if dc.exists():
        content = dc.read_text(errors="replace")
        if "restart:" not in content:
            issues.append({"file": "docker-compose.yml", "line": 0, "msg": "No restart policy"})
        if "healthcheck:" not in content:
            issues.append({"file": "docker-compose.yml", "line": 0, "msg": "No healthcheck configured"})

    dockerfile = root / "Dockerfile"
    if dockerfile.exists():
        content = dockerfile.read_text(errors="replace")
        if "USER" not in content:
            issues.append({"file": "Dockerfile", "line": 0, "msg": "No non-root USER directive"})

    score = max(0, 100 - len(issues) * 10)
    return GuardResult("runtime", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:10], score)


def knowledge_guard(root: Path) -> GuardResult:
    issues = []
    wiki = root / "wiki"
    if not wiki.is_dir():
        issues.append({"file": "", "line": 0, "msg": "No wiki/ directory"})
    else:
        md_count = len(list(wiki.rglob("*.md")))
        if md_count < 5:
            issues.append({"file": "wiki/", "line": 0, "msg": f"Sparse knowledge base ({md_count} pages)"})

    score = max(0, 100 - len(issues) * 15)
    return GuardResult("knowledge", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:10], score)


def documentation_guard(files: list[Path], root: Path) -> GuardResult:
    issues = []
    readme = root / "README.md"
    if not readme.exists():
        issues.append({"file": "", "line": 0, "msg": "No README.md"})

    undocumented_classes = 0
    for path in files[:80]:
        tree_ast = None
        try:
            tree_ast = ast.parse(path.read_text(errors="replace"))
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for node in ast.walk(tree_ast):
            if isinstance(node, ast.ClassDef):
                if not (node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, (ast.Constant, ast.Str))):
                    undocumented_classes += 1

    if undocumented_classes > 20:
        issues.append({"file": "", "line": 0, "msg": f"{undocumented_classes} classes without docstrings"})

    score = max(0, 100 - len(issues) * 10)
    return GuardResult("documentation", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:10], score)


def test_guard(root: Path) -> GuardResult:
    issues = []
    test_files = list(root.rglob("test_*.py")) + list(root.rglob("*_test.py"))
    test_files = [t for t in test_files if ".git" not in t.parts and "__pycache__" not in t.parts]

    if len(test_files) == 0:
        issues.append({"file": "", "line": 0, "msg": "No test files found"})
    elif len(test_files) < 5:
        issues.append({"file": "", "line": 0, "msg": f"Low test coverage ({len(test_files)} test files)"})

    score = max(0, 100 - len(issues) * 20)
    return GuardResult("test", "pass" if score >= 80 else "warn" if score >= 50 else "fail", issues[:10], score)


GUARD_ORDER = [
    "clean_code",
    "architecture",
    "security",
    "performance",
    "compatibility",
    "mcp",
    "runtime",
    "knowledge",
    "documentation",
    "test",
]


def run_pipeline(root: Path | None = None, guards: list[str] | None = None) -> dict[str, Any]:
    if root is None:
        root = get_settings().hydra_root

    selected = guards or GUARD_ORDER
    py_files = _walk_py(root)
    results: list[dict] = []

    for guard_name in selected:
        if guard_name not in GUARD_ORDER:
            continue
        try:
            if guard_name == "clean_code":
                r = clean_code_guard(py_files, root)
            elif guard_name == "security":
                r = security_guard(py_files, root)
            elif guard_name == "architecture":
                r = architecture_guard(root)
            elif guard_name == "performance":
                r = performance_guard(py_files, root)
            elif guard_name == "compatibility":
                r = compatibility_guard(root)
            elif guard_name == "mcp":
                r = mcp_guard(root)
            elif guard_name == "runtime":
                r = runtime_guard(root)
            elif guard_name == "knowledge":
                r = knowledge_guard(root)
            elif guard_name == "documentation":
                r = documentation_guard(py_files, root)
            elif guard_name == "test":
                r = test_guard(root)
            else:
                continue
            results.append(r.to_dict())
        except Exception as exc:
            results.append({"name": guard_name, "status": "error", "issues": [{"file": "", "line": 0, "msg": str(exc)}], "score": 0, "issue_count": 1})

    overall_score = int(sum(r["score"] for r in results) / max(len(results), 1))
    passed = sum(1 for r in results if r["status"] == "pass")
    warned = sum(1 for r in results if r["status"] == "warn")
    failed = sum(1 for r in results if r["status"] in ("fail", "error"))

    return {
        "guards": results,
        "overall_score": overall_score,
        "overall_status": "pass" if failed == 0 and warned == 0 else "warn" if failed == 0 else "fail",
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "total": len(results),
        "available_guards": GUARD_ORDER,
    }
