"""Repository Memory — AST-based repo indexing for engineering context."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from ..core.config import get_settings


def _walk_py(root: Path, max_files: int = 500) -> list[Path]:
    files = []
    for p in root.rglob("*.py"):
        if any(skip in p.parts for skip in (
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "env", ".tox", ".mypy_cache", "dist", "build", ".next",
        )):
            continue
        files.append(p)
        if len(files) >= max_files:
            break
    return files


def _safe_parse(path: Path) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(errors="replace"))
    except Exception:
        return None


def index_classes(root: Path) -> list[dict[str, Any]]:
    results = []
    for path in _walk_py(root):
        tree = _safe_parse(path)
        if not tree:
            continue
        rel = str(path.relative_to(root))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = [
                    n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                bases = []
                for b in node.bases:
                    if isinstance(b, ast.Name):
                        bases.append(b.id)
                    elif isinstance(b, ast.Attribute):
                        bases.append(ast.dump(b))
                results.append({
                    "name": node.name,
                    "file": rel,
                    "line": node.lineno,
                    "bases": bases,
                    "methods": methods,
                    "method_count": len(methods),
                })
    return results


def index_functions(root: Path) -> list[dict[str, Any]]:
    results = []
    for path in _walk_py(root):
        tree = _safe_parse(path)
        if not tree:
            continue
        rel = str(path.relative_to(root))
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [a.arg for a in node.args.args if a.arg != "self"]
                results.append({
                    "name": node.name,
                    "file": rel,
                    "line": node.lineno,
                    "args": args,
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                    "decorators": [
                        ast.dump(d) for d in node.decorator_list
                    ][:3],
                })
    return results


def index_modules(root: Path) -> list[dict[str, Any]]:
    modules = []
    for init in root.rglob("__init__.py"):
        if any(skip in init.parts for skip in (
            "node_modules", ".git", "__pycache__", ".venv", "venv",
        )):
            continue
        pkg = init.parent
        rel = str(pkg.relative_to(root))
        py_files = [f.stem for f in pkg.glob("*.py") if f.stem != "__init__"]
        sub_pkgs = [d.name for d in pkg.iterdir() if d.is_dir() and (d / "__init__.py").exists()]
        modules.append({
            "name": rel.replace("/", "."),
            "path": rel,
            "files": py_files[:20],
            "sub_packages": sub_pkgs[:20],
            "file_count": len(py_files),
        })
    return modules


def index_apis(root: Path) -> list[dict[str, Any]]:
    """Detect FastAPI/Flask route definitions."""
    apis = []
    route_re = re.compile(
        r'@\w+\.(get|post|put|patch|delete|options|head)\s*\(\s*["\']([^"\']+)',
        re.IGNORECASE,
    )
    for path in _walk_py(root):
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for match in route_re.finditer(content):
            method = match.group(1).upper()
            endpoint = match.group(2)
            line = content[: match.start()].count("\n") + 1
            apis.append({
                "method": method,
                "endpoint": endpoint,
                "file": rel,
                "line": line,
            })
    return apis


def index_dependencies(root: Path) -> dict[str, list[str]]:
    deps: dict[str, list[str]] = {}

    req = root / "requirements.txt"
    if req.exists():
        deps["python"] = [
            line.strip().split("==")[0].split(">=")[0].split("<=")[0].split("[")[0]
            for line in req.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            deps["node"] = list(data.get("dependencies", {}).keys())
            deps["node_dev"] = list(data.get("devDependencies", {}).keys())
        except Exception:
            pass

    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        try:
            content = setup_cfg.read_text()
            in_deps = False
            cfg_deps = []
            for line in content.splitlines():
                if "install_requires" in line:
                    in_deps = True
                    continue
                if in_deps:
                    stripped = line.strip()
                    if not stripped or (not stripped[0].isalpha() and stripped[0] != "-"):
                        break
                    cfg_deps.append(stripped.split(">=")[0].split("==")[0])
            if cfg_deps:
                deps["python_setup"] = cfg_deps
        except Exception:
            pass

    return deps


def index_imports(root: Path) -> dict[str, list[str]]:
    """Map each module to its imports (for architecture graph)."""
    import_map: dict[str, list[str]] = {}
    for path in _walk_py(root):
        tree = _safe_parse(path)
        if not tree:
            continue
        rel = str(path.relative_to(root))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        if imports:
            import_map[rel] = sorted(imports)
    return import_map


def detect_architecture(root: Path) -> dict[str, Any]:
    """Detect architectural patterns in the repo."""
    patterns = []
    services = []
    frameworks = []

    if (root / "docker-compose.yml").exists() or (root / "docker-compose.yaml").exists():
        patterns.append("microservices")
    if (root / "Dockerfile").exists():
        patterns.append("containerized")
    if any(root.rglob("*.proto")):
        patterns.append("grpc")
    if (root / "mcp_server.py").exists():
        patterns.append("mcp")
        frameworks.append("MCP")

    for init in root.rglob("__init__.py"):
        pkg_name = init.parent.name
        if pkg_name in ("api", "routes", "views", "endpoints"):
            patterns.append("api-layer")
        if pkg_name in ("services", "service"):
            patterns.append("service-layer")
        if pkg_name in ("models", "schemas"):
            patterns.append("data-layer")

    if (root / "hydra").is_dir():
        services.append("hydra-core")
        for sub in (root / "hydra").iterdir():
            if sub.is_dir() and (sub / "__init__.py").exists():
                services.append(f"hydra.{sub.name}")

    dc = root / "docker-compose.yml"
    if dc.exists():
        try:
            content = dc.read_text()
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.endswith(":") and not stripped.startswith("#") and not stripped.startswith("-"):
                    svc = stripped.rstrip(":")
                    if svc not in ("services", "volumes", "networks", "version"):
                        services.append(f"docker:{svc}")
        except Exception:
            pass

    return {
        "patterns": sorted(set(patterns)),
        "services": services[:50],
        "frameworks": frameworks,
    }


def build_full_index(root: Path | None = None) -> dict[str, Any]:
    if root is None:
        root = get_settings().hydra_root
    return {
        "classes": index_classes(root),
        "functions": index_functions(root),
        "modules": index_modules(root),
        "apis": index_apis(root),
        "dependencies": index_dependencies(root),
        "imports": index_imports(root),
        "architecture": detect_architecture(root),
        "stats": {
            "class_count": len(index_classes(root)),
            "function_count": len(index_functions(root)),
            "module_count": len(index_modules(root)),
            "api_count": len(index_apis(root)),
        },
    }


def build_summary(root: Path | None = None) -> dict[str, Any]:
    """Lightweight summary without full AST walk."""
    if root is None:
        root = get_settings().hydra_root

    py_files = list(_walk_py(root))
    modules = index_modules(root)
    deps = index_dependencies(root)
    arch = detect_architecture(root)
    apis = index_apis(root)

    return {
        "file_count": len(py_files),
        "module_count": len(modules),
        "api_count": len(apis),
        "dependency_count": sum(len(v) for v in deps.values()),
        "architecture": arch,
        "top_modules": [m["name"] for m in modules[:15]],
        "dependencies": {k: v[:10] for k, v in deps.items()},
    }
