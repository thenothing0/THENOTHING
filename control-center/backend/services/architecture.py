"""Architecture Intelligence — module graph, dependencies, runtime services."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.config import get_settings
from . import repo_memory


def build_graph(root: Path | None = None) -> dict[str, Any]:
    """Build the architecture graph for visualization."""
    if root is None:
        root = get_settings().hydra_root

    import_map = repo_memory.index_imports(root)
    modules = repo_memory.index_modules(root)
    arch = repo_memory.detect_architecture(root)

    nodes = []
    edges = []
    seen_nodes: set[str] = set()

    for mod in modules:
        name = mod["name"]
        if name not in seen_nodes:
            seen_nodes.add(name)
            nodes.append({
                "id": name,
                "type": "module",
                "file_count": mod["file_count"],
                "sub_packages": len(mod.get("sub_packages", [])),
            })

    for file_path, imports in import_map.items():
        source_mod = file_path.replace("/", ".").replace(".py", "").split(".")[0]
        for imp in imports:
            if imp in seen_nodes and source_mod in seen_nodes and imp != source_mod:
                edges.append({"source": source_mod, "target": imp, "type": "imports"})

    unique_edges = []
    edge_set: set[str] = set()
    for e in edges:
        key = f"{e['source']}->{e['target']}"
        if key not in edge_set:
            edge_set.add(key)
            unique_edges.append(e)

    return {
        "nodes": nodes,
        "edges": unique_edges,
        "node_count": len(nodes),
        "edge_count": len(unique_edges),
        "architecture": arch,
        "services": arch.get("services", []),
        "patterns": arch.get("patterns", []),
    }


def get_module_detail(module_name: str, root: Path | None = None) -> dict[str, Any]:
    if root is None:
        root = get_settings().hydra_root

    modules = repo_memory.index_modules(root)
    target = None
    for mod in modules:
        if mod["name"] == module_name or mod["path"] == module_name:
            target = mod
            break

    if not target:
        return {"error": f"Module {module_name} not found"}

    mod_path = root / target["path"]
    classes = []
    functions = []

    for cls in repo_memory.index_classes(root):
        if cls["file"].startswith(target["path"]):
            classes.append(cls)

    for fn in repo_memory.index_functions(root):
        if fn["file"].startswith(target["path"]):
            functions.append(fn)

    imports = {}
    full_imports = repo_memory.index_imports(root)
    for file_path, imps in full_imports.items():
        if file_path.startswith(target["path"]):
            imports[file_path] = imps

    return {
        "module": target,
        "classes": classes[:30],
        "functions": functions[:50],
        "imports": imports,
        "class_count": len(classes),
        "function_count": len(functions),
    }


def get_capabilities(root: Path | None = None) -> dict[str, Any]:
    """Discover runtime capabilities from the codebase."""
    if root is None:
        root = get_settings().hydra_root

    capabilities = []

    mcp_server = root / "mcp_server.py"
    if mcp_server.exists():
        capabilities.append({
            "name": "MCP Server",
            "type": "mcp",
            "file": "mcp_server.py",
            "status": "available",
        })

    hydra_dir = root / "hydra"
    if hydra_dir.is_dir():
        for sub in sorted(hydra_dir.iterdir()):
            if sub.is_dir() and (sub / "__init__.py").exists():
                capabilities.append({
                    "name": f"hydra.{sub.name}",
                    "type": "subsystem",
                    "file": str(sub.relative_to(root)),
                    "status": "available",
                })

    dc = root / "docker-compose.yml"
    if dc.exists():
        try:
            import re
            content = dc.read_text()
            in_services = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == "services:":
                    in_services = True
                    continue
                if in_services and not stripped.startswith("#"):
                    if stripped.endswith(":") and not line.startswith(" " * 4):
                        in_services = False
                        continue
                    if stripped.endswith(":") and line.startswith("  ") and not line.startswith("    "):
                        svc = stripped.rstrip(":")
                        capabilities.append({
                            "name": svc,
                            "type": "docker_service",
                            "file": "docker-compose.yml",
                            "status": "configured",
                        })
        except Exception:
            pass

    return {
        "capabilities": capabilities,
        "total": len(capabilities),
    }
