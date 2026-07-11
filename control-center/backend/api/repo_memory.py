"""Repository Memory API — code index and engineering context."""

from fastapi import APIRouter

from ..services import repo_memory

router = APIRouter(tags=["repo-memory"])


@router.get("/repo/summary")
async def repo_summary():
    return repo_memory.build_summary()


@router.get("/repo/classes")
async def repo_classes():
    return repo_memory.index_classes(repo_memory.get_settings().hydra_root)


@router.get("/repo/functions")
async def repo_functions():
    return repo_memory.index_functions(repo_memory.get_settings().hydra_root)


@router.get("/repo/modules")
async def repo_modules():
    return repo_memory.index_modules(repo_memory.get_settings().hydra_root)


@router.get("/repo/apis")
async def repo_apis():
    return repo_memory.index_apis(repo_memory.get_settings().hydra_root)


@router.get("/repo/dependencies")
async def repo_dependencies():
    return repo_memory.index_dependencies(repo_memory.get_settings().hydra_root)


@router.get("/repo/imports")
async def repo_imports():
    return repo_memory.index_imports(repo_memory.get_settings().hydra_root)


@router.get("/repo/full")
async def repo_full_index():
    return repo_memory.build_full_index()
