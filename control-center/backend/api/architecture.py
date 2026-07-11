"""Architecture Intelligence API — graph, modules, capabilities."""

from fastapi import APIRouter

from ..services import architecture

router = APIRouter(tags=["architecture"])


@router.get("/architecture/graph")
async def arch_graph():
    return architecture.build_graph()


@router.get("/architecture/module/{module_name:path}")
async def arch_module(module_name: str):
    return architecture.get_module_detail(module_name)


@router.get("/architecture/capabilities")
async def arch_capabilities():
    return architecture.get_capabilities()
