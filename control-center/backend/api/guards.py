"""Guard Skills API — quality gate pipeline."""

from fastapi import APIRouter, Query

from ..services import guard_pipeline

router = APIRouter(tags=["guards"])


@router.post("/guards/run")
async def run_guards(guards: list[str] | None = Query(default=None)):
    return guard_pipeline.run_pipeline(guards=guards)


@router.get("/guards/list")
async def list_guards():
    return {
        "guards": guard_pipeline.GUARD_ORDER,
        "count": len(guard_pipeline.GUARD_ORDER),
    }
