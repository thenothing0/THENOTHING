"""Harness Engineering API — unified /harness activation."""

from fastapi import APIRouter

from ..services import harness

router = APIRouter(tags=["harness"])


@router.post("/harness/activate")
async def activate_harness():
    return harness.activate()


@router.get("/harness/status")
async def harness_status():
    return {"status": "ready", "mode": "unified"}
