from fastapi import APIRouter

from ..models.schemas import ModelInfo
from ..services.model_discovery import discover_models

router = APIRouter(prefix="/models", tags=["models"])


@router.get("", response_model=list[ModelInfo])
async def list_models(provider_id: str | None = None):
    return await discover_models(provider_id)
