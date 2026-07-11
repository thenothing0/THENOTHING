from fastapi import APIRouter, HTTPException

from ..models.schemas import ProviderCreate, ProviderOut, ProviderUpdate
from ..services import provider_store
from ..services.model_discovery import test_provider_connection

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get("", response_model=list[ProviderOut])
async def list_providers():
    return provider_store.list_providers()


@router.get("/{provider_id}", response_model=ProviderOut)
async def get_provider(provider_id: str):
    prov = provider_store.get_provider(provider_id)
    if not prov:
        raise HTTPException(404, "provider not found")
    return prov


@router.post("", response_model=ProviderOut, status_code=201)
async def create_provider(req: ProviderCreate):
    return provider_store.create_provider(req)


@router.patch("/{provider_id}", response_model=ProviderOut)
async def update_provider(provider_id: str, req: ProviderUpdate):
    prov = provider_store.update_provider(provider_id, req)
    if not prov:
        raise HTTPException(404, "provider not found")
    return prov


@router.delete("/{provider_id}")
async def delete_provider(provider_id: str):
    if not provider_store.delete_provider(provider_id):
        raise HTTPException(404, "provider not found")
    return {"deleted": True}


@router.post("/{provider_id}/test")
async def test_connection(provider_id: str):
    result = await test_provider_connection(provider_id)
    return result
