from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional

from ..core.config import get_settings
from ..core.security import decrypt_value, encrypt_value, mask_key
from ..models.schemas import ProviderCreate, ProviderOut, ProviderType, ProviderUpdate

_DEFAULT_URLS: dict[str, str] = {
    ProviderType.openai: "https://api.openai.com/v1",
    ProviderType.anthropic: "https://api.anthropic.com/v1",
    ProviderType.gemini: "https://generativelanguage.googleapis.com/v1beta",
    ProviderType.deepseek: "https://api.deepseek.com/v1",
    ProviderType.kimi: "https://api.moonshot.cn/v1",
    ProviderType.xai: "https://api.x.ai/v1",
    ProviderType.openrouter: "https://openrouter.ai/api/v1",
    ProviderType.groq: "https://api.groq.com/openai/v1",
    ProviderType.ollama: "http://localhost:11434",
    ProviderType.lmstudio: "http://localhost:1234/v1",
    ProviderType.vllm: "http://localhost:8000/v1",
    ProviderType.openai_compat: "",
}


def _store_path() -> Path:
    p = get_settings().data_dir / "providers.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load() -> dict:
    p = _store_path()
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _save(data: dict) -> None:
    _store_path().write_text(json.dumps(data, indent=2))


def list_providers() -> list[ProviderOut]:
    data = _load()
    result = []
    for pid, rec in data.items():
        result.append(ProviderOut(
            id=pid,
            name=rec["name"],
            type=rec["type"],
            base_url=rec["base_url"],
            api_key_masked=mask_key(decrypt_value(rec["api_key"])) if rec.get("api_key") else "",
            enabled=rec.get("enabled", True),
            is_local=rec.get("is_local", False),
        ))
    return result


def get_provider(provider_id: str) -> Optional[ProviderOut]:
    data = _load()
    rec = data.get(provider_id)
    if not rec:
        return None
    return ProviderOut(
        id=provider_id,
        name=rec["name"],
        type=rec["type"],
        base_url=rec["base_url"],
        api_key_masked=mask_key(decrypt_value(rec["api_key"])) if rec.get("api_key") else "",
        enabled=rec.get("enabled", True),
        is_local=rec.get("is_local", False),
    )


def get_provider_key(provider_id: str) -> str:
    data = _load()
    rec = data.get(provider_id)
    if not rec or not rec.get("api_key"):
        return ""
    return decrypt_value(rec["api_key"])


def create_provider(req: ProviderCreate) -> ProviderOut:
    data = _load()
    pid = str(uuid.uuid4())[:8]
    base_url = req.base_url or _DEFAULT_URLS.get(req.type, "")
    is_local = req.is_local or req.type in (
        ProviderType.ollama, ProviderType.lmstudio, ProviderType.vllm,
    )
    data[pid] = {
        "name": req.name,
        "type": req.type.value,
        "base_url": base_url,
        "api_key": encrypt_value(req.api_key) if req.api_key else "",
        "enabled": req.enabled,
        "is_local": is_local,
    }
    _save(data)
    return ProviderOut(
        id=pid,
        name=req.name,
        type=req.type,
        base_url=base_url,
        api_key_masked=mask_key(req.api_key) if req.api_key else "",
        enabled=req.enabled,
        is_local=is_local,
    )


def update_provider(provider_id: str, req: ProviderUpdate) -> Optional[ProviderOut]:
    data = _load()
    rec = data.get(provider_id)
    if not rec:
        return None
    if req.name is not None:
        rec["name"] = req.name
    if req.base_url is not None:
        rec["base_url"] = req.base_url
    if req.api_key is not None:
        rec["api_key"] = encrypt_value(req.api_key) if req.api_key else ""
    if req.enabled is not None:
        rec["enabled"] = req.enabled
    _save(data)
    return get_provider(provider_id)


def delete_provider(provider_id: str) -> bool:
    data = _load()
    if provider_id not in data:
        return False
    del data[provider_id]
    _save(data)
    return True
