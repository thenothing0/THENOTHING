from __future__ import annotations

import logging
from typing import Any

import httpx

from ..models.schemas import ModelInfo, ProviderType
from . import provider_store

logger = logging.getLogger("cc.model_discovery")

_CAPABILITY_HINTS: dict[str, list[str]] = {
    "gpt-4o": ["vision", "tool_calling", "json_mode", "streaming"],
    "gpt-4o-mini": ["vision", "tool_calling", "json_mode", "streaming"],
    "gpt-4.1": ["vision", "tool_calling", "json_mode", "streaming", "long_context"],
    "o3": ["reasoning", "tool_calling", "streaming"],
    "o4-mini": ["reasoning", "tool_calling", "streaming"],
    "claude-opus-4": ["vision", "tool_calling", "streaming", "reasoning"],
    "claude-sonnet-4": ["vision", "tool_calling", "streaming", "reasoning"],
    "claude-haiku-4": ["vision", "tool_calling", "streaming"],
    "gemini-2.5-pro": ["vision", "tool_calling", "streaming", "reasoning", "long_context"],
    "gemini-2.5-flash": ["vision", "tool_calling", "streaming", "long_context"],
    "deepseek-chat": ["tool_calling", "streaming", "reasoning"],
    "deepseek-reasoner": ["reasoning", "streaming"],
    "moonshot-v1-128k": ["streaming", "long_context"],
}


def _match_capabilities(model_id: str) -> list[str]:
    for pattern, caps in _CAPABILITY_HINTS.items():
        if pattern in model_id:
            return caps
    return ["streaming"]


async def fetch_models_openai_compat(
    base_url: str, api_key: str, provider_id: str, provider_name: str,
) -> list[ModelInfo]:
    url = f"{base_url.rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning("model fetch failed for %s: %s", provider_name, e)
        return []

    models_raw = data.get("data", data.get("models", []))
    result = []
    for m in models_raw:
        mid = m.get("id", m.get("name", ""))
        if not mid:
            continue
        result.append(ModelInfo(
            id=mid,
            name=mid,
            provider_id=provider_id,
            provider_name=provider_name,
            context_length=m.get("context_length", m.get("context_window", 0)),
            capabilities=_match_capabilities(mid),
        ))
    return result


async def fetch_models_ollama(
    base_url: str, provider_id: str, provider_name: str,
) -> list[ModelInfo]:
    url = f"{base_url.rstrip('/')}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning("ollama model fetch failed: %s", e)
        return []

    result = []
    for m in data.get("models", []):
        name = m.get("name", "")
        result.append(ModelInfo(
            id=name,
            name=name,
            provider_id=provider_id,
            provider_name=provider_name,
            context_length=0,
            capabilities=["streaming"],
        ))
    return result


async def fetch_models_anthropic(
    api_key: str, provider_id: str, provider_name: str,
) -> list[ModelInfo]:
    known = [
        ("claude-opus-4-20250514", "Claude Opus 4", 200000),
        ("claude-sonnet-4-20250514", "Claude Sonnet 4", 200000),
        ("claude-haiku-4-5-20251001", "Claude Haiku 4.5", 200000),
    ]
    return [
        ModelInfo(
            id=mid, name=name, provider_id=provider_id,
            provider_name=provider_name, context_length=ctx,
            capabilities=_match_capabilities(mid),
        )
        for mid, name, ctx in known
    ]


async def discover_models(provider_id: str | None = None) -> list[ModelInfo]:
    providers = provider_store.list_providers()
    if provider_id:
        providers = [p for p in providers if p.id == provider_id]

    all_models: list[ModelInfo] = []
    for prov in providers:
        if not prov.enabled:
            continue
        key = provider_store.get_provider_key(prov.id)

        if prov.type == ProviderType.ollama:
            models = await fetch_models_ollama(prov.base_url, prov.id, prov.name)
        elif prov.type == ProviderType.anthropic:
            models = await fetch_models_anthropic(key, prov.id, prov.name)
        else:
            models = await fetch_models_openai_compat(
                prov.base_url, key, prov.id, prov.name,
            )
        all_models.extend(models)

    return all_models


async def test_provider_connection(provider_id: str) -> dict[str, Any]:
    prov = provider_store.get_provider(provider_id)
    if not prov:
        return {"ok": False, "error": "provider not found"}

    key = provider_store.get_provider_key(provider_id)
    try:
        if prov.type == ProviderType.ollama:
            models = await fetch_models_ollama(prov.base_url, prov.id, prov.name)
        elif prov.type == ProviderType.anthropic:
            models = await fetch_models_anthropic(key, prov.id, prov.name)
        else:
            models = await fetch_models_openai_compat(
                prov.base_url, key, prov.id, prov.name,
            )
        return {"ok": True, "model_count": len(models)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
