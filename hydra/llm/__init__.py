"""
THENOTHING LLM provider layer — point the platform's reasoning at ANY local or
hosted model (Ollama / LM Studio / OpenAI-compatible / Anthropic-compatible).

Decouples THENOTHING from a single hard-wired brain (PentesterFlow parity:
"whatever local model you point at"). Pure-stdlib transport (urllib) so it adds
no dependencies; deterministic, offline-friendly, and unit-testable via an
injectable transport.

Usage:
    from hydra.llm import make_client
    client = make_client(backend="ollama", model="qwen2.5-coder:32b")
    reply = client.chat([{"role": "user", "content": "plan recon for example.com"}])
"""

from .client import (
    LLMClient,
    LLMError,
    OllamaClient,
    OpenAICompatClient,
    make_client,
)

__all__ = [
    "LLMClient",
    "LLMError",
    "OllamaClient",
    "OpenAICompatClient",
    "make_client",
]
