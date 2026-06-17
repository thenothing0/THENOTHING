"""
Provider-agnostic LLM client. Two wire formats cover the whole local + hosted
ecosystem:

  * **OpenAI-compatible** ``/v1/chat/completions`` — LM Studio, vLLM, llama.cpp
    server, Groq, OpenRouter, DeepSeek, Kimi/Moonshot, and OpenAI itself.
  * **Ollama** native ``/api/chat``.

Transport is injectable (``transport=`` callable) so tests never touch the
network; the default transport is stdlib ``urllib`` (no third-party deps). API
keys come from the environment, never logged.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

# (url, headers, json-body, timeout) -> decoded-json dict
Transport = Callable[[str, Dict[str, str], dict, float], dict]

# backend -> (base_url, env var holding the api key, is_openai_wire, is_local)
# `is_local` backends keep target data on-box (the sensitive-data-safe path);
# hosted backends get outbound redaction applied to message content (TN-7).
_BACKENDS: Dict[str, tuple] = {
    "ollama": ("http://localhost:11434", "", False, True),
    "lmstudio": ("http://localhost:1234/v1", "", True, True),
    "openai-compat": ("", "OPENAI_API_KEY", True, False),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", True, False),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", True, False),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", True, False),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY", True, False),
    "kimi": ("https://api.moonshot.cn/v1", "MOONSHOT_API_KEY", True, False),
}


class LLMError(RuntimeError):
    """Raised on transport failure or a malformed provider response."""


def _urllib_transport(url: str, headers: Dict[str, str], body: dict, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 (http(s) only)
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500] if e.fp else ""
        raise LLMError(f"HTTP {e.code} from {url}: {detail}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise LLMError(f"transport error to {url}: {e}") from e
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise LLMError(f"non-JSON response from {url}: {raw[:200]}") from e


class LLMClient:
    """Base client. Subclasses implement ``chat()``; both share config + headers."""

    def __init__(self, base_url: str, model: str, api_key: str = "",
                 timeout: float = 120.0, transport: Optional[Transport] = None,
                 redact_outbound: bool = False):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._api_key = api_key
        self.timeout = timeout
        self._transport = transport or _urllib_transport
        # TN-7: redact operator secrets from prompts sent to HOSTED providers.
        self.redact_outbound = redact_outbound

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _prepare(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Apply outbound redaction when crossing to a third-party provider (TN-7)."""
        if not self.redact_outbound:
            return messages
        from hydra.safety import redact
        return [{**m, "content": redact(m.get("content", ""))} for m in messages]

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        raise NotImplementedError


class OpenAICompatClient(LLMClient):
    """OpenAI ``/v1/chat/completions`` wire format (covers most hosted + LM Studio/vLLM)."""

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        body = {"model": self.model, "messages": self._prepare(messages),
                "temperature": temperature, "stream": False}
        resp = self._transport(f"{self.base_url}/chat/completions",
                               self._headers(), body, self.timeout)
        try:
            msg = resp["choices"][0]["message"]
            # reasoning models may leave `content` empty and put text in reasoning_content
            return (msg.get("content") or msg.get("reasoning_content") or "").strip()
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"unexpected OpenAI-compat response shape: {str(resp)[:200]}") from e


class OllamaClient(LLMClient):
    """Ollama native ``/api/chat`` wire format."""

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        body = {"model": self.model, "messages": self._prepare(messages), "stream": False,
                "options": {"temperature": temperature}}
        resp = self._transport(f"{self.base_url}/api/chat",
                               self._headers(), body, self.timeout)
        try:
            return (resp["message"]["content"] or "").strip()
        except (KeyError, TypeError) as e:
            raise LLMError(f"unexpected Ollama response shape: {str(resp)[:200]}") from e


def make_client(backend: str, model: str, *, base_url: str = "", api_key: str = "",
                timeout: float = 120.0, transport: Optional[Transport] = None) -> LLMClient:
    """Build a client for ``backend``. ``base_url`` overrides the default endpoint
    (required for ``openai-compat``); ``api_key`` overrides the env-var lookup."""
    key = backend.lower()
    if key not in _BACKENDS:
        raise LLMError(f"unknown backend '{backend}'; known: {sorted(_BACKENDS)}")
    default_url, env_var, openai_wire, is_local = _BACKENDS[key]
    url = base_url or default_url
    if not url:
        raise LLMError(f"backend '{backend}' requires an explicit base_url")
    resolved_key = api_key or (os.environ.get(env_var, "") if env_var else "")
    cls = OpenAICompatClient if openai_wire else OllamaClient
    # Hosted backends get outbound redaction (TN-7); local models keep data on-box.
    return cls(url, model, api_key=resolved_key, timeout=timeout, transport=transport,
               redact_outbound=not is_local)
