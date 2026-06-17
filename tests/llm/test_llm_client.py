"""Unit tests for the provider-agnostic LLM client (no network — injected transport)."""

import pytest

from hydra.llm import LLMError, make_client


def _openai_ok(_url, _h, body, _t):
    return {"choices": [{"message": {"content": f"echo:{body['messages'][-1]['content']}"}}]}


def _ollama_ok(_url, _h, body, _t):
    return {"message": {"content": f"ollama:{body['messages'][-1]['content']}"}}


def test_openai_compat_roundtrip():
    c = make_client("lmstudio", "m", transport=_openai_ok)
    assert c.chat([{"role": "user", "content": "hi"}]) == "echo:hi"


def test_ollama_roundtrip():
    c = make_client("ollama", "m", transport=_ollama_ok)
    assert c.chat([{"role": "user", "content": "yo"}]) == "ollama:yo"


def test_reasoning_content_fallback():
    def t(_u, _h, _b, _to):
        return {"choices": [{"message": {"content": "", "reasoning_content": "r"}}]}
    assert make_client("groq", "m", transport=t).chat([{"role": "user", "content": "x"}]) == "r"


def test_unknown_backend():
    with pytest.raises(LLMError):
        make_client("does-not-exist", "m")


def test_openai_compat_requires_base_url():
    with pytest.raises(LLMError):
        make_client("openai-compat", "m")


def test_malformed_response_raises():
    def t(_u, _h, _b, _to):
        return {"unexpected": True}
    with pytest.raises(LLMError):
        make_client("ollama", "m", transport=t).chat([{"role": "user", "content": "x"}])


def test_api_key_from_explicit_arg_sets_auth_header():
    seen = {}

    def t(_u, headers, _b, _to):
        seen.update(headers)
        return {"choices": [{"message": {"content": "ok"}}]}
    make_client("openai", "m", api_key="sk-test", transport=t).chat(
        [{"role": "user", "content": "x"}])
    assert seen.get("Authorization") == "Bearer sk-test"
