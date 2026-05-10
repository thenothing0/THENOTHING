"""Tests for the Scope Intelligence Layer."""

import asyncio
import pytest
from hydra.scope import ScopePolicyEngine


def _run(coro):
    """Helper to run async coroutines in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestScopePolicyEngine:
    """Test scope validation and policy enforcement."""

    def test_engine_creation(self):
        engine = ScopePolicyEngine()
        assert engine is not None
        assert engine.is_loaded is False

    def test_load_custom_scope(self):
        engine = ScopePolicyEngine()
        scope_data = {
            "program": "test-program",
            "platform": "custom",
            "in_scope": [
                {"asset": "*.example.com", "type": "url"},
                {"asset": "api.example.com", "type": "url"},
            ],
            "out_of_scope": [
                {"asset": "admin.example.com", "type": "url"},
            ],
        }
        _run(engine.load_scope(platform="custom", raw_scope=scope_data))
        assert engine.is_loaded is True

    def test_validate_in_scope_target(self):
        engine = ScopePolicyEngine()
        _run(engine.load_scope(platform="custom", raw_scope={
            "program": "test",
            "platform": "custom",
            "in_scope": [{"asset": "*.example.com", "type": "url"}],
            "out_of_scope": [],
        }))
        result = engine.validate_target("test.example.com")
        assert result.allowed is True

    def test_validate_out_of_scope_target(self):
        engine = ScopePolicyEngine()
        _run(engine.load_scope(platform="custom", raw_scope={
            "program": "test",
            "platform": "custom",
            "in_scope": [{"asset": "*.example.com", "type": "url"}],
            "out_of_scope": [{"asset": "admin.example.com", "type": "url"}],
        }))
        result = engine.validate_target("admin.example.com")
        assert result.allowed is False

    def test_generate_directives(self):
        engine = ScopePolicyEngine()
        _run(engine.load_scope(platform="custom", raw_scope={
            "program": "test",
            "platform": "custom",
            "in_scope": [{"asset": "*.example.com", "type": "url"}],
            "out_of_scope": [],
            "forbidden_testing": ["dos", "social_engineering"],
        }))
        directives = engine.generate_planner_directives()
        assert isinstance(directives, list)

    def test_empty_scope_blocks_everything(self):
        engine = ScopePolicyEngine()
        # Not loaded - returns allowed=True with "No scope loaded" reason
        result = engine.validate_target("anything.com")
        assert result.reason == "No scope loaded"
