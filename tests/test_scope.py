"""Tests for the Scope Intelligence Layer."""

import pytest
from hydra.scope import ScopePolicyEngine


class TestScopePolicyEngine:
    """Test scope validation and policy enforcement."""

    def test_engine_creation(self):
        engine = ScopePolicyEngine()
        assert engine is not None

    def test_load_custom_scope(self):
        engine = ScopePolicyEngine()
        scope_data = {
            "program": "test-program",
            "platform": "custom",
            "in_scope": [
                {"identifier": "*.example.com", "type": "url"},
                {"identifier": "api.example.com", "type": "url"},
            ],
            "out_of_scope": [
                {"identifier": "admin.example.com", "type": "url"},
            ],
        }
        # Use the method that actually exists
        engine.load_from_dict(scope_data) if hasattr(engine, 'load_from_dict') else engine.load(scope_data)
        assert engine.is_loaded is True

    def test_validate_in_scope_target(self):
        engine = ScopePolicyEngine()
        scope_data = {
            "program": "test",
            "platform": "custom",
            "in_scope": [{"identifier": "*.example.com", "type": "url"}],
            "out_of_scope": [],
        }
        engine.load_from_dict(scope_data) if hasattr(engine, 'load_from_dict') else engine.load(scope_data)
        
        result = engine.validate_target("test.example.com")
        assert result.allowed is True

    def test_validate_out_of_scope_target(self):
        engine = ScopePolicyEngine()
        scope_data = {
            "program": "test",
            "platform": "custom",
            "in_scope": [{"identifier": "*.example.com", "type": "url"}],
            "out_of_scope": [{"identifier": "admin.example.com", "type": "url"}],
        }
        engine.load_from_dict(scope_data) if hasattr(engine, 'load_from_dict') else engine.load(scope_data)
        
        result = engine.validate_target("admin.example.com")
        assert result.allowed is False

    def test_generate_directives(self):
        engine = ScopePolicyEngine()
        scope_data = {
            "program": "test",
            "platform": "hackerone",
            "in_scope": [{"identifier": "*.example.com", "type": "url"}],
            "out_of_scope": [],
            "forbidden_testing": ["dos", "social_engineering"],
        }
        engine.load_from_dict(scope_data) if hasattr(engine, 'load_from_dict') else engine.load(scope_data)
        directives = engine.generate_planner_directives()
        assert isinstance(directives, list)

    def test_empty_scope_blocks_everything(self):
        engine = ScopePolicyEngine()
        # No scope loaded — should block by default (security first)
        result = engine.validate_target("anything.com")
        assert result.allowed is False, f"Expected blocked, got {result.allowed}"
