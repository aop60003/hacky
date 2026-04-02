"""Tests for vibee_hacker.config.config module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from vibee_hacker.config.config import Config, apply_saved_config, save_current_config


@pytest.fixture(autouse=True)
def _isolate_config(tmp_path, monkeypatch):
    """Isolate config file and clear cache between tests."""
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(Config, "_config_file_override", config_file)
    monkeypatch.setattr(Config, "_cached_file_config", None)
    # Remove any VIBEE_ env vars that could bleed between tests
    for key in list(os.environ.keys()):
        if key.startswith("VIBEE_"):
            monkeypatch.delenv(key, raising=False)
    yield
    Config._cached_file_config = None


class TestConfigDefaults:
    """Config returns correct class-level default values."""

    def test_default_timeout(self):
        assert Config.get("vibee_timeout") == "60"

    def test_default_concurrency(self):
        assert Config.get("vibee_concurrency") == "10"

    def test_default_safe_mode(self):
        assert Config.get("vibee_safe_mode") == "true"

    def test_default_llm_is_none(self):
        assert Config.get("vibee_llm") is None

    def test_default_llm_timeout(self):
        assert Config.get("vibee_llm_timeout") == "300"

    def test_get_int_default(self):
        assert Config.get_int("vibee_timeout") == 60

    def test_get_bool_safe_mode(self):
        assert Config.get_bool("vibee_safe_mode") is True

    def test_get_int_fallback_on_missing(self):
        assert Config.get_int("vibee_nonexistent_key", fallback=99) == 99


class TestEnvOverride:
    """ENV variables take priority over file and class defaults."""

    def test_env_overrides_default(self, monkeypatch):
        monkeypatch.setenv("VIBEE_TIMEOUT", "999")
        assert Config.get("vibee_timeout") == "999"

    def test_env_int_override(self, monkeypatch):
        monkeypatch.setenv("VIBEE_CONCURRENCY", "25")
        assert Config.get_int("vibee_concurrency") == 25

    def test_env_bool_override_false(self, monkeypatch):
        monkeypatch.setenv("VIBEE_SAFE_MODE", "false")
        assert Config.get_bool("vibee_safe_mode") is False

    def test_env_bool_truthy_values(self, monkeypatch):
        for val in ("1", "true", "yes", "on"):
            monkeypatch.setenv("VIBEE_SAFE_MODE", val)
            assert Config.get_bool("vibee_safe_mode") is True

    def test_env_overrides_file(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"env": {"VIBEE_TIMEOUT": "42"}}))
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        monkeypatch.setenv("VIBEE_TIMEOUT", "777")
        assert Config.get("vibee_timeout") == "777"


class TestFileConfig:
    """Config reads from file when no ENV override is set."""

    def test_load_from_file(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"env": {"VIBEE_TIMEOUT": "45"}}))
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        assert Config.get("vibee_timeout") == "45"

    def test_load_missing_file_returns_empty(self, tmp_path, monkeypatch):
        missing = tmp_path / "no_such.json"
        monkeypatch.setattr(Config, "_config_file_override", missing)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        result = Config.load()
        assert result == {}

    def test_load_corrupt_json_returns_empty(self, tmp_path, monkeypatch):
        config_file = tmp_path / "bad.json"
        config_file.write_text("not json {{{")
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        assert Config.load() == {}

    def test_save_and_reload(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        ok = Config.save({"env": {"VIBEE_TIMEOUT": "55"}})
        assert ok is True
        loaded = Config.load()
        assert loaded["env"]["VIBEE_TIMEOUT"] == "55"

    def test_save_invalidates_cache(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        # Pre-populate cache with stale value
        monkeypatch.setattr(Config, "_cached_file_config", {"env": {"VIBEE_TIMEOUT": "0"}})
        Config.save({"env": {"VIBEE_TIMEOUT": "88"}})
        assert Config._cached_file_config is None


class TestProfileLoading:
    """Profile presets return correct values."""

    def test_default_profile(self):
        p = Config.get_profile("default")
        assert p is not None
        assert p["vibee_concurrency"] == "10"
        assert p["vibee_timeout"] == "60"

    def test_stealth_profile(self):
        p = Config.get_profile("stealth")
        assert p["vibee_concurrency"] == "2"
        assert p["vibee_safe_mode"] == "true"

    def test_aggressive_profile(self):
        p = Config.get_profile("aggressive")
        assert p["vibee_concurrency"] == "50"
        assert p["vibee_safe_mode"] == "false"

    def test_ci_profile(self):
        p = Config.get_profile("ci")
        assert p["vibee_timeout"] == "30"

    def test_unknown_profile_returns_none(self):
        assert Config.get_profile("nonexistent") is None


class TestLLMConfig:
    """LLM-specific config keys behave correctly."""

    def test_llm_default_none(self):
        assert Config.get("vibee_llm") is None

    def test_llm_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("VIBEE_LLM_API_KEY", "sk-test-key")
        assert Config.get("vibee_llm_api_key") == "sk-test-key"

    def test_llm_timeout_default(self):
        assert Config.get_int("vibee_llm_timeout") == 300

    def test_llm_max_retries_default(self):
        assert Config.get_int("vibee_llm_max_retries") == 5

    def test_reasoning_effort_default(self):
        assert Config.get("vibee_reasoning_effort") == "high"


class TestTrackedVars:
    """tracked_vars() returns all VIBEE_ uppercase keys."""

    def test_tracked_vars_non_empty(self):
        tracked = Config.tracked_vars()
        assert len(tracked) > 0

    def test_tracked_vars_uppercase(self):
        for var in Config.tracked_vars():
            assert var == var.upper()

    def test_tracked_vars_contains_expected(self):
        tracked = Config.tracked_vars()
        assert "VIBEE_TIMEOUT" in tracked
        assert "VIBEE_LLM" in tracked


class TestApplySaved:
    """apply_saved() writes saved env vars into os.environ."""

    def test_apply_saved_sets_env(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"env": {"VIBEE_TIMEOUT": "77"}}))
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        applied = Config.apply_saved()
        assert "VIBEE_TIMEOUT" in applied
        assert os.environ.get("VIBEE_TIMEOUT") == "77"
        # cleanup
        monkeypatch.delenv("VIBEE_TIMEOUT", raising=False)

    def test_apply_saved_no_force_skips_existing(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"env": {"VIBEE_TIMEOUT": "77"}}))
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        monkeypatch.setenv("VIBEE_TIMEOUT", "existing")
        applied = Config.apply_saved(force=False)
        assert "VIBEE_TIMEOUT" not in applied
        assert os.environ.get("VIBEE_TIMEOUT") == "existing"


class TestConvenienceFunctions:
    """Module-level convenience wrappers delegate to Config."""

    def test_apply_saved_config_convenience(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"env": {}}))
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        result = apply_saved_config()
        assert isinstance(result, dict)

    def test_save_current_config_convenience(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        monkeypatch.setattr(Config, "_config_file_override", config_file)
        monkeypatch.setattr(Config, "_cached_file_config", None)
        result = save_current_config()
        assert result is True
