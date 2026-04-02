"""Configuration manager for VIBEE-Hacker.

Follows Strix's Config pattern: class-level defaults with ENV > file > default
priority chain. Persistent config stored at ~/.vibee-hacker/config.json.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Any


class Config:
    """Configuration manager with env -> file -> default priority."""

    # Scanner defaults
    vibee_timeout = "60"
    vibee_concurrency = "10"
    vibee_safe_mode = "true"
    vibee_crawler_timeout = "60"
    vibee_crawler_max_depth = "2"
    vibee_crawler_max_pages = "50"

    # Profile presets
    vibee_profile = None

    # LLM Configuration
    vibee_llm = None
    vibee_llm_api_key = None
    vibee_llm_api_base = None
    vibee_llm_timeout = "300"
    vibee_llm_max_retries = "5"
    vibee_reasoning_effort = "high"

    # Telemetry
    vibee_telemetry = "1"

    # Runtime / Sandbox
    vibee_runtime_backend = None
    vibee_sandbox_image = None
    vibee_sandbox_timeout = "120"

    # Config file override (for testing)
    _config_file_override: Path | None = None

    # Cached file config (invalidated on save)
    _cached_file_config: dict[str, Any] | None = None

    # Profiles mapping
    PROFILES: dict[str, dict[str, str]] = {
        "stealth":    {"vibee_concurrency": "2",  "vibee_timeout": "30",  "vibee_safe_mode": "true"},
        "default":    {"vibee_concurrency": "10", "vibee_timeout": "60",  "vibee_safe_mode": "true"},
        "aggressive": {"vibee_concurrency": "50", "vibee_timeout": "120", "vibee_safe_mode": "false"},
        "ci":         {"vibee_concurrency": "5",  "vibee_timeout": "30",  "vibee_safe_mode": "true"},
    }

    @classmethod
    def _tracked_names(cls) -> list[str]:
        """Return class-level config attribute names (lowercase, non-private)."""
        return [
            k
            for k, v in vars(cls).items()
            if not k.startswith("_")
            and k[0].islower()
            and k.startswith("vibee_")
            and (v is None or isinstance(v, str))
        ]

    @classmethod
    def tracked_vars(cls) -> list[str]:
        """Return uppercase env var names for all tracked config keys."""
        return [name.upper() for name in cls._tracked_names()]

    @classmethod
    def _invalidate_cache(cls) -> None:
        """Invalidate the cached file config."""
        cls._cached_file_config = None

    @classmethod
    def get(cls, name: str) -> str | None:
        """Get config value with ENV > file > default priority.

        Args:
            name: Config key (lowercase, e.g. 'vibee_timeout')

        Returns:
            Config value or None if not set anywhere.
        """
        env_name = name.upper()

        # 1. Check environment variable
        env_val = os.getenv(env_name)
        if env_val is not None:
            return env_val

        # 2. Check saved config file (cached to avoid repeated I/O)
        if cls._cached_file_config is None:
            cls._cached_file_config = cls.load()
        env_vars = cls._cached_file_config.get("env", {})
        if isinstance(env_vars, dict) and env_name in env_vars:
            return env_vars[env_name]

        # 3. Fall back to class default
        return getattr(cls, name, None)

    @classmethod
    def get_int(cls, name: str, fallback: int = 0) -> int:
        """Get config value as integer."""
        val = cls.get(name)
        if val is None:
            return fallback
        try:
            return int(val)
        except (ValueError, TypeError):
            return fallback

    @classmethod
    def get_bool(cls, name: str, fallback: bool = False) -> bool:
        """Get config value as boolean."""
        val = cls.get(name)
        if val is None:
            return fallback
        return val.lower() in ("1", "true", "yes", "on")

    @classmethod
    def config_dir(cls) -> Path:
        """Return the config directory path."""
        return Path.home() / ".vibee-hacker"

    @classmethod
    def config_file(cls) -> Path:
        """Return the config file path."""
        if cls._config_file_override is not None:
            return cls._config_file_override
        return cls.config_dir() / "config.json"

    @classmethod
    def load(cls) -> dict[str, Any]:
        """Load config from disk."""
        path = cls.config_file()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except (json.JSONDecodeError, OSError):
            return {}

    @classmethod
    def save(cls, config: dict[str, Any]) -> bool:
        """Save config to disk with safe permissions."""
        try:
            config_path = cls.config_file()
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with config_path.open("w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except OSError:
            return False
        with contextlib.suppress(OSError):
            config_path.chmod(0o600)
        cls._invalidate_cache()
        return True

    @classmethod
    def apply_saved(cls, force: bool = False) -> dict[str, str]:
        """Apply saved env vars to current environment.

        Args:
            force: If True, override existing env vars.

        Returns:
            Dict of applied var_name -> var_value.
        """
        saved = cls.load()
        env_vars = saved.get("env", {})
        if not isinstance(env_vars, dict):
            env_vars = {}

        applied = {}
        for var_name, var_value in env_vars.items():
            if var_name in cls.tracked_vars() and (force or var_name not in os.environ):
                os.environ[var_name] = var_value
                applied[var_name] = var_value

        return applied

    @classmethod
    def save_current(cls) -> bool:
        """Snapshot current environment to config file."""
        existing = cls.load().get("env", {})
        merged = dict(existing) if isinstance(existing, dict) else {}

        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value is None:
                pass
            elif value == "":
                merged.pop(var_name, None)
            else:
                merged[var_name] = value

        return cls.save({"env": merged})

    @classmethod
    def get_profile(cls, profile_name: str) -> dict[str, str] | None:
        """Get profile preset values."""
        return cls.PROFILES.get(profile_name)


def apply_saved_config(force: bool = False) -> dict[str, str]:
    """Convenience function for applying saved config."""
    return Config.apply_saved(force=force)


def save_current_config() -> bool:
    """Convenience function for saving current config."""
    return Config.save_current()
