"""Scan policy for controlling plugin behavior."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ScanPolicy:
    """Defines scan behavior: which plugins to run, severity thresholds, etc."""
    name: str = "default"
    description: str = ""

    # Plugin control
    enabled_plugins: list[str] | None = None  # None = all enabled
    disabled_plugins: list[str] = field(default_factory=list)
    enabled_categories: list[str] | None = None  # None = all
    disabled_categories: list[str] = field(default_factory=list)

    # Phase control
    enabled_phases: list[int] | None = None  # None = all

    # Severity filter
    min_severity: str = "info"  # Only report findings >= this severity

    # Scan limits
    max_requests_per_plugin: int = 100
    max_crawl_depth: int = 3
    max_crawl_pages: int = 50

    # Fuzzing control
    fuzz_params: bool = True
    fuzz_headers: bool = False
    fuzz_cookies: bool = False
    max_payloads_per_param: int = 10

    @classmethod
    def from_file(cls, path: str | Path) -> ScanPolicy:
        """Load policy from YAML or JSON file."""
        path = Path(path)
        with open(path) as f:
            if path.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(f) or {}
            else:
                data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_dict(cls, data: dict) -> ScanPolicy:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def is_plugin_enabled(self, plugin_name: str, plugin_category: str = "", plugin_phase: int = 0) -> bool:
        """Check if a plugin should run under this policy."""
        # Phase filter
        if self.enabled_phases is not None and plugin_phase not in self.enabled_phases:
            return False

        # Explicit disable
        if plugin_name in self.disabled_plugins:
            return False

        # Category disable
        if plugin_category in self.disabled_categories:
            return False

        # Explicit enable (whitelist)
        if self.enabled_plugins is not None:
            return plugin_name in self.enabled_plugins

        # Category enable (whitelist)
        if self.enabled_categories is not None:
            return plugin_category in self.enabled_categories

        return True

    def to_dict(self) -> dict:
        """Serialize policy to dict."""
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    def save(self, path: str | Path):
        """Save policy to file."""
        path = Path(path)
        with open(path, "w") as f:
            if path.suffix in (".yaml", ".yml"):
                yaml.dump(self.to_dict(), f, default_flow_style=False)
            else:
                json.dump(self.to_dict(), f, indent=2)


# Built-in policies
BUILTIN_POLICIES = {
    "default": ScanPolicy(name="default", description="Default balanced policy"),
    "quick": ScanPolicy(
        name="quick",
        description="Fast scan with limited coverage",
        enabled_phases=[1, 2],
        max_crawl_pages=10,
        max_payloads_per_param=3,
    ),
    "thorough": ScanPolicy(
        name="thorough",
        description="Deep scan with maximum coverage",
        max_crawl_depth=5,
        max_crawl_pages=200,
        max_payloads_per_param=20,
        fuzz_headers=True,
        fuzz_cookies=True,
    ),
    "passive": ScanPolicy(
        name="passive",
        description="No active probing, only analyze responses",
        enabled_phases=[1, 2],
        fuzz_params=False,
    ),
    "injection-only": ScanPolicy(
        name="injection-only",
        description="Only injection-related plugins",
        enabled_plugins=[
            "sqli", "xss", "cmdi", "ssrf", "ssti", "xxe",
            "nosql_injection", "ldap_injection", "xpath_injection",
        ],
    ),
}
