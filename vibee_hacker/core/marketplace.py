"""Plugin marketplace: discover, install, and manage community plugins."""

from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """Metadata about a marketplace plugin."""
    name: str
    version: str
    description: str
    author: str
    category: str  # blackbox, whitebox
    tags: list[str] = field(default_factory=list)
    url: str = ""  # git repo URL
    installed: bool = False
    downloads: int = 0


class Marketplace:
    """Discover and manage community plugins."""

    def __init__(self, registry_path: str | Path | None = None):
        self._registry: list[PluginInfo] = []
        self._installed: set[str] = set()
        if registry_path:
            self.load_registry(Path(registry_path))

    def load_registry(self, path: Path):
        """Load plugin registry from JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
            for item in data.get("plugins", []):
                info = PluginInfo(**{k: v for k, v in item.items() if k in PluginInfo.__dataclass_fields__})
                self._registry.append(info)
        except Exception as e:
            logger.warning("Failed to load registry: %s", e)

    def search(self, query: str = "", category: str = "", tags: list[str] | None = None) -> list[PluginInfo]:
        """Search for plugins."""
        results = list(self._registry)
        if query:
            q = query.lower()
            results = [p for p in results if q in p.name.lower() or q in p.description.lower()]
        if category:
            results = [p for p in results if p.category == category]
        if tags:
            results = [p for p in results if any(t in p.tags for t in tags)]
        return results

    def install(self, plugin_name: str) -> bool:
        """Mark a plugin as installed."""
        for p in self._registry:
            if p.name == plugin_name:
                p.installed = True
                self._installed.add(plugin_name)
                return True
        return False

    def uninstall(self, plugin_name: str) -> bool:
        """Mark a plugin as uninstalled."""
        for p in self._registry:
            if p.name == plugin_name:
                p.installed = False
                self._installed.discard(plugin_name)
                return True
        return False

    def list_installed(self) -> list[PluginInfo]:
        return [p for p in self._registry if p.installed]

    def add_to_registry(self, info: PluginInfo):
        self._registry.append(info)

    @property
    def count(self) -> int:
        return len(self._registry)
