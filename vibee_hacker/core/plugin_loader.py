"""Plugin auto-discovery and loading."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path

from vibee_hacker.core.plugin_base import PluginBase


class PluginLoader:
    """Discovers and manages plugins."""

    def __init__(self):
        self._plugins: list[PluginBase] = []

    @property
    def plugins(self) -> list[PluginBase]:
        return list(self._plugins)

    def discover(self, directory: str) -> list[PluginBase]:
        found = []
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return found

        for py_file in dir_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            classes = self._load_module_plugins(py_file)
            found.extend(classes)

        self._plugins.extend(found)
        return found

    def load_builtin(self) -> None:
        base = Path(__file__).parent.parent / "plugins"
        for subdir in ["blackbox", "whitebox"]:
            plugin_dir = base / subdir
            if plugin_dir.is_dir():
                self.discover(str(plugin_dir))

    def get_plugins(
        self,
        category: str | None = None,
        phase: int | None = None,
        name: str | None = None,
    ) -> list[PluginBase]:
        result = self._plugins
        if category:
            result = [p for p in result if p.category == category]
        if phase is not None:
            result = [p for p in result if p.phase == phase]
        if name:
            names = [n.strip() for n in name.split(",")]
            result = [p for p in result if p.name in names]
        return result

    def _load_module_plugins(self, path: Path) -> list[PluginBase]:
        module_name = f"vibee_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            return []

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            return []

        found = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, PluginBase)
                and obj is not PluginBase
                and not inspect.isabstract(obj)
            ):
                found.append(obj())
        return found
