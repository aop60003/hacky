"""Scan engine: orchestrates plugin execution across phases."""

from __future__ import annotations

import asyncio
import copy
import logging
from collections import defaultdict

from vibee_hacker.core.models import Target, Result, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

logger = logging.getLogger(__name__)


class ScanEngine:
    """Core scan engine that manages plugin lifecycle."""

    def __init__(self, timeout_per_plugin: int = 60, max_concurrency: int = 10):
        self._plugins: list[PluginBase] = []
        self._timeout = timeout_per_plugin
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def register_plugin(self, plugin: PluginBase) -> None:
        self._plugins.append(plugin)

    async def scan(
        self,
        target: Target,
        phases: list[int] | None = None,
        plugins: list[str] | None = None,
    ) -> list[Result]:
        applicable = self._filter_plugins(target, phases, plugins)
        by_phase: dict[int, list[PluginBase]] = defaultdict(list)
        for p in applicable:
            by_phase[p.phase].append(p)

        context = InterPhaseContext()
        all_results: list[Result] = []
        for phase_num in sorted(by_phase.keys()):
            phase_plugins = by_phase[phase_num]
            results = await self._run_phase(target, phase_plugins, context)
            all_results.extend(results)

        all_results.sort(key=lambda r: r.base_severity, reverse=True)
        return all_results

    async def _run_phase(
        self, target: Target, plugins: list[PluginBase], context: InterPhaseContext | None = None
    ) -> list[Result]:
        # Give each plugin a shallow copy of context to prevent cross-pollution
        tasks = [
            self._run_plugin_safe(plugin, target, copy.copy(context) if context else None)
            for plugin in plugins
        ]
        results_nested = await asyncio.gather(*tasks)
        return [r for sublist in results_nested for r in sublist]

    async def _run_plugin_safe(
        self, plugin: PluginBase, target: Target, context: InterPhaseContext | None = None
    ) -> list[Result]:
        async with self._semaphore:
            try:
                results = await asyncio.wait_for(
                    plugin.run(target, context=context), timeout=self._timeout
                )
                return results
            except asyncio.TimeoutError:
                logger.warning("Plugin %s timed out", plugin.name)
                return [self._make_error_result(plugin, "Plugin timed out")]
            except Exception as e:
                logger.warning("Plugin %s failed: %s", plugin.name, e)
                return [self._make_error_result(plugin, f"Plugin error: {e}")]

    def _filter_plugins(
        self,
        target: Target,
        phases: list[int] | None,
        plugins: list[str] | None,
    ) -> list[PluginBase]:
        result = [p for p in self._plugins if p.is_applicable(target)]
        if phases:
            result = [p for p in result if p.phase in phases]
        if plugins:
            result = [p for p in result if p.name in plugins]
        return result

    @staticmethod
    def _make_error_result(plugin: PluginBase, message: str) -> Result:
        return Result(
            plugin_name=plugin.name,
            base_severity=plugin.base_severity,
            title=f"{plugin.name}: Error",
            description=message,
            plugin_status="failed",
        )
