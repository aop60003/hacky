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

    def __init__(self, timeout_per_plugin: int = 60, max_concurrency: int = 10, safe_mode: bool = True):
        self._plugins: list[PluginBase] = []
        self._timeout = timeout_per_plugin
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._safe_mode = safe_mode

    def register_plugin(self, plugin: PluginBase) -> None:
        self._plugins.append(plugin)

    async def scan(
        self,
        target: Target,
        phases: list[int] | None = None,
        plugins: list[str] | None = None,
        safe_mode: bool | None = None,
    ) -> list[Result]:
        effective_safe_mode = self._safe_mode if safe_mode is None else safe_mode
        applicable = self._filter_plugins(target, phases, plugins, effective_safe_mode)
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
        # Give each plugin a deep copy of context to prevent cross-pollution within a phase
        plugin_contexts = [copy.deepcopy(context) if context else None for _ in plugins]
        tasks = [
            self._run_plugin_safe(plugin, target, ctx)
            for plugin, ctx in zip(plugins, plugin_contexts)
        ]
        results_nested = await asyncio.gather(*tasks)

        # Merge plugin-discovered data back into the shared context for next phase
        if context is not None:
            for ctx in plugin_contexts:
                if ctx is not None:
                    self._merge_context(context, ctx)

        return [r for sublist in results_nested for r in sublist]

    @staticmethod
    def _merge_context(target_ctx: InterPhaseContext, source_ctx: InterPhaseContext) -> None:
        """Merge plugin's context discoveries back into the shared context."""
        existing_tech = set(target_ctx.tech_stack)
        for item in source_ctx.tech_stack:
            if item not in existing_tech:
                target_ctx.tech_stack.append(item)
                existing_tech.add(item)
        existing_ssrf = set(target_ctx.ssrf_endpoints)
        for item in source_ctx.ssrf_endpoints:
            if item not in existing_ssrf:
                target_ctx.ssrf_endpoints.append(item)
                existing_ssrf.add(item)
        existing_cnames = set(target_ctx.dangling_cnames)
        for item in source_ctx.dangling_cnames:
            if item not in existing_cnames:
                target_ctx.dangling_cnames.append(item)
                existing_cnames.add(item)
        if source_ctx.waf_info and not target_ctx.waf_info:
            target_ctx.waf_info = source_ctx.waf_info
        if source_ctx.waf_bypass_payloads and not target_ctx.waf_bypass_payloads:
            target_ctx.waf_bypass_payloads = source_ctx.waf_bypass_payloads
        if source_ctx.discovered_api_schema and not target_ctx.discovered_api_schema:
            target_ctx.discovered_api_schema = source_ctx.discovered_api_schema

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
        safe_mode: bool = True,
    ) -> list[PluginBase]:
        result = [p for p in self._plugins if p.is_applicable(target)]
        if safe_mode:
            result = [p for p in result if p.destructive_level == 0]
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
