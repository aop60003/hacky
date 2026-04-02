"""Scan orchestrator: state-managed wrapper around ScanEngine.

Provides iteration-budgeted, pause/resume capable scan execution.
The orchestrator owns the ScanState and delegates actual scanning to ScanEngine.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Result, Target
from vibee_hacker.core.plugin_loader import PluginLoader
from vibee_hacker.core.state import ScanState

if TYPE_CHECKING:
    from vibee_hacker.telemetry.tracer import Tracer

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """State-managed scan orchestrator.

    Wraps ScanEngine with ScanState lifecycle management.
    Supports single-pass (deterministic) and iterative (future LLM-guided) modes.
    """

    def __init__(
        self,
        timeout_per_plugin: int = 60,
        max_concurrency: int = 10,
        safe_mode: bool = True,
        tracer: Optional["Tracer"] = None,
        state: Optional[ScanState] = None,
        loader: Optional[PluginLoader] = None,
    ):
        self._timeout = timeout_per_plugin
        self._concurrency = max_concurrency
        self._safe_mode = safe_mode
        self._tracer = tracer
        self.state = state or ScanState()

        # Plugin loading — accept external loader to avoid redundant disk I/O
        if loader is not None:
            self._loader = loader
        else:
            self._loader = PluginLoader()
            self._loader.load_builtin()

        # Engine (created per run)
        self._engine: Optional[ScanEngine] = None

    def _create_engine(self) -> ScanEngine:
        """Create a fresh ScanEngine with current settings."""
        engine = ScanEngine(
            timeout_per_plugin=self._timeout,
            max_concurrency=self._concurrency,
            safe_mode=self._safe_mode,
            tracer=self._tracer,
        )
        for p in self._loader.plugins:
            engine.register_plugin(p)
        return engine

    @property
    def plugin_count(self) -> int:
        """Total number of loaded plugins."""
        return len(self._loader.plugins)

    async def run(
        self,
        target: Target,
        phases: Optional[List[int]] = None,
        plugins: Optional[List[str]] = None,
    ) -> List[Result]:
        """Run a single-pass scan (equivalent to ScanEngine.scan).

        This is the backward-compatible entry point that produces identical
        results to calling ScanEngine.scan() directly.
        """
        self.state.target = target.url or target.path or ""
        self.state.mode = target.mode
        if self.state.started_at is None:
            self.state.started_at = datetime.now(timezone.utc)
        self.state.total_plugins = self.plugin_count

        engine = self._create_engine()
        self._engine = engine

        self.state.increment_iteration()

        try:
            results = await engine.scan(target, phases=phases, plugins=plugins)
        except Exception as e:
            self.state.errors.append(str(e))
            logger.error("Scan failed: %s", e)
            results = []

        # Update state with results
        self.state.add_results([r.to_dict() for r in results])
        for r in results:
            if r.plugin_status == "completed":
                self.state.mark_plugin_complete(r.plugin_name)
            elif r.plugin_status == "failed":
                self.state.mark_plugin_failed(r.plugin_name, r.description)

        self.state.set_completed()

        # Save tracer data
        if self._tracer:
            self._tracer.save_run_data(mark_complete=True)

        return results

    async def run_iterative(
        self,
        target: Target,
        max_iterations: int = 3,
        phases: Optional[List[int]] = None,
        plugins: Optional[List[str]] = None,
    ) -> List[Result]:
        """Run multiple scan passes (for future LLM-guided re-scanning).

        Each iteration can refine plugin selection based on previous results.
        Currently runs a single pass; LLM-guided iteration will be added in
        a future sprint by overriding the loop body.
        """
        self.state.max_iterations = max_iterations

        # Single pass for now
        return await self.run(target, phases=phases, plugins=plugins)

    def get_state_dict(self) -> Dict[str, Any]:
        """Get serializable state for session persistence."""
        return self.state.model_dump()

    @classmethod
    def from_state_dict(
        cls,
        state_dict: Dict[str, Any],
        tracer: Optional["Tracer"] = None,
    ) -> "ScanOrchestrator":
        """Restore orchestrator from serialized state."""
        state = ScanState.model_validate(state_dict)
        return cls(
            timeout_per_plugin=state.options.get("timeout", 60),
            max_concurrency=state.options.get("concurrency", 10),
            safe_mode=state.options.get("safe_mode", True),
            tracer=tracer,
            state=state,
        )
