"""Base class for all VIBEE-Hacker plugins."""

from __future__ import annotations

import abc
from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext


class PluginBase(abc.ABC):
    """Abstract base class for scanner plugins."""

    name: str = ""
    description: str = ""
    category: str = ""
    phase: int = 0
    base_severity: Severity = Severity.INFO
    requires: list[str] = []
    provides: list[str] = []
    detection_criteria: str = ""
    expected_evidence: str = ""
    destructive_level: int = 0

    def is_applicable(self, target: Target) -> bool:
        return True

    @abc.abstractmethod
    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        ...
