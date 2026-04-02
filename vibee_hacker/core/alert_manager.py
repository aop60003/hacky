"""Alert management: group, filter, deduplicate, and sort scan results."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

from vibee_hacker.core.models import Result, Severity

SEVERITY_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


@dataclass
class AlertGroup:
    """A group of related alerts."""
    key: str
    label: str
    results: list[Result] = field(default_factory=list)
    max_severity: Severity = Severity.INFO

    @property
    def count(self) -> int:
        return len(self.results)


class AlertManager:
    """Manage, group, filter, and deduplicate scan results."""

    def __init__(self, results: list[Result] | None = None):
        self._results: list[Result] = list(results or [])

    @property
    def results(self) -> list[Result]:
        return list(self._results)

    @property
    def count(self) -> int:
        return len(self._results)

    def add(self, result: Result):
        self._results.append(result)

    def filter_by_severity(self, min_severity: str) -> list[Result]:
        """Return results with severity >= min_severity."""
        min_sev = SEVERITY_MAP.get(min_severity.lower(), Severity.INFO)
        return [r for r in self._results if r.base_severity >= min_sev]

    def filter_by_plugin(self, plugin_name: str) -> list[Result]:
        """Return results from a specific plugin."""
        return [r for r in self._results if r.plugin_name == plugin_name]

    def filter_by_confidence(self, confidence: str) -> list[Result]:
        """Return results with a specific confidence level."""
        return [r for r in self._results if r.confidence == confidence]

    def exclude_rules(self, rule_ids: list[str]) -> list[Result]:
        """Return results excluding specific rule_ids."""
        exclude_set = set(rule_ids)
        return [r for r in self._results if r.rule_id not in exclude_set]

    def group_by_plugin(self) -> list[AlertGroup]:
        """Group results by plugin name."""
        groups: dict[str, AlertGroup] = {}
        for r in self._results:
            key = r.plugin_name or "unknown"
            if key not in groups:
                groups[key] = AlertGroup(key=key, label=f"Plugin: {key}")
            groups[key].results.append(r)
            if r.base_severity > groups[key].max_severity:
                groups[key].max_severity = r.base_severity
        return sorted(groups.values(), key=lambda g: g.max_severity, reverse=True)

    def group_by_severity(self) -> list[AlertGroup]:
        """Group results by severity level."""
        groups: dict[int, AlertGroup] = {}
        labels = {
            Severity.CRITICAL: "Critical", Severity.HIGH: "High",
            Severity.MEDIUM: "Medium", Severity.LOW: "Low", Severity.INFO: "Info",
        }
        for r in self._results:
            key = r.base_severity
            if key not in groups:
                groups[key] = AlertGroup(key=str(key), label=labels.get(key, "Unknown"), max_severity=key)
            groups[key].results.append(r)
        return sorted(groups.values(), key=lambda g: g.max_severity, reverse=True)

    def group_by_endpoint(self) -> list[AlertGroup]:
        """Group results by endpoint path."""
        groups: dict[str, AlertGroup] = {}
        for r in self._results:
            path = urlparse(r.endpoint).path if r.endpoint else "N/A"
            if path not in groups:
                groups[path] = AlertGroup(key=path, label=f"Endpoint: {path}")
            groups[path].results.append(r)
            if r.base_severity > groups[path].max_severity:
                groups[path].max_severity = r.base_severity
        return sorted(groups.values(), key=lambda g: g.max_severity, reverse=True)

    def group_by_cwe(self) -> list[AlertGroup]:
        """Group results by CWE ID."""
        groups: dict[str, AlertGroup] = {}
        for r in self._results:
            cwe = r.cwe_id or "No CWE"
            if cwe not in groups:
                groups[cwe] = AlertGroup(key=cwe, label=f"CWE: {cwe}")
            groups[cwe].results.append(r)
            if r.base_severity > groups[cwe].max_severity:
                groups[cwe].max_severity = r.base_severity
        return sorted(groups.values(), key=lambda g: g.max_severity, reverse=True)

    def deduplicate(self) -> list[Result]:
        """Remove duplicate results by (rule_id, endpoint, param_name)."""
        seen = set()
        deduped = []
        for r in self._results:
            key = (r.rule_id or "", r.endpoint or "", r.param_name or "")
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        return deduped

    def summary(self) -> dict:
        """Get a summary of all results."""
        sev_counts = defaultdict(int)
        plugin_counts = defaultdict(int)
        for r in self._results:
            sev_counts[r.base_severity] += 1
            plugin_counts[r.plugin_name] += 1
        return {
            "total": len(self._results),
            "by_severity": dict(sev_counts),
            "by_plugin": dict(plugin_counts),
            "unique_endpoints": len(set(r.endpoint for r in self._results if r.endpoint)),
            "unique_rules": len(set(r.rule_id for r in self._results if r.rule_id)),
        }
