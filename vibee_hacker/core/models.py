"""Core data models for VIBEE-Hacker."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse


class Severity(enum.IntEnum):
    """Vulnerability severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Target:
    """Scan target definition."""
    url: str | None = None
    path: str | None = None
    mode: str = "blackbox"

    @property
    def host(self) -> str | None:
        if self.url:
            return urlparse(self.url).hostname
        return None

    @property
    def port(self) -> int | None:
        if self.url:
            parsed = urlparse(self.url)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == "https" else 80
        return None


@dataclass
class Result:
    """Scan result from a plugin."""
    plugin_name: str
    base_severity: Severity
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: str | None = None
    cvss_score: float | None = None
    request_raw: str = ""
    response_raw: str = ""
    curl_command: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint: str = ""
    param_name: str | None = None
    context_severity: Severity | None = None
    validated: bool = False
    validation_count: int = 0
    confidence: str = "tentative"
    plugin_status: str = "completed"
    rule_id: str = ""

    def __post_init__(self):
        if self.context_severity is None:
            self.context_severity = self.base_severity

    def to_dict(self) -> dict:
        return {
            "plugin_name": self.plugin_name,
            "base_severity": str(self.base_severity),
            "context_severity": str(self.context_severity),
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "endpoint": self.endpoint,
            "param_name": self.param_name,
            "confidence": self.confidence,
            "plugin_status": self.plugin_status,
            "rule_id": self.rule_id,
            "timestamp": self.timestamp.isoformat(),
            "curl_command": self.curl_command,
        }


@dataclass
class InterPhaseContext:
    """Shared state passed between phases and plugins."""
    waf_info: dict | None = None
    waf_bypass_payloads: dict | None = None
    tech_stack: list[str] = field(default_factory=list)
    ssrf_endpoints: list[str] = field(default_factory=list)
    dangling_cnames: list[str] = field(default_factory=list)
    discovered_api_schema: dict | None = None
