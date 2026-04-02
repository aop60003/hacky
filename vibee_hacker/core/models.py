"""Core data models for VIBEE-Hacker.

Pydantic v2 models with backward-compatible interface (drop-in replacement
for the original dataclass-based models).
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(enum.IntEnum):
    """Vulnerability severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()


class Target(BaseModel):
    """Scan target definition."""

    url: Optional[str] = None
    path: Optional[str] = None
    mode: str = "blackbox"
    verify_ssl: bool = True
    proxy: Optional[str] = None
    delay: int = 0

    @model_validator(mode="after")
    def _validate_target(self) -> "Target":
        if self.mode == "blackbox" and not self.url:
            if self.path:
                return self  # whitebox fallback
        if self.mode == "whitebox" and not self.path:
            if self.url:
                return self  # blackbox fallback
        return self

    @property
    def host(self) -> Optional[str]:
        if self.url:
            return urlparse(self.url).hostname
        return None

    @property
    def port(self) -> Optional[int]:
        if self.url:
            parsed = urlparse(self.url)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == "https" else 80
        return None


class Result(BaseModel):
    """Scan result from a plugin."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    plugin_name: str
    base_severity: Severity
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    request_raw: str = ""
    response_raw: str = ""
    curl_command: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint: str = ""
    param_name: Optional[str] = None
    context_severity: Optional[Severity] = None
    validated: bool = False
    validation_count: int = 0
    confidence: str = "tentative"
    plugin_status: str = "completed"
    rule_id: str = ""

    @model_validator(mode="after")
    def _set_context_severity(self) -> "Result":
        if self.context_severity is None:
            self.context_severity = self.base_severity
        return self

    def to_dict(self) -> Dict[str, Any]:
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
            "validated": self.validated,
            "validation_count": self.validation_count,
            "plugin_status": self.plugin_status,
            "rule_id": self.rule_id,
            "timestamp": self.timestamp.isoformat(),
            "curl_command": self.curl_command,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
        }


class InterPhaseContext(BaseModel):
    """Shared state passed between phases and plugins."""

    waf_info: Optional[Dict[str, Any]] = None
    waf_bypass_payloads: Optional[Dict[str, Any]] = None
    tech_stack: List[str] = Field(default_factory=list)
    ssrf_endpoints: List[str] = Field(default_factory=list)
    dangling_cnames: List[str] = Field(default_factory=list)
    discovered_api_schema: Optional[Dict[str, Any]] = None
    # Crawler results shared with later phases
    crawl_urls: List[str] = Field(default_factory=list)
    crawl_forms: List[Dict[str, Any]] = Field(default_factory=list)
    crawl_parameters: Dict[str, List[str]] = Field(default_factory=dict)
    crawl_status: str = "ok"
