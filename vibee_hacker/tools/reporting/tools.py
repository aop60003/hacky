"""Structured finding reporting with CVSS scoring.

Allows the agent to record vulnerability findings in a structured
format with CVSS vectors, code locations, and fix suggestions.
Follows Strix's reporting pattern.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

_findings: List[Dict[str, Any]] = []
_lock = threading.Lock()

CVSS_SEVERITY = {
    (0.0, 0.1): "none",
    (0.1, 4.0): "low",
    (4.0, 7.0): "medium",
    (7.0, 9.0): "high",
    (9.0, 10.1): "critical",
}


def _cvss_to_severity(score: float) -> str:
    for (lo, hi), sev in CVSS_SEVERITY.items():
        if lo <= score < hi:
            return sev
    return "info"


@register_tool(
    description="Record a structured vulnerability finding with CVSS score, "
    "affected endpoint, evidence, code location, and fix suggestion.",
)
def add_finding(
    title: str,
    description: str,
    severity: str = "medium",
    cvss_score: Optional[float] = None,
    cvss_vector: Optional[str] = None,
    endpoint: Optional[str] = None,
    evidence: Optional[str] = None,
    request: Optional[str] = None,
    response: Optional[str] = None,
    cwe_id: Optional[str] = None,
    fix_description: Optional[str] = None,
    fix_before: Optional[str] = None,
    fix_after: Optional[str] = None,
    code_file: Optional[str] = None,
    code_line: Optional[int] = None,
) -> Dict[str, Any]:
    """Record a vulnerability finding.

    Args:
        title: Finding title (e.g., "SQL Injection in /api/users").
        description: Detailed description of the vulnerability.
        severity: critical/high/medium/low/info (auto-set from CVSS if provided).
        cvss_score: CVSS v3.1 base score (0.0-10.0).
        cvss_vector: CVSS vector string (e.g., "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N").
        endpoint: Affected URL or endpoint.
        evidence: Proof of vulnerability (payload, response excerpt).
        request: Raw HTTP request that demonstrates the issue.
        response: Raw HTTP response showing the vulnerability.
        cwe_id: CWE identifier (e.g., "CWE-89").
        fix_description: How to fix the vulnerability.
        fix_before: Vulnerable code snippet.
        fix_after: Fixed code snippet.
        code_file: Source file path (for whitebox findings).
        code_line: Line number in source file.
    """
    if cvss_score is not None:
        severity = _cvss_to_severity(cvss_score)

    finding_id = f"finding-{uuid4().hex[:8]}"
    finding = {
        "id": finding_id,
        "title": title,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "endpoint": endpoint,
        "evidence": evidence,
        "request": request,
        "response": response,
        "cwe_id": cwe_id,
        "fix": {
            "description": fix_description,
            "before": fix_before,
            "after": fix_after,
        } if fix_description else None,
        "code_location": {
            "file": code_file,
            "line": code_line,
        } if code_file else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    with _lock:
        _findings.append(finding)

    logger.info("Finding recorded: [%s] %s", severity.upper(), title)
    return {"id": finding_id, "severity": severity, "title": title}


@register_tool(description="List all recorded findings with severity summary.")
def list_findings() -> Dict[str, Any]:
    """Get all recorded findings."""
    with _lock:
        severity_counts: Dict[str, int] = {}
        for f in _findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "findings": [
                {
                    "id": f["id"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "endpoint": f.get("endpoint"),
                    "cvss_score": f.get("cvss_score"),
                }
                for f in _findings
            ],
            "severity_summary": severity_counts,
            "total": len(_findings),
        }


@register_tool(description="Get full details of a specific finding by ID.")
def get_finding(finding_id: str) -> Dict[str, Any]:
    """Get full finding details."""
    with _lock:
        for f in _findings:
            if f["id"] == finding_id:
                return dict(f)
    return {"error": f"Finding {finding_id} not found"}


def get_all_findings() -> List[Dict[str, Any]]:
    """Get all findings (internal API, not a tool)."""
    with _lock:
        return list(_findings)
