"""Secure Code Gateway: scan staged files before git commit."""

from __future__ import annotations
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class GatewayConfig:
    """Gateway configuration."""
    fail_on_severity: str = "high"  # critical, high, medium, low
    max_findings: int = 0  # 0 = unlimited
    exclude_rules: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=lambda: ["*.py", "*.js", "*.ts", "*.java", "*.go", "*.php"])


@dataclass
class GatewayResult:
    """Result of a gateway scan."""
    passed: bool
    total_findings: int
    blocking_findings: int
    findings: list = field(default_factory=list)
    staged_files: list[str] = field(default_factory=list)
    message: str = ""


class CodeGateway:
    """Scans staged git changes to block insecure code."""

    def __init__(self, config: GatewayConfig | None = None):
        self.config = config or GatewayConfig()

    def get_staged_files(self, repo_path: str = ".") -> list[str]:
        """Get list of staged files from git."""
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                capture_output=True, text=True, cwd=repo_path, timeout=10,
            )
            if result.returncode != 0:
                return []
            files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
            # Filter by patterns
            from fnmatch import fnmatch
            filtered = []
            for f in files:
                if any(fnmatch(f, pat) for pat in self.config.include_patterns):
                    filtered.append(f)
            return filtered
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def evaluate(self, findings: list, staged_files: list[str]) -> GatewayResult:
        """Evaluate scan findings against gateway policy."""
        from vibee_hacker.core.models import Severity
        severity_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }
        min_sev = severity_map.get(self.config.fail_on_severity.lower(), Severity.HIGH)

        # Filter excluded rules
        exclude = set(self.config.exclude_rules)
        relevant = [f for f in findings if getattr(f, "rule_id", "") not in exclude]

        # Count blocking findings
        blocking = [f for f in relevant if getattr(f, "base_severity", 0) >= min_sev]

        # Check max findings
        if self.config.max_findings > 0 and len(relevant) > self.config.max_findings:
            passed = False
            message = f"Too many findings: {len(relevant)} > {self.config.max_findings}"
        elif blocking:
            passed = False
            message = f"{len(blocking)} finding(s) at or above {self.config.fail_on_severity} severity"
        else:
            passed = True
            message = f"Gateway passed ({len(relevant)} findings, none blocking)"

        return GatewayResult(
            passed=passed,
            total_findings=len(relevant),
            blocking_findings=len(blocking),
            findings=relevant,
            staged_files=staged_files,
            message=message,
        )
