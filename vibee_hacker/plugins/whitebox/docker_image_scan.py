"""Docker image security scanner — analyzes Dockerfile and image configs."""

from __future__ import annotations
import os
import re

from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Result, Severity, Target

DANGEROUS_INSTRUCTIONS = {
    r"curl\s+.*\|\s*(bash|sh)": ("Pipe to shell from curl", Severity.HIGH, "CWE-829"),
    r"wget\s+.*\|\s*(bash|sh)": ("Pipe to shell from wget", Severity.HIGH, "CWE-829"),
    r"ADD\s+https?://": ("ADD from remote URL", Severity.MEDIUM, "CWE-829"),
    r"ENV\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=": ("Secret in ENV", Severity.CRITICAL, "CWE-798"),
    r"--allow-root": ("Running as root explicitly", Severity.MEDIUM, "CWE-250"),
    r"chmod\s+777": ("World-writable permissions", Severity.HIGH, "CWE-732"),
    r"apt-get\s+install(?!.*--no-install-recommends)": (
        "Install without --no-install-recommends",
        Severity.LOW,
        "CWE-1104",
    ),
    r"apk\s+add(?!.*--no-cache)": ("APK add without --no-cache", Severity.LOW, "CWE-1104"),
}


class DockerImageScanPlugin(PluginBase):
    name = "docker_image_scan"
    description = "Advanced Docker image security analysis"
    category = "whitebox"
    phase = 2
    destructive_level = 0

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.path:
            return []
        results: list[Result] = []
        for root, _dirs, files in os.walk(target.path):
            for f in files:
                if f in ("Dockerfile", "Containerfile") or f.startswith("Dockerfile."):
                    filepath = os.path.join(root, f)
                    results.extend(self._scan_dockerfile(filepath))
                    if len(results) >= 30:
                        return results[:30]
        return results

    def _scan_dockerfile(self, filepath: str) -> list[Result]:
        results: list[Result] = []
        try:
            with open(filepath, encoding="utf-8") as f:
                content = f.read()
                lines = content.split("\n")
        except (OSError, UnicodeDecodeError):
            return []

        for pattern, (title, severity, cwe) in DANGEROUS_INSTRUCTIONS.items():
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=severity,
                            title=f"Docker: {title}",
                            description=f"Found in {filepath}:{i}: {line.strip()[:100]}",
                            endpoint=filepath,
                            rule_id=f"docker_{re.sub(r'[^a-z0-9]', '_', title.lower())}",
                            cwe_id=cwe,
                            recommendation="Review and fix the Dockerfile instruction.",
                        )
                    )

        # Check for missing HEALTHCHECK
        if "HEALTHCHECK" not in content:
            results.append(
                Result(
                    plugin_name=self.name,
                    base_severity=Severity.LOW,
                    title="Docker: No HEALTHCHECK instruction",
                    description=f"Dockerfile {filepath} has no HEALTHCHECK.",
                    endpoint=filepath,
                    rule_id="docker_no_healthcheck",
                    cwe_id="CWE-693",
                    recommendation="Add a HEALTHCHECK instruction.",
                )
            )

        # Check for :latest tag
        for line in lines:
            if re.match(r"FROM\s+\S+:latest", line, re.IGNORECASE):
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="Docker: Using :latest tag",
                        description=f"FROM with :latest tag is not reproducible: {line.strip()[:80]}",
                        endpoint=filepath,
                        rule_id="docker_latest_tag",
                        cwe_id="CWE-1104",
                        recommendation="Pin to a specific image version.",
                    )
                )

        return results
