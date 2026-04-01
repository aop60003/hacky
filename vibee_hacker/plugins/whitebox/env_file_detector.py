"""Plugin 4: .env File Detector (Phase 1, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

ENV_PATTERNS = [
    re.compile(r"(?i)(KEY|SECRET|PASSWORD|TOKEN|PASS|PWD|API_KEY|APIKEY|AUTH)\s*=\s*\S+"),
]

ENV_FILE_GLOBS = [".env", ".env.local", ".env.production", ".env.development", ".env.staging"]


class EnvFileDetectorPlugin(PluginBase):
    name = "env_file_detector"
    description = "Detect committed .env files containing secrets"
    category = "whitebox"
    phase = 1
    base_severity = Severity.CRITICAL

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        # Search for .env files recursively
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            # Match .env, .env.local, .env.production, etc.
            if not (f.name == ".env" or f.name.startswith(".env.")):
                continue
            try:
                content = f.read_text(errors="ignore")
            except OSError:
                continue

            secret_lines: list[str] = []
            for line in content.splitlines():
                for pat in ENV_PATTERNS:
                    if pat.search(line):
                        # Redact the value
                        redacted = re.sub(r"(=\s*)\S+", r"\1[REDACTED]", line)
                        secret_lines.append(redacted)
                        break

            if secret_lines:
                evidence = f"File: {f.relative_to(root)}; Secrets found: {'; '.join(secret_lines[:5])}"
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title=f"Committed .env File with Secrets: {f.name}",
                        description=(
                            f"The file '{f.relative_to(root)}' appears to contain sensitive credentials "
                            "and should not be committed to source control."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Remove the .env file from version control, rotate all exposed credentials, "
                            "and add .env* to .gitignore."
                        ),
                        cwe_id="CWE-798",
                        rule_id="env_file_committed",
                        endpoint=str(f),
                    )
                )

        return results
