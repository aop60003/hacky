"""Plugin: GitLab CI Security Check (Phase 5, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"}

# curl or wget piped to sh or bash
_CURL_PIPE_SHELL = re.compile(
    r'(?:curl|wget)\s+[^\n]*\|\s*(?:ba)?sh\b',
    re.IGNORECASE,
)

# allow_failure: true (security-sensitive jobs should not silently pass)
_ALLOW_FAILURE = re.compile(r'^\s*allow_failure\s*:\s*true\b', re.IGNORECASE | re.MULTILINE)

# Variables defined without masked/protected markers
# Pattern: variable assignment with an unquoted or plain value (heuristic)
_PLAIN_VARIABLE = re.compile(
    r'(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\s*:\s*["\']?[A-Za-z0-9_\-]{6,}["\']?',
    re.IGNORECASE,
)

# Unprotected runner tags: tags: section with generic names
_UNPROTECTED_TAG = re.compile(
    r'^\s*tags\s*:\s*\n(?:\s*-\s*(?:shared|default|any|all|generic)\b.*\n)+',
    re.IGNORECASE | re.MULTILINE,
)


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


class GitLabCICheckPlugin(PluginBase):
    name = "gitlab_ci_check"
    description = "Scan .gitlab-ci.yml for security misconfigurations"
    category = "whitebox"
    phase = 5
    base_severity = Severity.HIGH

    def is_applicable(self, target: Target) -> bool:
        return target.path is not None

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        # Find .gitlab-ci.yml anywhere in the tree
        ci_files: list[Path] = []
        for candidate in root.rglob(".gitlab-ci.yml"):
            if candidate.is_file() and not _should_skip(candidate):
                ci_files.append(candidate)

        for ci_path in ci_files:
            try:
                content = ci_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = ci_path.relative_to(root)

            # curl/wget piped to shell
            for match in _CURL_PIPE_SHELL.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title="Remote script executed via curl/wget piped to shell",
                        description=(
                            "Piping curl/wget output directly to sh/bash executes arbitrary remote code "
                            f"without verification. Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation=(
                            "Download the script separately, verify its checksum, "
                            "then execute it in a separate step."
                        ),
                        cwe_id="CWE-78",
                        rule_id="gitlab_ci_curl_pipe_shell",
                        endpoint=str(ci_path),
                    )
                )

            # allow_failure: true
            for match in _ALLOW_FAILURE.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="allow_failure: true may silence security job failures",
                        description=(
                            "Jobs with allow_failure: true will not block the pipeline on failure, "
                            f"potentially hiding security issues. Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation=(
                            "Remove allow_failure: true from security-critical jobs, "
                            "or use when: on_failure rules instead."
                        ),
                        cwe_id="CWE-78",
                        rule_id="gitlab_ci_allow_failure",
                        endpoint=str(ci_path),
                    )
                )

            # Plaintext secrets in variables
            for match in _PLAIN_VARIABLE.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="Potential plaintext secret in CI variables",
                        description=(
                            "A variable with a secret-like name appears to contain a hardcoded value. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation=(
                            "Use GitLab CI/CD protected and masked variables for secrets; "
                            "never hardcode credentials in .gitlab-ci.yml."
                        ),
                        cwe_id="CWE-78",
                        rule_id="gitlab_ci_plaintext_secret",
                        endpoint=str(ci_path),
                    )
                )

        return results
