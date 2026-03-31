"""Plugin: Dockerfile Security Check (Phase 5, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"}


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


# (rule_id, pattern, title, description, recommendation)
_CHECKS: list[tuple[str, re.Pattern, str, str, str]] = [
    (
        "dockerfile_user_root",
        re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE | re.MULTILINE),
        "Dockerfile runs as root (USER root)",
        "Explicitly running as root inside a container grants excessive privileges.",
        "Add a non-root user via `RUN useradd -m appuser` and switch with `USER appuser`.",
    ),
    (
        "dockerfile_latest_tag",
        re.compile(r"^\s*FROM\s+\S+:latest(\s|$)", re.IGNORECASE | re.MULTILINE),
        "Unpinned base image using :latest tag",
        "Using :latest makes builds non-reproducible and may pull vulnerable images.",
        "Pin to a specific digest or version tag, e.g. `FROM ubuntu:22.04`.",
    ),
    (
        "dockerfile_copy_all",
        re.compile(r"^\s*COPY\s+\.\s+\.", re.MULTILINE),
        "COPY . . may include secrets or sensitive files",
        "`COPY . .` copies everything including .env files, credentials, and source secrets.",
        "Use .dockerignore to exclude sensitive files, or copy only specific directories.",
    ),
    (
        "dockerfile_privileged",
        re.compile(r"^\s*RUN\s+--privileged\b", re.IGNORECASE | re.MULTILINE),
        "RUN with --privileged flag",
        "Running privileged build steps grants full host access during build.",
        "Remove --privileged from RUN instructions and redesign the build step.",
    ),
    (
        "dockerfile_no_user",
        re.compile(r"^\s*USER\b", re.IGNORECASE | re.MULTILINE),
        "No USER directive found — container runs as root by default",
        "Without a USER directive Docker defaults to root which increases attack surface.",
        "Add `USER nonroot` or a dedicated application user before the CMD/ENTRYPOINT.",
    ),
]

_FROM_PATTERN = re.compile(r"^\s*FROM\b", re.IGNORECASE | re.MULTILINE)
_USER_PATTERN = re.compile(r"^\s*USER\b", re.IGNORECASE | re.MULTILINE)


class DockerfileCheckPlugin(PluginBase):
    name = "dockerfile_check"
    description = "Scan Dockerfiles for security misconfigurations"
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

        # Find Dockerfile* files
        dockerfile_paths: list[Path] = []
        for candidate in root.rglob("Dockerfile*"):
            if candidate.is_file() and not _should_skip(candidate):
                dockerfile_paths.append(candidate)

        for df_path in dockerfile_paths:
            try:
                content = df_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = df_path.relative_to(root)

            # Check explicit USER root and :latest
            for rule_id, pattern, title, description, recommendation in _CHECKS[:4]:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    line_text = content.splitlines()[line_num - 1].strip()
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title=title,
                            description=f"{description} Found in '{rel}' at line {line_num}.",
                            evidence=f"{rel}:{line_num}: {line_text[:120]}",
                            recommendation=recommendation,
                            cwe_id="CWE-250",
                            rule_id=rule_id,
                            endpoint=str(df_path),
                        )
                    )

            # Check for missing USER directive (no USER at all, but has FROM)
            if _FROM_PATTERN.search(content) and not _USER_PATTERN.search(content):
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title=_CHECKS[4][2],
                        description=f"{_CHECKS[4][3]} In '{rel}'.",
                        evidence=f"{rel}: no USER directive found",
                        recommendation=_CHECKS[4][4],
                        cwe_id="CWE-250",
                        rule_id="dockerfile_no_user",
                        endpoint=str(df_path),
                    )
                )

        return results
