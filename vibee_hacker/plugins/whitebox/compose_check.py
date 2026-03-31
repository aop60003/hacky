"""Plugin: Docker Compose Security Check (Phase 5, MEDIUM)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"}

# privileged: true
_PRIVILEGED = re.compile(r'^\s*privileged\s*:\s*true\b', re.IGNORECASE | re.MULTILINE)

# Ports bound to 0.0.0.0 (e.g. "0.0.0.0:8080:8080" or just "8080:8080" which defaults to 0.0.0.0)
_PORT_EXPOSED = re.compile(
    r'["\']?(?:0\.0\.0\.0:)?\d+:\d+["\']?',
    re.IGNORECASE,
)
_PORT_BOUND_ALL = re.compile(
    r'["\']?0\.0\.0\.0:\d+:\d+["\']?',
    re.IGNORECASE,
)

# Sensitive volume mounts
_SENSITIVE_MOUNTS = [
    (re.compile(r'(?:^|["\'\s:])(/var/run/docker\.sock)["\'\s:]?', re.IGNORECASE), "docker socket"),
    (re.compile(r'(?:^|["\'\s:])(/etc)(?:/|["\'\s:])', re.IGNORECASE), "/etc directory"),
    (re.compile(r'(?:^|["\'\s:])(/)["\'\s:]', re.IGNORECASE), "root filesystem"),
]

# Plaintext secrets in environment variables
_PLAINTEXT_ENV_SECRET = re.compile(
    r'(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\s*=\s*[^\s${\n]{4,}',
    re.IGNORECASE,
)


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _is_compose_file(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith("docker-compose") and path.suffix.lower() in (".yml", ".yaml")


class ComposeCheckPlugin(PluginBase):
    name = "compose_check"
    description = "Scan docker-compose files for security misconfigurations"
    category = "whitebox"
    phase = 5
    base_severity = Severity.MEDIUM

    def is_applicable(self, target: Target) -> bool:
        return target.path is not None

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        compose_files = [
            p for p in root.rglob("docker-compose*.y*ml")
            if p.is_file() and _is_compose_file(p) and not _should_skip(p)
        ]

        for cf_path in compose_files:
            try:
                content = cf_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = cf_path.relative_to(root)

            # privileged: true
            for match in _PRIVILEGED.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="Docker Compose service running in privileged mode",
                        description=(
                            "privileged: true grants the container nearly all host capabilities. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation="Remove `privileged: true`; grant only required capabilities via `cap_add`.",
                        cwe_id="CWE-250",
                        rule_id="compose_privileged",
                        endpoint=str(cf_path),
                    )
                )

            # Ports bound to 0.0.0.0
            for match in _PORT_BOUND_ALL.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="Port exposed on all interfaces (0.0.0.0)",
                        description=(
                            "Binding to 0.0.0.0 exposes the port on all network interfaces including public ones. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation="Bind to 127.0.0.1 for local-only access, e.g. `127.0.0.1:8080:8080`.",
                        cwe_id="CWE-250",
                        rule_id="compose_exposed_port",
                        endpoint=str(cf_path),
                    )
                )

            # Sensitive volume mounts
            for pattern, label in _SENSITIVE_MOUNTS:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    line_text = content.splitlines()[line_num - 1].strip()
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.CRITICAL,
                            title=f"Sensitive host path mounted into container: {label}",
                            description=(
                                f"Mounting {label} gives the container access to sensitive host data. "
                                f"Found in '{rel}' at line {line_num}."
                            ),
                            evidence=f"{rel}:{line_num}: {line_text[:120]}",
                            recommendation=(
                                f"Remove the {label} mount. Use named volumes for data persistence "
                                "and avoid mounting host system directories."
                            ),
                            cwe_id="CWE-250",
                            rule_id="compose_sensitive_mount",
                            endpoint=str(cf_path),
                        )
                    )

            # Plaintext secrets in environment
            for match in _PLAINTEXT_ENV_SECRET.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="Potential plaintext secret in docker-compose environment",
                        description=(
                            "An environment variable with a secret-like name contains a plaintext value. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation=(
                            "Use Docker secrets or reference variables from a .env file "
                            "that is excluded from version control via .gitignore."
                        ),
                        cwe_id="CWE-250",
                        rule_id="compose_plaintext_secret",
                        endpoint=str(cf_path),
                    )
                )

        return results
