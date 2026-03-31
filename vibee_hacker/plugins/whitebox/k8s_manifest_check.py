"""Plugin: Kubernetes Manifest Security Check (Phase 5, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"}

# Kubernetes-specific markers to distinguish from other YAML files
_K8S_MARKERS = re.compile(
    r"^\s*(apiVersion|kind)\s*:", re.MULTILINE
)

_LINE_CHECKS: list[tuple[str, re.Pattern, str, str, str]] = [
    (
        "k8s_privileged",
        re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE | re.MULTILINE),
        "Kubernetes container running in privileged mode",
        "privileged: true gives the container nearly all host capabilities.",
        "Remove `privileged: true` and grant only specific capabilities if needed.",
    ),
    (
        "k8s_host_network",
        re.compile(r"^\s*hostNetwork\s*:\s*true\b", re.IGNORECASE | re.MULTILINE),
        "Kubernetes pod using host network namespace",
        "hostNetwork: true allows the pod to sniff all traffic on the node.",
        "Remove `hostNetwork: true`; use Services/Ingress for network exposure instead.",
    ),
    (
        "k8s_run_as_root",
        re.compile(
            r"^\s*(runAsRoot\s*:\s*true|runAsUser\s*:\s*0)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        "Kubernetes container configured to run as root (UID 0)",
        "Running as UID 0 inside a container escalates risk if the container is compromised.",
        "Set `runAsNonRoot: true` and `runAsUser` to a non-zero UID.",
    ),
    (
        "k8s_host_pid",
        re.compile(r"^\s*hostPID\s*:\s*true\b", re.IGNORECASE | re.MULTILINE),
        "Kubernetes pod sharing host PID namespace",
        "hostPID: true allows the pod to see and signal all processes on the node.",
        "Remove `hostPID: true` unless absolutely required.",
    ),
]

# imagePullPolicy should be Always for non-digest images
_IMAGE_PULL_POLICY = re.compile(
    r"^\s*imagePullPolicy\s*:\s*(?!Always)(Never|IfNotPresent)\b",
    re.IGNORECASE | re.MULTILINE,
)


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _is_k8s_manifest(content: str) -> bool:
    return bool(_K8S_MARKERS.search(content))


class K8sManifestCheckPlugin(PluginBase):
    name = "k8s_manifest_check"
    description = "Scan Kubernetes YAML manifests for security misconfigurations"
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

        for yaml_path in root.rglob("*.y*ml"):
            if not yaml_path.is_file() or _should_skip(yaml_path):
                continue
            if yaml_path.suffix.lower() not in (".yaml", ".yml"):
                continue
            try:
                content = yaml_path.read_text(errors="ignore")
            except OSError:
                continue

            if not _is_k8s_manifest(content):
                continue

            rel = yaml_path.relative_to(root)

            for rule_id, pattern, title, description, recommendation in _LINE_CHECKS:
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
                            endpoint=str(yaml_path),
                        )
                    )

            # imagePullPolicy check
            for match in _IMAGE_PULL_POLICY.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="imagePullPolicy not set to Always",
                        description=(
                            f"imagePullPolicy is not Always; stale or tampered images may be used. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation="Set `imagePullPolicy: Always` for mutable image tags.",
                        cwe_id="CWE-250",
                        rule_id="k8s_image_pull_policy",
                        endpoint=str(yaml_path),
                    )
                )

        return results
