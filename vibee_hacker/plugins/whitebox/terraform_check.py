"""Plugin: Terraform Security Check (Phase 5, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor", ".terraform"}

_LINE_CHECKS: list[tuple[str, re.Pattern, Severity, str, str, str]] = [
    (
        "terraform_s3_public",
        re.compile(r'acl\s*=\s*["\']public-read(-write)?["\']', re.IGNORECASE),
        Severity.CRITICAL,
        "S3 bucket with public ACL",
        "Public-read ACL exposes all bucket objects to the internet.",
        'Change `acl` to "private" and use bucket policies for controlled access.',
    ),
    (
        "terraform_encrypted_false",
        re.compile(r'\bencrypted\s*=\s*false\b', re.IGNORECASE),
        Severity.HIGH,
        "Resource with encryption explicitly disabled",
        "Disabling encryption leaves data at rest unprotected.",
        "Set `encrypted = true` and specify a KMS key for encryption at rest.",
    ),
    (
        "terraform_iam_wildcard",
        re.compile(r'(?:actions|Action)\s*=\s*\[[^\]]*"\*"[^\]]*\]', re.IGNORECASE),
        Severity.CRITICAL,
        "IAM policy with wildcard (*) actions",
        'Using "*" in IAM actions grants excessive permissions.',
        "Restrict IAM actions to the minimum required set (principle of least privilege).",
    ),
    (
        "terraform_no_mfa_delete",
        re.compile(r'\bmfa_delete\s*=\s*["\']?Disabled["\']?', re.IGNORECASE),
        Severity.MEDIUM,
        "S3 bucket versioning without MFA delete",
        "MFA delete disabled allows accidental or malicious permanent deletion.",
        'Set `mfa_delete = "Enabled"` for critical buckets.',
    ),
]

# Open ingress on non-443 ports
_CIDR_ZERO = re.compile(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"[^\]]*\]', re.IGNORECASE)
_PORT_LINE = re.compile(r'(?:from_port|to_port)\s*=\s*(\d+)', re.IGNORECASE)


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _check_open_ingress(content: str, tf_path: Path, root: Path) -> list[Result]:
    """Detect ingress rules open to 0.0.0.0/0 on non-443 ports."""
    results: list[Result] = []
    rel = tf_path.relative_to(root)

    # Split into resource blocks for context-aware analysis
    # We search for occurrences of cidr_blocks with 0.0.0.0/0
    for match in _CIDR_ZERO.finditer(content):
        line_num = content[: match.start()].count("\n") + 1
        # Look backward for port info within the same block (~30 lines)
        block_start = max(0, match.start() - 800)
        block = content[block_start : match.end()]

        ports = [int(m.group(1)) for m in _PORT_LINE.finditer(block)]
        # If any port is not 443, flag it
        non_https_ports = [p for p in ports if p != 443]
        if non_https_ports or not ports:
            line_text = content.splitlines()[line_num - 1].strip()
            results.append(
                Result(
                    plugin_name="terraform_check",
                    base_severity=Severity.CRITICAL,
                    title="Security group ingress open to 0.0.0.0/0 on non-HTTPS port",
                    description=(
                        f"Ingress rule allows traffic from any IP on port(s) {non_https_ports or 'unknown'}. "
                        f"Found in '{rel}' at line {line_num}."
                    ),
                    evidence=f"{rel}:{line_num}: {line_text[:120]}",
                    recommendation="Restrict cidr_blocks to known IP ranges; never use 0.0.0.0/0 except for port 443.",
                    cwe_id="CWE-284",
                    rule_id="terraform_open_ingress",
                    endpoint=str(tf_path),
                )
            )

    return results


class TerraformCheckPlugin(PluginBase):
    name = "terraform_check"
    description = "Scan Terraform files for cloud infrastructure security misconfigurations"
    category = "whitebox"
    phase = 5
    base_severity = Severity.CRITICAL

    def is_applicable(self, target: Target) -> bool:
        return target.path is not None

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for tf_path in root.rglob("*.tf"):
            if not tf_path.is_file() or _should_skip(tf_path):
                continue
            try:
                content = tf_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = tf_path.relative_to(root)

            for rule_id, pattern, severity, title, description, recommendation in _LINE_CHECKS:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    line_text = content.splitlines()[line_num - 1].strip()
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=severity,
                            title=title,
                            description=f"{description} Found in '{rel}' at line {line_num}.",
                            evidence=f"{rel}:{line_num}: {line_text[:120]}",
                            recommendation=recommendation,
                            cwe_id="CWE-284",
                            rule_id=rule_id,
                            endpoint=str(tf_path),
                        )
                    )

            results.extend(_check_open_ingress(content, tf_path, root))

        return results
