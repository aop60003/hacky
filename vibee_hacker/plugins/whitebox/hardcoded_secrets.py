"""Plugin 5: Hardcoded Secrets Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import math
import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Regex patterns for known secret formats
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private Key", re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----")),
    ("Password Assignment", re.compile(r'(?i)password\s*[=:]\s*["\'][^"\']{4,}["\']')),
    ("API Key Assignment", re.compile(r'(?i)api_?key\s*[=:]\s*["\'][^"\']{4,}["\']')),
    ("Secret Assignment", re.compile(r'(?i)secret\s*[=:]\s*["\'][^"\']{4,}["\']')),
    ("Token Assignment", re.compile(r'(?i)token\s*[=:]\s*["\'][^"\']{8,}["\']')),
]

# Skip these false-positive patterns
FP_PATTERNS = [
    # Template/placeholder values only — do NOT match generic words like 'example' in code
    re.compile(r'(?i)(your[_\-]?password|your[_\-]?secret|your[_\-]?api[_\-]?key|changeme|<[^>]+>|\$\{[^}]+\}|%s|%\([^)]+\)s|os\.environ|getenv|environ\.get)'),
    re.compile(r'(?i)(password\s*[=:]\s*["\']?\s*["\']?\s*$)'),  # empty password
]

HIGH_ENTROPY_PATTERN = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']')


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_false_positive(line: str) -> bool:
    return any(pat.search(line) for pat in FP_PATTERNS)



class HardcodedSecretsPlugin(PluginBase):
    name = "hardcoded_secrets"
    description = "Detect hardcoded secrets, credentials, and high-entropy strings in source code"
    category = "whitebox"
    phase = 2
    base_severity = Severity.CRITICAL

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            # Only scan text-like files
            if src_file.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".ico", ".bin", ".exe", ".pyc"):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                if _is_false_positive(line):
                    continue

                # Check known patterns
                for label, pat in SECRET_PATTERNS:
                    match = pat.search(line)
                    if match:
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Hardcoded Secret Detected: {label}",
                                description=(
                                    f"A potential hardcoded secret was found in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Remove the hardcoded secret, store it in environment variables "
                                    "or a secrets manager, and rotate the exposed credential immediately."
                                ),
                                cwe_id="CWE-798",
                                rule_id="hardcoded_secret",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

                else:
                    # High-entropy string check
                    for m in HIGH_ENTROPY_PATTERN.finditer(line):
                        candidate = m.group(1)
                        if _shannon_entropy(candidate) > 4.5:
                            results.append(
                                Result(
                                    plugin_name=self.name,
                                    base_severity=Severity.CRITICAL,
                                    title="High-Entropy String (Possible Secret)",
                                    description=(
                                        f"A high-entropy string was found in "
                                        f"'{src_file.relative_to(root)}' at line {lineno} — "
                                        "likely a hardcoded secret or key."
                                    ),
                                    evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                    recommendation=(
                                        "Verify whether the string is a secret. If so, move it to "
                                        "environment variables or a secrets manager."
                                    ),
                                    cwe_id="CWE-798",
                                    rule_id="hardcoded_secret",
                                    endpoint=str(src_file),
                                )
                            )
                            break  # one result per line

        return results
