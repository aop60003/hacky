"""Plugin: Go Insecure Configuration Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern, cwe)
CONFIG_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("math/rand (weak randomness)", re.compile(r'"math/rand"'), "CWE-330"),
    ("http.Server without timeout", re.compile(
        r'&http\.Server\s*\{'
    ), "CWE-400"),
    ("CORS Allow-Origin: *", re.compile(
        r'(?:Access-Control-Allow-Origin|Allow-Origin)[^"\']*["\'][*]["\']',
        re.IGNORECASE
    ), "CWE-942"),
    ("w.Header().Set Allow-Origin *", re.compile(
        r'\.Header\(\)\.Set\s*\([^)]*\*[^)]*\)',
        re.IGNORECASE
    ), "CWE-942"),
]


class GoConfigCheckPlugin(PluginBase):
    name = "go_config_check"
    description = "Detect insecure Go configurations (math/rand, missing server timeouts, wildcard CORS)"
    category = "whitebox"
    phase = 2
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*.go"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            # For math/rand: only flag if crypto/rand is NOT also imported
            has_crypto_rand = '"crypto/rand"' in content

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, cwe in CONFIG_PATTERNS:
                    if pat.search(line):
                        # Skip math/rand if crypto/rand is used
                        if "math/rand" in line and has_crypto_rand:
                            continue
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Insecure Go Configuration: {label}",
                                description=(
                                    f"Insecure Go configuration '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This may lead to weak randomness, DoS, or CORS bypass attacks."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Address the insecure configuration for '{label}': "
                                    "use crypto/rand instead of math/rand, set server read/write timeouts, "
                                    "and restrict CORS allowed origins."
                                ),
                                cwe_id=cwe,
                                rule_id="go_insecure_config",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
