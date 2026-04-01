"""Plugin 9: Insecure JWT Usage Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

JWT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "JWT signature verification disabled (verify=False)",
        re.compile(r'jwt\.decode\s*\([^)]*verify\s*=\s*False'),
        "Disabling JWT verification allows forged tokens to be accepted.",
    ),
    (
        "JWT signature verification disabled (verify_signature=False)",
        re.compile(r'options\s*=\s*\{[^}]*["\']verify_signature["\']\s*:\s*False'),
        "Setting verify_signature=False bypasses JWT integrity checks.",
    ),
    (
        "JWT 'none' algorithm",
        # Match: algorithms=["none"], algorithms=['none'], algorithm="none", algorithm='none'
        re.compile(r'''algorithms?\s*=\s*(?:\[['"]none['"]\]|['"]none['"])''', re.IGNORECASE),
        "The 'none' algorithm disables JWT signing entirely.",
    ),
    (
        "Hardcoded JWT secret",
        re.compile(r'jwt\.encode\s*\([^,]+,\s*["\'][^"\']{1,30}["\']'),
        "Hardcoded JWT secrets can be discovered and used to forge tokens.",
    ),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class InsecureJwtPlugin(PluginBase):
    name = "insecure_jwt"
    description = "Detect insecure JWT usage patterns like disabled verification or 'none' algorithm"
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
            if not src_file.is_file() or _should_skip(src_file):
                continue
            if src_file.suffix.lower() not in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".go"):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for label, pat, rationale in JWT_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Insecure JWT Usage: {label}",
                                description=(
                                    f"{rationale} Found in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Always verify JWT signatures, specify allowed algorithms explicitly, "
                                    "and store secrets in environment variables."
                                ),
                                cwe_id="CWE-347",
                                rule_id="insecure_jwt",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
