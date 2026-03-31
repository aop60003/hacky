"""Plugin 7: Insecure Cryptographic Usage Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

CRYPTO_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "MD5 used for hashing",
        re.compile(r'hashlib\.md5\s*\('),
        "MD5 is cryptographically broken and should not be used for password hashing or integrity checks.",
    ),
    (
        "SHA-1 used for hashing",
        re.compile(r'hashlib\.sha1\s*\('),
        "SHA-1 is deprecated and collision-prone; use SHA-256 or higher.",
    ),
    (
        "Insecure random for security purposes",
        re.compile(r'random\.random\s*\(\)|random\.randint\s*\(|random\.choice\s*\('),
        "random module is not cryptographically secure; use secrets module instead.",
    ),
    (
        "AES ECB mode",
        re.compile(r'AES\.(new|MODE_ECB|encrypt)\s*\(.*?MODE_ECB|AES\.new\s*\([^)]*AES\.MODE_ECB'),
        "AES ECB mode leaks patterns in ciphertext; use GCM, CBC with HMAC, or another authenticated mode.",
    ),
    (
        "Hardcoded IV/salt",
        re.compile(r'(?i)\b(iv|salt|nonce)\s*=\s*["\'][^"\']{4,}["\']'),
        "Hardcoded IV or salt defeats the purpose of using them; generate randomly per operation.",
    ),
    (
        "DES usage",
        re.compile(r'\bDES\.new\s*\(|\bDES3\.new\s*\('),
        "DES/3DES is deprecated and insecure; use AES with an authenticated mode.",
    ),
]

# Skip lines that appear to be in test/comment context for the random module only
SAFE_RANDOM_PATTERNS = re.compile(
    r'(?i)(test|mock|fake|dummy|sample|example|secrets\.token|os\.urandom)'
)


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class InsecureCryptoPlugin(PluginBase):
    name = "insecure_crypto"
    description = "Detect insecure cryptographic algorithms and practices"
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

        for src_file in root.rglob("*"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            if src_file.suffix.lower() not in (".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", ".rb", ".cs"):
                continue
            try:
                if src_file.stat().st_size > 5_000_000:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for label, pat, rationale in CRYPTO_PATTERNS:
                    if pat.search(line):
                        # Skip lines that are safe random usage (test/mock/secrets context)
                        if "random." in line and SAFE_RANDOM_PATTERNS.search(line):
                            continue
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Insecure Cryptography: {label}",
                                description=(
                                    f"{rationale} Found in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Replace with secure alternatives: bcrypt/argon2 for passwords, "
                                    "secrets module for tokens, AES-GCM for encryption."
                                ),
                                cwe_id="CWE-327",
                                rule_id="insecure_crypto",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
