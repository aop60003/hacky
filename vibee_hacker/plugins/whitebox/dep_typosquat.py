"""Plugin: Dependency Typosquatting Detector (Phase 4, CRITICAL)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Known typosquat pairs: {typo_name: legitimate_name}
KNOWN_TYPOSQUATS: dict[str, str] = {
    # Python typosquats
    "requets": "requests",
    "reqeusts": "requests",
    "reqests": "requests",
    "request": "requests",
    "djnago": "django",
    "dajngo": "django",
    "djang0": "django",
    "flasK": "flask",
    "flask2": "flask",
    "numpY": "numpy",
    "nunpy": "numpy",
    "nmpy": "numpy",
    "panads": "pandas",
    "pandes": "pandas",
    "scipY": "scipy",
    "matplotlb": "matplotlib",
    "matplotllib": "matplotlib",
    "pilows": "pillow",
    "pilow": "pillow",
    "cryptographY": "cryptography",
    "crytpography": "cryptography",
    "boto3s": "boto3",
    "SQLAlchemy1": "sqlalchemy",
    "pyjwt2": "pyjwt",
    "urllb3": "urllib3",
    "urlib3": "urllib3",
    "chardet2": "chardet",
    # JS typosquats
    "lodasH": "lodash",
    "loadsh": "lodash",
    "lodas": "lodash",
    "axois": "axios",
    "axio": "axios",
    "epxress": "express",
    "expres": "express",
    "expresss": "express",
    "reakt": "react",
    "raect": "react",
    "vuejs": "vue",
    "momet": "moment",
    "momnet": "moment",
    "jqeury": "jquery",
    "jqurey": "jquery",
}

# Canonical lowercase map
KNOWN_TYPOSQUATS_LOWER: dict[str, str] = {k.lower(): v for k, v in KNOWN_TYPOSQUATS.items()}

_REQ_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")


def _parse_requirements(content: str) -> list[str]:
    names: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            names.append(m.group(1))
    return names


def _parse_package_json(content: str) -> list[str]:
    names: list[str] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return names
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        names.extend(data.get(section, {}).keys())
    return names


class DepTyposquatPlugin(PluginBase):
    name = "dep_typosquat"
    description = "Detect known typosquatting package names in dependency files"
    category = "whitebox"
    phase = 4
    base_severity = Severity.CRITICAL

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        def _check_names(pkg_names: list[str], source_file: str) -> None:
            for name in pkg_names:
                real = KNOWN_TYPOSQUATS_LOWER.get(name.lower())
                if real:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title=f"Potential Typosquat Package: '{name}'",
                        description=(
                            f"Package name '{name}' in {source_file} closely resembles "
                            f"the popular package '{real}'. This may be a typosquatting attack "
                            f"attempting to install malicious code."
                        ),
                        evidence=f"{source_file}: {name} (possible typo of '{real}')",
                        recommendation=(
                            f"Verify this package is intentional. "
                            f"If you meant '{real}', update the dependency name. "
                            "Remove the package and audit for any malicious code execution."
                        ),
                        cwe_id="CWE-506",
                        rule_id="dep_typosquat",
                        endpoint=str(root / source_file),
                    ))

        req_file = root / "requirements.txt"
        if req_file.is_file():
            try:
                content = req_file.read_text(errors="ignore")
            except OSError:
                content = ""
            _check_names(_parse_requirements(content), "requirements.txt")

        pkg_json_file = root / "package.json"
        if pkg_json_file.is_file():
            try:
                content = pkg_json_file.read_text(errors="ignore")
            except OSError:
                content = ""
            _check_names(_parse_package_json(content), "package.json")

        return results
