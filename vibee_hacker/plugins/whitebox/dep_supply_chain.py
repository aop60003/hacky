"""Plugin: Dependency Supply Chain Risk Detector (Phase 4, HIGH)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Suspicious commands in install scripts
_SUSPICIOUS_SCRIPT_CMDS = re.compile(
    r"\b(curl|wget|eval|exec|bash\s+-c|sh\s+-c|python\s+-c|node\s+-e|powershell)\b",
    re.IGNORECASE,
)

# Non-standard index flags in requirements.txt
_INDEX_URL_RE = re.compile(
    r"^--(?:index-url|extra-index-url|trusted-host)\s+\S+",
    re.MULTILINE,
)

# Git-sourced packages in requirements.txt
_GIT_URL_RE = re.compile(
    r"^git\+https?://|^git\+ssh://|^-e\s+git\+",
    re.MULTILINE | re.IGNORECASE,
)

# Lifecycle scripts that run during npm install
_INSTALL_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}


class DepSupplyChainPlugin(PluginBase):
    name = "dep_supply_chain"
    description = (
        "Detect supply chain risk indicators: suspicious install scripts, "
        "non-standard package indexes, and git-sourced dependencies"
    )
    category = "whitebox"
    phase = 4
    base_severity = Severity.HIGH

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        # --- package.json: suspicious install scripts ---
        for pkg_json_file in root.rglob("package.json"):
            if any(p in pkg_json_file.parts for p in ("node_modules", "vendor", "dist", "build")):
                continue
            try:
                content = pkg_json_file.read_text(errors="ignore")
            except OSError:
                continue

            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                continue

            scripts = data.get("scripts", {})
            for script_name, script_body in scripts.items():
                if script_name.lower() not in _INSTALL_SCRIPTS:
                    continue
                if not isinstance(script_body, str):
                    continue
                m = _SUSPICIOUS_SCRIPT_CMDS.search(script_body)
                if m:
                    rel = str(pkg_json_file.relative_to(root))
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title=f"Suspicious Install Script in {rel}",
                        description=(
                            f"The '{script_name}' lifecycle script in '{rel}' contains a "
                            f"potentially dangerous command ('{m.group(0)}'). "
                            "This script runs automatically during npm install and could execute "
                            "malicious code."
                        ),
                        evidence=f"{rel} scripts.{script_name}: {script_body[:200]}",
                        recommendation=(
                            "Review the install script carefully. "
                            "Avoid running untrusted packages that execute network commands "
                            "during installation. Consider using --ignore-scripts flag."
                        ),
                        cwe_id="CWE-506",
                        rule_id="dep_supply_chain_risk",
                        endpoint=str(pkg_json_file),
                    ))

        # --- requirements.txt: non-standard indexes and git URLs ---
        req_file = root / "requirements.txt"
        if req_file.is_file():
            try:
                content = req_file.read_text(errors="ignore")
            except OSError:
                content = ""

            # Non-standard index URLs
            for m in _INDEX_URL_RE.finditer(content):
                line = m.group(0).strip()
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.HIGH,
                    title="Non-Standard Package Index in requirements.txt",
                    description=(
                        f"requirements.txt specifies a non-standard package index: '{line}'. "
                        "Custom indexes can be used to serve malicious packages "
                        "(dependency confusion / index substitution attack)."
                    ),
                    evidence=f"requirements.txt: {line}",
                    recommendation=(
                        "Verify the custom index is legitimate and controlled by your organization. "
                        "Consider using hash-pinning (--require-hashes) for all packages."
                    ),
                    cwe_id="CWE-506",
                    rule_id="dep_supply_chain_risk",
                    endpoint=str(req_file),
                ))

            # Git-sourced packages
            for m in _GIT_URL_RE.finditer(content):
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.end())
                full_line = content[line_start:line_end if line_end != -1 else None].strip()
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title="Git URL Dependency in requirements.txt",
                    description=(
                        f"Package installed directly from a git URL: '{full_line[:200]}'. "
                        "Git URL dependencies bypass PyPI's security checks and may point to "
                        "unreviewed, mutable, or malicious code."
                    ),
                    evidence=f"requirements.txt: {full_line[:200]}",
                    recommendation=(
                        "Pin dependencies to specific PyPI releases with verified hashes. "
                        "If a git dependency is necessary, pin to a specific commit SHA."
                    ),
                    cwe_id="CWE-506",
                    rule_id="dep_supply_chain_risk",
                    endpoint=str(req_file),
                ))

        return results
