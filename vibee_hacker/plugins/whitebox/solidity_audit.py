"""Plugin: Solidity Smart Contract Security Audit (whitebox)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import iter_files, safe_read
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Reentrancy: external call before state change
REENTRANCY_RE = re.compile(r'\.(call|send|transfer)\s*\{?\s*value\s*:', re.IGNORECASE)
TX_ORIGIN_RE = re.compile(r'\btx\.origin\b')
SELFDESTRUCT_RE = re.compile(r'\bselfdestruct\s*\(|\bsuicide\s*\(')
UNCHECKED_RETURN_RE = re.compile(r'\.(call|send)\s*\((?![^;]*require)(?![^;]*assert)(?![^;]*bool\s)', re.IGNORECASE)


class SolidityAuditPlugin(PluginBase):
    name = "solidity_audit"
    description = "Audit Solidity smart contracts for reentrancy, tx.origin auth, selfdestruct, unchecked returns"
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

        for src_file in iter_files(root, {".sol"}):
            content = safe_read(src_file)
            if content is None:
                continue

            lines = content.splitlines()

            for lineno, line in enumerate(lines, start=1):
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue

                # Reentrancy check
                if REENTRANCY_RE.search(line):
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.CRITICAL,
                            title="Potential Reentrancy Vulnerability",
                            description=(
                                f"External call with value transfer detected in "
                                f"'{src_file.relative_to(root)}' at line {lineno}. "
                                "If state is updated after the call, reentrancy attacks may drain funds."
                            ),
                            evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                            recommendation=(
                                "Follow the Checks-Effects-Interactions pattern: update state before "
                                "making external calls. Consider using OpenZeppelin ReentrancyGuard."
                            ),
                            cwe_id="CWE-841",
                            rule_id="solidity_reentrancy",
                            endpoint=str(src_file),
                        )
                    )
                    continue

                # tx.origin authentication
                if TX_ORIGIN_RE.search(line):
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title="tx.origin Used for Authentication",
                            description=(
                                f"tx.origin used for authorization in "
                                f"'{src_file.relative_to(root)}' at line {lineno}. "
                                "Malicious contracts can exploit this via phishing."
                            ),
                            evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                            recommendation=(
                                "Replace tx.origin with msg.sender for authorization checks."
                            ),
                            cwe_id="CWE-670",
                            rule_id="solidity_tx_origin",
                            endpoint=str(src_file),
                        )
                    )
                    continue

                # selfdestruct
                if SELFDESTRUCT_RE.search(line):
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.CRITICAL,
                            title="selfdestruct() Usage Detected",
                            description=(
                                f"selfdestruct() found in '{src_file.relative_to(root)}' at line {lineno}. "
                                "If not properly protected, attackers can destroy the contract."
                            ),
                            evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                            recommendation=(
                                "Ensure selfdestruct() is protected by strong access controls. "
                                "Consider using a pause mechanism instead."
                            ),
                            cwe_id="CWE-841",
                            rule_id="solidity_selfdestruct",
                            endpoint=str(src_file),
                        )
                    )
                    continue

                # Unchecked return value from low-level call
                if re.search(r'\.(call|send)\s*\(', line, re.IGNORECASE):
                    # Check if the return value is checked (assigned to bool or used in require/assert)
                    if not re.search(r'(bool\s+\w+\s*=|require\s*\(|assert\s*\(|\w+\s*=\s*\w+\.(call|send))', line, re.IGNORECASE):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="Unchecked Low-Level Call Return Value",
                                description=(
                                    f"Low-level call/send without return value check in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "Silent failures may allow the contract to continue in an inconsistent state."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Always check the return value of low-level calls: "
                                    "(bool success, ) = addr.call{value:...}(''); require(success);"
                                ),
                                cwe_id="CWE-670",
                                rule_id="solidity_unchecked_return",
                                endpoint=str(src_file),
                            )
                        )

        return results
