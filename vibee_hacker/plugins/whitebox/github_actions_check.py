"""Plugin: GitHub Actions Security Check (Phase 5, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"}

# Unpinned action: uses: owner/repo@main|master|HEAD (not a SHA or vX.Y.Z)
_UNPINNED_ACTION = re.compile(
    r'^\s*-?\s*uses\s*:\s*\S+@(?:main|master|HEAD|latest)\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Script injection via github context in run: steps
_SCRIPT_INJECTION = re.compile(
    r'\$\{\{\s*github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|head_commit\.message)',
    re.IGNORECASE,
)

# Dangerous trigger
_PRT_TRIGGER = re.compile(r'^\s*pull_request_target\s*:', re.MULTILINE)

# Plaintext secrets (naive: variable name contains SECRET/TOKEN/PASSWORD/KEY and value is quoted literal)
_PLAINTEXT_SECRET = re.compile(
    r'(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\s*:\s*["\'][^${\n]{4,}["\']',
    re.IGNORECASE,
)


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _find_workflow_files(root: Path) -> list[Path]:
    """Find all .github/workflows/*.yml files."""
    workflows: list[Path] = []
    for yml in root.rglob("*.yml"):
        if not yml.is_file() or _should_skip(yml):
            continue
        # Must be under .github/workflows/
        parts = yml.parts
        try:
            idx = parts.index(".github")
            if idx + 1 < len(parts) and parts[idx + 1] == "workflows":
                workflows.append(yml)
        except ValueError:
            pass
    return workflows


class GitHubActionsCheckPlugin(PluginBase):
    name = "github_actions_check"
    description = "Scan GitHub Actions workflow files for security issues"
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
        workflow_files = _find_workflow_files(root)

        for wf_path in workflow_files:
            try:
                content = wf_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = wf_path.relative_to(root)

            # Unpinned actions
            for match in _UNPINNED_ACTION.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="GitHub Action pinned to mutable ref (main/master/HEAD/latest)",
                        description=(
                            "Using a mutable ref such as @main allows the action's author to "
                            f"push malicious code that runs in your pipeline. Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation="Pin actions to a full commit SHA, e.g. `uses: actions/checkout@abc1234`.",
                        cwe_id="CWE-829",
                        rule_id="gha_unpinned_action",
                        endpoint=str(wf_path),
                    )
                )

            # Script injection
            for match in _SCRIPT_INJECTION.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title="Potential script injection via github.event context",
                        description=(
                            "Interpolating untrusted github.event data directly into a run: step "
                            f"can allow command injection. Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation=(
                            "Store the value in an environment variable first, "
                            "e.g. `env: TITLE: ${{ github.event.issue.title }}` and use `$TITLE`."
                        ),
                        cwe_id="CWE-78",
                        rule_id="gha_script_injection",
                        endpoint=str(wf_path),
                    )
                )

            # pull_request_target
            for match in _PRT_TRIGGER.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="Dangerous pull_request_target trigger in use",
                        description=(
                            "pull_request_target runs with write permissions and access to secrets "
                            f"even for forks — a common vector for supply-chain attacks. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation=(
                            "Avoid pull_request_target unless required; if used, never check out "
                            "PR code or use it to trigger untrusted scripts."
                        ),
                        cwe_id="CWE-829",
                        rule_id="gha_pull_request_target",
                        endpoint=str(wf_path),
                    )
                )

            # Plaintext secrets
            for match in _PLAINTEXT_SECRET.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1].strip()
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title="Potential plaintext secret in workflow file",
                        description=(
                            "A variable with a secret-like name appears to contain a hardcoded value. "
                            f"Found in '{rel}' at line {line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {line_text[:120]}",
                        recommendation="Use `${{ secrets.MY_SECRET }}` to reference repository secrets.",
                        cwe_id="CWE-798",
                        rule_id="gha_plaintext_secret",
                        endpoint=str(wf_path),
                    )
                )

        return results
