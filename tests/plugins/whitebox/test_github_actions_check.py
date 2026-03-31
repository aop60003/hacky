# tests/plugins/whitebox/test_github_actions_check.py
"""Tests for GitHubActionsCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.github_actions_check import GitHubActionsCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestGitHubActionsCheck:
    @pytest.fixture
    def plugin(self):
        return GitHubActionsCheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Unpinned action + script injection detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_unpinned_and_injection_detected(self, plugin, tmp_path):
        """Unpinned actions and script injection are flagged."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(
            "name: CI\n"
            "on:\n"
            "  pull_request_target:\n"
            "    types: [opened]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@main\n"
            "      - name: Echo title\n"
            '        run: echo "${{ github.event.issue.title }}"\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("gha_" in rid for rid in rule_ids)
        assert any("gha_unpinned_action" in rid for rid in rule_ids)
        assert any("gha_script_injection" in rid for rid in rule_ids)
        assert any("gha_pull_request_target" in rid for rid in rule_ids)
        cwe_by_rule = {r.rule_id: r.cwe_id for r in results}
        assert cwe_by_rule["gha_unpinned_action"] == "CWE-829"
        assert cwe_by_rule["gha_script_injection"] == "CWE-78"
        assert cwe_by_rule["gha_pull_request_target"] == "CWE-829"

    # ------------------------------------------------------------------ #
    # Test 2: Secure workflow — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_secure_workflow_no_findings(self, plugin, tmp_path):
        """A hardened workflow produces no results."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(
            "name: CI\n"
            "on:\n"
            "  push:\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - name: Run tests\n"
            "        run: pytest tests/\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No workflows — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_workflows_returns_empty(self, plugin, tmp_path):
        """Directories without workflow files produce no results."""
        (tmp_path / "app.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []
