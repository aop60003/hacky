# tests/plugins/whitebox/test_gitlab_ci_check.py
"""Tests for GitLabCICheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.gitlab_ci_check import GitLabCICheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestGitLabCICheck:
    @pytest.fixture
    def plugin(self):
        return GitLabCICheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: curl piped to sh + allow_failure detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_curl_pipe_sh_detected(self, plugin, tmp_path):
        """curl|wget piped to sh/bash is flagged."""
        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages:\n"
            "  - deploy\n"
            "deploy_job:\n"
            "  stage: deploy\n"
            "  allow_failure: true\n"
            "  script:\n"
            "    - curl https://install.example.com | sh\n"
            "    - wget -qO- https://get.example.com | bash\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("gitlab_ci_" in rid for rid in rule_ids)
        assert any("gitlab_ci_curl_pipe_shell" in rid for rid in rule_ids)
        assert any("gitlab_ci_allow_failure" in rid for rid in rule_ids)
        for r in results:
            assert r.cwe_id == "CWE-78"

    # ------------------------------------------------------------------ #
    # Test 2: Clean CI config — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_clean_ci_no_findings(self, plugin, tmp_path):
        """A safe .gitlab-ci.yml produces no results."""
        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages:\n"
            "  - test\n"
            "  - deploy\n"
            "test_job:\n"
            "  stage: test\n"
            "  script:\n"
            "    - pytest tests/\n"
            "deploy_job:\n"
            "  stage: deploy\n"
            "  script:\n"
            "    - ./deploy.sh\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No .gitlab-ci.yml — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_gitlab_ci_returns_empty(self, plugin, tmp_path):
        """Directories without .gitlab-ci.yml produce no results."""
        (tmp_path / "app.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []
