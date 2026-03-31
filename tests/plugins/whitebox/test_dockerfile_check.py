# tests/plugins/whitebox/test_dockerfile_check.py
"""Tests for DockerfileCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dockerfile_check import DockerfileCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestDockerfileCheck:
    @pytest.fixture
    def plugin(self):
        return DockerfileCheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: USER root + latest tag detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_user_root_and_latest_detected(self, plugin, tmp_path):
        """USER root and FROM :latest are flagged."""
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:latest\n"
            "RUN apt-get update\n"
            "COPY . .\n"
            "USER root\n"
            "CMD [\"/bin/bash\"]\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("dockerfile_" in rid for rid in rule_ids)
        # USER root
        assert any("dockerfile_user_root" in rid for rid in rule_ids)
        # FROM :latest
        assert any("dockerfile_latest_tag" in rid for rid in rule_ids)
        # COPY . .
        assert any("dockerfile_copy_all" in rid for rid in rule_ids)
        for r in results:
            assert r.cwe_id == "CWE-250"

    # ------------------------------------------------------------------ #
    # Test 2: Secure Dockerfile — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_secure_dockerfile_no_findings(self, plugin, tmp_path):
        """A hardened Dockerfile produces no results."""
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:22.04\n"
            "RUN apt-get update && apt-get install -y python3\n"
            "COPY src/ /app/src/\n"
            "USER nobody\n"
            "CMD [\"/app/run.sh\"]\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No Dockerfiles — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_dockerfiles_returns_empty(self, plugin, tmp_path):
        """Directories without Dockerfiles produce no results."""
        (tmp_path / "app.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 4: --privileged in RUN
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_privileged_run_detected(self, plugin, tmp_path):
        """RUN with --privileged is flagged."""
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.11\n"
            "RUN --privileged apt-get install -y something\n"
            "USER appuser\n"
            "CMD [\"python\"]\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("dockerfile_privileged" in rid for rid in rule_ids)
