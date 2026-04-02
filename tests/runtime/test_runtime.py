"""Tests for vibee_hacker.runtime.runtime module."""

from __future__ import annotations

import pytest
import pytest_asyncio

from vibee_hacker.runtime.runtime import (
    AbstractRuntime,
    DockerRuntime,
    LocalRuntime,
    SandboxInfo,
    get_runtime,
)


class TestSandboxInfo:
    """SandboxInfo Pydantic model behaves correctly."""

    def test_required_field(self):
        info = SandboxInfo(sandbox_id="test-123")
        assert info.sandbox_id == "test-123"

    def test_defaults(self):
        info = SandboxInfo(sandbox_id="x")
        assert info.host == "localhost"
        assert info.port == 0
        assert info.status == "created"
        assert info.container_id is None
        assert info.token is None

    def test_custom_values(self):
        info = SandboxInfo(
            sandbox_id="s1",
            container_id="c1",
            host="127.0.0.1",
            port=8080,
            token="tok",
            status="running",
        )
        assert info.container_id == "c1"
        assert info.port == 8080
        assert info.status == "running"


class TestAbstractRuntime:
    """AbstractRuntime cannot be instantiated directly."""

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            AbstractRuntime()  # type: ignore[abstract]

    def test_requires_create_sandbox(self):
        # All three abstract methods must be implemented
        abstract_methods = AbstractRuntime.__abstractmethods__
        assert "create_sandbox" in abstract_methods
        assert "execute_in_sandbox" in abstract_methods
        assert "destroy_sandbox" in abstract_methods


class TestLocalRuntime:
    """LocalRuntime creates no-op sandboxes in-process."""

    @pytest.mark.asyncio
    async def test_create_sandbox_returns_sandbox_info(self):
        rt = LocalRuntime()
        info = await rt.create_sandbox("scan-001")
        assert isinstance(info, SandboxInfo)
        assert "scan-001" in info.sandbox_id
        assert info.status == "running"

    @pytest.mark.asyncio
    async def test_create_sandbox_with_image_ignored(self):
        rt = LocalRuntime()
        info = await rt.create_sandbox("scan-002", image="some-image:latest")
        assert info.sandbox_id == "local-scan-002"

    @pytest.mark.asyncio
    async def test_destroy_sandbox_is_noop(self):
        rt = LocalRuntime()
        info = await rt.create_sandbox("scan-003")
        # Should not raise
        await rt.destroy_sandbox(info)

    @pytest.mark.asyncio
    async def test_cleanup_is_noop(self):
        rt = LocalRuntime()
        # Should not raise
        await rt.cleanup()

    @pytest.mark.asyncio
    async def test_execute_unknown_plugin_returns_error(self):
        rt = LocalRuntime()
        info = await rt.create_sandbox("scan-004")
        results = await rt.execute_in_sandbox(
            info,
            plugin_name="nonexistent_plugin_xyz",
            target_data={"url": "http://example.com"},
            timeout=5,
        )
        assert len(results) == 1
        assert "error" in results[0]
        assert "nonexistent_plugin_xyz" in results[0]["error"]


class TestGetRuntime:
    """get_runtime() factory returns correct backend."""

    def test_default_returns_local_runtime(self, monkeypatch):
        monkeypatch.delenv("VIBEE_RUNTIME_BACKEND", raising=False)
        rt = get_runtime()
        assert isinstance(rt, LocalRuntime)

    def test_explicit_local(self):
        rt = get_runtime(backend="local")
        # Any non-"docker" string falls through to LocalRuntime
        assert isinstance(rt, LocalRuntime)

    def test_docker_backend_returns_docker_runtime(self):
        rt = get_runtime(backend="docker")
        assert isinstance(rt, DockerRuntime)

    def test_env_backend_selection(self, monkeypatch):
        monkeypatch.setenv("VIBEE_RUNTIME_BACKEND", "docker")
        # Need to clear the Config cache so it picks up the env var
        from vibee_hacker.config.config import Config
        Config._cached_file_config = None
        rt = get_runtime()
        assert isinstance(rt, DockerRuntime)
        Config._cached_file_config = None


class TestDockerRuntimeInit:
    """DockerRuntime initialises with correct defaults."""

    def test_default_image_from_config(self, monkeypatch):
        monkeypatch.delenv("VIBEE_SANDBOX_IMAGE", raising=False)
        from vibee_hacker.config.config import Config
        Config._cached_file_config = None
        rt = DockerRuntime()
        assert rt._image == "vibee-hacker:sandbox"

    def test_custom_image_override(self):
        rt = DockerRuntime(image="my-image:latest")
        assert rt._image == "my-image:latest"

    def test_connect_timeout_stored(self):
        rt = DockerRuntime(connect_timeout=30)
        assert rt._connect_timeout == 30
