"""Abstract runtime interface for sandboxed plugin execution.

Defines the contract for runtime backends (Docker, process-based, etc.)
that isolate plugin execution from the host system.
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SandboxInfo(BaseModel):
    """Information about a running sandbox."""
    sandbox_id: str
    container_id: Optional[str] = None
    host: str = "localhost"
    port: int = 0
    token: Optional[str] = None
    status: str = "created"


class AbstractRuntime(abc.ABC):
    """Abstract base for plugin execution runtimes.

    Implementations provide isolated environments for running plugins:
    - DockerRuntime: Docker container-based isolation
    - ProcessRuntime: Process-based isolation (lighter weight)
    - LocalRuntime: No isolation (direct execution, default)
    """

    @abc.abstractmethod
    async def create_sandbox(
        self,
        scan_id: str,
        image: Optional[str] = None,
    ) -> SandboxInfo:
        """Create a new sandbox for plugin execution."""
        ...

    @abc.abstractmethod
    async def execute_in_sandbox(
        self,
        sandbox: SandboxInfo,
        plugin_name: str,
        target_data: Dict[str, Any],
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        """Execute a plugin inside the sandbox and return results."""
        ...

    @abc.abstractmethod
    async def destroy_sandbox(self, sandbox: SandboxInfo) -> None:
        """Destroy a sandbox and clean up resources."""
        ...

    async def cleanup(self) -> None:
        """Clean up all sandboxes. Called on shutdown."""
        pass


class LocalRuntime(AbstractRuntime):
    """No-isolation runtime. Runs plugins directly in the current process.

    This is the default when no sandbox is configured.
    """

    async def create_sandbox(
        self,
        scan_id: str,
        image: Optional[str] = None,
    ) -> SandboxInfo:
        return SandboxInfo(sandbox_id=f"local-{scan_id}", status="running")

    async def execute_in_sandbox(
        self,
        sandbox: SandboxInfo,
        plugin_name: str,
        target_data: Dict[str, Any],
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        """Execute plugin directly (no isolation)."""
        import asyncio
        from vibee_hacker.core.models import Target
        from vibee_hacker.core.plugin_loader import PluginLoader

        loader = PluginLoader()
        loader.load_builtin()

        plugin = None
        for p in loader.plugins:
            if p.name == plugin_name:
                plugin = p
                break

        if not plugin:
            return [{"error": f"Plugin not found: {plugin_name}"}]

        target = Target(**target_data)
        try:
            results = await asyncio.wait_for(
                plugin.run(target), timeout=timeout
            )
            return [r.to_dict() for r in results]
        except asyncio.TimeoutError:
            return [{"error": f"Plugin {plugin_name} timed out"}]
        except Exception as e:
            return [{"error": f"Plugin {plugin_name} failed: {e}"}]

    async def destroy_sandbox(self, sandbox: SandboxInfo) -> None:
        pass


class DockerRuntime(AbstractRuntime):
    """Docker-based sandbox runtime for isolated plugin execution.

    Spins up a container from the configured image, executes plugins
    via HTTP API, and destroys the container on completion.
    """

    def __init__(self, image: Optional[str] = None, connect_timeout: int = 10):
        from vibee_hacker.config import Config
        self._image = image or Config.get("vibee_sandbox_image") or "vibee-hacker:sandbox"
        self._connect_timeout = connect_timeout
        self._containers: Dict[str, Any] = {}

    async def create_sandbox(
        self,
        scan_id: str,
        image: Optional[str] = None,
    ) -> SandboxInfo:
        """Create a Docker container for sandboxed execution."""
        try:
            import docker
        except ImportError:
            raise RuntimeError(
                "Docker SDK not installed. Run: pip install docker"
            )

        client = docker.from_env()
        use_image = image or self._image

        # Verify image exists
        try:
            client.images.get(use_image)
        except docker.errors.ImageNotFound:
            logger.info("Pulling sandbox image: %s", use_image)
            client.images.pull(use_image)

        container = client.containers.run(
            use_image,
            detach=True,
            remove=True,
            network_mode="bridge",
            environment={"VIBEE_SANDBOX_MODE": "1"},
        )

        self._containers[scan_id] = container

        return SandboxInfo(
            sandbox_id=scan_id,
            container_id=container.id,
            status="running",
        )

    async def execute_in_sandbox(
        self,
        sandbox: SandboxInfo,
        plugin_name: str,
        target_data: Dict[str, Any],
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        """Execute a plugin inside the Docker sandbox."""
        container = self._containers.get(sandbox.sandbox_id)
        if not container:
            return [{"error": "Sandbox container not found"}]

        # Execute plugin command inside container
        import json
        cmd = f"python -m vibee_hacker.runtime.sandbox_worker {plugin_name} '{json.dumps(target_data)}'"

        try:
            exit_code, output = container.exec_run(cmd, demux=True)
            stdout = output[0].decode() if output[0] else ""

            if exit_code != 0:
                stderr = output[1].decode() if output[1] else ""
                return [{"error": f"Sandbox execution failed: {stderr}"}]

            return json.loads(stdout)
        except Exception as e:
            return [{"error": f"Sandbox execution error: {e}"}]

    async def destroy_sandbox(self, sandbox: SandboxInfo) -> None:
        """Stop and remove the sandbox container."""
        container = self._containers.pop(sandbox.sandbox_id, None)
        if container:
            try:
                container.stop(timeout=5)
            except Exception as e:
                logger.warning("Failed to stop container %s: %s", sandbox.sandbox_id, e)

    async def cleanup(self) -> None:
        """Destroy all active sandboxes."""
        for scan_id in list(self._containers.keys()):
            await self.destroy_sandbox(SandboxInfo(sandbox_id=scan_id))


def get_runtime(backend: Optional[str] = None) -> AbstractRuntime:
    """Get the configured runtime backend."""
    from vibee_hacker.config import Config
    backend = backend or Config.get("vibee_runtime_backend")

    if backend == "docker":
        return DockerRuntime()
    return LocalRuntime()
