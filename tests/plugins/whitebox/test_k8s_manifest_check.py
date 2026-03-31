# tests/plugins/whitebox/test_k8s_manifest_check.py
"""Tests for K8sManifestCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.k8s_manifest_check import K8sManifestCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestK8sManifestCheck:
    @pytest.fixture
    def plugin(self):
        return K8sManifestCheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Privileged container detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_privileged_container_detected(self, plugin, tmp_path):
        """privileged: true and hostNetwork: true are flagged."""
        (tmp_path / "deployment.yaml").write_text(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: myapp\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      hostNetwork: true\n"
            "      containers:\n"
            "      - name: myapp\n"
            "        image: myapp:1.0\n"
            "        securityContext:\n"
            "          privileged: true\n"
            "          runAsUser: 0\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("k8s_" in rid for rid in rule_ids)
        assert any("k8s_privileged" in rid for rid in rule_ids)
        assert any("k8s_host_network" in rid for rid in rule_ids)
        assert any("k8s_run_as_root" in rid for rid in rule_ids)
        for r in results:
            assert r.cwe_id == "CWE-250"

    # ------------------------------------------------------------------ #
    # Test 2: Secure manifest — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_secure_manifest_no_findings(self, plugin, tmp_path):
        """A hardened k8s manifest produces no results."""
        (tmp_path / "deployment.yaml").write_text(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: myapp\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: myapp\n"
            "        image: myapp:1.0\n"
            "        imagePullPolicy: Always\n"
            "        securityContext:\n"
            "          privileged: false\n"
            "          runAsNonRoot: true\n"
            "          runAsUser: 1000\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No k8s files — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_k8s_files_returns_empty(self, plugin, tmp_path):
        """Directories without YAML files produce no results."""
        (tmp_path / "main.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []
