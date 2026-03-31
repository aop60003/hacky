import pytest
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target, Result, Severity
from vibee_hacker.core.plugin_base import PluginBase


class PassivePlugin(PluginBase):
    name = "passive_test"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target, context=None):
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="Header missing",
            description="X-Frame-Options missing",
        )]


class ActivePlugin(PluginBase):
    name = "active_test"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL

    async def run(self, target, context=None):
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="SQLi found",
            description="SQL injection",
        )]


class FailingPlugin(PluginBase):
    name = "failing_test"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH

    async def run(self, target, context=None):
        raise ConnectionError("Target unreachable")


class TestScanEngine:
    @pytest.fixture
    def engine(self):
        e = ScanEngine()
        e.register_plugin(PassivePlugin())
        e.register_plugin(ActivePlugin())
        return e

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_scan_returns_results(self, engine, target):
        results = await engine.scan(target)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_results_sorted_by_severity(self, engine, target):
        results = await engine.scan(target)
        assert results[0].base_severity >= results[1].base_severity

    @pytest.mark.asyncio
    async def test_phase_ordering(self, engine, target):
        results = await engine.scan(target)
        passive = [r for r in results if r.plugin_name == "passive_test"]
        active = [r for r in results if r.plugin_name == "active_test"]
        assert len(passive) == 1
        assert len(active) == 1

    @pytest.mark.asyncio
    async def test_scan_specific_phase(self, engine, target):
        results = await engine.scan(target, phases=[2])
        assert all(r.plugin_name == "passive_test" for r in results)

    @pytest.mark.asyncio
    async def test_plugin_failure_isolated(self, target):
        engine = ScanEngine()
        engine.register_plugin(PassivePlugin())
        engine.register_plugin(FailingPlugin())
        results = await engine.scan(target)
        assert len(results) >= 1
        passed = [r for r in results if r.plugin_name == "passive_test"]
        assert len(passed) == 1

    @pytest.mark.asyncio
    async def test_plugin_timeout_isolated(self, target):
        import asyncio as _asyncio

        class SlowPlugin(PluginBase):
            name = "slow_test"
            category = "blackbox"
            phase = 2
            base_severity = Severity.LOW

            async def run(self, target, context=None):
                await _asyncio.sleep(10)
                return []

        engine = ScanEngine(timeout_per_plugin=1)
        engine.register_plugin(SlowPlugin())
        results = await engine.scan(target)
        assert len(results) == 1
        assert results[0].plugin_status == "failed"
        assert "timed out" in results[0].description

    @pytest.mark.asyncio
    async def test_safe_mode_filters_destructive_plugins(self, target):
        """safe_mode=True (default) should exclude plugins with destructive_level > 0."""

        class DestructivePlugin(PluginBase):
            name = "destructive_test"
            category = "blackbox"
            phase = 2
            base_severity = Severity.HIGH
            destructive_level = 1

            async def run(self, target, context=None):
                return [Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="Destructive action",
                    description="Would cause side effects",
                )]

        engine = ScanEngine(safe_mode=True)
        engine.register_plugin(PassivePlugin())
        engine.register_plugin(DestructivePlugin())
        results = await engine.scan(target)
        names = [r.plugin_name for r in results]
        assert "passive_test" in names
        assert "destructive_test" not in names

    @pytest.mark.asyncio
    async def test_safe_mode_false_includes_destructive_plugins(self, target):
        """safe_mode=False should allow plugins with destructive_level > 0 to run."""

        class DestructivePlugin(PluginBase):
            name = "destructive_test2"
            category = "blackbox"
            phase = 2
            base_severity = Severity.HIGH
            destructive_level = 1

            async def run(self, target, context=None):
                return [Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="Destructive action",
                    description="Would cause side effects",
                )]

        engine = ScanEngine(safe_mode=False)
        engine.register_plugin(PassivePlugin())
        engine.register_plugin(DestructivePlugin())
        results = await engine.scan(target)
        names = [r.plugin_name for r in results]
        assert "passive_test" in names
        assert "destructive_test2" in names

    @pytest.mark.asyncio
    async def test_scan_safe_mode_override_per_call(self, target):
        """safe_mode kwarg on scan() overrides the engine-level setting."""

        class DestructivePlugin(PluginBase):
            name = "destructive_test3"
            category = "blackbox"
            phase = 2
            base_severity = Severity.HIGH
            destructive_level = 2

            async def run(self, target, context=None):
                return [Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="Destructive action",
                    description="Would cause side effects",
                )]

        # Engine default is safe_mode=True, but call overrides to False
        engine = ScanEngine(safe_mode=True)
        engine.register_plugin(DestructivePlugin())
        results = await engine.scan(target, safe_mode=False)
        names = [r.plugin_name for r in results]
        assert "destructive_test3" in names
