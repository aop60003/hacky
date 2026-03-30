# tests/fixtures/sample_plugin.py
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target, Result, Severity


class SamplePlugin(PluginBase):
    name = "Sample Plugin"
    description = "A test plugin"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target, context=None):
        return [
            Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="Test finding",
                description="Found something",
            )
        ]
