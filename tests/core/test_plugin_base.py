import pytest
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target


class TestPluginBase:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            PluginBase()

    def test_concrete_plugin(self):
        from tests.fixtures.sample_plugin import SamplePlugin
        p = SamplePlugin()
        assert p.name == "Sample Plugin"
        assert p.category == "blackbox"
        assert p.phase == 3

    def test_is_applicable_default(self):
        from tests.fixtures.sample_plugin import SamplePlugin
        p = SamplePlugin()
        target = Target(url="https://example.com")
        assert p.is_applicable(target) is True

    def test_requires_provides(self):
        from tests.fixtures.sample_plugin import SamplePlugin
        p = SamplePlugin()
        assert p.requires == []
        assert p.provides == []

    def test_destructive_level_default(self):
        from tests.fixtures.sample_plugin import SamplePlugin
        p = SamplePlugin()
        assert p.destructive_level == 0
