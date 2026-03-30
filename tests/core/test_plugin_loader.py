from vibee_hacker.core.plugin_loader import PluginLoader


class TestPluginLoader:
    def test_discover_plugins_from_directory(self, tmp_path):
        plugin_code = '''
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target, Result, Severity

class DummyPlugin(PluginBase):
    name = "Dummy"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO

    async def run(self, target, context=None):
        return []
'''
        (tmp_path / "__init__.py").write_text("")
        (tmp_path / "dummy.py").write_text(plugin_code)

        loader = PluginLoader()
        plugins = loader.discover(str(tmp_path))
        assert len(plugins) >= 1
        assert plugins[0].name == "Dummy"

    def test_filter_by_category(self):
        loader = PluginLoader()
        loader.load_builtin()
        bb = loader.get_plugins(category="blackbox")
        wb = loader.get_plugins(category="whitebox")
        assert isinstance(bb, list)
        assert isinstance(wb, list)

    def test_filter_by_phase(self):
        loader = PluginLoader()
        loader.load_builtin()
        phase1 = loader.get_plugins(phase=1)
        assert isinstance(phase1, list)
