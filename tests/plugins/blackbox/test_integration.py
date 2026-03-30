"""Integration test: plugin loader discovers blackbox plugins."""
from vibee_hacker.core.plugin_loader import PluginLoader


class TestBlackboxPluginDiscovery:
    def test_builtin_plugins_discovered(self):
        loader = PluginLoader()
        loader.load_builtin()
        bb = loader.get_plugins(category="blackbox")
        assert len(bb) >= 6
        names = [p.name for p in bb]
        assert "header_check" in names
        assert "cors_check" in names
        assert "sqli" in names
        assert "xss" in names
        assert "cmdi" in names
        assert "path_traversal" in names

    def test_phase_distribution(self):
        loader = PluginLoader()
        loader.load_builtin()
        phase2 = loader.get_plugins(category="blackbox", phase=2)
        phase3 = loader.get_plugins(category="blackbox", phase=3)
        assert len(phase2) >= 2
        assert len(phase3) >= 4
