# tests/plugins/whitebox/test_py_flask_check.py
"""Tests for PyFlaskCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_flask_check import PyFlaskCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestPyFlaskCheck:
    @pytest.fixture
    def plugin(self):
        return PyFlaskCheckPlugin()

    @pytest.mark.asyncio
    async def test_debug_true_detected(self, plugin, tmp_path):
        """app.run(debug=True) is flagged as HIGH."""
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.run(debug=True)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id.startswith("py_flask_")
        assert r.cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_secure_config_clean(self, plugin, tmp_path):
        """Secure Flask config returns empty."""
        (tmp_path / "app.py").write_text(
            "import os\n"
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.secret_key = os.environ.get('SECRET_KEY')\n"
            "if __name__ == '__main__':\n"
            "    app.run(debug=False)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
