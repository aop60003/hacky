# tests/plugins/whitebox/test_py_django_check.py
"""Tests for PyDjangoCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_django_check import PyDjangoCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestPyDjangoCheck:
    @pytest.fixture
    def plugin(self):
        return PyDjangoCheckPlugin()

    @pytest.mark.asyncio
    async def test_debug_true_and_csrf_exempt(self, plugin, tmp_path):
        """DEBUG=True and @csrf_exempt are flagged as HIGH."""
        (tmp_path / "settings.py").write_text(
            "DEBUG = True\n"
            "ALLOWED_HOSTS = ['*']\n"
        )
        (tmp_path / "views.py").write_text(
            "from django.views.decorators.csrf import csrf_exempt\n"
            "@csrf_exempt\n"
            "def my_view(request):\n"
            "    pass\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = [r.rule_id for r in results]
        assert any(rid.startswith("py_django_") for rid in rule_ids)
        assert all(r.cwe_id == "CWE-16" for r in results)

    @pytest.mark.asyncio
    async def test_secure_settings_clean(self, plugin, tmp_path):
        """Secure Django settings return empty."""
        (tmp_path / "settings.py").write_text(
            "import os\n"
            "DEBUG = False\n"
            "ALLOWED_HOSTS = ['myapp.example.com']\n"
            "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
