# tests/plugins/whitebox/test_log_injection.py
"""Tests for LogInjectionPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.log_injection import LogInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestLogInjection:
    @pytest.fixture
    def plugin(self):
        return LogInjectionPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: f-string with request in logger
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_fstring_request_in_logger_detected(self, plugin, tmp_path):
        """logger.info with request.args in f-string is flagged as MEDIUM."""
        (tmp_path / "views.py").write_text(
            "import logging\nlogger = logging.getLogger(__name__)\n"
            "def view(request):\n"
            "    logger.info(f'User visited: {request.args}')\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.MEDIUM
        assert r.rule_id == "log_injection"
        assert r.cwe_id == "CWE-117"

    # ------------------------------------------------------------------ #
    # Test 2: Clean logging — no results
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_clean_logging_not_flagged(self, plugin, tmp_path):
        """Logging with static messages is not flagged."""
        (tmp_path / "views.py").write_text(
            "import logging\nlogger = logging.getLogger(__name__)\n"
            "def view(request):\n"
            "    logger.info('User visited the page')\n"
            "    logger.debug('Processing request')\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No path
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Bonus: Direct user_input in logging.info
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_direct_user_input_detected(self, plugin, tmp_path):
        (tmp_path / "app.py").write_text(
            "import logging\n"
            "def handle(user_input):\n"
            "    logging.info(user_input)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "log_injection"
