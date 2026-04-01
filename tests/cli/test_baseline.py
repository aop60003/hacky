# tests/cli/test_baseline.py
"""Tests for --baseline CLI option (P2-4)."""
from click.testing import CliRunner
from vibee_hacker.cli.main import cli


class TestBaselineCLI:
    def test_baseline_help(self):
        """--baseline option must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--baseline" in result.output
