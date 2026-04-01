# tests/cli/test_false_positive.py
"""Tests for --false-positive CLI option (P2-5)."""
from click.testing import CliRunner
from vibee_hacker.cli.main import cli


class TestFalsePositiveCLI:
    def test_false_positive_help(self):
        """--false-positive option must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--false-positive" in result.output
