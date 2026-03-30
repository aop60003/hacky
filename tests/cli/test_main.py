from click.testing import CliRunner
from vibee_hacker.cli.main import cli


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    def test_scan_requires_target(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--mode" in result.output
