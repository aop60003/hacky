from click.testing import CliRunner
from vibee_hacker.cli.main import cli


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        from vibee_hacker import __version__
        assert __version__ in result.output

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

    def test_sarif_format_option(self):
        """--format sarif must appear in scan --help choices."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "sarif" in result.output

    def test_safe_mode_flag(self):
        """--safe-mode / --no-safe-mode must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "safe-mode" in result.output

    def test_proxy_option(self):
        """--proxy must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--proxy" in result.output

    def test_profile_option(self):
        """--profile with choices stealth/default/aggressive/ci must appear."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--profile" in result.output
        assert "stealth" in result.output
        assert "aggressive" in result.output
        assert "ci" in result.output

    def test_dashboard_help(self):
        """dashboard command must be listed and show --host/--port options."""
        runner = CliRunner()
        # dashboard must appear in root help
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "dashboard" in result.output

        # dashboard --help must work
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output

    def test_insecure_flag(self):
        """--insecure must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--insecure" in result.output

    def test_concurrency_option(self):
        """--concurrency must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--concurrency" in result.output

    def test_delay_option(self):
        """--delay must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--delay" in result.output
