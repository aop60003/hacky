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

    # Feature 3: batch command
    def test_batch_help(self):
        """batch command must appear in root help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "batch" in result.output

    def test_batch_help_options(self):
        """batch --help must show --file and --output-dir."""
        runner = CliRunner()
        result = runner.invoke(cli, ["batch", "--help"])
        assert result.exit_code == 0
        assert "--file" in result.output
        assert "--output-dir" in result.output

    def test_batch_help_mode_format(self):
        """batch --help must show --mode and --format options."""
        runner = CliRunner()
        result = runner.invoke(cli, ["batch", "--help"])
        assert result.exit_code == 0
        assert "--mode" in result.output
        assert "--format" in result.output

    def test_batch_requires_file(self):
        """batch without --file must fail."""
        runner = CliRunner()
        result = runner.invoke(cli, ["batch"])
        assert result.exit_code != 0

    def test_batch_scans_targets(self):
        """batch reads targets file and produces reports."""
        import os
        import tempfile
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = os.path.join(tmpdir, "targets.txt")
            with open(targets_file, "w") as f:
                f.write("http://127.0.0.1:19998\n")
                f.write("# comment line\n")
                f.write("http://127.0.0.1:19997\n")
            output_dir = os.path.join(tmpdir, "reports")
            result = runner.invoke(
                cli,
                ["batch", "-f", targets_file, "--output-dir", output_dir, "--quiet"],
            )
            assert result.exit_code == 0
            # output dir should be created
            assert os.path.isdir(output_dir)

    def test_batch_targets_file_option_in_scan(self):
        """--targets-file must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--targets-file" in result.output

    # Feature 4: authenticated crawling options
    def test_cookie_option(self):
        """--cookie must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--cookie" in result.output

    def test_header_option(self):
        """--header must appear in scan --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--header" in result.output
