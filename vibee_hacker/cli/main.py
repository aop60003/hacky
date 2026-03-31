"""VIBEE-Hacker CLI interface."""

from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console
from rich.table import Table

from vibee_hacker import __version__
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target
from vibee_hacker.core.plugin_loader import PluginLoader

console = Console()

PROFILES: dict[str, dict] = {
    "stealth":    {"concurrency": 2,  "timeout": 30,  "safe_mode": True},
    "default":    {"concurrency": 10, "timeout": 60,  "safe_mode": True},
    "aggressive": {"concurrency": 50, "timeout": 120, "safe_mode": False},
    "ci":         {"concurrency": 5,  "timeout": 30,  "safe_mode": True},
}


@click.group()
@click.version_option(__version__)
def cli():
    """VIBEE-Hacker: Security vulnerability scanner."""
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL or path")
@click.option(
    "--mode", "-m", default="blackbox", type=click.Choice(["blackbox", "whitebox"])
)
@click.option("--phase", type=int, multiple=True, help="Run specific phases only")
@click.option("--plugin", type=str, help="Comma-separated plugin names")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "fmt", default="json", type=click.Choice(["json", "html", "sarif"])
)
@click.option("--timeout", default=60, type=int, help="Per-plugin timeout (seconds)")
@click.option(
    "--fail-on", type=str, help="Exit 1 if severity found (e.g. critical,high)"
)
@click.option("--quiet", is_flag=True, help="Minimal output")
@click.option("--proxy", default=None, help="HTTP proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--safe-mode/--no-safe-mode", default=True, help="Enable/disable safe mode")
@click.option("--concurrency", default=10, type=int, help="Max concurrent plugins (default: 10)")
@click.option("--delay", default=0, type=int, help="Delay between requests in ms (default: 0)")
@click.option("--insecure", is_flag=True, help="Disable SSL verification")
@click.option(
    "--profile",
    default=None,
    type=click.Choice(["stealth", "default", "aggressive", "ci"]),
    help="Scan profile preset (stealth/default/aggressive/ci)",
)
def scan(
    target, mode, phase, plugin, output, fmt, timeout, fail_on, quiet,
    proxy, safe_mode, concurrency, delay, insecure, profile,
):
    """Run a security scan against a target."""
    # Apply profile presets first; explicit flags override them
    effective_concurrency = concurrency
    effective_timeout = timeout
    effective_safe_mode = safe_mode

    if profile and profile != "default":
        preset = PROFILES[profile]
        ctx = click.get_current_context()
        if ctx.get_parameter_source("timeout") == click.core.ParameterSource.DEFAULT:
            effective_timeout = preset["timeout"]
        if ctx.get_parameter_source("concurrency") == click.core.ParameterSource.DEFAULT:
            effective_concurrency = preset["concurrency"]
        if ctx.get_parameter_source("safe_mode") == click.core.ParameterSource.DEFAULT:
            effective_safe_mode = preset["safe_mode"]

    verify_ssl = not insecure

    if mode == "blackbox":
        t = Target(url=target, mode=mode, verify_ssl=verify_ssl, proxy=proxy, delay=delay)
    else:
        t = Target(path=target, mode=mode, verify_ssl=verify_ssl, proxy=proxy, delay=delay)

    loader = PluginLoader()
    loader.load_builtin()

    engine = ScanEngine(
        timeout_per_plugin=effective_timeout,
        max_concurrency=effective_concurrency,
        safe_mode=effective_safe_mode,
    )
    for p in loader.plugins:
        engine.register_plugin(p)

    phases = list(phase) if phase else None
    plugin_names = [n.strip() for n in plugin.split(",")] if plugin else None

    results = asyncio.run(engine.scan(t, phases=phases, plugins=plugin_names))

    if output:
        if fmt == "html":
            from vibee_hacker.reports.html_report import HtmlReporter
            reporter = HtmlReporter()
        elif fmt == "sarif":
            from vibee_hacker.reports.sarif_report import SarifReporter
            reporter = SarifReporter()
        else:
            from vibee_hacker.reports.json_report import JsonReporter
            reporter = JsonReporter()
        reporter.generate(results, t, output)
        if not quiet:
            console.print(f"[green]Results saved to {output}[/green]")

    if not quiet:
        _print_summary(results)

    if fail_on:
        levels = [s.strip().upper() for s in fail_on.split(",")]
        for r in results:
            if str(r.context_severity).upper() in levels:
                sys.exit(1)


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
@click.option("--port", default=8000, type=int, help="Bind port (default: 8000)")
def dashboard(host, port):
    """Start the web dashboard."""
    import uvicorn
    from vibee_hacker.web.app import app
    uvicorn.run(app, host=host, port=port)


def _print_summary(results):
    if not results:
        console.print("[green]No vulnerabilities found.[/green]")
        return

    table = Table(title="Scan Results")
    table.add_column("Severity", style="bold")
    table.add_column("Plugin")
    table.add_column("Title")
    table.add_column("Confidence")

    severity_colors = {
        "critical": "red",
        "high": "bright_red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for r in results:
        sev = str(r.context_severity)
        color = severity_colors.get(sev, "white")
        table.add_row(f"[{color}]{sev}[/{color}]", r.plugin_name, r.title, r.confidence)

    console.print(table)
    console.print(f"\nTotal: {len(results)} findings")


if __name__ == "__main__":
    cli()
