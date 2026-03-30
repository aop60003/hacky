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
def scan(target, mode, phase, plugin, output, fmt, timeout, fail_on, quiet):
    """Run a security scan against a target."""
    if mode == "blackbox":
        t = Target(url=target, mode=mode)
    else:
        t = Target(path=target, mode=mode)

    loader = PluginLoader()
    loader.load_builtin()

    engine = ScanEngine(timeout_per_plugin=timeout)
    for p in loader.plugins:
        engine.register_plugin(p)

    phases = list(phase) if phase else None
    plugin_names = [n.strip() for n in plugin.split(",")] if plugin else None

    results = asyncio.run(engine.scan(t, phases=phases, plugins=plugin_names))

    if output:
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
