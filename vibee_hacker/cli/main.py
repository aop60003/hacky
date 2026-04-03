"""VIBEE-Hacker CLI interface."""

from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console
from rich.table import Table

from vibee_hacker import __version__
from vibee_hacker.config import Config, apply_saved_config
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Result, Target
from vibee_hacker.core.plugin_loader import PluginLoader

console = Console()

# Apply saved config on import (env vars from ~/.vibee-hacker/config.json)
apply_saved_config()


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
    "--format", "fmt", default="json", type=click.Choice(["json", "html", "sarif", "pdf"])
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
@click.option("--save-session", type=str, default=None, help="Save scan session with given ID")
@click.option("--resume", type=click.Path(exists=True), default=None, help="Resume scan from session file path")
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Previous report JSON for diff")
@click.option("--false-positive", "false_positive", type=click.Path(exists=True), default=None, help="JSON file with rule_ids to suppress")
@click.option("--targets-file", type=click.Path(exists=True), default=None, help="File with one target URL per line")
@click.option("--cookie", type=str, default=None, help="Cookie header (e.g., 'session=abc123')")
@click.option("--header", "extra_headers", type=str, multiple=True, help="Extra header (repeatable, e.g., 'Authorization: Bearer token')")
@click.option("--policy", type=str, default=None, help="Scan policy name or YAML/JSON file path")
@click.option("--llm-enhance", is_flag=True, help="Enhance results with LLM analysis (requires VIBEE_LLM)")
@click.option("--skills", type=str, default=None, help="Comma-separated skill names for LLM context (e.g., xss,sqli)")
@click.option("--agent", is_flag=True, help="Agentic mode: LLM autonomously selects plugins and explores (requires VIBEE_LLM)")
@click.option("--agent-iterations", default=30, type=int, help="Max iterations for agentic mode (default: 30)")
@click.option("--poc", is_flag=True, help="Generate PoC exploits for found vulnerabilities")
def scan(
    target, mode, phase, plugin, output, fmt, timeout, fail_on, quiet,
    proxy, safe_mode, concurrency, delay, insecure, profile,
    save_session, resume, baseline, false_positive,
    targets_file, cookie, extra_headers, policy, llm_enhance, skills,
    agent, agent_iterations, poc,
):
    """Run a security scan against a target."""
    # Apply profile presets first; explicit flags override them
    effective_concurrency = concurrency
    effective_timeout = timeout
    effective_safe_mode = safe_mode

    if profile:
        preset = Config.get_profile(profile)
        if preset:
            ctx = click.get_current_context()
            if ctx.get_parameter_source("timeout") == click.core.ParameterSource.DEFAULT:
                effective_timeout = int(preset["vibee_timeout"])
            if ctx.get_parameter_source("concurrency") == click.core.ParameterSource.DEFAULT:
                effective_concurrency = int(preset["vibee_concurrency"])
            if ctx.get_parameter_source("safe_mode") == click.core.ParameterSource.DEFAULT:
                effective_safe_mode = preset["vibee_safe_mode"].lower() in ("true", "1", "yes")

    verify_ssl = not insecure

    # Resolve scan policy
    active_policy = None
    if policy:
        from vibee_hacker.core.scan_policy import BUILTIN_POLICIES, ScanPolicy
        import os
        if policy in BUILTIN_POLICIES:
            active_policy = BUILTIN_POLICIES[policy]
        elif os.path.exists(policy):
            active_policy = ScanPolicy.from_file(policy)
        else:
            console.print(f"[red]Unknown policy: {policy}. Available: {', '.join(BUILTIN_POLICIES)}[/red]")
            raise SystemExit(1)
        if not quiet:
            console.print(f"[cyan]Policy: {active_policy.name} — {active_policy.description}[/cyan]")

    # Build auth_headers from --cookie and --header options
    auth_headers: dict[str, str] = {}
    if cookie:
        auth_headers["Cookie"] = cookie
    for h in extra_headers:
        if ": " in h:
            key, val = h.split(": ", 1)
            auth_headers[key] = val

    if mode == "blackbox":
        t = Target(url=target, mode=mode, verify_ssl=verify_ssl, proxy=proxy, delay=delay)
    else:
        t = Target(path=target, mode=mode, verify_ssl=verify_ssl, proxy=proxy, delay=delay)

    # --- Agentic mode: LLM-driven autonomous scanning ---
    if agent:
        from vibee_hacker.llm.config import LLMConfig
        llm_config = LLMConfig.from_config()
        if not llm_config.is_configured:
            console.print("[red]Error: --agent requires VIBEE_LLM to be set.[/red]")
            console.print("[dim]Example: export VIBEE_LLM=anthropic/claude-sonnet-4-20250514[/dim]")
            raise SystemExit(1)

        from vibee_hacker.core.agent_scanner import AgentScanner
        from vibee_hacker.telemetry import Tracer

        tracer = Tracer()
        scanner = AgentScanner(
            llm_config=llm_config,
            timeout_per_plugin=effective_timeout,
            max_concurrency=effective_concurrency,
            safe_mode=effective_safe_mode,
            max_iterations=agent_iterations,
            tracer=tracer,
        )

        if not quiet:
            console.print(f"[bold cyan]VIBEE-Hacker Agent Mode[/bold cyan]")
            console.print(f"[cyan]Target: {target} | Mode: {mode} | Max iterations: {agent_iterations}[/cyan]")
            console.print(f"[cyan]LLM: {llm_config.model_name}[/cyan]")
            console.print("[dim]The LLM will autonomously select plugins and explore...[/dim]\n")

        agent_result = asyncio.run(scanner.scan(t))

        if not quiet:
            console.print(f"\n[bold green]Agent Scan Complete[/bold green]")
            console.print(f"[cyan]Iterations: {agent_result.iterations_used} | "
                          f"Plugins: {len(agent_result.plugins_run)} | "
                          f"Findings: {len(agent_result.findings)}[/cyan]")
            console.print(f"[cyan]Risk: {agent_result.risk_rating.upper()}[/cyan]")
            if agent_result.llm_stats:
                console.print(f"[dim]{agent_result.llm_stats}[/dim]")
            console.print(f"\n[bold]Executive Summary:[/bold]\n{agent_result.summary}")
            if agent_result.exploit_chains:
                console.print(f"\n[bold red]Exploit Chains:[/bold red]")
                for chain in agent_result.exploit_chains:
                    console.print(f"  - {chain}")
            if agent_result.priority_fixes:
                console.print(f"\n[bold yellow]Priority Fixes:[/bold yellow]")
                for fix in agent_result.priority_fixes:
                    console.print(f"  - {fix}")

        results = agent_result.findings

        if poc:
            from vibee_hacker.core.poc_generator import PoCGenerator
            gen = PoCGenerator()
            pocs = gen.generate_all(results)
            if pocs:
                poc_report = gen.generate_report(pocs)
                poc_path = (output or "poc_report") + ".poc.md"
                with open(poc_path, "w", encoding="utf-8") as f:
                    f.write(poc_report)
                if not quiet:
                    console.print(f"[red]PoC report: {poc_path} ({len(pocs)} exploits)[/red]")

        if output:
            import json as json_mod
            if fmt == "json":
                with open(output, "w") as f:
                    json_mod.dump(agent_result.to_dict(), f, indent=2, default=str)
            else:
                # Use standard reporters for other formats
                if fmt == "html":
                    from vibee_hacker.reports.html_report import HtmlReporter
                    HtmlReporter().generate(results, t, output)
                elif fmt == "sarif":
                    from vibee_hacker.reports.sarif_report import SarifReporter
                    SarifReporter().generate(results, t, output)
                elif fmt == "pdf":
                    from vibee_hacker.reports.pdf_report import PdfReporter
                    PdfReporter().generate(results, t, output)
            if not quiet:
                console.print(f"[green]Results saved to {output}[/green]")

        if not quiet:
            _print_summary(results)

        if fail_on:
            levels = [s.strip().upper() for s in fail_on.split(",")]
            for r in results:
                if str(r.context_severity).upper() in levels:
                    sys.exit(1)
        return

    # --- Standard mode: rule-based scanning ---
    loader = PluginLoader()
    loader.load_builtin()

    # Initialize telemetry tracer
    from vibee_hacker.telemetry import Tracer
    tracer = Tracer()

    # Set up live display callbacks (when not quiet)
    live_display = None
    if not quiet:
        from vibee_hacker.cli.live_display import LiveScanDisplay
        live_display = LiveScanDisplay(console=console)
        display_target = target[:60] + "..." if len(target) > 60 else target
        live_display.set_scan_info(display_target, mode, len(loader.plugins))
        tracer.on_plugin_start = live_display.on_plugin_start
        tracer.on_plugin_complete = live_display.on_plugin_complete
        tracer.on_finding = live_display.on_finding

    engine = ScanEngine(
        timeout_per_plugin=effective_timeout,
        max_concurrency=effective_concurrency,
        safe_mode=effective_safe_mode,
        tracer=tracer,
    )
    for p in loader.plugins:
        engine.register_plugin(p)

    phases = list(phase) if phase else None
    plugin_names = [n.strip() for n in plugin.split(",")] if plugin else None

    # Session management: load existing session if --resume provided
    from vibee_hacker.core.session import ScanSession, SessionManager

    active_session: ScanSession | None = None
    if resume:
        sm = SessionManager()
        try:
            active_session = sm.load(resume)
            if not quiet:
                console.print(f"[cyan]Resuming session {active_session.session_id} "
                              f"(skipping {len(active_session.completed_plugins)} completed plugins)[/cyan]")
            # Exclude already-completed plugins from this run
            skip_set = set(active_session.completed_plugins)
            if plugin_names:
                plugin_names = [p for p in plugin_names if p not in skip_set]
            else:
                all_names = [p.name for p in loader.plugins]
                plugin_names = [p for p in all_names if p not in skip_set]
        except (ValueError, FileNotFoundError) as exc:
            console.print(f"[red]Failed to load session: {exc}[/red]")
            raise SystemExit(1)

    # Run scan with optional live display
    if live_display:
        with live_display.start():
            results = asyncio.run(engine.scan(t, phases=phases, plugins=plugin_names))
    else:
        results = asyncio.run(engine.scan(t, phases=phases, plugins=plugin_names))

    # P2-4: Baseline diff — filter out findings already in a previous report
    if baseline:
        import json
        with open(baseline) as f:
            prev_data = json.load(f)
        prev_keys: set[tuple[str, str, str]] = set()
        for finding in prev_data.get("findings", []):
            key = (
                finding.get("rule_id") or "",
                finding.get("endpoint") or "",
                finding.get("param_name") or "",
            )
            prev_keys.add(key)
        new_results = [
            r for r in results
            if (r.rule_id or "", r.endpoint or "", r.param_name or "") not in prev_keys
        ]
        if not quiet:
            console.print(
                f"[cyan]Baseline: {len(results) - len(new_results)} existing filtered, "
                f"{len(new_results)} new[/cyan]"
            )
        results = new_results

    # P2-5: False-positive suppression — filter out rule_ids listed in suppress file
    if false_positive:
        import json
        with open(false_positive) as f:
            fp_data = json.load(f)
        suppress_rules: set[str] = set(fp_data.get("suppress", []))
        results = [r for r in results if r.rule_id not in suppress_rules]

    # Merge resumed results with new results
    if active_session is not None:
        from vibee_hacker.core.models import Severity
        prior: list = []
        for rd in active_session.results:
            # Reconstruct lightweight Result objects for reporting
            prior_r = Result(
                plugin_name=rd.get("plugin_name", ""),
                base_severity=Severity[rd.get("base_severity", "info").upper()],
                title=rd.get("title", ""),
                description=rd.get("description", ""),
                evidence=rd.get("evidence", ""),
                recommendation=rd.get("recommendation", ""),
                endpoint=rd.get("endpoint", ""),
                confidence=rd.get("confidence", "tentative"),
            )
            prior.append(prior_r)
        results = prior + results

    # Build / update session if --save-session provided
    if save_session:
        sm = SessionManager()
        if active_session is None:
            active_session = ScanSession(
                session_id=save_session,
                target=target,
                mode=mode,
                options={
                    "timeout": timeout,
                    "safe_mode": safe_mode,
                    "concurrency": concurrency,
                },
            )
        else:
            active_session.session_id = save_session

        # Record all completed plugin names from this run
        run_plugins = plugin_names or [p.name for p in loader.plugins]
        for pname in run_plugins:
            active_session.mark_plugin_complete(pname)

        # Replace results with the full merged set
        active_session.results = [r.to_dict() for r in results]
        active_session.status = "completed"
        path = sm.save(active_session)
        if not quiet:
            console.print(f"[green]Session saved to {path}[/green]")

    # LLM enhancement: generate context-aware autofix suggestions
    if llm_enhance:
        from vibee_hacker.llm.config import LLMConfig
        llm_config = LLMConfig.from_config()
        if not llm_config.is_configured:
            if not quiet:
                console.print("[yellow]Warning: VIBEE_LLM not set. Skipping LLM enhancement.[/yellow]")
                console.print("[dim]Set VIBEE_LLM=<model> and VIBEE_LLM_API_KEY=<key> to enable.[/dim]")
        else:
            from vibee_hacker.llm import LLM
            from vibee_hacker.core.autofix import LLMAutofixEngine
            llm = LLM(llm_config)
            # Load skills into LLM system prompt
            if skills:
                from vibee_hacker.skills import generate_skills_description, validate_skill_names
                skill_names = [s.strip() for s in skills.split(",")]
                valid, invalid = validate_skill_names(skill_names)
                if invalid and not quiet:
                    console.print(f"[yellow]Unknown skills: {', '.join(invalid)}[/yellow]")
                if valid:
                    skills_desc = generate_skills_description(valid)
                    llm.set_system_prompt(skills_desc)
                    if not quiet:
                        console.print(f"[cyan]Loaded skills: {', '.join(valid)}[/cyan]")
            if llm.is_available:
                if not quiet:
                    console.print("[cyan]Enhancing results with LLM analysis...[/cyan]")
                autofix = LLMAutofixEngine(llm=llm)

                async def _enhance_results():
                    for r in results[:10]:  # Limit to top 10 findings
                        if r.recommendation.strip():
                            continue
                        fix_text = await autofix.get_llm_fix(
                            rule_id=r.rule_id,
                            title=r.title,
                            description=r.description,
                            evidence=r.evidence,
                        )
                        if fix_text:
                            r.recommendation = fix_text

                asyncio.run(_enhance_results())
                if not quiet:
                    console.print(f"[green]LLM enhancement complete. {llm.stats.to_summary()}[/green]")
            else:
                if not quiet:
                    console.print("[yellow]Warning: litellm not installed. Run: pip install litellm[/yellow]")

    if poc:
        from vibee_hacker.core.poc_generator import PoCGenerator
        gen = PoCGenerator()
        pocs = gen.generate_all(results)
        if pocs:
            poc_report = gen.generate_report(pocs)
            poc_path = (output or "poc_report") + ".poc.md"
            with open(poc_path, "w", encoding="utf-8") as f:
                f.write(poc_report)
            if not quiet:
                console.print(f"[red]PoC report: {poc_path} ({len(pocs)} exploits)[/red]")

    if output:
        if fmt == "html":
            from vibee_hacker.reports.html_report import HtmlReporter
            reporter = HtmlReporter()
        elif fmt == "sarif":
            from vibee_hacker.reports.sarif_report import SarifReporter
            reporter = SarifReporter()
        elif fmt == "pdf":
            from vibee_hacker.reports.pdf_report import PdfReporter
            reporter = PdfReporter()
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
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="File with one target per line")
@click.option("--mode", "-m", default="blackbox", type=click.Choice(["blackbox", "whitebox"]))
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "html", "sarif", "pdf"]))
@click.option("--output-dir", "-o", default="./reports", help="Output directory for reports")
@click.option("--quiet", is_flag=True)
def batch(file, mode, fmt, output_dir, quiet):
    """Batch scan multiple targets from a file."""
    import os
    os.makedirs(output_dir, exist_ok=True)

    with open(file) as f:
        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not quiet:
        console.print(f"[cyan]Batch scanning {len(targets)} targets...[/cyan]")

    for i, target_str in enumerate(targets, 1):
        if not quiet:
            console.print(f"[cyan][{i}/{len(targets)}] Scanning {target_str}...[/cyan]")

        if mode == "blackbox":
            t = Target(url=target_str, mode=mode)
        else:
            t = Target(path=target_str, mode=mode)

        loader = PluginLoader()
        loader.load_builtin()
        engine = ScanEngine(timeout_per_plugin=30, safe_mode=True)
        for p in loader.plugins:
            engine.register_plugin(p)

        results = asyncio.run(engine.scan(t))

        # Generate report
        safe_name = (
            target_str.replace("://", "_").replace("/", "_").replace(":", "_")[:50]
        )
        output_path = os.path.join(output_dir, f"{safe_name}.{fmt}")

        if fmt == "html":
            from vibee_hacker.reports.html_report import HtmlReporter
            HtmlReporter().generate(results, t, output_path)
        elif fmt == "sarif":
            from vibee_hacker.reports.sarif_report import SarifReporter
            SarifReporter().generate(results, t, output_path)
        elif fmt == "pdf":
            from vibee_hacker.reports.pdf_report import PdfReporter
            PdfReporter().generate(results, t, output_path)
        else:
            from vibee_hacker.reports.json_report import JsonReporter
            JsonReporter().generate(results, t, output_path)

        if not quiet:
            console.print(f"  [green]{len(results)} findings -> {output_path}[/green]")

    if not quiet:
        console.print(f"[green]Batch complete: {len(targets)} targets scanned.[/green]")


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
