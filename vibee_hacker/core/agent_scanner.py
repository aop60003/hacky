"""Agentic scan engine: LLM-driven security testing with tool execution.

The agent operates as an autonomous penetration tester that can:
- Run shell commands (nmap, sqlmap, curl, dig, etc.)
- Execute Python code (custom payloads, API calls, crypto)
- Send crafted HTTP requests (header injection, parameter fuzzing)
- Run built-in scanner plugins (135 vulnerability checks)
- Chain findings into multi-step exploits

The agent loop follows Strix's pattern:
  observe → reason → act → observe → repeat
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vibee_hacker.core.models import Result, Target
from vibee_hacker.core.state import ScanState

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are VIBEE-Agent, an expert penetration tester conducting an authorized security assessment.

## Target
- URL/Path: {target}
- Mode: {mode}
- Scope: ONLY test the specified target. Do NOT scan other hosts.

## Available Tools
You have these tools. Call ONE tool per response using the JSON format below.

### terminal_execute
Run shell commands: nmap, sqlmap, curl, dig, whois, openssl, nuclei, etc.
```json
{{"tool": "terminal_execute", "args": {{"command": "nmap -sV -p 80,443 target.com", "timeout": 120}}}}
```

### python_execute
Run Python code for custom payloads, data parsing, API calls, crypto.
```json
{{"tool": "python_execute", "args": {{"code": "import jwt\\ntoken = jwt.encode({{'admin': True}}, 'secret', algorithm='HS256')\\nprint(token)"}}}}
```

### http_request
Send crafted HTTP requests with full header/body/method control.
```json
{{"tool": "http_request", "args": {{"url": "https://target.com/api/users", "method": "POST", "headers": {{"Content-Type": "application/json"}}, "body": "{{\\\"id\\\": 1}}"}}}}
```

### run_plugin
Run a built-in VIBEE scanner plugin (135 available).
```json
{{"tool": "run_plugin", "args": {{"plugin_name": "sqli", "target_url": "https://target.com"}}}}
```

### browser_new_tab / browser_goto / browser_click / browser_type / browser_execute_js
Full browser automation via Playwright. Navigate, interact, execute JS, capture console logs.
```json
{{"tool": "browser_new_tab", "args": {{"url": "https://target.com/login"}}}}
{{"tool": "browser_type", "args": {{"selector": "#username", "text": "admin"}}}}
{{"tool": "browser_execute_js", "args": {{"js_code": "document.cookie"}}}}
{{"tool": "browser_get_console_logs", "args": {{}}}}
```

### web_search
Search the internet for CVEs, PoCs, exploit techniques.
```json
{{"tool": "web_search", "args": {{"query": "CVE-2024-1234 proof of concept"}}}}
```

### create_note / list_notes / get_note / update_note
Persistent notes for tracking findings, methodology, and plans.
```json
{{"tool": "create_note", "args": {{"title": "SQLi in /api/users", "content": "...", "category": "findings"}}}}
```

### add_finding / list_findings
Record structured vulnerability findings with CVSS scores and fix suggestions.
```json
{{"tool": "add_finding", "args": {{"title": "SQL Injection", "description": "...", "severity": "critical", "cvss_score": 9.8, "endpoint": "/api/users", "evidence": "...", "cwe_id": "CWE-89"}}}}
```

### view_file / edit_file
Read and modify source code files (whitebox mode).
```json
{{"tool": "view_file", "args": {{"file_path": "/path/to/app.py", "start_line": 1, "end_line": 50}}}}
```

### load_skill
Load additional security knowledge at runtime.
```json
{{"tool": "load_skill", "args": {{"skill_name": "jwt"}}}}
```

### think
Record your reasoning before taking complex decisions.
```json
{{"tool": "think", "args": {{"thought": "The target uses JWT. I should test for algorithm confusion..."}}}}
```

### create_agent / send_agent_message / agent_finish
Delegate tasks to sub-agents for parallel testing.
```json
{{"tool": "create_agent", "args": {{"name": "recon-agent", "task": "Enumerate subdomains of target.com"}}}}
```

### finish
End the assessment and provide your final report.
```json
{{"tool": "finish", "args": {{"summary": "...", "risk_rating": "high", "exploit_chains": ["..."], "priority_fixes": ["..."]}}}}
```

## Strategy
1. **Recon first**: Run nmap, enumerate directories (gobuster/ffuf), fingerprint tech stack
2. **Attack surface mapping**: Discover all endpoints, parameters, forms, APIs, WebSockets
3. **Vulnerability testing**: Test EVERY discovered endpoint for injection flaws (SQLi, XSS, SSRF, SSTI, XXE, CMDi, NoSQLi, path traversal)
4. **Authentication attacks**: Test login flows, JWT tokens, OAuth, session management, default creds
5. **Chain exploits aggressively**:
   - SSRF → cloud metadata → credential theft → API access
   - SQLi → file read → source code → more vulns
   - XSS → session hijack → account takeover
   - XXE → SSRF → internal services
   - IDOR → PII exposure → privilege escalation
6. **Prove impact**: Execute the chain end-to-end. Extract real data. Demonstrate RCE if possible.
7. **Use web_search**: Look up CVEs for discovered software versions. Find known PoCs.
8. **Take notes**: Record findings with add_finding (CVSS scored). Use create_note for methodology tracking.
9. **Load skills on demand**: If you encounter JWT, load_skill("jwt"). If you find Docker, load_skill("docker").
10. **Never stop early**: You have {max_iterations} iterations. Use them ALL. After each finding, ask "what else can I chain this with?"

## Rules
- ALWAYS respond with exactly ONE tool call in JSON format
- After each tool result, analyze it and decide the next step
- When you've gathered enough evidence or exhausted useful tests, call finish
- Include your reasoning BEFORE the JSON tool call

{skills_context}
"""


class AgentScanner:
    """LLM-driven autonomous security scanner with tool execution."""

    def __init__(
        self,
        llm_config: Optional[Any] = None,
        timeout_per_plugin: int = 60,
        max_concurrency: int = 10,
        safe_mode: bool = True,
        max_iterations: int = 30,
        tracer: Optional[Any] = None,
    ):
        if llm_config is None:
            from vibee_hacker.llm.config import LLMConfig
            llm_config = LLMConfig.from_config()
        self._llm_config = llm_config
        self._timeout = timeout_per_plugin
        self._concurrency = max_concurrency
        self._safe_mode = safe_mode
        self._max_iterations = max_iterations
        self._tracer = tracer

        self.state = ScanState(max_iterations=max_iterations)
        self._findings: List[Result] = []
        self._conversation: List[Dict[str, Any]] = []

        # Register all tools
        self._register_tools()

    def _register_tools(self) -> None:
        """Ensure all agent tools are registered."""
        import vibee_hacker.tools.terminal  # noqa: F401
        import vibee_hacker.tools.python_exec  # noqa: F401
        import vibee_hacker.tools.http_client  # noqa: F401
        import vibee_hacker.tools.scanner  # noqa: F401
        import vibee_hacker.tools.browser  # noqa: F401
        import vibee_hacker.tools.agents_graph  # noqa: F401
        import vibee_hacker.tools.notes  # noqa: F401
        import vibee_hacker.tools.web_search  # noqa: F401
        import vibee_hacker.tools.reporting  # noqa: F401
        import vibee_hacker.tools.thinking  # noqa: F401
        import vibee_hacker.tools.file_edit  # noqa: F401
        import vibee_hacker.tools.load_skill  # noqa: F401

    async def scan(self, target: Target) -> AgentScanResult:
        """Run an agentic security assessment."""
        from vibee_hacker.llm import LLM

        self.state.target = target.url or target.path or ""
        self.state.mode = target.mode
        self.state.started_at = datetime.now(timezone.utc)

        llm = LLM(self._llm_config)
        if not llm.is_available:
            return AgentScanResult(
                findings=[], summary="LLM not configured. Set VIBEE_LLM."
            )

        # Build system prompt
        system_prompt = self._build_system_prompt(target)
        llm.set_system_prompt(system_prompt)

        # Start conversation
        self._conversation = [
            {"role": "user", "content": self._build_initial_prompt(target)},
        ]

        # Agent loop
        for iteration in range(1, self._max_iterations + 1):
            self.state.iteration = iteration
            logger.info("=== Agent iteration %d/%d ===", iteration, self._max_iterations)

            # Get LLM decision
            response = await self._llm_turn(llm)
            if not response:
                break

            # Parse tool call
            tool_call = self._parse_tool_call(response)
            if not tool_call:
                logger.warning("No tool call parsed from response, retrying...")
                self._conversation.append({
                    "role": "user",
                    "content": "Please respond with a JSON tool call. Example: {\"tool\": \"terminal_execute\", \"args\": {\"command\": \"echo hello\"}}",
                })
                continue

            tool_name = tool_call.get("tool", "")
            tool_args = tool_call.get("args", {})

            # Handle finish
            if tool_name == "finish":
                self.state.set_completed()
                return self._build_result(tool_args)

            # Execute tool
            logger.info("Executing tool: %s", tool_name)
            tool_result = await self._execute_tool(tool_name, tool_args, target)

            # Feed result back to LLM
            result_text = self._format_tool_result(tool_name, tool_result)
            self._conversation.append({
                "role": "user",
                "content": f"Tool result from `{tool_name}`:\n```\n{result_text}\n```\n\nAnalyze this result and decide your next action.",
            })

            if self._tracer:
                self._tracer.log_plugin_started(f"agent:{tool_name}", phase=iteration)

        # Max iterations — force finish
        self.state.set_completed()
        final = await self._force_finish(llm)
        return final

    async def _llm_turn(self, llm: Any) -> str:
        """Get one response from the LLM."""
        result = ""
        async for resp in llm.generate(self._conversation, temperature=0.4, max_tokens=4096):
            if resp.finished:
                result = resp.content
        self._conversation.append({"role": "assistant", "content": result})
        return result

    async def _execute_tool(
        self, tool_name: str, args: Dict[str, Any], target: Target
    ) -> Any:
        """Execute a tool and return its result."""
        from vibee_hacker.tools.registry import get_tool_by_name
        import asyncio

        # Map agent tool names to registered tools
        if tool_name == "run_plugin":
            args.setdefault("target_url", target.url or target.path or "")
            args.setdefault("mode", target.mode)

        fn = get_tool_by_name(tool_name)
        if fn is None:
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            if asyncio.iscoroutinefunction(fn):
                return await fn(**args)
            return fn(**args)
        except TypeError as e:
            return {"error": f"Invalid arguments for {tool_name}: {e}"}
        except Exception as e:
            return {"error": f"Tool execution failed: {e}"}

    async def _force_finish(self, llm: Any) -> "AgentScanResult":
        """Force the agent to produce a final report."""
        self._conversation.append({
            "role": "user",
            "content": "Max iterations reached. Call the finish tool NOW with your assessment summary.",
        })
        response = await self._llm_turn(llm)
        tool_call = self._parse_tool_call(response)
        if tool_call and tool_call.get("tool") == "finish":
            return self._build_result(tool_call.get("args", {}))
        # LLM didn't produce finish — extract what we can
        return AgentScanResult(
            findings=self._findings,
            summary=response[:500] if response else "Assessment incomplete.",
            iterations_used=self.state.iteration,
        )

    def _build_system_prompt(self, target: Target) -> str:
        """Build system prompt with skills."""
        from vibee_hacker.skills import auto_select_skills, generate_skills_description

        skill_names = auto_select_skills(
            profile="aggressive",
            mode=target.mode,
        )
        skills_context = generate_skills_description(skill_names)

        return SYSTEM_PROMPT.format(
            target=target.url or target.path or "",
            mode=target.mode,
            max_iterations=self._max_iterations,
            skills_context=skills_context if skills_context else "",
        )

    def _build_initial_prompt(self, target: Target) -> str:
        """Build the first user message to kick off the agent."""
        target_str = target.url or target.path or ""
        return (
            f"Begin your security assessment of {target_str}.\n"
            f"Mode: {target.mode}.\n\n"
            f"Phase 1 — Reconnaissance:\n"
            f"1. Run nmap to discover open ports and services\n"
            f"2. Use terminal to enumerate directories (gobuster or curl for common paths)\n"
            f"3. Send HTTP requests to discover API endpoints, headers, and tech stack\n"
            f"4. Check for robots.txt, sitemap.xml, .well-known/security.txt\n"
            f"5. Use web_search to look up any identified software versions for CVEs\n\n"
            f"After recon, move to Phase 2 — attack every discovered endpoint.\n"
            f"Be thorough. Be creative. Chain everything."
        )

    @staticmethod
    def _parse_tool_call(text: str) -> Optional[Dict[str, Any]]:
        """Extract a JSON tool call from LLM response."""
        # Try code block first
        match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find raw JSON with "tool" key
        for m in re.finditer(r'\{[^{}]*"tool"[^{}]*\}', text, re.DOTALL):
            try:
                parsed = json.loads(m.group())
                if "tool" in parsed:
                    return parsed
            except json.JSONDecodeError:
                continue

        # Try nested JSON (args might contain nested objects)
        brace_start = text.find('{"tool"')
        if brace_start < 0:
            brace_start = text.find("{\"tool\"")
        if brace_start >= 0:
            depth = 0
            for i in range(brace_start, len(text)):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[brace_start:i + 1])
                        except json.JSONDecodeError:
                            break

        return None

    @staticmethod
    def _format_tool_result(tool_name: str, result: Any) -> str:
        """Format tool result for inclusion in conversation."""
        if isinstance(result, dict):
            if "error" in result:
                return f"ERROR: {result['error']}"
            if "stdout" in result:
                parts = []
                if result.get("stdout"):
                    parts.append(f"STDOUT:\n{result['stdout'][:10000]}")
                if result.get("stderr"):
                    parts.append(f"STDERR:\n{result['stderr'][:5000]}")
                parts.append(f"EXIT CODE: {result.get('exit_code', 'unknown')}")
                return "\n".join(parts)
            if "status_code" in result:
                parts = [
                    f"HTTP {result['status_code']} ({result.get('elapsed_ms', '?')}ms)",
                    f"Headers: {json.dumps(result.get('headers', {}), indent=2)[:3000]}",
                ]
                body = result.get("body", "")
                if len(body) > 5000:
                    parts.append(f"Body ({result.get('body_length', len(body))} chars, truncated):\n{body[:5000]}")
                else:
                    parts.append(f"Body:\n{body}")
                return "\n".join(parts)
            return json.dumps(result, indent=2, default=str)[:15000]
        if isinstance(result, list):
            return json.dumps(result, indent=2, default=str)[:15000]
        return str(result)[:15000]

    def _build_result(self, args: Dict[str, Any]) -> "AgentScanResult":
        """Build final result from finish tool args."""
        return AgentScanResult(
            findings=self._findings,
            summary=args.get("summary", "Assessment completed."),
            exploit_chains=args.get("exploit_chains", []),
            risk_rating=args.get("risk_rating", "info"),
            priority_fixes=args.get("priority_fixes", []),
            iterations_used=self.state.iteration,
        )


class AgentScanResult:
    """Result of an agentic security assessment."""

    def __init__(
        self,
        findings: Optional[List[Result]] = None,
        summary: str = "",
        exploit_chains: Optional[List[str]] = None,
        risk_rating: str = "info",
        priority_fixes: Optional[List[str]] = None,
        iterations_used: int = 0,
        llm_stats: str = "",
    ):
        self.findings = findings or []
        self.summary = summary
        self.exploit_chains = exploit_chains or []
        self.risk_rating = risk_rating
        self.priority_fixes = priority_fixes or []
        self.iterations_used = iterations_used
        self.llm_stats = llm_stats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "risk_rating": self.risk_rating,
            "exploit_chains": self.exploit_chains,
            "priority_fixes": self.priority_fixes,
            "iterations_used": self.iterations_used,
            "total_findings": len(self.findings),
            "findings": [r.to_dict() for r in self.findings],
            "llm_stats": self.llm_stats,
        }
