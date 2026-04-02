# VIBEE-Hacker — Claude Code Harness Design

## Project Overview

Python-based security vulnerability scanner. Plugin architecture supporting both whitebox (source code analysis) and blackbox (external scanning).
CLI + web dashboard interface, HTML/JSON/SARIF/PDF report generation.

## Harness Architecture: 3-Agent Pattern

This project follows Anthropic's harness design principles.

### 1. Planner

- Receives user requests and expands them into **complete feature specifications**
- Focuses on high-level design; delegates implementation details to the Generator
- Breaks each feature into independent **sprint units**
- Defines **success criteria (sprint contract)** before each sprint begins

### 2. Generator

- Implements only one sprint (feature) at a time
- Must hand off to the Evaluator after sprint completion
- Does not evaluate its own code (limitation of self-assessment)

### 3. Evaluator

- **Independently** verifies the Generator's output
- Makes pass/fail decisions based on the sprint contract
- Verification methods: test execution, actual scan behavior, code review
- On failure, returns to the Generator with specific feedback

## Sprint Workflow

```
1. Planner: Define sprint scope + write success criteria
2. Generator: Implement code (one feature/plugin)
3. Evaluator: Verify against success criteria
   - Pass → Move to next sprint
   - Fail → Return to Generator with feedback
4. Repeat
```

## Context Management

### Context Reset Strategy

- Prefer **reset over compression** when context grows long
- Always write a **structured handoff artifact** on reset:
  - What has been completed so far
  - What needs to be done next
  - Known issues and decisions
- Store handoff artifacts in `docs/handoff/`

### Context Anxiety Prevention

- Resist the urge to mark work as complete prematurely
- Do not mark a sprint as done until all contract criteria are met

## Evaluator Rubric

### Code Quality

- Does it correctly implement the plugin interface (PluginBase)?
- Is error handling adequate (timeouts, network failures, etc.)?
- Are type hints consistent?

### Functionality

- Does the plugin actually detect vulnerabilities (test cases pass)?
- Does it work correctly from the CLI?
- Are reports generated correctly?

### Security

- Is the tool itself free of security vulnerabilities?
- Is user input properly validated?
- Does it avoid affecting systems outside the scan target?

## Development Rules

### Sprint Contract First

Always define the sprint contract **before** writing code:
- What this sprint will implement
- Conditions for success (specific, verifiable)
- What is out of scope

### Plugin Development Rules

- All plugins inherit from `PluginBase`
- One plugin = one file
- `is_applicable()` determines applicability
- `run()` returns `list[Result]`
- No inter-plugin dependencies (guaranteed independent execution)

### Testing

- At least 1 detection test + 1 non-detection test per plugin
- Blackbox plugins tested with mock servers
- Whitebox plugins tested with vulnerable sample code
- Use `pytest`

### Iterative Simplification

- Every harness component is an assumption about "what the model cannot do independently"
- Re-evaluate regularly: remove scaffolding that is no longer needed
- Find the simplest solution; increase complexity only when necessary

## Work Discipline

### Pre-Work

- Before refactoring any file >300 LOC, first remove all dead code, unused imports, and debug logs. Commit this cleanup separately.
- Never attempt multi-file refactors in a single pass. Break into explicit phases, touching no more than 5 files per phase.
- Plan and implementation are separate steps. When asked to "plan," output only the plan. Write code only after approval.
- For non-trivial features (3+ steps or architectural decisions), write a detailed spec and reach agreement before implementing.

### Code Quality Standards

- **Forced Verification**: Never report a task as complete until the type checker, linter, and test suite have all been run. Never say "Done!" with errors outstanding.
- **Senior Standard**: If architecture is flawed, state is duplicated, or patterns are inconsistent, propose and implement structural fixes.
- **No Over-Engineering**: Do not design for imaginary scenarios nobody asked for. Simple and correct beats elaborate and speculative.
- **Demand Elegance**: For non-trivial changes, ask "is there a cleaner way?" If a fix feels hacky, implement the clean solution.

### Context Decay Prevention

- After 10+ messages in a conversation, MUST re-read any file before editing it. Do not trust memory of file contents.
- If context degradation is detected (forgetting file structures, referencing nonexistent variables), run `/compact` proactively.
- For tasks touching 5+ independent files, distribute work across sub-agents in parallel.

### Edit Safety

- Re-read the file before every edit. Read it again after editing to confirm the change applied correctly.
- When renaming any function/type/variable, grep for: direct calls, type references, string literals, dynamic imports, and test files. Do not assume a single grep caught everything.
- Never delete a file without verifying nothing references it. Never push to a shared repository without explicit instruction.

### File System Usage

- Do not blindly dump large files into context. Use bash grep/search to selectively read only what is needed.
- Write intermediate results to files. Work across multiple passes grounded in reproducible data.
- When debugging, save logs and outputs to files for verification against reproducible artifacts.

### Self-Improvement

- After any user correction, log the pattern to `gotchas.md` and convert it into a rule that prevents the same category of error.
- After fixing a bug, explain why it happened and whether anything can prevent that category of bug in the future.
- If a fix fails after 2 attempts, stop. Re-read the entire relevant section top-down and identify where the mental model was wrong.
- When the user says "rethink" or "we're going in circles," drop everything and propose a fundamentally different approach.

### Housekeeping

- When given a bug report, just fix it. Trace logs, errors, and failing tests, then resolve. Zero hand-holding required.
- Offer to checkpoint before risky changes. If a file gets long enough to be hard to reason about, suggest splitting it.

## Tech Stack

- **Language**: Python 3.10+
- **CLI**: Click
- **Web**: FastAPI + Jinja2 templates
- **Async**: asyncio (parallel plugin execution)
- **Testing**: pytest + pytest-asyncio
- **HTTP**: httpx (async support)
- **Models**: Pydantic v2
- **LLM**: litellm (optional, multi-provider)
- **Reports**: HTML (Jinja2), JSON, SARIF, PDF
- **Telemetry**: JSONL event tracing

## Project Structure

```
vibee-hacker/
├── vibee_hacker/
│   ├── core/           # Engine, models, state management
│   │   ├── engine.py        # ScanEngine — plugin execution orchestration
│   │   ├── plugin_base.py   # PluginBase — plugin interface
│   │   ├── models.py        # Target, Result, InterPhaseContext (Pydantic)
│   │   ├── state.py         # ScanState — scan lifecycle state machine
│   │   ├── orchestrator.py  # ScanOrchestrator — state-managed scan execution
│   │   ├── autofix.py       # AutofixEngine + LLMAutofixEngine
│   │   └── crawler.py       # Web crawler
│   ├── plugins/
│   │   ├── blackbox/   # 85 DAST plugins
│   │   └── whitebox/   # 50 SAST plugins
│   ├── config/         # Config management (ENV → file → default)
│   ├── llm/            # LLM integration (litellm, streaming, cost tracking)
│   ├── telemetry/      # JSONL event tracing
│   ├── skills/         # Security knowledge packages (Markdown)
│   │   ├── vulnerabilities/  # xss, sqli, ssrf, cmdi, idor
│   │   ├── technologies/     # wordpress, graphql, jwt
│   │   └── protocols/        # http, tls
│   ├── tools/          # Tool registry for LLM agent
│   ├── cli/            # Click CLI + Rich Live display
│   ├── web/            # FastAPI dashboard
│   └── reports/        # JSON, HTML, SARIF, PDF reporters
├── tests/
├── docs/
│   ├── handoff/
│   └── sprints/
├── pyproject.toml
├── CLAUDE.md
└── README.md
```
