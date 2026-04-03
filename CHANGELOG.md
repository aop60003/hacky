# Changelog

## [2.2.0] - 2026-04-03

### Added
- Cross-file Taint Tracker (Python AST + JavaScript regex)
- WebSocket Security Scanner (ws:// discovery, upgrade probe, socket.io)
- HTTP Request Smuggling Detection (CL.TE, TE.CL, proxy detection)
- GitHub Release v2.2.0 tag
- Dockerfile (python:3.12-slim, non-root, Playwright)
- CI improvements (pip cache, coverage, Docker build job)
- E2E benchmark: 20/20 BB detection (100%), 85 WB findings, 12s scan

### Fixed
- Python sandbox hardened (getattr/dunder/attribute blocking, -S -I flags)
- Terminal pipe validation (segment-by-segment, dangerous redirect blocking)
- Telemetry body filtering (JWT, AWS keys, passwords, 0o600 permissions)
- State transition validation with VALID_TRANSITIONS
- Repeater DeprecationWarning (cookies → header)

## [2.1.0] - 2026-04-02

### Added
- LLM integration (litellm multi-provider support)
- Agent Scanner with autonomous pentesting
- 38 security knowledge skills (vulnerabilities, technologies, protocols, cloud)
- 18 agent tools (terminal, python, browser, http, scanner, etc.)
- Telemetry system (JSONL event tracing)
- Config management (ENV → file → default chain)
- ScanState state machine with transition validation
- ScanOrchestrator for state-managed scan execution
- Python execution sandboxing (AST validation + blocked modules)
- Terminal pipe command validation
- Telemetry body sensitive data filtering (JWT, AWS keys, passwords)

### Changed
- Migrated models to Pydantic v2
- Updated CLAUDE.md with v2.1 architecture
- Added pydantic>=2.0 dependency

## [2.0.0] - 2026-04-02

### Added
- YAML Template Engine (Nuclei-style rules)
- Authentication Framework (login macro, cookie/JWT capture)
- Scan Policy system (5 built-in policies)
- Interactsh Client (external OOB detection)
- OpenAPI/Swagger Fuzzer
- PDF Report generation
- Headless Browser Crawler (Playwright)
- OOB Callback Server
- Multi-target Batch Scan
- Authenticated Crawling (--cookie, --header)
- Workflow Chaining Engine
- Request Repeater (Burp-style)
- Alert Manager (group, filter, dedup)
- DNS Check + SSL Deep Check plugins
- Autofix Engine (code fix suggestions)
- CVSS v3.1 Calculator
- Dynamic Rate Limiter
- Docker Image Security Scanner
- Advanced Dashboard (stats/trends/compare API)
- Scan Scheduler with trend analysis
- Secure Code Gateway (pre-commit hook)
- Plugin Marketplace

## [1.3.0] - 2026-04-01

### Added
- Crawler → Plugin integration (auto-crawl + URL feeding)
- E2E vulnerable app testing (20/20 vuln types detected)
- P0 fixes: SSRF, blind SQLi, taint ordering, sanitizers
- P1 fixes: JS taint analyzer, port scan, tech fingerprint, CVE lookup
- P2 fixes: dir_enum, default_creds, api_key_exposure, baseline diff

## [1.1.0] - 2026-04-01

### Added
- Python Taint Analyzer
- Web Crawler (async BFS)
- Session Management (save/resume)

## [1.0.0] - 2026-04-01

### Added
- Core engine with phase-based execution
- 123 security plugins (blackbox + whitebox)
- CLI (Click) with 20+ options
- Web Dashboard (FastAPI)
- Reports: JSON, HTML, SARIF
- CI: GitHub Actions, Docker
