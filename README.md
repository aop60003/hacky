# VIBEE-Hacker

Python 기반 보안 취약점 점검 도구. 블랙박스(외부 스캐닝)와 화이트박스(소스코드 분석)를 모두 지원하는 플러그인 아키텍처.

## Features

- **123 Security Plugins** — 75 blackbox + 48 whitebox
- **Blackbox Scanning** — SQL Injection, XSS, SSRF, XXE, SSTI, Command Injection, and 69 more
- **Whitebox Analysis** — Pattern matching for Python, JavaScript, PHP, Java, Go
- **IaC Security** — Dockerfile, Kubernetes, Terraform, GitHub Actions, GitLab CI
- **Dependency Audit** — Vulnerable packages, typosquatting, supply chain risks
- **Reports** — JSON, HTML (dark theme), SARIF 2.1.0
- **Web Dashboard** — FastAPI-based scan management
- **CI/CD Integration** — `--fail-on`, `--profile ci`, SARIF output
- **OWASP Coverage** — Top 10 fully covered (blackbox 10/10, whitebox 8/10)

## Quick Start

```bash
pip install .
vibee-hacker scan --target https://example.com --mode blackbox --format html --output report.html
vibee-hacker scan --target ./my-project --mode whitebox --format sarif --output report.sarif
vibee-hacker dashboard --port 8000
```

## CLI Options

```
vibee-hacker scan [OPTIONS]

Options:
  -t, --target TEXT          Target URL or path (required)
  -m, --mode [blackbox|whitebox]  Scan mode (default: blackbox)
  -o, --output PATH          Output file path
  --format [json|html|sarif]  Report format (default: json)
  --profile [stealth|default|aggressive|ci]  Scan profile
  --proxy TEXT               HTTP proxy (e.g., http://127.0.0.1:8080)
  --safe-mode / --no-safe-mode  Filter destructive plugins (default: on)
  --insecure                 Disable SSL verification
  --concurrency INTEGER      Max concurrent plugins (default: 10)
  --delay INTEGER            Delay between requests in ms
  --timeout INTEGER          Per-plugin timeout in seconds (default: 60)
  --phase INTEGER            Run specific phases only (repeatable)
  --plugin TEXT              Comma-separated plugin names
  --fail-on TEXT             Exit 1 if severity found (e.g., critical,high)
  --quiet                    Minimal output
```

## Scan Profiles

| Profile | Concurrency | Timeout | Safe Mode |
|---------|------------|---------|-----------|
| stealth | 2 | 30s | Yes |
| default | 10 | 60s | Yes |
| aggressive | 50 | 120s | No |
| ci | 5 | 30s | Yes |

## Plugin Architecture

All plugins inherit from `PluginBase`:

```python
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target, Result, Severity

class MyPlugin(PluginBase):
    name = "my_plugin"
    category = "blackbox"  # or "whitebox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target, context=None):
        # Your detection logic here
        return [Result(...)]
```

Drop the file in `vibee_hacker/plugins/blackbox/` or `whitebox/` — it's auto-discovered.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT License
