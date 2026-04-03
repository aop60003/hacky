# Contributing to VIBEE-Hacker

## Setup

```bash
git clone https://github.com/your-org/vibee-hacker.git
cd vibee-hacker
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Plugin Development

All plugins inherit from `PluginBase`. One plugin per file.

### Blackbox plugin skeleton

```python
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target, Result, Severity

class MyBlackboxPlugin(PluginBase):
    name = "my_plugin"          # unique snake_case name
    category = "blackbox"
    phase = 3                   # 1=recon, 2=passive, 3=active, 4=post
    base_severity = Severity.HIGH
    safe_mode = True            # set False only for destructive tests

    def is_applicable(self, target: Target) -> bool:
        return target.url is not None

    async def run(self, target: Target, context=None) -> list[Result]:
        # Use target.url, target.session, etc.
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="Vulnerability title",
            description="Evidence and details",
            url=target.url,
        )]
```

Drop the file in `vibee_hacker/plugins/blackbox/` — it's auto-discovered.

### Whitebox plugin skeleton

```python
class MyWhiteboxPlugin(PluginBase):
    name = "my_whitebox"
    category = "whitebox"
    phase = 2
    base_severity = Severity.MEDIUM

    def is_applicable(self, target: Target) -> bool:
        return target.path is not None

    async def run(self, target: Target, context=None) -> list[Result]:
        results = []
        for src_file in target.path.rglob("*.py"):
            content = src_file.read_text(errors="ignore")
            if "dangerous_pattern" in content:
                results.append(Result(...))
        return results
```

Drop in `vibee_hacker/plugins/whitebox/`.

## Test Requirements

Every plugin needs **at minimum**:

1. A **detection test** — verifies the plugin returns ≥1 `Result` for a known-vulnerable input.
2. A **non-detection test** — verifies the plugin returns `[]` for a clean input.

Blackbox plugins: use `pytest-httpserver` or `respx` to mock HTTP responses.
Whitebox plugins: write a small in-memory snippet string as the target.

```bash
# Run all tests
pytest tests/ -q

# Run only plugin tests
pytest tests/plugins/ -q

# Run with coverage
pytest tests/ --cov=vibee_hacker --cov-report=term-missing
```

Tests live in `tests/` mirroring the source layout:
- `tests/plugins/blackbox/test_<name>.py`
- `tests/plugins/whitebox/test_<name>.py`

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/my-plugin`
2. Implement the plugin and its tests (both detection + non-detection).
3. Run `pytest tests/ -q` — all tests must pass.
4. Run `python -m vibee_hacker scan --target http://localhost --mode blackbox --plugin my_plugin` to confirm CLI integration.
5. Open a PR with a description covering:
   - What vulnerability the plugin detects
   - How it was tested
   - Any known limitations or false-positive risks

## Code Style

- Python 3.10+, type hints required on all public methods.
- `ruff` for linting: `ruff check vibee_hacker/`
- No inter-plugin dependencies — each plugin must be independently runnable.
- Error handling: catch network/timeout errors, return `[]` on non-critical failures, never raise from `run()`.

## Security

- Plugins must never write to disk or modify the host environment.
- Blackbox plugins must respect `safe_mode=True` to skip destructive payloads.
- Do not commit credentials, API keys, or tokens.
