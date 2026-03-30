# VIBEE-Hacker Core Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** VIBEE-Hacker의 코어 엔진, 플러그인 시스템, Result 모델, CLI 기본 구조를 구현하여 모든 후속 플러그인이 동작할 수 있는 기반을 만든다.

**Architecture:** 플러그인 아키텍처 기반. `PluginBase` 추상 클래스를 상속하는 플러그인들이 `plugins/` 디렉터리에서 자동 발견되어 엔진에 등록. 엔진은 Phase별로 적용 가능한 플러그인을 asyncio로 병렬 실행하고 결과를 수집. CLI(Click)가 진입점.

**Tech Stack:** Python 3.10+, Click (CLI), asyncio, httpx, pytest, pyproject.toml (packaging)

**Project Root:** `C:/Users/qwaqw/desktop/hacker` — 모든 상대 경로는 이 디렉터리 기준.

**Scope Note:** 이 Plan은 코어 엔진 기반만 구축. 다음은 후속 Plan에서 구현:
- EndpointRegistry 전체 기능 → Plan 2 (Blackbox Plugins)
- CLI 고급 옵션 (`--proxy`, `--profile`, `--safe-mode`, `--session` 등) → Plan 2+
- HTML/PDF/SARIF 리포트 → Plan 4 (Dashboard & Reports)
- `base_severity`는 스펙의 문자열 대신 IntEnum으로 구현 (더 나은 타입 안전성). `to_dict()`에서 문자열로 직렬화하여 호환.

---

## File Structure

```
vibee-hacker/
├── pyproject.toml                      # 패키지 설정, 의존성, entry_points
├── vibee_hacker/
│   ├── __init__.py                     # 버전 정보
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py                   # Target, Result, WhiteboxResult 데이터 모델
│   │   ├── plugin_base.py              # PluginBase 추상 클래스
│   │   ├── plugin_loader.py            # 플러그인 자동 발견/등록
│   │   ├── engine.py                   # 스캔 엔진 (Phase 관리, 플러그인 실행)
│   │   └── endpoint_registry.py        # EndpointRegistry (URL 정규화, 중복 제거)
│   ├── plugins/
│   │   ├── __init__.py
│   │   ├── blackbox/
│   │   │   └── __init__.py
│   │   └── whitebox/
│   │       └── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py                     # Click CLI 진입점
│   └── reports/
│       ├── __init__.py
│       └── json_report.py              # JSON 리포트 생성
├── tests/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── test_models.py
│   │   ├── test_plugin_base.py
│   │   ├── test_plugin_loader.py
│   │   ├── test_engine.py
│   │   └── test_endpoint_registry.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── test_main.py
│   └── fixtures/
│       └── sample_plugin.py            # 테스트용 더미 플러그인
└── README.md
```

---

### Task 1: 프로젝트 초기화 + pyproject.toml

**Files:**
- Create: `pyproject.toml`
- Create: `vibee_hacker/__init__.py`
- Create: `tests/__init__.py`

- [ ] **Step 1: pyproject.toml 생성**

```toml
[build-system]
requires = ["setuptools>=68.0", "setuptools-scm"]
build-backend = "setuptools.build_meta"

[project]
name = "vibee-hacker"
version = "0.1.0"
description = "Security vulnerability scanner with plugin architecture"
requires-python = ">=3.10"
dependencies = [
    "click>=8.1",
    "httpx>=0.27",
    "rich>=13.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=5.0",
]

[project.scripts]
vibee-hacker = "vibee_hacker.cli.main:cli"

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2: vibee_hacker/__init__.py 생성**

```python
"""VIBEE-Hacker: Security vulnerability scanner."""

__version__ = "0.1.0"
```

- [ ] **Step 3: 필수 __init__.py 파일 생성**

빈 `__init__.py` 파일들:
- `tests/__init__.py`
- `tests/core/__init__.py`
- `tests/cli/__init__.py`
- `vibee_hacker/core/__init__.py`
- `vibee_hacker/plugins/__init__.py`
- `vibee_hacker/plugins/blackbox/__init__.py`
- `vibee_hacker/plugins/whitebox/__init__.py`
- `vibee_hacker/cli/__init__.py`
- `vibee_hacker/reports/__init__.py`

- [ ] **Step 4: git 초기화 + 의존성 설치**

```bash
cd C:/Users/qwaqw/desktop/hacker
git init
echo "__pycache__/\n*.pyc\n.pytest_cache/\n*.egg-info/\ndist/\nbuild/\n.vibee-cache/\n.env" > .gitignore
pip install -e ".[dev]"
```

- [ ] **Step 5: 빌드 확인**

Run: `python -c "import vibee_hacker; print(vibee_hacker.__version__)"`
Expected: `0.1.0`

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore vibee_hacker/ tests/
git commit -m "chore: initialize project structure with pyproject.toml"
```

---

### Task 2: 데이터 모델 (Target, Result)

**Files:**
- Create: `vibee_hacker/core/models.py`
- Create: `tests/core/test_models.py`

- [ ] **Step 1: 모델 테스트 작성**

```python
# tests/core/test_models.py
from vibee_hacker.core.models import Target, Result, Severity


class TestTarget:
    def test_create_url_target(self):
        t = Target(url="https://example.com")
        assert t.url == "https://example.com"
        assert t.mode == "blackbox"

    def test_create_whitebox_target(self):
        t = Target(path="/src/project", mode="whitebox")
        assert t.path == "/src/project"
        assert t.mode == "whitebox"

    def test_target_host_extraction(self):
        t = Target(url="https://example.com:8080/api")
        assert t.host == "example.com"
        assert t.port == 8080


class TestResult:
    def test_create_result(self):
        r = Result(
            plugin_name="sqli",
            base_severity=Severity.CRITICAL,
            title="SQL Injection in /api/users",
            description="Parameter 'id' is vulnerable",
            evidence="' OR 1=1--",
        )
        assert r.base_severity == Severity.CRITICAL
        assert r.context_severity == Severity.CRITICAL
        assert r.confidence == "tentative"
        assert r.plugin_status == "completed"

    def test_result_to_dict(self):
        r = Result(
            plugin_name="xss",
            base_severity=Severity.HIGH,
            title="XSS",
            description="Reflected XSS",
        )
        d = r.to_dict()
        assert d["plugin_name"] == "xss"
        assert d["base_severity"] == "high"
        assert "timestamp" in d

    def test_severity_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
```

- [ ] **Step 2: 테스트 실행하여 실패 확인**

Run: `pytest tests/core/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: 모델 구현**

```python
# vibee_hacker/core/models.py
"""Core data models for VIBEE-Hacker."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse


class Severity(enum.IntEnum):
    """Vulnerability severity levels."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Target:
    """Scan target definition."""

    url: str | None = None
    path: str | None = None
    mode: str = "blackbox"

    @property
    def host(self) -> str | None:
        if self.url:
            return urlparse(self.url).hostname
        return None

    @property
    def port(self) -> int | None:
        if self.url:
            parsed = urlparse(self.url)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == "https" else 80
        return None


@dataclass
class Result:
    """Scan result from a plugin."""

    plugin_name: str
    base_severity: Severity
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: str | None = None
    cvss_score: float | None = None
    request_raw: str = ""
    response_raw: str = ""
    curl_command: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint: str = ""
    param_name: str | None = None
    context_severity: Severity | None = None
    validated: bool = False
    validation_count: int = 0
    confidence: str = "tentative"
    plugin_status: str = "completed"
    rule_id: str = ""

    def __post_init__(self):
        if self.context_severity is None:
            self.context_severity = self.base_severity

    def to_dict(self) -> dict:
        return {
            "plugin_name": self.plugin_name,
            "base_severity": str(self.base_severity),
            "context_severity": str(self.context_severity),
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "endpoint": self.endpoint,
            "param_name": self.param_name,
            "confidence": self.confidence,
            "plugin_status": self.plugin_status,
            "rule_id": self.rule_id,
            "timestamp": self.timestamp.isoformat(),
            "curl_command": self.curl_command,
        }


@dataclass
class InterPhaseContext:
    """Shared state passed between phases and plugins."""

    waf_info: dict | None = None
    waf_bypass_payloads: dict | None = None
    tech_stack: list[str] = field(default_factory=list)
    ssrf_endpoints: list[str] = field(default_factory=list)
    dangling_cnames: list[str] = field(default_factory=list)
    discovered_api_schema: dict | None = None
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/core/test_models.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add vibee_hacker/core/models.py tests/core/test_models.py
git commit -m "feat: add Target and Result data models with severity enum"
```

---

### Task 3: PluginBase 추상 클래스

**Files:**
- Create: `vibee_hacker/core/plugin_base.py`
- Create: `tests/core/test_plugin_base.py`
- Create: `tests/fixtures/sample_plugin.py`

- [ ] **Step 1: PluginBase 테스트 작성**

```python
# tests/core/test_plugin_base.py
import pytest
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target


class TestPluginBase:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            PluginBase()

    def test_concrete_plugin(self):
        from tests.fixtures.sample_plugin import SamplePlugin

        p = SamplePlugin()
        assert p.name == "Sample Plugin"
        assert p.category == "blackbox"
        assert p.phase == 3

    def test_is_applicable_default(self):
        from tests.fixtures.sample_plugin import SamplePlugin

        p = SamplePlugin()
        target = Target(url="https://example.com")
        assert p.is_applicable(target) is True

    def test_requires_provides(self):
        from tests.fixtures.sample_plugin import SamplePlugin

        p = SamplePlugin()
        assert p.requires == []
        assert p.provides == []

    def test_destructive_level_default(self):
        from tests.fixtures.sample_plugin import SamplePlugin

        p = SamplePlugin()
        assert p.destructive_level == 0
```

- [ ] **Step 2: 테스트용 더미 플러그인 작성**

```python
# tests/fixtures/__init__.py
```

```python
# tests/fixtures/sample_plugin.py
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target, Result, Severity


class SamplePlugin(PluginBase):
    name = "Sample Plugin"
    description = "A test plugin"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target) -> list[Result]:
        return [
            Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="Test finding",
                description="Found something",
            )
        ]
```

- [ ] **Step 3: 테스트 실행하여 실패 확인**

Run: `pytest tests/core/test_plugin_base.py -v`
Expected: FAIL

- [ ] **Step 4: PluginBase 구현**

```python
# vibee_hacker/core/plugin_base.py
"""Base class for all VIBEE-Hacker plugins."""

from __future__ import annotations

import abc
from vibee_hacker.core.models import Target, Result, Severity


class PluginBase(abc.ABC):
    """Abstract base class for scanner plugins."""

    name: str = ""
    description: str = ""
    category: str = ""          # "blackbox" or "whitebox"
    phase: int = 0              # 1, 2, 3 (blackbox) or 1-5 (whitebox)
    base_severity: Severity = Severity.INFO
    requires: list[str] = []    # InterPhaseContext fields needed
    provides: list[str] = []    # InterPhaseContext fields produced
    detection_criteria: str = ""
    expected_evidence: str = ""
    destructive_level: int = 0  # 0: safe, 1: data change, 2: account impact

    def is_applicable(self, target: Target) -> bool:
        """Check if this plugin should run against the target."""
        return True

    @abc.abstractmethod
    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        """Execute the plugin scan. Must be implemented by subclasses."""
        ...
```

- [ ] **Step 5: 테스트 통과 확인**

Run: `pytest tests/core/test_plugin_base.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add vibee_hacker/core/plugin_base.py tests/core/test_plugin_base.py tests/fixtures/
git commit -m "feat: add PluginBase abstract class with metadata fields"
```

---

### Task 4: 플러그인 자동 로더

**Files:**
- Create: `vibee_hacker/core/plugin_loader.py`
- Create: `tests/core/test_plugin_loader.py`

- [ ] **Step 1: 로더 테스트 작성**

```python
# tests/core/test_plugin_loader.py
from vibee_hacker.core.plugin_loader import PluginLoader


class TestPluginLoader:
    def test_discover_plugins_from_directory(self, tmp_path):
        # Create a dummy plugin file
        plugin_code = '''
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Target, Result, Severity

class DummyPlugin(PluginBase):
    name = "Dummy"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO

    async def run(self, target, context=None):
        return []
'''
        (tmp_path / "__init__.py").write_text("")
        (tmp_path / "dummy.py").write_text(plugin_code)

        loader = PluginLoader()
        plugins = loader.discover(str(tmp_path))
        assert len(plugins) >= 1
        assert plugins[0].name == "Dummy"

    def test_filter_by_category(self):
        loader = PluginLoader()
        loader.load_builtin()
        bb = loader.get_plugins(category="blackbox")
        wb = loader.get_plugins(category="whitebox")
        assert isinstance(bb, list)
        assert isinstance(wb, list)

    def test_filter_by_phase(self):
        loader = PluginLoader()
        loader.load_builtin()
        phase1 = loader.get_plugins(phase=1)
        assert isinstance(phase1, list)
```

- [ ] **Step 2: 테스트 실행하여 실패 확인**

Run: `pytest tests/core/test_plugin_loader.py -v`
Expected: FAIL

- [ ] **Step 3: 플러그인 로더 구현**

```python
# vibee_hacker/core/plugin_loader.py
"""Plugin auto-discovery and loading."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path

from vibee_hacker.core.plugin_base import PluginBase


class PluginLoader:
    """Discovers and manages plugins."""

    def __init__(self):
        self._plugins: list[PluginBase] = []

    @property
    def plugins(self) -> list[PluginBase]:
        return list(self._plugins)

    def discover(self, directory: str) -> list[PluginBase]:
        """Discover plugins in a directory by scanning for PluginBase subclasses."""
        found = []
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return found

        for py_file in dir_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            classes = self._load_module_plugins(py_file)
            found.extend(classes)

        self._plugins.extend(found)
        return found

    def load_builtin(self) -> None:
        """Load built-in plugins from vibee_hacker/plugins/."""
        base = Path(__file__).parent.parent / "plugins"
        for subdir in ["blackbox", "whitebox"]:
            plugin_dir = base / subdir
            if plugin_dir.is_dir():
                self.discover(str(plugin_dir))

    def get_plugins(
        self,
        category: str | None = None,
        phase: int | None = None,
        name: str | None = None,
    ) -> list[PluginBase]:
        """Filter plugins by criteria."""
        result = self._plugins
        if category:
            result = [p for p in result if p.category == category]
        if phase is not None:
            result = [p for p in result if p.phase == phase]
        if name:
            names = [n.strip() for n in name.split(",")]
            result = [p for p in result if p.name in names]
        return result

    def _load_module_plugins(self, path: Path) -> list[PluginBase]:
        """Load all PluginBase subclasses from a Python file."""
        module_name = f"vibee_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            return []

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            return []

        found = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, PluginBase)
                and obj is not PluginBase
                and not inspect.isabstract(obj)
            ):
                found.append(obj())
        return found
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/core/test_plugin_loader.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add vibee_hacker/core/plugin_loader.py tests/core/test_plugin_loader.py
git commit -m "feat: add plugin auto-discovery and loading system"
```

---

### Task 5: 스캔 엔진

**Files:**
- Create: `vibee_hacker/core/engine.py`
- Create: `tests/core/test_engine.py`

- [ ] **Step 1: 엔진 테스트 작성**

```python
# tests/core/test_engine.py
import pytest
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target, Result, Severity
from vibee_hacker.core.plugin_base import PluginBase


class PassivePlugin(PluginBase):
    name = "passive_test"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target, context=None):
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="Header missing",
            description="X-Frame-Options missing",
        )]


class ActivePlugin(PluginBase):
    name = "active_test"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL

    async def run(self, target, context=None):
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="SQLi found",
            description="SQL injection",
        )]


class FailingPlugin(PluginBase):
    name = "failing_test"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH

    async def run(self, target, context=None):
        raise ConnectionError("Target unreachable")


class TestScanEngine:
    @pytest.fixture
    def engine(self):
        e = ScanEngine()
        e.register_plugin(PassivePlugin())
        e.register_plugin(ActivePlugin())
        return e

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_scan_returns_results(self, engine, target):
        results = await engine.scan(target)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_results_sorted_by_severity(self, engine, target):
        results = await engine.scan(target)
        assert results[0].base_severity >= results[1].base_severity

    @pytest.mark.asyncio
    async def test_phase_ordering(self, engine, target):
        results = await engine.scan(target)
        # passive (phase 2) runs before active (phase 3)
        passive = [r for r in results if r.plugin_name == "passive_test"]
        active = [r for r in results if r.plugin_name == "active_test"]
        assert len(passive) == 1
        assert len(active) == 1

    @pytest.mark.asyncio
    async def test_scan_specific_phase(self, engine, target):
        results = await engine.scan(target, phases=[2])
        assert all(r.plugin_name == "passive_test" for r in results)

    @pytest.mark.asyncio
    async def test_plugin_failure_isolated(self, target):
        engine = ScanEngine()
        engine.register_plugin(PassivePlugin())
        engine.register_plugin(FailingPlugin())
        results = await engine.scan(target)
        # PassivePlugin succeeds, FailingPlugin fails gracefully
        assert len(results) >= 1
        passed = [r for r in results if r.plugin_name == "passive_test"]
        assert len(passed) == 1
```

- [ ] **Step 2: 테스트 실행하여 실패 확인**

Run: `pytest tests/core/test_engine.py -v`
Expected: FAIL

- [ ] **Step 3: 엔진 구현**

```python
# vibee_hacker/core/engine.py
"""Scan engine: orchestrates plugin execution across phases."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from vibee_hacker.core.models import Target, Result
from vibee_hacker.core.plugin_base import PluginBase

logger = logging.getLogger(__name__)


class ScanEngine:
    """Core scan engine that manages plugin lifecycle."""

    def __init__(self, timeout_per_plugin: int = 60):
        self._plugins: list[PluginBase] = []
        self._timeout = timeout_per_plugin

    def register_plugin(self, plugin: PluginBase) -> None:
        self._plugins.append(plugin)

    async def scan(
        self,
        target: Target,
        phases: list[int] | None = None,
        plugins: list[str] | None = None,
    ) -> list[Result]:
        """Run scan against target, executing plugins by phase order."""
        applicable = self._filter_plugins(target, phases, plugins)
        by_phase: dict[int, list[PluginBase]] = defaultdict(list)
        for p in applicable:
            by_phase[p.phase].append(p)

        all_results: list[Result] = []
        for phase_num in sorted(by_phase.keys()):
            phase_plugins = by_phase[phase_num]
            results = await self._run_phase(target, phase_plugins)
            all_results.extend(results)

        all_results.sort(key=lambda r: r.base_severity, reverse=True)
        return all_results

    async def _run_phase(
        self, target: Target, plugins: list[PluginBase]
    ) -> list[Result]:
        """Run all plugins in a phase concurrently."""
        tasks = [
            self._run_plugin_safe(plugin, target) for plugin in plugins
        ]
        results_nested = await asyncio.gather(*tasks)
        return [r for sublist in results_nested for r in sublist]

    async def _run_plugin_safe(
        self, plugin: PluginBase, target: Target
    ) -> list[Result]:
        """Run a single plugin with error isolation and timeout."""
        try:
            results = await asyncio.wait_for(
                plugin.run(target, context=None), timeout=self._timeout
            )
            return results
        except asyncio.TimeoutError:
            logger.warning("Plugin %s timed out", plugin.name)
            return [self._make_error_result(plugin, "Plugin timed out")]
        except Exception as e:
            logger.warning("Plugin %s failed: %s", plugin.name, e)
            return [self._make_error_result(plugin, f"Plugin error: {e}")]

    def _filter_plugins(
        self,
        target: Target,
        phases: list[int] | None,
        plugins: list[str] | None,
    ) -> list[PluginBase]:
        result = [p for p in self._plugins if p.is_applicable(target)]
        if phases:
            result = [p for p in result if p.phase in phases]
        if plugins:
            result = [p for p in result if p.name in plugins]
        return result

    @staticmethod
    def _make_error_result(plugin: PluginBase, message: str) -> Result:
        return Result(
            plugin_name=plugin.name,
            base_severity=plugin.base_severity,
            title=f"{plugin.name}: Error",
            description=message,
            plugin_status="failed",
        )
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/core/test_engine.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add vibee_hacker/core/engine.py tests/core/test_engine.py
git commit -m "feat: add scan engine with phase-ordered plugin execution"
```

---

### Task 6: CLI 기본 구조

**Files:**
- Create: `vibee_hacker/cli/main.py`
- Create: `tests/cli/test_main.py`

- [ ] **Step 1: CLI 테스트 작성**

```python
# tests/cli/test_main.py
from click.testing import CliRunner
from vibee_hacker.cli.main import cli


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

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
```

- [ ] **Step 2: 테스트 실행하여 실패 확인**

Run: `pytest tests/cli/test_main.py -v`
Expected: FAIL

- [ ] **Step 3: CLI 구현**

```python
# vibee_hacker/cli/main.py
"""VIBEE-Hacker CLI interface."""

from __future__ import annotations

import asyncio
import json
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
        data = [r.to_dict() for r in results]
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
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
    """Print scan results summary table."""
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
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/cli/test_main.py -v`
Expected: All PASS

- [ ] **Step 5: CLI 실행 확인**

Run: `python -m vibee_hacker.cli.main --version`
Expected: `version 0.1.0`

- [ ] **Step 6: Commit**

```bash
git add vibee_hacker/cli/main.py tests/cli/test_main.py
git commit -m "feat: add Click CLI with scan command and rich output"
```

---

### Task 7: JSON 리포트 생성

**Files:**
- Create: `vibee_hacker/reports/json_report.py`
- Create: `tests/reports/test_json_report.py`

- [ ] **Step 1: 리포트 테스트 작성**

```python
# tests/reports/__init__.py
```

```python
# tests/reports/test_json_report.py
import json
from vibee_hacker.reports.json_report import JsonReporter
from vibee_hacker.core.models import Result, Severity, Target


class TestJsonReporter:
    def test_generate_report(self, tmp_path):
        results = [
            Result(
                plugin_name="sqli",
                base_severity=Severity.CRITICAL,
                title="SQL Injection",
                description="Found SQLi",
                rule_id="sqli_error_based",
            )
        ]
        target = Target(url="https://example.com")
        output = tmp_path / "report.json"

        reporter = JsonReporter()
        reporter.generate(results, target, str(output))

        data = json.loads(output.read_text())
        assert data["target"] == "https://example.com"
        assert data["total_findings"] == 1
        assert data["findings"][0]["title"] == "SQL Injection"
        assert "scan_date" in data

    def test_empty_results(self, tmp_path):
        target = Target(url="https://example.com")
        output = tmp_path / "report.json"

        reporter = JsonReporter()
        reporter.generate([], target, str(output))

        data = json.loads(output.read_text())
        assert data["total_findings"] == 0
        assert data["findings"] == []
```

- [ ] **Step 2: 테스트 실행하여 실패 확인**

Run: `pytest tests/reports/test_json_report.py -v`
Expected: FAIL

- [ ] **Step 3: 리포트 생성기 구현**

```python
# vibee_hacker/reports/json_report.py
"""JSON report generator."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from vibee_hacker.core.models import Result, Target


class JsonReporter:
    """Generates JSON scan reports."""

    def generate(self, results: list[Result], target: Target, output_path: str) -> None:
        severity_counts = Counter(str(r.context_severity) for r in results)
        report = {
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "target": target.url or target.path,
            "mode": target.mode,
            "total_findings": len(results),
            "severity_summary": dict(severity_counts),
            "findings": [r.to_dict() for r in results],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/reports/test_json_report.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add vibee_hacker/reports/json_report.py tests/reports/
git commit -m "feat: add JSON report generator"
```

---

### Task 8: 전체 통합 테스트

**Files:**
- Create: `tests/test_integration.py`

- [ ] **Step 1: 통합 테스트 작성**

```python
# tests/test_integration.py
"""End-to-end integration test."""

import json
import pytest
from click.testing import CliRunner

from vibee_hacker.cli.main import cli
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target, Result, Severity
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.plugin_loader import PluginLoader


class IntegrationPlugin(PluginBase):
    name = "integration_test"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target, context=None):
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="Integration test finding",
            description="This is a test",
            endpoint=target.url or "",
        )]


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_full_scan_pipeline(self):
        """Engine → Plugin → Result → Sort pipeline."""
        engine = ScanEngine()
        engine.register_plugin(IntegrationPlugin())
        target = Target(url="https://example.com")
        results = await engine.scan(target)
        assert len(results) == 1
        assert results[0].title == "Integration test finding"

    def test_cli_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert "0.1.0" in result.output

    def test_plugin_loader_discovers_nothing_in_empty(self, tmp_path):
        loader = PluginLoader()
        plugins = loader.discover(str(tmp_path))
        assert plugins == []
```

- [ ] **Step 2: 전체 테스트 실행**

Run: `pytest tests/ -v --tb=short`
Expected: All PASS

- [ ] **Step 3: 커버리지 확인**

Run: `pytest tests/ --cov=vibee_hacker --cov-report=term-missing`
Expected: Core modules coverage > 80%

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add end-to-end integration tests for core engine"
```

---

## Summary

| Task | 내용 | 산출물 |
|------|------|--------|
| 1 | 프로젝트 초기화 | pyproject.toml, 디렉터리 구조 |
| 2 | 데이터 모델 | Target, Result, Severity |
| 3 | PluginBase | 추상 클래스 + 메타데이터 |
| 4 | Plugin Loader | 자동 발견/등록/필터링 |
| 5 | Scan Engine | Phase별 실행, 에러 격리 |
| 6 | CLI | Click 기반 scan 명령어 |
| 7 | JSON Report | 리포트 생성기 |
| 8 | 통합 테스트 | E2E 파이프라인 검증 |

이 Plan 완료 후 다음 단계: **Plan 2 (Blackbox Tier 1 Plugins)** — SQLi, XSS, CMDi 등 핵심 플러그인 구현.
