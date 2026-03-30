# VIBEE-Hacker Blackbox Tier 1 Plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 핵심 블랙박스 플러그인 6개를 구현하여 실제 보안 스캔이 동작하는 MVP를 완성한다.

**Architecture:** 각 플러그인은 `PluginBase`를 상속, `plugins/blackbox/` 디렉터리에 파일 하나로 구현. httpx async 클라이언트로 HTTP 요청 수행. 각 플러그인에 mock 서버 기반 테스트 포함.

**Tech Stack:** Python 3.10+, httpx (async HTTP), pytest, pytest-httpx (mock HTTP)

**Project Root:** `C:/Users/qwaqw/desktop/hacker`

**Scope:** 이 Plan에서 구현하는 플러그인:
1. `header_check.py` — Phase 2, 보안 헤더 누락 점검
2. `cors_check.py` — Phase 2, CORS 설정 오류 점검
3. `sqli.py` — Phase 3, SQL Injection 탐지 (에러 기반)
4. `xss.py` — Phase 3, Reflected XSS 탐지
5. `cmdi.py` — Phase 3, OS Command Injection 탐지 (시간 기반)
6. `path_traversal.py` — Phase 3, 경로 순회 탐지

---

## File Structure

```
vibee_hacker/plugins/blackbox/
├── header_check.py
├── cors_check.py
├── sqli.py
├── xss.py
├── cmdi.py
└── path_traversal.py

tests/plugins/blackbox/
├── __init__.py
├── test_header_check.py
├── test_cors_check.py
├── test_sqli.py
├── test_xss.py
├── test_cmdi.py
└── test_path_traversal.py
```

---

### Task 1: 테스트 인프라 + pytest-httpx 설치

**Files:**
- Modify: `pyproject.toml`
- Create: `tests/plugins/__init__.py`
- Create: `tests/plugins/blackbox/__init__.py`

- [ ] **Step 1: pytest-httpx 의존성 추가**

`pyproject.toml` dev 의존성에 `"pytest-httpx>=0.30"` 추가.

- [ ] **Step 2: 설치**

```bash
cd C:/Users/qwaqw/desktop/hacker && pip install -e ".[dev]"
```

- [ ] **Step 3: 테스트 디렉터리 생성**

빈 `__init__.py`:
- `tests/plugins/__init__.py`
- `tests/plugins/blackbox/__init__.py`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml tests/plugins/
git commit -m "chore: add pytest-httpx dependency and plugin test directories"
```

---

### Task 2: header_check.py — 보안 헤더 점검

**Files:**
- Create: `vibee_hacker/plugins/blackbox/header_check.py`
- Create: `tests/plugins/blackbox/test_header_check.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/plugins/blackbox/test_header_check.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.header_check import HeaderCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestHeaderCheck:
    @pytest.fixture
    def plugin(self):
        return HeaderCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_missing_all_headers(self, plugin, target, httpx_mock):
        httpx_mock.add_response(url="https://example.com", headers={})
        results = await plugin.run(target)
        assert len(results) >= 4  # CSP, X-Frame-Options, HSTS, X-Content-Type-Options
        titles = [r.title for r in results]
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)

    @pytest.mark.asyncio
    async def test_all_headers_present(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "camera=()",
            },
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_severity_is_medium(self, plugin, target, httpx_mock):
        httpx_mock.add_response(url="https://example.com", headers={})
        results = await plugin.run(target)
        assert all(r.base_severity == Severity.MEDIUM for r in results)
```

- [ ] **Step 2: 테스트 실패 확인**
- [ ] **Step 3: 플러그인 구현**

```python
# vibee_hacker/plugins/blackbox/header_check.py
"""Security header check plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

REQUIRED_HEADERS = {
    "Content-Security-Policy": "CSP prevents XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking by controlling iframe embedding",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature permissions",
}


class HeaderCheckPlugin(PluginBase):
    name = "header_check"
    description = "Check for missing security headers"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "HTTP response missing recommended security headers"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except httpx.HTTPError:
                return []

        results = []
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, reason in REQUIRED_HEADERS.items():
            if header.lower() not in resp_headers:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Missing header: {header}",
                    description=f"{header} header is not set. {reason}.",
                    recommendation=f"Add the {header} header to HTTP responses.",
                    endpoint=target.url,
                    rule_id=f"header_missing_{header.lower().replace('-', '_')}",
                ))

        return results
```

- [ ] **Step 4: 테스트 통과 확인**
- [ ] **Step 5: Commit**

---

### Task 3: cors_check.py — CORS 설정 오류

**Files:**
- Create: `vibee_hacker/plugins/blackbox/cors_check.py`
- Create: `tests/plugins/blackbox/test_cors_check.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/plugins/blackbox/test_cors_check.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cors_check import CorsCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestCorsCheck:
    @pytest.fixture
    def plugin(self):
        return CorsCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_wildcard_origin_reflected(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={"Access-Control-Allow-Origin": "https://evil.com"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_cors_headers(self, plugin, target, httpx_mock):
        httpx_mock.add_response(url="https://example.com", headers={})
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        results = await plugin.run(target)
        assert any("Credentials" in r.title for r in results)
```

- [ ] **Step 2: 테스트 실패 확인**
- [ ] **Step 3: 플러그인 구현**

```python
# vibee_hacker/plugins/blackbox/cors_check.py
"""CORS misconfiguration check plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


class CorsCheckPlugin(PluginBase):
    name = "cors_check"
    description = "Check for CORS misconfigurations"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "Server reflects arbitrary Origin or uses wildcard with credentials"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results = []
        evil_origin = "https://evil.com"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(
                    target.url, headers={"Origin": evil_origin}
                )
            except httpx.HTTPError:
                return []

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == evil_origin:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="CORS: Arbitrary Origin reflected",
                description=f"Server reflects attacker-controlled Origin header: {evil_origin}",
                recommendation="Validate Origin against an allowlist instead of reflecting it.",
                cwe_id="CWE-942",
                endpoint=target.url,
                rule_id="cors_origin_reflected",
            ))

        if acao == "*" and acac == "true":
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.CRITICAL,
                title="CORS: Wildcard with Credentials",
                description="Access-Control-Allow-Origin: * combined with Allow-Credentials: true",
                recommendation="Never combine wildcard origin with credentials.",
                cwe_id="CWE-942",
                endpoint=target.url,
                rule_id="cors_wildcard_credentials",
            ))

        if acao == "null":
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.MEDIUM,
                title="CORS: null Origin allowed",
                description="Server allows null origin, exploitable via sandboxed iframes.",
                recommendation="Do not allow null origin in CORS configuration.",
                cwe_id="CWE-942",
                endpoint=target.url,
                rule_id="cors_null_origin",
            ))

        return results
```

- [ ] **Step 4: 테스트 통과 확인**
- [ ] **Step 5: Commit**

---

### Task 4: sqli.py — SQL Injection (에러 기반)

**Files:**
- Create: `vibee_hacker/plugins/blackbox/sqli.py`
- Create: `tests/plugins/blackbox/test_sqli.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/plugins/blackbox/test_sqli.py
import pytest
from vibee_hacker.plugins.blackbox.sqli import SqliPlugin
from vibee_hacker.core.models import Target, Severity


class TestSqli:
    @pytest.fixture
    def plugin(self):
        return SqliPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/search?q=test")

    @pytest.mark.asyncio
    async def test_error_based_detection(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/search?q=test",
            text="<html>Normal page</html>",
        )
        httpx_mock.add_response(
            url="https://example.com/search?q=test%27",
            text="You have an error in your SQL syntax near",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_sqli(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/search?q=test",
            text="<html>Normal page</html>",
        )
        httpx_mock.add_response(
            url="https://example.com/search?q=test%27",
            text="<html>Normal page</html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skip(self, plugin, httpx_mock):
        target = Target(url="https://example.com/")
        results = await plugin.run(target)
        assert len(results) == 0
```

- [ ] **Step 2: 테스트 실패 확인**
- [ ] **Step 3: 플러그인 구현**

```python
# vibee_hacker/plugins/blackbox/sqli.py
"""SQL Injection detection plugin (error-based)."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sql syntax.*error", re.I),
    re.compile(r"microsoft.*odbc.*driver", re.I),
    re.compile(r"oracle.*error", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"sqlite3?\.OperationalError", re.I),
    re.compile(r"pg_query\(\).*failed", re.I),
]

PAYLOADS = ["'", '"', "' OR '1'='1", "1' AND '1'='2", "1; SELECT 1--"]


class SqliPlugin(PluginBase):
    name = "sqli"
    description = "SQL Injection detection (error-based)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "SQL error patterns in response after injecting SQL payloads"
    expected_evidence = "SQL syntax error message in HTTP response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param_name, values in params.items():
                original_value = values[0] if values else ""
                for payload in PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue

                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern.search(resp.text):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"SQL Injection in parameter '{param_name}'",
                                description=f"Error-based SQLi detected with payload: {payload}",
                                evidence=pattern.pattern,
                                cwe_id="CWE-89",
                                endpoint=target.url,
                                param_name=param_name,
                                curl_command=f"curl '{test_url}'",
                                rule_id="sqli_error_based",
                            ))
                            return results  # Stop on first confirmed finding

        return results
```

- [ ] **Step 4: 테스트 통과 확인**
- [ ] **Step 5: Commit**

---

### Task 5: xss.py — Reflected XSS

**Files:**
- Create: `vibee_hacker/plugins/blackbox/xss.py`
- Create: `tests/plugins/blackbox/test_xss.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/plugins/blackbox/test_xss.py
import pytest
from vibee_hacker.plugins.blackbox.xss import XssPlugin
from vibee_hacker.core.models import Target, Severity


class TestXss:
    @pytest.fixture
    def plugin(self):
        return XssPlugin()

    @pytest.mark.asyncio
    async def test_reflected_xss_detected(self, plugin, httpx_mock):
        target = Target(url="https://example.com/search?q=test")
        httpx_mock.add_response(
            url="https://example.com/search?q=%3Cscript%3Ealert%28%27vbh%27%29%3C%2Fscript%3E",
            text="<html>Results for <script>alert('vbh')</script></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_xss(self, plugin, httpx_mock):
        target = Target(url="https://example.com/search?q=test")
        httpx_mock.add_response(
            url="https://example.com/search?q=%3Cscript%3Ealert%28%27vbh%27%29%3C%2Fscript%3E",
            text="<html>Results for &lt;script&gt;alert('vbh')&lt;/script&gt;</html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skip(self, plugin, httpx_mock):
        target = Target(url="https://example.com/")
        results = await plugin.run(target)
        assert len(results) == 0
```

- [ ] **Step 2: 테스트 실패 확인**
- [ ] **Step 3: 플러그인 구현**

```python
# vibee_hacker/plugins/blackbox/xss.py
"""Reflected XSS detection plugin."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

XSS_PAYLOADS = [
    "<script>alert('vbh')</script>",
    "<img src=x onerror=alert('vbh')>",
    "'\"><svg/onload=alert('vbh')>",
]


class XssPlugin(PluginBase):
    name = "xss"
    description = "Reflected XSS detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Injected XSS payload reflected unescaped in response body"
    expected_evidence = "XSS payload string found verbatim in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param_name in params:
                for payload in XSS_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue

                    if payload in resp.text:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Reflected XSS in parameter '{param_name}'",
                            description=f"Payload reflected unescaped: {payload[:50]}",
                            evidence=payload,
                            cwe_id="CWE-79",
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=f"curl '{test_url}'",
                            rule_id="xss_reflected",
                        ))
                        return results

        return results
```

- [ ] **Step 4: 테스트 통과 확인**
- [ ] **Step 5: Commit**

---

### Task 6: cmdi.py — OS Command Injection (시간 기반)

**Files:**
- Create: `vibee_hacker/plugins/blackbox/cmdi.py`
- Create: `tests/plugins/blackbox/test_cmdi.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/plugins/blackbox/test_cmdi.py
import pytest
from vibee_hacker.plugins.blackbox.cmdi import CmdiPlugin
from vibee_hacker.core.models import Target, Severity


class TestCmdi:
    @pytest.fixture
    def plugin(self):
        return CmdiPlugin()

    @pytest.mark.asyncio
    async def test_output_based_detection(self, plugin, httpx_mock):
        target = Target(url="https://example.com/ping?host=test")
        httpx_mock.add_response(
            url="https://example.com/ping?host=test",
            text="PING test",
        )
        httpx_mock.add_response(
            url="https://example.com/ping?host=test%3Becho+VIBEE_CMD_MARKER",
            text="PING test\nVIBEE_CMD_MARKER",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert "CWE-78" in (results[0].cwe_id or "")

    @pytest.mark.asyncio
    async def test_no_cmdi(self, plugin, httpx_mock):
        target = Target(url="https://example.com/ping?host=test")
        httpx_mock.add_response(
            url="https://example.com/ping?host=test",
            text="PING test",
        )
        httpx_mock.add_response(
            url="https://example.com/ping?host=test%3Becho+VIBEE_CMD_MARKER",
            text="PING test",
        )
        results = await plugin.run(target)
        assert len(results) == 0
```

- [ ] **Step 2: 테스트 실패 확인**
- [ ] **Step 3: 플러그인 구현**

```python
# vibee_hacker/plugins/blackbox/cmdi.py
"""OS Command Injection detection plugin."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

MARKER = "VIBEE_CMD_MARKER"
PAYLOADS = [
    f";echo {MARKER}",
    f"|echo {MARKER}",
    f"`echo {MARKER}`",
    f"$(echo {MARKER})",
    f"&&echo {MARKER}",
]


class CmdiPlugin(PluginBase):
    name = "cmdi"
    description = "OS Command Injection detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Command output marker found in response after injecting shell commands"
    expected_evidence = "VIBEE_CMD_MARKER string in response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param_name, values in params.items():
                original = values[0] if values else ""
                for payload in PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue

                    if MARKER in resp.text:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Command Injection in parameter '{param_name}'",
                            description=f"Output-based CMDi with payload: {payload}",
                            evidence=MARKER,
                            cwe_id="CWE-78",
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=f"curl '{test_url}'",
                            rule_id="cmdi_output_based",
                        ))
                        return results

        return results
```

- [ ] **Step 4: 테스트 통과 확인**
- [ ] **Step 5: Commit**

---

### Task 7: path_traversal.py — 경로 순회

**Files:**
- Create: `vibee_hacker/plugins/blackbox/path_traversal.py`
- Create: `tests/plugins/blackbox/test_path_traversal.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/plugins/blackbox/test_path_traversal.py
import pytest
from vibee_hacker.plugins.blackbox.path_traversal import PathTraversalPlugin
from vibee_hacker.core.models import Target, Severity


class TestPathTraversal:
    @pytest.fixture
    def plugin(self):
        return PathTraversalPlugin()

    @pytest.mark.asyncio
    async def test_lfi_detected(self, plugin, httpx_mock):
        target = Target(url="https://example.com/read?file=report.pdf")
        httpx_mock.add_response(
            url="https://example.com/read?file=report.pdf",
            text="PDF content",
        )
        httpx_mock.add_response(
            url="https://example.com/read?file=..%2F..%2F..%2Fetc%2Fpasswd",
            text="root:x:0:0:root:/root:/bin/bash",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_traversal(self, plugin, httpx_mock):
        target = Target(url="https://example.com/read?file=report.pdf")
        httpx_mock.add_response(
            url="https://example.com/read?file=report.pdf",
            text="PDF content",
        )
        httpx_mock.add_response(
            url="https://example.com/read?file=..%2F..%2F..%2Fetc%2Fpasswd",
            text="File not found",
        )
        results = await plugin.run(target)
        assert len(results) == 0
```

- [ ] **Step 2: 테스트 실패 확인**
- [ ] **Step 3: 플러그인 구현**

```python
# vibee_hacker/plugins/blackbox/path_traversal.py
"""Path traversal / LFI detection plugin."""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

FILE_SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.I),          # /etc/passwd
    re.compile(r"\[extensions\]", re.I),          # win.ini
    re.compile(r"\[fonts\]", re.I),               # win.ini
]


class PathTraversalPlugin(PluginBase):
    name = "path_traversal"
    description = "Path traversal / Local File Inclusion detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Known file content signatures in response after path traversal payload"
    expected_evidence = "root:x:0:0: or [extensions] patterns in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param_name in params:
                for payload in TRAVERSAL_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue

                    for sig in FILE_SIGNATURES:
                        if sig.search(resp.text):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"Path Traversal in parameter '{param_name}'",
                                description=f"LFI detected with payload: {payload}",
                                evidence=sig.pattern,
                                cwe_id="CWE-22",
                                endpoint=target.url,
                                param_name=param_name,
                                curl_command=f"curl '{test_url}'",
                                rule_id="path_traversal_lfi",
                            ))
                            return results

        return results
```

- [ ] **Step 4: 테스트 통과 확인**
- [ ] **Step 5: Commit**

---

### Task 8: 통합 테스트 — 플러그인 자동 발견 + 엔진 실행

**Files:**
- Create: `tests/plugins/blackbox/test_integration.py`

- [ ] **Step 1: 통합 테스트 작성**

```python
# tests/plugins/blackbox/test_integration.py
"""Integration test: plugin loader discovers blackbox plugins."""

from vibee_hacker.core.plugin_loader import PluginLoader


class TestBlackboxPluginDiscovery:
    def test_builtin_plugins_discovered(self):
        loader = PluginLoader()
        loader.load_builtin()
        bb = loader.get_plugins(category="blackbox")
        assert len(bb) >= 6
        names = [p.name for p in bb]
        assert "header_check" in names
        assert "cors_check" in names
        assert "sqli" in names
        assert "xss" in names
        assert "cmdi" in names
        assert "path_traversal" in names

    def test_phase_distribution(self):
        loader = PluginLoader()
        loader.load_builtin()
        phase2 = loader.get_plugins(category="blackbox", phase=2)
        phase3 = loader.get_plugins(category="blackbox", phase=3)
        assert len(phase2) >= 2  # header_check, cors_check
        assert len(phase3) >= 4  # sqli, xss, cmdi, path_traversal
```

- [ ] **Step 2: 전체 테스트 실행**

Run: `cd C:/Users/qwaqw/desktop/hacker && pytest tests/ -v --tb=short`

- [ ] **Step 3: Commit**

```bash
git add tests/plugins/blackbox/test_integration.py
git commit -m "test: add blackbox plugin integration tests"
```

---

## Summary

| Task | 플러그인 | Phase | 심각도 | 탐지 방식 |
|------|----------|-------|--------|-----------|
| 2 | header_check | 2 | medium | 보안 헤더 유무 |
| 3 | cors_check | 2 | high | Origin 반영 + Credentials |
| 4 | sqli | 3 | critical | 에러 기반 SQL 패턴 |
| 5 | xss | 3 | high | 반사형 페이로드 반영 |
| 6 | cmdi | 3 | critical | 출력 기반 마커 탐지 |
| 7 | path_traversal | 3 | critical | 파일 시그니처 매칭 |
