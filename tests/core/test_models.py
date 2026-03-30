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
