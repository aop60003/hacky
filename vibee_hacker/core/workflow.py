"""Workflow chaining: combine plugin results for advanced detection."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from vibee_hacker.core.models import Result, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


@dataclass
class WorkflowCondition:
    """A single condition to match against scan results."""
    plugin_name: str = ""       # Match by plugin name (regex)
    rule_id: str = ""           # Match by rule_id (regex)
    title_contains: str = ""    # Match if title contains this string
    min_severity: str = ""      # Match if severity >= this

    def matches(self, result: Result) -> bool:
        if self.plugin_name and not re.search(self.plugin_name, result.plugin_name or ""):
            return False
        if self.rule_id and not re.search(self.rule_id, result.rule_id or ""):
            return False
        if self.title_contains and self.title_contains.lower() not in (result.title or "").lower():
            return False
        if self.min_severity:
            min_sev = SEVERITY_MAP.get(self.min_severity.lower(), Severity.INFO)
            if result.base_severity < min_sev:
                return False
        return True


@dataclass
class WorkflowRule:
    """A workflow rule: when ALL conditions match, produce a new finding."""
    id: str
    name: str
    description: str
    conditions: list[WorkflowCondition]
    output_severity: str = "critical"
    output_title: str = ""
    output_recommendation: str = ""
    logic: str = "and"  # "and" = all conditions, "or" = any condition

    def evaluate(self, results: list[Result]) -> Result | None:
        """Check if this workflow rule triggers based on scan results."""
        if self.logic == "and":
            for condition in self.conditions:
                if not any(condition.matches(r) for r in results):
                    return None
        elif self.logic == "or":
            if not any(
                condition.matches(r) for condition in self.conditions for r in results
            ):
                return None

        return Result(
            plugin_name="workflow",
            base_severity=SEVERITY_MAP.get(self.output_severity.lower(), Severity.CRITICAL),
            title=self.output_title or self.name,
            description=self.description,
            rule_id=f"workflow_{self.id}",
            recommendation=self.output_recommendation,
        )


class WorkflowEngine:
    """Evaluates workflow rules against scan results."""

    def __init__(self):
        self.rules: list[WorkflowRule] = []

    def add_rule(self, rule: WorkflowRule):
        self.rules.append(rule)

    def load_builtin_rules(self):
        """Load built-in workflow rules."""
        self.rules.extend(BUILTIN_RULES)

    def evaluate(self, results: list[Result]) -> list[Result]:
        """Evaluate all workflow rules and return new findings."""
        new_findings = []
        for rule in self.rules:
            finding = rule.evaluate(results)
            if finding:
                new_findings.append(finding)
        return new_findings


# Built-in workflow rules
BUILTIN_RULES = [
    WorkflowRule(
        id="wp_config_exposed",
        name="WordPress Configuration File Exposed",
        description="WordPress detected AND wp-config.php or similar config file is accessible. This likely exposes database credentials.",
        conditions=[
            WorkflowCondition(title_contains="WordPress"),
            WorkflowCondition(rule_id="dir_enum"),
        ],
        output_severity="critical",
        output_title="WordPress config file exposed with credentials",
        output_recommendation="Remove config files from web root. Restrict access via .htaccess.",
    ),
    WorkflowRule(
        id="sqli_plus_debug",
        name="SQL Injection with Debug Mode",
        description="SQL injection found while debug mode is enabled. Debug info may reveal database structure aiding exploitation.",
        conditions=[
            WorkflowCondition(plugin_name="sqli"),
            WorkflowCondition(plugin_name="debug_detection"),
        ],
        output_severity="critical",
        output_title="SQL Injection exploitable via debug information",
        output_recommendation="Fix SQL injection and disable debug mode in production.",
    ),
    WorkflowRule(
        id="default_creds_admin",
        name="Default Credentials on Admin Panel",
        description="Default credentials work AND admin panel is accessible. Full administrative compromise likely.",
        conditions=[
            WorkflowCondition(plugin_name="default_creds"),
            WorkflowCondition(rule_id="dir_enum.*admin|forced_browsing.*admin"),
        ],
        output_severity="critical",
        output_title="Admin panel accessible with default credentials",
        output_recommendation="Change default credentials immediately. Implement MFA.",
    ),
    WorkflowRule(
        id="api_key_no_auth",
        name="API Key Exposed on Unauthenticated Endpoint",
        description="API key found in response AND endpoint has no authentication requirement.",
        conditions=[
            WorkflowCondition(plugin_name="api_key_exposure"),
            WorkflowCondition(rule_id="openapi_no_auth"),
        ],
        output_severity="critical",
        output_title="API key exposed on unauthenticated endpoint",
        output_recommendation="Remove API keys from responses. Add authentication.",
        logic="and",
    ),
    WorkflowRule(
        id="xss_plus_no_csp",
        name="XSS with No Content Security Policy",
        description="XSS vulnerability found AND no CSP header. XSS is trivially exploitable.",
        conditions=[
            WorkflowCondition(plugin_name="xss"),
            WorkflowCondition(rule_id="header_missing.*Content-Security-Policy|csp_analysis"),
        ],
        output_severity="critical",
        output_title="XSS exploitable due to missing Content-Security-Policy",
        output_recommendation="Fix XSS vulnerability and implement strict CSP.",
    ),
]
