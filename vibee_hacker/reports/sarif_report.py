"""SARIF report generator (Static Analysis Results Interchange Format)."""
from __future__ import annotations

import json
from vibee_hacker.core.models import Result, Target


class SarifReporter:
    def generate(self, results: list[Result], target: Target, output_path: str) -> None:
        rules = self._build_rules(results)
        rule_index_map: dict[str, int] = {r["id"]: i for i, r in enumerate(rules)}
        runs = [
            {
                "tool": {
                    "driver": {
                        "name": "VIBEE-Hacker",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": [self._build_result(r, rule_index_map) for r in results],
            }
        ]
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

    def _build_rules(self, results: list[Result]) -> list[dict]:
        seen: dict[str, bool] = {}
        rules: list[dict] = []
        for r in results:
            rid = r.rule_id or r.plugin_name
            if rid not in seen:
                seen[rid] = True
                rule: dict = {"id": rid, "shortDescription": {"text": r.title}}
                if r.cwe_id:
                    rule["properties"] = {"tags": [r.cwe_id]}
                rules.append(rule)
        return rules

    def _build_result(self, r: Result, rule_index_map: dict[str, int]) -> dict:
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        rule_id = r.rule_id or r.plugin_name
        uri = r.endpoint or "unknown"
        # Normalize absolute paths to forward-slash relative URIs
        if uri.startswith("/") or (len(uri) > 1 and uri[1] == ":"):
            uri = uri.replace("\\", "/")

        result: dict = {
            "ruleId": rule_id,
            "level": severity_map.get(str(r.context_severity), "note"),
            "message": {"text": r.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri}
                    }
                }
            ],
        }
        if rule_id in rule_index_map:
            result["ruleIndex"] = rule_index_map[rule_id]
        return result
