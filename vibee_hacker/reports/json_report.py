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
