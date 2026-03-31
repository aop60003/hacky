"""HTML report generator using Jinja2."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from jinja2 import Template

from vibee_hacker.core.models import Result, Target

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VIBEE-Hacker Scan Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#1a1a2e;color:#eee;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{color:#e94560;margin-bottom:10px}
.meta{color:#888;margin-bottom:20px}
.summary{display:flex;gap:15px;margin-bottom:30px;flex-wrap:wrap}
.stat{background:#16213e;padding:15px 25px;border-radius:8px;text-align:center}
.stat .count{font-size:2em;font-weight:bold}
.stat .label{font-size:.85em;color:#888}
.critical .count{color:#ff4444}
.high .count{color:#ff8c00}
.medium .count{color:#ffd700}
.low .count{color:#4da6ff}
.info .count{color:#888}
table{width:100%;border-collapse:collapse;margin-top:20px}
th{background:#16213e;padding:12px;text-align:left;border-bottom:2px solid #333}
td{padding:10px 12px;border-bottom:1px solid #333;vertical-align:top}
tr:hover{background:#16213e}
.badge{padding:3px 10px;border-radius:4px;font-size:.8em;font-weight:bold;text-transform:uppercase}
.badge-critical{background:#ff4444;color:#fff}
.badge-high{background:#ff8c00;color:#fff}
.badge-medium{background:#ffd700;color:#000}
.badge-low{background:#4da6ff;color:#fff}
.badge-info{background:#666;color:#fff}
.evidence{font-family:monospace;font-size:.85em;background:#0f0f23;padding:5px 8px;border-radius:4px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cwe{color:#4da6ff;font-size:.85em}
.desc{max-width:300px;font-size:.9em}
</style>
</head>
<body>
<div class="container">
<h1>VIBEE-Hacker Scan Report</h1>
<div class="meta">Target: {{ target }} | Mode: {{ mode }} | Date: {{ scan_date }}</div>
<div class="summary">
<div class="stat critical"><div class="count">{{ severity.get('critical', 0) }}</div><div class="label">Critical</div></div>
<div class="stat high"><div class="count">{{ severity.get('high', 0) }}</div><div class="label">High</div></div>
<div class="stat medium"><div class="count">{{ severity.get('medium', 0) }}</div><div class="label">Medium</div></div>
<div class="stat low"><div class="count">{{ severity.get('low', 0) }}</div><div class="label">Low</div></div>
<div class="stat info"><div class="count">{{ severity.get('info', 0) }}</div><div class="label">Info</div></div>
</div>
<h2>Findings ({{ total }})</h2>
<table>
<tr><th>Severity</th><th>Plugin</th><th>Title</th><th>Description</th><th>CWE</th><th>Evidence</th></tr>
{% for f in findings %}
<tr>
<td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
<td>{{ f.plugin }}</td>
<td>{{ f.title }}</td>
<td class="desc">{{ f.description[:200] }}</td>
<td class="cwe">{{ f.cwe or '-' }}</td>
<td><div class="evidence">{{ (f.evidence or '')[:120] or '-' }}</div></td>
</tr>
{% endfor %}
</table>
</div>
</body>
</html>"""


class HtmlReporter:
    """Generates HTML scan reports."""

    def generate(self, results: list[Result], target: Target, output_path: str) -> None:
        severity_counts = Counter(str(r.context_severity) for r in results)
        findings = [
            {
                "severity": str(r.context_severity),
                "plugin": r.plugin_name,
                "title": r.title,
                "description": r.description,
                "cwe": r.cwe_id,
                "evidence": r.evidence,
                "recommendation": r.recommendation,
            }
            for r in results
        ]
        tmpl = Template(HTML_TEMPLATE)
        html = tmpl.render(
            target=target.url or target.path,
            mode=target.mode,
            scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            severity=dict(severity_counts),
            total=len(results),
            findings=findings,
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
