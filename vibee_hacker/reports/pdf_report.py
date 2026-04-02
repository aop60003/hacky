"""PDF report generator."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from vibee_hacker.core.models import Result, Target, Severity

logger = logging.getLogger(__name__)

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


class PdfReporter:
    """Generate PDF security scan reports."""

    def generate(self, results: list[Result], target: Target, output_path: str) -> str:
        """Generate a PDF report. Falls back to text if reportlab unavailable."""
        try:
            return self._generate_reportlab(results, target, output_path)
        except ImportError:
            return self._generate_text(results, target, output_path)

    def _generate_reportlab(self, results: list[Result], target: Target, output_path: str) -> str:
        """Generate PDF using reportlab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        elements.append(Paragraph("VIBEE-Hacker Security Scan Report", styles["Title"]))
        elements.append(Spacer(1, 10 * mm))

        # Summary
        target_str = target.url or target.path or "Unknown"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        summary_data = [
            ["Target", target_str],
            ["Scan Date", now],
            ["Total Findings", str(len(results))],
            ["Critical", str(sum(1 for r in results if r.base_severity == Severity.CRITICAL))],
            ["High", str(sum(1 for r in results if r.base_severity == Severity.HIGH))],
            ["Medium", str(sum(1 for r in results if r.base_severity == Severity.MEDIUM))],
            ["Low", str(sum(1 for r in results if r.base_severity == Severity.LOW))],
            ["Info", str(sum(1 for r in results if r.base_severity == Severity.INFO))],
        ]
        table = Table(summary_data, colWidths=[40 * mm, 120 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10 * mm))

        # Findings
        elements.append(Paragraph("Findings", styles["Heading2"]))
        for i, r in enumerate(results, 1):
            sev = SEVERITY_LABELS.get(r.base_severity, "INFO")
            elements.append(Paragraph(f"<b>{i}. [{sev}] {r.title}</b>", styles["Heading3"]))
            elements.append(Paragraph(f"Plugin: {r.plugin_name}", styles["Normal"]))
            if r.endpoint:
                elements.append(Paragraph(f"Endpoint: {r.endpoint}", styles["Normal"]))
            if r.description:
                elements.append(Paragraph(r.description[:500], styles["Normal"]))
            if r.recommendation:
                elements.append(Paragraph(f"<i>Recommendation: {r.recommendation}</i>", styles["Normal"]))
            elements.append(Spacer(1, 5 * mm))

        doc.build(elements)
        return output_path

    def _generate_text(self, results: list[Result], target: Target, output_path: str) -> str:
        """Fallback: generate plain text report saved as .pdf."""
        target_str = target.url or target.path or "Unknown"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = []
        lines.append("=" * 60)
        lines.append("VIBEE-Hacker Security Scan Report")
        lines.append("=" * 60)
        lines.append(f"Target: {target_str}")
        lines.append(f"Date: {now}")
        lines.append(f"Total Findings: {len(results)}")
        lines.append("")

        sev_counts: dict[str, int] = {}
        for r in results:
            sev = SEVERITY_LABELS.get(r.base_severity, "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        for sev, count in sev_counts.items():
            lines.append(f"  {sev}: {count}")
        lines.append("")
        lines.append("-" * 60)

        for i, r in enumerate(results, 1):
            sev = SEVERITY_LABELS.get(r.base_severity, "INFO")
            lines.append(f"\n{i}. [{sev}] {r.title}")
            lines.append(f"   Plugin: {r.plugin_name}")
            if r.endpoint:
                lines.append(f"   Endpoint: {r.endpoint}")
            if r.description:
                lines.append(f"   {r.description[:200]}")
            if r.recommendation:
                lines.append(f"   Rec: {r.recommendation}")

        lines.append("\n" + "=" * 60)
        lines.append("Generated by VIBEE-Hacker")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return output_path
