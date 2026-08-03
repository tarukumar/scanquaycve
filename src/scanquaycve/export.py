"""Export findings to CSV / JSON and format console summaries."""

from __future__ import annotations

import csv
import json
import os
from typing import Any

from scanquaycve.config import SEVERITY_LABELS
from scanquaycve.domain import Finding, FindingStats, summarize_findings

_CSV_COLUMNS = (
    "CVE",
    "Severity",
    "Package",
    "Installed_Version",
    "Fixed_By",
    "Fixable",
    "Description",
    "Link",
)


def render_stats_table(stats: FindingStats) -> str:
    lines = [
        f"{'Severity':<12} {'Fixable':>8} {'Non-fixable':>13} {'Total':>8}",
        "-" * 44,
    ]
    for severity in SEVERITY_LABELS:
        bucket = stats.by_severity.get(severity)
        if bucket is None or bucket.total == 0:
            continue
        lines.append(
            f"{severity:<12} {bucket.fixable:>8} {bucket.non_fixable:>13} "
            f"{bucket.total:>8}"
        )
    lines.append("-" * 44)
    lines.append(
        f"{'TOTAL':<12} {stats.fixable:>8} {stats.non_fixable:>13} "
        f"{stats.total:>8}"
    )
    return "\n".join(lines)


def render_findings_table(findings: list[Finding], *, max_rows: int = 200) -> str:
    """Render a terminal table of findings including fix versions."""
    if not findings:
        return "No matching vulnerabilities."

    header = (
        f"{'CVE':<20} {'Severity':<10} {'Package':<28} "
        f"{'Installed':<18} {'Fixed by':<18}"
    )
    lines = [header, "-" * len(header)]
    shown = findings[:max_rows]
    for finding in shown:
        fixed = finding.fixed_by.strip() or "—"
        lines.append(
            f"{finding.cve:<20} {finding.severity:<10} "
            f"{finding.package:<28} {finding.installed_version:<18} "
            f"{fixed:<18}"
        )
    if len(findings) > max_rows:
        lines.append(
            f"... {len(findings) - max_rows} more "
            f"(see all-vulnerabilities.csv for full list)"
        )
    return "\n".join(lines)


def export_reports(
    findings: list[Finding],
    report_dir: str,
    *,
    meta: dict[str, Any],
    raw_report: dict[str, Any] | None = None,
) -> FindingStats:
    """Write CSV + summary JSON under *report_dir*."""
    os.makedirs(report_dir, exist_ok=True)
    stats = summarize_findings(findings)

    _write_csv(findings, os.path.join(report_dir, "all-vulnerabilities.csv"))
    _write_csv(
        [f for f in findings if f.fixable],
        os.path.join(report_dir, "fixable-vulnerabilities.csv"),
    )
    _write_csv(
        [f for f in findings if not f.fixable],
        os.path.join(report_dir, "non-fixable-vulnerabilities.csv"),
    )

    payload = {"meta": meta, **stats.to_dict()}
    with open(os.path.join(report_dir, "summary.json"), "w") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")

    if raw_report is not None:
        with open(os.path.join(report_dir, "vulnerabilities.json"), "w") as fh:
            json.dump(raw_report, fh, indent=2)
            fh.write("\n")

    return stats


def _write_csv(findings: list[Finding], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(finding.to_csv_row() for finding in findings)
