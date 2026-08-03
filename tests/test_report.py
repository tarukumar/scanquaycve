"""Tests for report export and console summary."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from scanquaycve.domain import summarize_findings
from scanquaycve.export import (
    export_reports,
    render_findings_table,
    render_stats_table,
)
from tests.conftest import make_finding


def test_write_reports(tmp_path: Path) -> None:
    findings = [
        make_finding("CVE-1", "Critical", fixed_by="2.0"),
        make_finding("CVE-2", "High"),
    ]
    report_dir = tmp_path / "image" / "latest"
    stats = export_reports(
        findings,
        str(report_dir),
        meta={"image": "quay.io/org/image:latest", "digest": "sha256:abc"},
        raw_report={"status": "scanned"},
    )
    assert stats.total == 2
    assert (report_dir / "all-vulnerabilities.csv").is_file()
    assert (report_dir / "fixable-vulnerabilities.csv").is_file()
    assert (report_dir / "non-fixable-vulnerabilities.csv").is_file()
    assert (report_dir / "summary.json").is_file()
    assert (report_dir / "vulnerabilities.json").is_file()

    with open(report_dir / "all-vulnerabilities.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["CVE"] == "CVE-1"
    assert rows[0]["Fixable"] == "true"
    assert rows[1]["Fixable"] == "false"

    with open(report_dir / "fixable-vulnerabilities.csv", newline="") as fh:
        fixable_rows = list(csv.DictReader(fh))
    assert len(fixable_rows) == 1

    data = json.loads((report_dir / "summary.json").read_text())
    assert data["total"] == 2
    assert data["meta"]["digest"] == "sha256:abc"


def test_console_summary_contains_totals() -> None:
    stats = summarize_findings(
        [
            make_finding("CVE-1", "Critical", fixed_by="2.0"),
            make_finding("CVE-2", "High"),
        ]
    )
    text = render_stats_table(stats)
    assert "Critical" in text
    assert "TOTAL" in text
    assert "1" in text


def test_console_findings_include_fix_versions() -> None:
    findings = [
        make_finding(
            "CVE-1",
            "Critical",
            package="openssl",
            version="1.1.1",
            fixed_by="1.1.2",
        ),
        make_finding("CVE-2", "High", package="curl", version="7.0"),
    ]
    text = render_findings_table(findings)
    assert "CVE-1" in text
    assert "openssl" in text
    assert "1.1.1" in text
    assert "1.1.2" in text
    assert "—" in text  # non-fixable Fixed by placeholder
