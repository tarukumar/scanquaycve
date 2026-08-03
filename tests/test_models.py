"""Tests for finding extraction, filtering, and summaries."""

from __future__ import annotations

from scanquaycve.domain import filter_findings, summarize_findings
from scanquaycve.quay import QuayScanner
from tests.conftest import make_feature, make_finding


def test_extract_and_fixable_flag() -> None:
    report = {
        "data": {
            "Layer": {
                "Features": [
                    make_feature(
                        "openssl",
                        "1.1.1",
                        [
                            {
                                "name": "CVE-1",
                                "severity": "Critical",
                                "fixed_by": "1.1.2",
                                "description": "fixed",
                                "link": "https://example.com/1",
                            },
                            {
                                "name": "CVE-2",
                                "severity": "High",
                                "fixed_by": "",
                                "description": "open",
                                "link": "https://example.com/2 more",
                            },
                        ],
                    )
                ]
            }
        }
    }
    findings = QuayScanner.parse_findings(report)
    assert len(findings) == 2
    assert findings[0].cve == "CVE-1"
    assert findings[0].fixable is True
    assert findings[0].fixed_by == "1.1.2"
    assert findings[1].cve == "CVE-2"
    assert findings[1].fixable is False
    assert findings[1].link == "https://example.com/2"


def test_feature_count_from_report() -> None:
    report = {
        "status": "scanned",
        "data": {"Layer": {"Features": [make_feature("bash", "5.0", [])]}},
    }
    assert QuayScanner.feature_count(report) == 1


def test_summarize_by_severity_and_fixability() -> None:
    findings = [
        make_finding("CVE-1", "Critical", fixed_by="2.0"),
        make_finding("CVE-2", "Critical"),
        make_finding("CVE-3", "High", fixed_by="3.0"),
        make_finding("CVE-4", "Low"),
    ]
    stats = summarize_findings(findings)
    assert stats.total == 4
    assert stats.fixable == 2
    assert stats.non_fixable == 2
    assert stats.by_severity["Critical"].fixable == 1
    assert stats.by_severity["Critical"].non_fixable == 1
    assert stats.by_severity["High"].fixable == 1
    assert stats.by_severity["Low"].non_fixable == 1


def test_filter_severity_and_fixable() -> None:
    findings = [
        make_finding("CVE-1", "Critical", fixed_by="2.0"),
        make_finding("CVE-2", "High"),
        make_finding("CVE-3", "Medium", fixed_by="1.1"),
    ]
    filtered = filter_findings(
        findings, severities={"Critical", "High"}, fixable_only=True
    )
    assert [f.cve for f in filtered] == ["CVE-1"]
