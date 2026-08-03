"""Shared test helpers."""

from __future__ import annotations

from typing import Any

from scanquaycve.domain import Finding


def make_feature(
    name: str,
    version: str,
    vulns: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "Name": name,
        "Version": version,
        "Vulnerabilities": [
            {
                "Name": v.get("name", ""),
                "Severity": v.get("severity", "Unknown"),
                "FixedBy": v.get("fixed_by", ""),
                "Description": v.get("description", ""),
                "Link": v.get("link", ""),
            }
            for v in vulns
        ],
    }


def make_finding(
    cve: str,
    severity: str,
    package: str = "pkg",
    version: str = "1.0",
    fixed_by: str = "",
) -> Finding:
    return Finding(
        cve=cve,
        severity=severity,
        package=package,
        installed_version=version,
        fixed_by=fixed_by,
        description="desc",
        link="https://example.com",
    )
