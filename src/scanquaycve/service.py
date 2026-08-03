"""Scan orchestration: resolve image → fetch Clair data → filter → export."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from scanquaycve.client import QuaySession
from scanquaycve.config import SCANNED_STATUS, SEVERITY_LABELS, parse_severity
from scanquaycve.domain import (
    Finding,
    FindingStats,
    ImageReference,
    filter_findings,
    parse_image_reference,
)
from scanquaycve.export import export_reports
from scanquaycve.quay import QuayScanner


@dataclass(frozen=True)
class ScanOptions:
    image: str
    output_dir: str = "reports"
    arch: str = "amd64"
    token: str | None = None
    severities: set[str] | None = None
    min_severity: str | None = None
    fixable_only: bool = False
    non_fixable_only: bool = False
    save_raw_json: bool = False


@dataclass
class ScanResult:
    reference: ImageReference
    digest: str
    status: str
    findings: list[Finding]
    stats: FindingStats
    report_dir: str
    package_count: int
    raw_count: int


@dataclass
class ScanProgress:
    """Messages emitted during a scan for the CLI to display."""

    lines: list[str]
    warnings: list[str]


def run_scan(options: ScanOptions) -> tuple[ScanResult, ScanProgress]:
    """Execute a full vulnerability scan for *options*."""
    progress = ScanProgress(lines=[], warnings=[])
    reference = parse_image_reference(options.image)

    session = QuaySession(reference.registry, oauth_token=options.token)
    if not options.token and not session.has_credentials:
        progress.warnings.append(
            f"Warning: no credentials found for {reference.registry};"
            " trying unauthenticated."
        )

    scanner = QuayScanner(session, reference.repository)

    if reference.digest:
        digest = reference.digest
    else:
        assert reference.tag is not None
        progress.lines.append(
            f"Resolving tag {reference.tag} for {reference.repository}..."
        )
        digest = scanner.resolve_platform_digest(reference.tag, options.arch)

    progress.lines.append(
        f"Fetching security report for {reference.repository} @ {digest[:23]}..."
    )
    report = scanner.fetch_security_report(digest)

    status = report.get("status", "unknown")
    if status != SCANNED_STATUS:
        progress.warnings.append(
            f"Warning: scan status is '{status}'; report may be incomplete."
        )

    package_count = QuayScanner.feature_count(report)
    findings = QuayScanner.parse_findings(report)
    progress.lines.append(
        f"Found {len(findings)} vulnerabilities across {package_count} packages."
    )

    severities = options.severities
    if severities:
        ordered = [s for s in SEVERITY_LABELS if s in severities]
        progress.lines.append(f"Filtering severities: {', '.join(ordered)}")

    filtered = filter_findings(
        findings,
        severities=severities,
        fixable_only=options.fixable_only,
        non_fixable_only=options.non_fixable_only,
    )
    if len(filtered) != len(findings):
        progress.lines.append(f"After filters: {len(filtered)} vulnerabilities.")

    report_dir = os.path.join(
        options.output_dir, reference.short_name, reference.output_label
    )
    meta: dict[str, Any] = {
        "image": options.image,
        "server": reference.registry,
        "repo": reference.repository,
        "tag": reference.tag,
        "digest": digest,
        "arch": options.arch,
        "status": status,
        "severities": (
            [s for s in SEVERITY_LABELS if severities and s in severities]
            if severities
            else list(SEVERITY_LABELS)
        ),
        "min_severity": (
            parse_severity(options.min_severity).label if options.min_severity else None
        ),
        "fixable_only": options.fixable_only,
        "non_fixable_only": options.non_fixable_only,
    }
    stats = export_reports(
        filtered,
        report_dir,
        meta=meta,
        raw_report=report if options.save_raw_json else None,
    )

    result = ScanResult(
        reference=reference,
        digest=digest,
        status=status,
        findings=filtered,
        stats=stats,
        report_dir=report_dir,
        package_count=package_count,
        raw_count=len(findings),
    )
    return result, progress
