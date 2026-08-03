"""Command-line entrypoint for scanquaycve."""

from __future__ import annotations

import argparse
import sys

from scanquaycve.config import (
    DEFAULT_ARCH,
    DEFAULT_OUTPUT_DIR,
    SEVERITY_LABELS,
    labels_at_or_above,
    parse_severity_names,
)
from scanquaycve.errors import ApiError, InvalidImageReference, TransportError
from scanquaycve.export import render_findings_table, render_stats_table
from scanquaycve.service import ScanOptions, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanquaycve",
        description=(
            "Scan Quay/Clair vulnerability reports for a container image. "
            "Pass a single IMAGE reference with a tag or digest."
        ),
        epilog=(
            "Examples:\n"
            "  scanquaycve quay.io/org/image:1.2.3\n"
            "  scanquaycve org/image@sha256:abc123...\n"
            "  scanquaycve quay.io/org/image:latest -s High,Medium\n"
            "  scanquaycve quay.io/org/image:latest --min-severity High\n"
            "  scanquaycve quay.io/org/image:latest -s critical --fixable-only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "image",
        help="Image reference: [server/]org/image:tag or [server/]org/image@sha256:...",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Base output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    severity = parser.add_mutually_exclusive_group()
    severity.add_argument(
        "-s",
        "--severity",
        action="append",
        metavar="LEVEL",
        dest="severity",
        help=(
            "Only include these severities (repeatable or comma-separated; "
            "case-insensitive). "
            f"Choices: {', '.join(SEVERITY_LABELS)}. "
            "Example: -s High,Medium  or  -s High -s Medium"
        ),
    )
    severity.add_argument(
        "--min-severity",
        metavar="LEVEL",
        help=(
            "Only include this severity and higher "
            "(Critical > High > Medium > Low > Negligible > Unknown). "
            "Example: --min-severity High  → Critical + High"
        ),
    )
    parser.add_argument(
        "--fixable-only",
        action="store_true",
        help="Only include vulnerabilities with a known fix",
    )
    parser.add_argument(
        "--non-fixable-only",
        action="store_true",
        help="Only include vulnerabilities without a known fix",
    )
    parser.add_argument(
        "--arch",
        default=DEFAULT_ARCH,
        help=f"Architecture for multi-arch tags (default: {DEFAULT_ARCH})",
    )
    parser.add_argument(
        "--token",
        help="OAuth bearer token; skips podman/docker credential lookup",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also save the raw Quay security JSON report",
    )
    return parser


def resolve_severity_filter(
    severity_args: list[str] | None,
    min_severity: str | None,
) -> set[str] | None:
    if min_severity:
        try:
            return labels_at_or_above(min_severity)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    if not severity_args:
        return None

    selected: set[str] = set()
    try:
        for entry in severity_args:
            selected.update(parse_severity_names(entry))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return selected


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.fixable_only and args.non_fixable_only:
        parser.error("use only one of --fixable-only or --non-fixable-only")

    try:
        severities = resolve_severity_filter(args.severity, args.min_severity)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    options = ScanOptions(
        image=args.image,
        output_dir=args.output_dir,
        arch=args.arch,
        token=args.token,
        severities=severities,
        min_severity=args.min_severity,
        fixable_only=args.fixable_only,
        non_fixable_only=args.non_fixable_only,
        save_raw_json=args.json,
    )

    try:
        result, progress = run_scan(options)
    except InvalidImageReference as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    except (ApiError, TransportError, ValueError) as exc:
        msg = str(exc)
        if "no credentials" in msg or "Authentication required" in msg:
            msg += " Log in via 'podman login' / 'docker login' or pass --token."
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(1)

    for warning in progress.warnings:
        print(warning, file=sys.stderr)
    for line in progress.lines:
        print(line)

    print()
    print(render_stats_table(result.stats))
    print()
    print(render_findings_table(result.findings))
    print()
    print(f"Reports written to {result.report_dir}/")
    print(f"  all-vulnerabilities.csv ({result.stats.total} rows)")
    print(f"  fixable-vulnerabilities.csv ({result.stats.fixable} rows)")
    print(
        f"  non-fixable-vulnerabilities.csv ({result.stats.non_fixable} rows)"
    )
    print("  summary.json")
    if args.json:
        print("  vulnerabilities.json")
    print("Done.")


if __name__ == "__main__":
    main()
