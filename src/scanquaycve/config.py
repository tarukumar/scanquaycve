"""Defaults and severity policy."""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Clair severity ranks (lower = more severe)."""

    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    NEGLIGIBLE = 4
    UNKNOWN = 5

    @property
    def label(self) -> str:
        return _LABELS[self]


_LABELS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.NEGLIGIBLE: "Negligible",
    Severity.UNKNOWN: "Unknown",
}

SEVERITY_LABELS: tuple[str, ...] = tuple(_LABELS[s] for s in Severity)
_BY_NAME = {label.lower(): sev for sev, label in _LABELS.items()}

DEFAULT_REGISTRY = "quay.io"
DEFAULT_ARCH = "amd64"
DEFAULT_OUTPUT_DIR = "reports"
HTTP_TIMEOUT = 30
DESCRIPTION_LIMIT = 300
SCANNED_STATUS = "scanned"

MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.oci.image.manifest.v1+json"
)

INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)


def parse_severity(value: str) -> Severity:
    """Parse a case-insensitive severity name."""
    key = value.strip().lower()
    if key not in _BY_NAME:
        raise ValueError(
            f"unknown severity '{value}'. Valid: {', '.join(SEVERITY_LABELS)}"
        )
    return _BY_NAME[key]


def parse_severity_names(value: str) -> set[str]:
    """Parse a comma-separated severity list into canonical labels."""
    parts = {part.strip() for part in value.split(",") if part.strip()}
    if not parts:
        raise ValueError("severity list must not be empty")
    return {parse_severity(part).label for part in parts}


def labels_at_or_above(min_severity: str) -> set[str]:
    """Return severity labels at or above *min_severity*."""
    floor = parse_severity(min_severity)
    return {sev.label for sev in Severity if sev <= floor}
