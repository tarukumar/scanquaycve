"""Domain types for image references and vulnerability findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from scanquaycve.config import (
    DEFAULT_REGISTRY,
    SEVERITY_LABELS,
    Severity,
    parse_severity,
)
from scanquaycve.errors import InvalidImageReference


@dataclass(frozen=True)
class ImageReference:
    """Parsed container image reference (tag or digest)."""

    registry: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def short_name(self) -> str:
        return self.repository.rsplit("/", 1)[-1]

    @property
    def output_label(self) -> str:
        if self.tag:
            return self.tag
        if self.digest:
            return self.digest.split(":", 1)[-1][:12]
        return "unknown"


def parse_image_reference(raw: str) -> ImageReference:
    """Parse ``[registry/]org/image[:tag|@sha256:…]``."""
    text = raw.strip()
    if not text or text.startswith("sha256:"):
        raise InvalidImageReference(
            f"invalid image reference '{raw}'. "
            "Expected format: [server/]org/image[:tag|@sha256:digest]"
        )

    tag: str | None = None
    digest: str | None = None

    if "@sha256:" in text:
        at_idx = text.index("@sha256:")
        image_part = text[:at_idx]
        digest = text[at_idx + 1 :]
        if not digest.startswith("sha256:") or len(digest) < len("sha256:") + 12:
            raise InvalidImageReference(f"invalid digest in image reference '{raw}'")
    elif ":" in text:
        last_colon = text.rfind(":")
        last_slash = text.rfind("/")
        if last_slash > last_colon:
            image_part = text
        else:
            image_part = text[:last_colon]
            tag = text[last_colon + 1 :]
            if not tag or "/" in tag:
                raise InvalidImageReference(f"invalid tag in image reference '{raw}'")
    else:
        image_part = text

    if not tag and not digest:
        raise InvalidImageReference(
            f"image reference '{raw}' must include a tag (:tag) or digest (@sha256:...)"
        )

    parts = image_part.split("/")
    if len(parts) < 2:
        raise InvalidImageReference(
            f"invalid image reference '{raw}'. "
            "Expected format: [server/]org/image[:tag|@sha256:digest]"
        )

    first = parts[0]
    if "." in first or first == "localhost" or ":" in first:
        registry = first
        repository = "/".join(parts[1:])
    else:
        registry = DEFAULT_REGISTRY
        repository = image_part

    if not repository:
        raise InvalidImageReference(
            f"invalid image reference '{raw}': missing repository path"
        )

    return ImageReference(
        registry=registry, repository=repository, tag=tag, digest=digest
    )


@dataclass(frozen=True)
class Finding:
    """One Clair vulnerability finding for a package."""

    cve: str
    severity: str
    package: str
    installed_version: str
    fixed_by: str
    description: str
    link: str

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_by.strip())

    def to_csv_row(self) -> dict[str, str]:
        return {
            "CVE": self.cve,
            "Severity": self.severity,
            "Package": self.package,
            "Installed_Version": self.installed_version,
            "Fixed_By": self.fixed_by,
            "Fixable": "true" if self.fixable else "false",
            "Description": self.description,
            "Link": self.link,
        }

    def to_dict(self) -> dict[str, str | bool]:
        data = asdict(self)
        data["fixable"] = self.fixable
        return data


@dataclass(frozen=True)
class SeverityBucket:
    fixable: int = 0
    non_fixable: int = 0

    @property
    def total(self) -> int:
        return self.fixable + self.non_fixable


@dataclass
class FindingStats:
    by_severity: dict[str, SeverityBucket] = field(default_factory=dict)
    total: int = 0
    fixable: int = 0
    non_fixable: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "fixable": self.fixable,
            "non_fixable": self.non_fixable,
            "by_severity": {
                sev: {
                    "fixable": bucket.fixable,
                    "non_fixable": bucket.non_fixable,
                    "total": bucket.total,
                }
                for sev, bucket in self.by_severity.items()
            },
        }


def summarize_findings(findings: list[Finding]) -> FindingStats:
    buckets = {label: SeverityBucket() for label in SEVERITY_LABELS}
    fixable = 0
    non_fixable = 0

    for finding in findings:
        severity = finding.severity if finding.severity in buckets else "Unknown"
        current = buckets[severity]
        if finding.fixable:
            buckets[severity] = SeverityBucket(
                fixable=current.fixable + 1,
                non_fixable=current.non_fixable,
            )
            fixable += 1
        else:
            buckets[severity] = SeverityBucket(
                fixable=current.fixable,
                non_fixable=current.non_fixable + 1,
            )
            non_fixable += 1

    return FindingStats(
        by_severity=buckets,
        total=len(findings),
        fixable=fixable,
        non_fixable=non_fixable,
    )


def filter_findings(
    findings: list[Finding],
    *,
    severities: set[str] | None = None,
    fixable_only: bool = False,
    non_fixable_only: bool = False,
) -> list[Finding]:
    result: list[Finding] = []
    for finding in findings:
        if severities and finding.severity not in severities:
            continue
        if fixable_only and not finding.fixable:
            continue
        if non_fixable_only and finding.fixable:
            continue
        result.append(finding)
    result.sort(key=finding_sort_key)
    return result


def finding_sort_key(finding: Finding) -> tuple[int, str]:
    try:
        rank = parse_severity(finding.severity)
    except ValueError:
        rank = Severity.UNKNOWN
    return (int(rank), finding.cve)
