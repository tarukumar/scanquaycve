"""Quay API + OCI Distribution operations for vulnerability scanning."""

from __future__ import annotations

import urllib.parse
from typing import Any

from scanquaycve.client import Credentials, QuaySession
from scanquaycve.config import DESCRIPTION_LIMIT, INDEX_MEDIA_TYPES, MANIFEST_ACCEPT
from scanquaycve.domain import Finding, finding_sort_key
from scanquaycve.errors import ApiError, TransportError


class QuayScanner:
    """Resolve tags and download Clair security reports from Quay."""

    def __init__(self, session: QuaySession, repository: str) -> None:
        self._session = session
        self.repository = repository
        self.registry = session.registry

    @property
    def _base(self) -> str:
        return f"https://{self.registry}"

    def _security_url(self, digest: str) -> str:
        return (
            f"{self._base}/api/v1/repository/{self.repository}"
            f"/manifest/{digest}/security?vulnerabilities=true"
        )

    def _v2_auth_url(self) -> str:
        params = urllib.parse.urlencode(
            {
                "service": self.registry,
                "scope": f"repository:{self.repository}:pull",
            }
        )
        return f"{self._base}/v2/auth?{params}"

    def _v2_manifest_url(self, reference: str) -> str:
        return f"{self._base}/v2/{self.repository}/manifests/{reference}"

    def _v2_bearer(self) -> str:
        if self._session.credentials.oauth_token:
            return self._session.credentials.oauth_token
        if not self._session.credentials.basic:
            raise TransportError(
                f"no credentials found for {self.registry}. "
                "Log in via 'podman login' / 'docker login' or pass --token."
            )
        try:
            data = self._session.get_json(
                self._v2_auth_url(),
                auth=Credentials(basic=self._session.credentials.basic),
            )
        except ApiError as exc:
            raise ApiError(
                f"v2 token exchange failed. Verify your login for {self.registry}."
            ) from exc
        token = data.get("token")
        if not token:
            raise ApiError("v2 auth response did not contain a token.")
        return str(token)

    def resolve_platform_digest(self, tag: str, arch: str) -> str:
        """Resolve *tag* to a platform-specific manifest digest."""
        token = self._v2_bearer()
        bearer = Credentials(oauth_token=token)
        headers = {"Accept": MANIFEST_ACCEPT}

        try:
            resp_headers = self._session.head(
                self._v2_manifest_url(tag), headers=headers, auth=bearer
            )
        except ApiError as exc:
            if exc.status == 404:
                raise ApiError(
                    f"tag '{tag}' not found in {self.repository}.",
                    status=404,
                ) from exc
            raise ApiError(
                f"HTTP error resolving tag '{tag}': {exc}",
                status=exc.status,
            ) from exc

        digest = resp_headers.get("Docker-Content-Digest", "")
        if not digest:
            raise ApiError(
                f"registry did not return Docker-Content-Digest header for tag '{tag}'."
            )

        content_type = resp_headers.get("Content-Type", "")
        if content_type not in INDEX_MEDIA_TYPES:
            return digest

        index = self._session.get_json(
            self._v2_manifest_url(digest), headers=headers, auth=bearer
        )
        available: list[str] = []
        for entry in index.get("manifests", []):
            platform = entry.get("platform", {})
            entry_arch = platform.get("architecture", "")
            available.append(entry_arch)
            if entry_arch == arch:
                return str(entry["digest"])

        raise ValueError(
            f"architecture '{arch}' not found in manifest index. "
            f"Available: {', '.join(available)}"
        )

    def fetch_security_report(self, digest: str) -> dict[str, Any]:
        """Download the Quay security JSON for *digest*."""
        url = self._security_url(digest)
        try:
            return self._session.get_json(url)
        except ApiError as exc:
            if exc.status == 401:
                raise ApiError(
                    f"{exc}. Authentication required for {self.registry}.",
                    status=401,
                ) from exc
            if exc.status == 404:
                raise ApiError(
                    f"{exc}. Repository or manifest not found. "
                    "Check the image reference and digest.",
                    status=404,
                ) from exc
            raise

    @staticmethod
    def parse_findings(report: dict[str, Any]) -> list[Finding]:
        """Convert a Quay/Clair security report into domain findings."""
        features = report.get("data", {}).get("Layer", {}).get("Features", [])
        if not isinstance(features, list):
            features = []

        findings: list[Finding] = []
        for feature in features:
            for vuln in feature.get("Vulnerabilities", []):
                fixed_by = vuln.get("FixedBy", "") or ""
                findings.append(
                    Finding(
                        cve=vuln.get("Name", ""),
                        severity=vuln.get("Severity", "Unknown"),
                        package=feature.get("Name", ""),
                        installed_version=feature.get("Version", ""),
                        fixed_by=fixed_by,
                        description=vuln.get("Description", "").replace("\n", " ")[
                            :DESCRIPTION_LIMIT
                        ],
                        link=(vuln.get("Link", "") or "").split(" ")[0],
                    )
                )
        findings.sort(key=finding_sort_key)
        return findings

    @staticmethod
    def feature_count(report: dict[str, Any]) -> int:
        features = report.get("data", {}).get("Layer", {}).get("Features", [])
        return len(features) if isinstance(features, list) else 0
