"""Application error types."""

from __future__ import annotations


class ScanError(Exception):
    """Base error for scanquaycve failures."""


class InvalidImageReference(ScanError, ValueError):
    """The IMAGE argument could not be parsed."""


class TransportError(ScanError):
    """Network failure talking to Quay or the registry."""


class ApiError(ScanError):
    """HTTP or API-level failure from Quay / OCI endpoints."""

    def __init__(self, message: str, *, status: int = 0) -> None:
        super().__init__(message)
        self.status = status
