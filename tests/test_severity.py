"""Tests for severity helpers."""

from __future__ import annotations

import pytest

from scanquaycve.config import (
    labels_at_or_above,
    parse_severity,
    parse_severity_names,
)


def test_normalize_severity_case_insensitive() -> None:
    assert parse_severity("high").label == "High"
    assert parse_severity("CRITICAL").label == "Critical"
    assert parse_severity(" Medium ").label == "Medium"


def test_normalize_severity_invalid() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        parse_severity("Ultra")


def test_parse_severity_list() -> None:
    assert parse_severity_names("high,medium") == {"High", "Medium"}
    assert parse_severity_names("Critical") == {"Critical"}


def test_severities_at_or_above() -> None:
    assert labels_at_or_above("High") == {"Critical", "High"}
    assert labels_at_or_above("medium") == {"Critical", "High", "Medium"}
    assert labels_at_or_above("Critical") == {"Critical"}
