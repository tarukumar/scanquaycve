"""Tests for credential header building."""

from __future__ import annotations

from scanquaycve.client import Credentials


def test_credentials_bearer() -> None:
    assert Credentials(oauth_token="abc").authorization_header() == {
        "Authorization": "Bearer abc"
    }


def test_credentials_basic() -> None:
    headers = Credentials(basic="user:pass").authorization_header()
    assert headers["Authorization"].startswith("Basic ")


def test_credentials_empty() -> None:
    assert Credentials().authorization_header() == {}
