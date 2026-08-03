"""Tests for image reference parsing."""

from __future__ import annotations

import pytest

from scanquaycve.domain import parse_image_reference
from scanquaycve.errors import InvalidImageReference


def test_parse_tag_with_server() -> None:
    ref = parse_image_reference("quay.io/org/image:1.2.3")
    assert ref.registry == "quay.io"
    assert ref.repository == "org/image"
    assert ref.tag == "1.2.3"
    assert ref.digest is None
    assert ref.short_name == "image"
    assert ref.output_label == "1.2.3"


def test_parse_tag_default_server() -> None:
    ref = parse_image_reference("org/image:latest")
    assert ref.registry == "quay.io"
    assert ref.repository == "org/image"
    assert ref.tag == "latest"


def test_parse_digest() -> None:
    digest = "sha256:" + ("a" * 64)
    ref = parse_image_reference(f"quay.io/org/image@{digest}")
    assert ref.registry == "quay.io"
    assert ref.repository == "org/image"
    assert ref.tag is None
    assert ref.digest == digest
    assert ref.output_label == "a" * 12


def test_parse_nested_repo() -> None:
    ref = parse_image_reference("quay.io/org/ns/image:v1")
    assert ref.repository == "org/ns/image"
    assert ref.tag == "v1"


def test_parse_localhost_with_port() -> None:
    ref = parse_image_reference("localhost:5000/org/image:dev")
    assert ref.registry == "localhost:5000"
    assert ref.repository == "org/image"
    assert ref.tag == "dev"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "sha256:abc",
        "org/image",
        "image:latest",
        "quay.io/org/image@",
    ],
)
def test_parse_invalid(bad: str) -> None:
    with pytest.raises(InvalidImageReference):
        parse_image_reference(bad)
