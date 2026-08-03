"""CLI argument and image-ref validation tests."""

from __future__ import annotations

import pytest

from scanquaycve.cli import build_parser, main, resolve_severity_filter


def test_mutually_exclusive_fixable_flags(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "quay.io/org/image:latest",
                "--fixable-only",
                "--non-fixable-only",
            ]
        )
    assert exc.value.code == 2


def test_invalid_image_exits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["org/image"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "must include a tag" in err or "invalid image" in err


def test_invalid_severity(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["quay.io/org/image:latest", "--severity", "Ultra"])
    assert exc.value.code == 2


def test_severity_flags_are_exclusive(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "quay.io/org/image:latest",
                "-s",
                "High",
                "--min-severity",
                "Medium",
            ]
        )
    assert exc.value.code == 2


def test_parser_accepts_image() -> None:
    parser = build_parser()
    args = parser.parse_args(["quay.io/org/image@sha256:" + ("a" * 64), "-o", "out"])
    assert args.image.startswith("quay.io/org/image@")
    assert args.output_dir == "out"


def test_resolve_severity_list_and_repeatable() -> None:
    assert resolve_severity_filter(["high,medium"], None) == {"High", "Medium"}
    assert resolve_severity_filter(["High", "low"], None) == {"High", "Low"}


def test_resolve_min_severity() -> None:
    assert resolve_severity_filter(None, "High") == {"Critical", "High"}
