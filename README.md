# scanquaycve

Scan Quay/Clair vulnerability reports for a container image by **tag** or **digest**. Reports include severity and fixable vs non-fixable classification.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- For private repos: `podman login quay.io` / `docker login quay.io`, or an OAuth `--token`

## Setup

```bash
uv sync --group dev
```

## Usage

Pass a single IMAGE reference:

```bash
# by tag
uv run scanquaycve quay.io/org/image:1.2.3

# short form (server defaults to quay.io)
uv run scanquaycve org/image:latest

# by digest
uv run scanquaycve quay.io/org/image@sha256:abc123...

# only High and Medium
uv run scanquaycve quay.io/org/image:latest -s High,Medium

# same thing, repeatable flags (case-insensitive)
uv run scanquaycve quay.io/org/image:latest -s high -s medium

# Critical + High (and anything more severe than the floor)
uv run scanquaycve quay.io/org/image:latest --min-severity High

# severity + fixable filter
uv run scanquaycve quay.io/org/image:latest \
  --min-severity Medium \
  --fixable-only \
  -o reports \
  --json \
  --token "$QUAY_TOKEN"
```

### Options

| Flag | Description |
|------|-------------|
| `-o`, `--output-dir` | Base output directory (default: `reports`) |
| `-s`, `--severity` | Exact severities to include (repeatable or comma-separated; case-insensitive): Critical, High, Medium, Low, Negligible, Unknown |
| `--min-severity` | Include this severity and higher (e.g. `High` → Critical + High). Mutually exclusive with `-s` |
| `--fixable-only` | Only CVEs with a known fix (`FixedBy`) |
| `--non-fixable-only` | Only CVEs without a known fix |
| `--arch` | Platform for multi-arch tags (default: `amd64`) |
| `--token` | Quay OAuth bearer token |
| `--json` | Also save the raw Quay security JSON |

## Output

```
reports/<image>/<tag-or-short-digest>/
  all-vulnerabilities.csv
  fixable-vulnerabilities.csv
  non-fixable-vulnerabilities.csv
  summary.json
  vulnerabilities.json   # with --json
```

Console also prints a severity x fixability summary.

**Fixable** means Clair returned a non-empty `FixedBy` version.

## Development

```bash
uv run ruff check .
uv run mypy
uv run pytest
```

## Auth

Credentials are resolved in order:

1. `--token` (OAuth bearer)
2. Podman auth file (`$XDG_RUNTIME_DIR/containers/auth.json`)
3. Docker config (`~/.docker/config.json`)
4. Unauthenticated (public repositories only)
