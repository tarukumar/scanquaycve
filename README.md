# scanquaycve

Scan Quay/Clair vulnerability reports for a container image by **tag** or **digest**. Reports include severity and fixable vs non-fixable classification.

## Requirements

- Python 3.12+ (stdlib only — no third-party runtime deps)
- For private repos: `podman login quay.io` / `docker login quay.io`, or an OAuth `--token`

## Setup

### Plain Python / pip

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

Or run from a checkout without installing:

```bash
PYTHONPATH=src python3 -m scanquaycve quay.io/org/image:latest
```

### uv (optional, for development)

```bash
uv sync --group dev
```

## Usage

Pass a single IMAGE reference:

```bash
# by tag
scanquaycve quay.io/org/image:1.2.3

# short form (server defaults to quay.io)
scanquaycve org/image:latest

# by digest
scanquaycve quay.io/org/image@sha256:abc123...

# only High and Medium
scanquaycve quay.io/org/image:latest -s High,Medium

# same thing, repeatable flags (case-insensitive)
scanquaycve quay.io/org/image:latest -s high -s medium

# Critical + High (and anything more severe than the floor)
scanquaycve quay.io/org/image:latest --min-severity High

# severity + fixable filter
scanquaycve quay.io/org/image:latest \
  --min-severity Medium \
  --fixable-only \
  -o reports \
  --json \
  --token "$QUAY_TOKEN"
```

With uv, prefix the same commands with `uv run` (e.g. `uv run scanquaycve …`).

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
pip install -e . && pip install pytest ruff mypy
# or: uv sync --group dev
ruff check .
mypy
pytest
```

## Auth

Credentials are resolved in order:

1. `--token` (OAuth bearer)
2. Podman auth file (`$XDG_RUNTIME_DIR/containers/auth.json`)
3. Docker config (`~/.docker/config.json`)
4. Unauthenticated (public repositories only)
