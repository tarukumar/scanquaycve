"""HTTP session with credential resolution for Quay / OCI registries."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from scanquaycve.config import HTTP_TIMEOUT
from scanquaycve.errors import ApiError, TransportError


@dataclass(frozen=True)
class Credentials:
    """Auth material for Quay API and/or OCI v2 calls."""

    oauth_token: str | None = None
    basic: str | None = None  # user:pass

    def authorization_header(self) -> dict[str, str]:
        if self.oauth_token:
            return {"Authorization": f"Bearer {self.oauth_token}"}
        if self.basic:
            encoded = base64.b64encode(self.basic.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        return {}


def load_local_credentials(registry: str) -> str | None:
    """Read user:pass from podman/docker auth files for *registry*."""
    candidates = [
        os.path.join(os.environ.get("XDG_RUNTIME_DIR", ""), "containers/auth.json"),
        os.path.expanduser("~/.docker/config.json"),
    ]
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        with open(path) as fh:
            data = json.load(fh)
        auths = data.get("auths", {})
        for key in (registry, f"https://{registry}", f"https://{registry}/v2/"):
            entry = auths.get(key, {})
            if entry.get("auth"):
                return base64.b64decode(entry["auth"]).decode()
    return None


class QuaySession:
    """Thin urllib wrapper plus credential helpers for a single registry."""

    def __init__(self, registry: str, *, oauth_token: str | None = None) -> None:
        self.registry = registry
        basic = None if oauth_token else load_local_credentials(registry)
        self.credentials = Credentials(oauth_token=oauth_token, basic=basic)

    @property
    def has_credentials(self) -> bool:
        return bool(self.credentials.oauth_token or self.credentials.basic)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        auth: Credentials | None = None,
    ) -> tuple[bytes, dict[str, str]]:
        creds = auth if auth is not None else self.credentials
        merged = {**creds.authorization_header(), **(headers or {})}
        req = urllib.request.Request(url, method=method)
        for key, value in merged.items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            raise ApiError(f"HTTP {exc.code} from {url}", status=exc.code) from exc
        except urllib.error.URLError as exc:
            raise TransportError(f"could not connect to server: {exc.reason}") from exc

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        auth: Credentials | None = None,
    ) -> dict[str, Any]:
        body, _ = self.request(url, headers=headers, auth=auth)
        data: dict[str, Any] = json.loads(body)
        return data

    def head(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        auth: Credentials | None = None,
    ) -> dict[str, str]:
        _, resp_headers = self.request(
            url, method="HEAD", headers=headers, auth=auth
        )
        return resp_headers
