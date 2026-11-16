"""Strict private configuration for the independent Gemini listener."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import urlsplit

SCOPES = frozenset({"files:read", "files:write", "files:delete"})
GOOGLE_REDIRECT_HOSTS = frozenset({
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
    "oauth-redirect-test.googleusercontent.com",
})


@dataclass(frozen=True)
class Config:
    public_url: str
    client_id: str
    client_secret: str
    listen_port: int = 8766
    gateway_port: int = 8765
    scopes: tuple[str, ...] = ("files:read", "files:write", "files:delete")
    workspaces: tuple[str, ...] = ()
    redirect_uris: tuple[str, ...] = ()
    state_file: Path | None = None

    @property
    def resource(self) -> str:
        return self.public_url + "/mcp"

    @property
    def issuer(self) -> str:
        return self.public_url

    @property
    def upstream(self) -> str:
        return f"http://127.0.0.1:{self.gateway_port}/mcp"

    def validate_redirect(self, value: str) -> bool:
        """Only operator-approved exact redirect URIs; never trust host alone."""
        if not isinstance(value, str) or len(value) > 2048 or "\\" in value:
            return False
        try:
            p = urlsplit(value)
            if p.scheme != "https" or p.port is not None or p.username or p.password or p.query or p.fragment:
                return False
            if p.hostname not in GOOGLE_REDIRECT_HOSTS or p.netloc != p.hostname:
                return False
            if not re.fullmatch(r"/(?:r|a)/[A-Za-z0-9_./~-]{1,512}", p.path):
                return False
            if "/../" in p.path or "/./" in p.path or p.path.endswith("/.."):
                return False
            return value in self.redirect_uris
        except (ValueError, AttributeError):
            return False


def _check_private_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Gemini config must be a user-owned regular file with mode 0600")


def load_config(path: str | Path) -> Config:
    path = Path(path).expanduser().absolute()
    _check_private_file(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"public_url", "client_id", "client_secret", "listen_port", "gateway_port", "scopes", "workspaces", "redirect_uris"}:
        raise ValueError("Unknown Gemini config field")
    base = data.get("public_url", "")
    p = urlsplit(base)
    if not (p.scheme == "https" and p.hostname and p.netloc == p.hostname and not p.path and not p.query and not p.fragment):
        raise ValueError("public_url must be a bare HTTPS origin with no path or port")
    for key in ("listen_port", "gateway_port"):
        n = data.get(key, 8766 if key == "listen_port" else 8765)
        if type(n) is not int or not 1024 <= n <= 65535:
            raise ValueError(f"Invalid {key}")
    if data.get("listen_port", 8766) == data.get("gateway_port", 8765):
        raise ValueError("Gemini and Gateway ports must be different")
    if not (isinstance(data.get("client_id"), str) and len(data["client_id"]) >= 12
            and isinstance(data.get("client_secret"), str) and len(data["client_secret"]) >= 32):
        raise ValueError("Client credentials are missing or too short")
    scopes = data.get("scopes", sorted(SCOPES))
    workspaces = data.get("workspaces", [])
    redirects = data.get("redirect_uris", [])
    if not isinstance(scopes, list) or not scopes or any(not isinstance(x, str) or x not in SCOPES for x in scopes) or len(set(scopes)) != len(scopes):
        raise ValueError("Invalid scopes")
    if (not isinstance(workspaces, list) or len(workspaces) > 100
            or any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", x) for x in workspaces)
            or len(set(workspaces)) != len(workspaces)):
        raise ValueError("Invalid workspaces")
    if not isinstance(redirects, list) or len(redirects) > 20 or any(not isinstance(x, str) for x in redirects):
        raise ValueError("Invalid redirect_uris")
    config = Config(
        public_url=base, client_id=data["client_id"], client_secret=data["client_secret"],
        listen_port=data.get("listen_port", 8766), gateway_port=data.get("gateway_port", 8765),
        scopes=tuple(scopes), workspaces=tuple(workspaces), redirect_uris=tuple(redirects),
        state_file=path.with_name("gemini-state.sqlite3"),
    )
    if len(set(redirects)) != len(redirects):
        raise ValueError("Duplicate redirect URI")
    if any(not config.validate_redirect(x) for x in redirects):
        raise ValueError("Disallowed redirect URI")
    return config


def initialize_config(path: str | Path, *, public_url: str, workspaces: tuple[str, ...] = ()) -> Config:
    """Creates local secrets once; refuse replacement of existing config."""
    path = Path(path).expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("Config directory must not grant access to group/other")
    data = {
        "public_url": public_url,
        "client_id": "mfg-" + secrets.token_urlsafe(18),
        "client_secret": secrets.token_urlsafe(48),
        "listen_port": 8766, "gateway_port": 8765,
        "scopes": sorted(SCOPES), "workspaces": list(workspaces), "redirect_uris": [],
    }
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return load_config(path)
