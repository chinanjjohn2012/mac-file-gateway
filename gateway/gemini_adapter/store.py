"""Operator-approved, persistent, opaque OAuth grants.

Database content is private to the local OS user. Tokens/codes/cookies are
stored as SHA-256 digests, never as bearer plaintext. All mutations serialize.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def challenge_for(verifier: str) -> str:
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.stat().st_mode & 0o077:
            raise ValueError("OAuth state directory must be private (0700)")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("OAuth state file must be user-owned, regular, mode 0600")
        else:
            os.close(fd)
        self.db = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript("""
                PRAGMA busy_timeout = 5000;
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, sid_hash TEXT NOT NULL, client TEXT NOT NULL,
                    redirect TEXT NOT NULL, state TEXT NOT NULL,
                    challenge TEXT NOT NULL, scopes TEXT NOT NULL,
                    workspaces TEXT NOT NULL, status TEXT NOT NULL, expires INTEGER NOT NULL,
                    code_hash TEXT UNIQUE, code_expires INTEGER
                );
                CREATE TABLE IF NOT EXISTS tokens (
                    token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    grant_id TEXT NOT NULL, client TEXT NOT NULL, scopes TEXT NOT NULL,
                    workspaces TEXT NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS token_grant ON tokens(grant_id);
                CREATE TABLE IF NOT EXISTS revoked_grants (grant_id TEXT PRIMARY KEY);
            """)

    def close(self):
        with self.lock:
            self.db.close()

    def create_request(self, *, client: str, redirect: str, state: str,
                       challenge: str, scopes: tuple[str, ...], workspaces: tuple[str, ...]):
        rid, sid = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        with self.lock:
            now = int(time.time())
            self.db.execute("DELETE FROM requests WHERE expires<?", (now,))
            count = self.db.execute("SELECT count(*) FROM requests WHERE status IN ('pending','approved') AND expires>?", (now,)).fetchone()[0]
            if count >= 32:
                raise ValueError("Too many pending OAuth authorization requests")
            self.db.execute(
                "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, digest(sid), client, redirect, state, challenge,
                 json.dumps(scopes), json.dumps(workspaces), "pending", int(time.time())+600, None, None),
            )
        return rid, sid

    def get_request(self, rid: str):
        with self.lock:
            row = self.db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return dict(row) if row is not None else None

    def pending(self):
        with self.lock:
            rows = self.db.execute("SELECT id,client,redirect,scopes,workspaces,expires FROM requests WHERE status='pending' AND expires>? ORDER BY expires", (int(time.time()),)).fetchall()
        return [dict(x) for x in rows]

    def approve(self, rid: str, *, scopes: tuple[str, ...] | None = None,
                workspaces: tuple[str, ...] | None = None):
        with self.lock:
            row = self.db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
            if not row or row["status"] != "pending" or row["expires"] <= int(time.time()):
                raise ValueError("Unknown, consumed, or expired pending request")
            requested = set(json.loads(row["scopes"]))
            requested_ws = set(json.loads(row["workspaces"]))
            scoped = set(scopes) if scopes is not None else requested
            workspace_subset = set(workspaces) if workspaces is not None else requested_ws
            if not scoped or not scoped <= requested or not workspace_subset <= requested_ws:
                raise ValueError("Approval cannot extend requested scope/workspaces")
            self.db.execute(
                "UPDATE requests SET scopes=?, workspaces=?, status='approved' WHERE id=? AND status='pending'",
                (json.dumps(sorted(scoped)), json.dumps(sorted(workspace_subset)), rid),
            )

    def deny(self, rid: str):
        with self.lock:
            self.db.execute("UPDATE requests SET status='denied' WHERE id=? AND status IN ('pending','approved')", (rid,))

    def issue_code(self, rid: str, sid: str):
        now = int(time.time())
        code = secrets.token_urlsafe(40)
        with self.lock:
            row = self.db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
            if not row or row["status"] != "approved" or row["expires"] <= now:
                raise ValueError("Not authorized")
            if not hmac.compare_digest(row["sid_hash"], digest(sid)):
                raise ValueError("Session mismatch")
            self.db.execute("UPDATE requests SET code_hash=?, code_expires=?, status='code' WHERE id=? AND status='approved'", (digest(code), now + 120, rid))
        return code, row["redirect"], row["state"]

    def exchange_code(self, *, code: str, client: str, redirect: str, verifier: str):
        now = int(time.time())
        with self.lock:
            row = self.db.execute("SELECT * FROM requests WHERE code_hash=? AND status='code'", (digest(code),)).fetchone()
            if (not row or row["code_expires"] <= now or row["client"] != client
                or row["redirect"] != redirect or not hmac.compare_digest(row["challenge"], challenge_for(verifier))):
                return None
            self.db.execute("UPDATE requests SET status='used', code_hash=NULL WHERE id=?", (row["id"],))
            return self._new_grant(client=client, scopes=row["scopes"], workspaces=row["workspaces"], grant_id=secrets.token_urlsafe(24))

    def _new_grant(self, *, client: str, scopes: str, workspaces: str, grant_id: str):
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        self.db.executemany("INSERT INTO tokens(token_hash,kind,grant_id,client,scopes,workspaces,expires) VALUES (?,?,?,?,?,?,?)", [
            (digest(access), "access", grant_id, client, scopes, workspaces, now+3600),
            (digest(refresh), "refresh", grant_id, client, scopes, workspaces, now+30*86400),
        ])
        return {"access_token":access, "token_type":"Bearer", "expires_in":3600, "refresh_token":refresh, "scope":" ".join(json.loads(scopes))}

    def rotate_refresh(self, *, refresh: str, client: str):
        now = int(time.time())
        with self.lock:
            row = self.db.execute("SELECT * FROM tokens WHERE token_hash=? AND kind='refresh'", (digest(refresh),)).fetchone()
            if not row or row["client"] != client or row["expires"] <= now:
                return None
            if self._revoked(row["grant_id"]):
                return None
            if row["consumed"]:
                self.revoke_grant(row["grant_id"])
                return None
            self.db.execute("UPDATE tokens SET consumed=1 WHERE token_hash=?", (digest(refresh),))
            return self._new_grant(client=client,scopes=row["scopes"],workspaces=row["workspaces"],grant_id=row["grant_id"])

    def _revoked(self, grant_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM revoked_grants WHERE grant_id=?", (grant_id,)).fetchone() is not None

    def lookup(self, token: str):
        with self.lock:
            row = self.db.execute("SELECT * FROM tokens WHERE token_hash=? AND kind='access'", (digest(token),)).fetchone()
            if not row or row["expires"] <= int(time.time()) or self._revoked(row["grant_id"]):
                return None
            return {"client":row["client"], "scopes":tuple(json.loads(row["scopes"])), "workspaces":tuple(json.loads(row["workspaces"]))}

    def revoke_grant(self, grant_id: str):
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO revoked_grants(grant_id) VALUES (?)", (grant_id,))

    def revoke(self, token: str, client: str):
        with self.lock:
            row = self.db.execute("SELECT grant_id FROM tokens WHERE token_hash=? AND client=?", (digest(token), client)).fetchone()
            if row:
                self.revoke_grant(row["grant_id"])

    def revoke_all(self):
        with self.lock:
            # An emergency operator revoke must also invalidate pending
            # browser consents and already-issued unredeemed codes.
            self.db.execute("UPDATE requests SET status='denied', code_hash=NULL WHERE status IN ('pending','approved','code')")
            self.db.execute("INSERT OR IGNORE INTO revoked_grants SELECT DISTINCT grant_id FROM tokens")
