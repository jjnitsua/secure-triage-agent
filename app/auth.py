"""Authentication and the signed principal (Phase 2).

Two parts. (1) Token lookup: `load_users()` reads data/users.json (dev-only fake tokens) and
`TokenDirectory.authenticate()` turns a bearer token into a Principal, or None for any
token it does not know. It compares the token against every known token in constant time
and never prints tokens. This is the only place a user's identity is decided. (2) The signed
principal, described next: how the agent tells the MCP server who is calling.

The agent service decides who the user is (from the bearer token), then signs that
identity and sends it with every tool call in the MCP request's `_meta`, never in the
tool arguments, so the model cannot read or change it. The MCP server verifies the
signature on every call and takes the team and role only from the verified result.

Scheme (a deliberate simplification; production MCP over HTTP uses OAuth):
  package = base64url(JSON payload) + "." + hex(HMAC-SHA256(key, base64url(JSON payload)))
  payload = user_id, team, role, iat (issued at), exp (expires at), in Unix seconds

Both sides share one secret key, read from the TRIAGE_SIGNING_KEY environment variable.
There is no key in the code: if it is missing or too short, signing and verifying fail
instead of falling back to a default. Anyone who holds the key can forge any identity.

This module proves who the caller is. It does not decide what they may do (that is the
tool-boundary authorization) and it does not stop a manipulated model from misusing a
valid user's access. There is no one-time-use ID yet; the 60-second expiry limits replay.

Standard library only.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USERS_ENV = "TRIAGE_USERS"
ROLES = ("analyst", "manager")
USER_KEYS = {"user_id", "display_name", "team", "role", "token"}
MIN_TOKEN_LENGTH = 8
MAX_TOKEN_LENGTH = 256

KEY_ENV = "TRIAGE_SIGNING_KEY"
MIN_KEY_LENGTH = 16
DEFAULT_TTL_SECONDS = 60
META_KEY = "triage/principal"  # key under which the package travels in MCP `_meta`


class AuthError(Exception):
    """The signed principal is missing, malformed, forged or expired."""


@dataclass(frozen=True)
class Principal:
    user_id: str
    team: str | None  # None for the manager, who is not tied to one team
    role: str


def _key() -> bytes:
    key = os.environ.get(KEY_ENV, "")
    if len(key) < MIN_KEY_LENGTH:
        # A setup mistake, not a bad caller, so it is not an AuthError. Fail closed.
        raise RuntimeError(f"{KEY_ENV} must be set to at least {MIN_KEY_LENGTH} characters")
    return key.encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(body: str) -> str:
    return hmac.new(_key(), body.encode("ascii"), hashlib.sha256).hexdigest()


def sign_principal(principal: Principal, ttl: int = DEFAULT_TTL_SECONDS, now: float | None = None) -> str:
    """Return the signed package for `principal`, valid for `ttl` seconds."""
    issued = int(time.time() if now is None else now)
    payload = {
        "user_id": principal.user_id,
        "team": principal.team,
        "role": principal.role,
        "iat": issued,
        "exp": issued + ttl,
    }
    body = _b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"{body}.{_mac(body)}"


def verify_principal(package: object, now: float | None = None) -> Principal:
    """Return the Principal if `package` is genuine and unexpired, else raise AuthError.

    The signature is checked before the payload is parsed, so unsigned or altered
    content is never interpreted.
    """
    if not isinstance(package, str):
        raise AuthError("missing principal")
    parts = package.split(".")
    if len(parts) != 2 or not all(parts):
        raise AuthError("malformed principal")
    body, sig = parts
    try:
        expected = _mac(body)
    except UnicodeEncodeError:
        raise AuthError("malformed principal") from None
    if not hmac.compare_digest(expected.encode("ascii"), sig.encode("utf-8")):
        raise AuthError("bad signature")

    try:
        payload = json.loads(_b64decode(body))
        user_id, team, role, exp = payload["user_id"], payload["team"], payload["role"], payload["exp"]
    except (ValueError, KeyError, TypeError):
        raise AuthError("malformed principal") from None
    if not (isinstance(user_id, str) and user_id and isinstance(role, str) and role
            and (team is None or isinstance(team, str))
            and isinstance(exp, int) and not isinstance(exp, bool)):
        raise AuthError("malformed principal")

    if (time.time() if now is None else now) >= exp:
        raise AuthError("expired principal")
    return Principal(user_id=user_id, team=team, role=role)


class TokenDirectory:
    """Maps bearer tokens to principals. Built by load_users(); its repr never shows tokens."""

    def __init__(self, entries):
        self._entries = tuple((token.encode("utf-8"), principal) for token, principal in entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"TokenDirectory({len(self._entries)} users)"

    def authenticate(self, token: object) -> Principal | None:
        """Return the Principal for a known token, else None.

        The candidate is compared with every known token, with no early exit, so the time
        taken does not reveal which token matched or how close a guess was.
        """
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
            return None
        candidate = token.encode("utf-8")
        found = None
        for known, principal in self._entries:
            if hmac.compare_digest(known, candidate) and found is None:
                found = principal
        return found


def load_users(path=None) -> TokenDirectory:
    """Load and validate the users file (data/users.json, or TRIAGE_USERS if set).

    Strict, like the config loader: unknown keys, wrong types, unknown roles, an analyst
    without a team, a token that is too short or too long, and duplicate user IDs or
    tokens all raise ValueError. Error messages name the user, never the token.
    """
    path = Path(path or os.environ.get(USERS_ENV) or ROOT / "data" / "users.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("users"), list) or not raw["users"]:
        raise ValueError("users file must hold a non-empty 'users' list")
    if set(raw) - {"_note", "users"}:
        raise ValueError("unknown top-level key in users file")

    entries, user_ids, tokens = [], set(), set()
    for number, user in enumerate(raw["users"], start=1):
        if not isinstance(user, dict):
            raise ValueError(f"user #{number} must be an object")
        if set(user) - USER_KEYS:
            raise ValueError(f"user #{number} has unknown keys: {sorted(set(user) - USER_KEYS)}")
        user_id, team, role, token = (user.get(k) for k in ("user_id", "team", "role", "token"))
        if not (isinstance(user_id, str) and user_id):
            raise ValueError(f"user #{number} needs a user_id")
        if role not in ROLES:
            raise ValueError(f"user {user_id!r} has an unknown role")
        if not (team is None or (isinstance(team, str) and team)):
            raise ValueError(f"user {user_id!r} has an invalid team")
        if role == "analyst" and team is None:
            raise ValueError(f"analyst {user_id!r} needs a team")
        if not (isinstance(token, str) and MIN_TOKEN_LENGTH <= len(token) <= MAX_TOKEN_LENGTH):
            raise ValueError(f"user {user_id!r} needs a token of {MIN_TOKEN_LENGTH} to {MAX_TOKEN_LENGTH} characters")
        if user_id in user_ids:
            raise ValueError(f"duplicate user_id {user_id!r}")
        if token in tokens:
            raise ValueError(f"user {user_id!r} has a token that another user already has")
        user_ids.add(user_id)
        tokens.add(token)
        entries.append((token, Principal(user_id=user_id, team=team, role=role)))
    return TokenDirectory(entries)
