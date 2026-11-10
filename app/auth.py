"""Signed principal: how the agent tells the MCP server who is calling (Phase 2).

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
