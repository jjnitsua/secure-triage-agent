"""Security configuration loader (Phase 2).

Reads config/security.yaml (or the file named by TRIAGE_CONFIG). The loader is strict on
purpose: an unknown key, a wrong type, or a value for a feature that does not exist yet
raises ValueError instead of being ignored, so a typo cannot silently turn a protection
off (or pretend one is on). A missing key falls back to the safe default.

Standard library plus PyYAML (already installed as a Garak dependency).
"""
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_ENV = "TRIAGE_CONFIG"

KNOWN_KEYS = {
    "auth": {"token_auth"},
    "controls": {"tool_authz", "approval_policy"},
}


@dataclass(frozen=True)
class Config:
    token_auth: bool = True
    tool_authz: bool = True
    approval_policy: str = "none"


def _section(raw: dict, name: str) -> dict:
    section = raw.get(name) or {}
    if not isinstance(section, dict):
        raise ValueError(f"{name} must be a mapping")
    unknown = set(section) - KNOWN_KEYS[name]
    if unknown:
        raise ValueError(f"unknown key(s) in {name}: {sorted(unknown)}")
    return section


def _bool(section: dict, key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false, got {value!r}")
    return value


def load_config(path=None) -> Config:
    path = Path(path or os.environ.get(CONFIG_ENV) or ROOT / "config" / "security.yaml")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("config must be a mapping")
    unknown = set(raw) - set(KNOWN_KEYS)
    if unknown:
        raise ValueError(f"unknown top-level key(s): {sorted(unknown)}")

    auth = _section(raw, "auth")
    controls = _section(raw, "controls")

    token_auth = _bool(auth, "token_auth", True)
    if not token_auth:
        raise ValueError("token_auth: false is for the identity experiment and is not implemented yet")
    approval_policy = controls.get("approval_policy", "none")
    if approval_policy != "none":
        raise ValueError(f"approval_policy {approval_policy!r} is not implemented yet (only 'none')")
    return Config(token_auth=token_auth, tool_authz=_bool(controls, "tool_authz", True),
                  approval_policy=approval_policy)
