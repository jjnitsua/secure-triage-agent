"""Deterministic tests for app/auth.py (signed principal). No model, no network.

Run from the repo folder:  python tests/control/test_auth.py -v
"""
import base64
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import auth  # noqa: E402
from app.auth import AuthError, Principal, sign_principal, verify_principal  # noqa: E402

KEY = "test-only-signing-key-not-a-secret"
OTHER_KEY = "a-different-test-only-signing-key"
ANALYST = Principal("analyst-web", "team-web", "analyst")
MANAGER = Principal("manager", None, "manager")
T0 = 1_000_000  # fixed "now" so the tests do not depend on the clock


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class SignedPrincipalTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict("os.environ", {auth.KEY_ENV: KEY})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_round_trip(self):
        self.assertEqual(verify_principal(sign_principal(ANALYST, now=T0), now=T0 + 1), ANALYST)

    def test_manager_without_team(self):
        self.assertEqual(verify_principal(sign_principal(MANAGER, now=T0), now=T0 + 1), MANAGER)

    def test_altered_role_is_rejected(self):
        body, sig = sign_principal(ANALYST, now=T0).split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["role"] = "manager"
        forged_body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaisesRegex(AuthError, "bad signature"):
            verify_principal(f"{forged_body}.{sig}", now=T0 + 1)

    def test_signature_from_another_user_is_rejected(self):
        body_a, _ = sign_principal(ANALYST, now=T0).split(".")
        _, sig_m = sign_principal(MANAGER, now=T0).split(".")
        with self.assertRaisesRegex(AuthError, "bad signature"):
            verify_principal(f"{body_a}.{sig_m}", now=T0 + 1)

    def test_signed_with_wrong_key_is_rejected(self):
        with mock.patch.dict("os.environ", {auth.KEY_ENV: OTHER_KEY}):
            package = sign_principal(ANALYST, now=T0)
        with self.assertRaisesRegex(AuthError, "bad signature"):
            verify_principal(package, now=T0 + 1)

    def test_expired_is_rejected(self):
        package = sign_principal(ANALYST, ttl=60, now=T0)
        verify_principal(package, now=T0 + 59)  # still valid
        with self.assertRaisesRegex(AuthError, "expired"):
            verify_principal(package, now=T0 + 60)

    def test_garbage_and_missing_are_rejected(self):
        for bad in (None, 123, b"bytes", "", ".", "abc", "a.b.c", "a.", ".b", "é.é", "a.b"):
            with self.subTest(bad=bad), self.assertRaises(AuthError):
                verify_principal(bad, now=T0)

    def test_validly_signed_but_wrong_shape_is_rejected(self):
        # Someone who holds the key signed a payload that is not a proper principal.
        for payload in ({"user_id": "x"}, {"user_id": "", "team": None, "role": "analyst", "exp": T0 + 60},
                        {"user_id": "x", "team": 5, "role": "analyst", "exp": T0 + 60},
                        {"user_id": "x", "team": None, "role": "analyst", "exp": "soon"},
                        ["not", "a", "dict"]):
            body = _b64(json.dumps(payload).encode())
            package = f"{body}.{auth._mac(body)}"
            with self.subTest(payload=payload), self.assertRaisesRegex(AuthError, "malformed"):
                verify_principal(package, now=T0)

    def test_request_id_is_signed_and_comes_back(self):
        tagged = Principal("analyst-web", "team-web", "analyst", request_id="0123456789abcdef")
        verified = verify_principal(sign_principal(tagged, now=T0), now=T0 + 1)
        self.assertEqual(verified.request_id, "0123456789abcdef")
        self.assertEqual(verified, ANALYST)  # the request id is not part of who the caller is

    def test_no_request_id_means_none(self):
        self.assertIsNone(verify_principal(sign_principal(ANALYST, now=T0), now=T0 + 1).request_id)

    def test_altered_request_id_is_rejected(self):
        body, sig = sign_principal(Principal("analyst-web", "team-web", "analyst", request_id="aaaaaaaaaaaaaaaa"), now=T0).split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["request_id"] = "bbbbbbbbbbbbbbbb"
        forged_body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaisesRegex(AuthError, "bad signature"):
            verify_principal(f"{forged_body}.{sig}", now=T0 + 1)

    def test_a_bad_request_id_is_refused_when_signing_and_when_verifying(self):
        for bad in ("", "short", "UPPERCASE0123456", "not-hex-not-hex!!", "a" * 65, "abc def0 1234 5678"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sign_principal(Principal("x", "t", "analyst", request_id=bad), now=T0)
        for bad in ("", "short", 12345, ["0123456789abcdef"], "x" * 16):
            payload = {"user_id": "x", "team": None, "role": "analyst", "request_id": bad, "exp": T0 + 60}
            body = _b64(json.dumps(payload).encode())
            with self.subTest(payload_value=bad), self.assertRaisesRegex(AuthError, "malformed"):
                verify_principal(f"{body}.{auth._mac(body)}", now=T0)

    def test_missing_or_short_key_fails_closed(self):
        for value in ("", "too-short"):
            with mock.patch.dict("os.environ", {auth.KEY_ENV: value}):
                with self.subTest(key=value):
                    with self.assertRaises(RuntimeError):
                        sign_principal(ANALYST, now=T0)
                    with self.assertRaises(RuntimeError):
                        verify_principal("a.b", now=T0)
        with mock.patch.dict("os.environ", clear=True):
            with self.assertRaises(RuntimeError):
                sign_principal(ANALYST, now=T0)


if __name__ == "__main__":
    unittest.main()
