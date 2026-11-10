"""Tests for token lookup in app/auth.py (load_users, TokenDirectory). No model, no network.

Run from the repo folder:  python tests/control/test_token_auth.py -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import hmac  # noqa: E402

from app import auth  # noqa: E402
from app.auth import Principal, load_users, sign_principal, verify_principal  # noqa: E402

WEB = Principal("analyst-web", "team-web", "analyst")
INFRA = Principal("analyst-infra", "team-infra", "analyst")
MANAGER = Principal("manager", None, "manager")


def good_user(user_id="u1", token="token-for-u1", **extra):
    return {"user_id": user_id, "team": "team-web", "role": "analyst", "token": token, **extra}


class RepoUsersTests(unittest.TestCase):
    def setUp(self):
        self.users = load_users(ROOT / "data" / "users.json")

    def test_each_dev_token_maps_to_its_own_principal(self):
        self.assertEqual(len(self.users), 3)
        self.assertEqual(self.users.authenticate("dev-token-analyst-web"), WEB)
        self.assertEqual(self.users.authenticate("dev-token-analyst-infra"), INFRA)
        self.assertEqual(self.users.authenticate("dev-token-manager"), MANAGER)

    def test_anything_else_is_unknown(self):
        long_token = "dev-token-manager" + "x" * 10000
        for bad in (None, 123, b"dev-token-manager", "", " ", "dev-token-manager ", " dev-token-manager",
                    "DEV-TOKEN-MANAGER", "dev-token-manage", "dev-token-managers", "Bearer dev-token-manager",
                    "dev-token-manager\n", long_token, "analyst-web", "manager"):
            with self.subTest(token=bad if not isinstance(bad, str) or len(bad) < 50 else "very long"):
                self.assertIsNone(self.users.authenticate(bad))

    def test_every_known_token_is_compared_whether_or_not_one_matches(self):
        real = hmac.compare_digest
        for token in ("dev-token-analyst-web", "dev-token-manager", "not-a-token"):  # first, last, none
            with self.subTest(token=token), mock.patch("app.auth.hmac.compare_digest", side_effect=real) as spy:
                self.users.authenticate(token)
                self.assertEqual(spy.call_count, 3)

    def test_repr_does_not_show_tokens(self):
        self.assertNotIn("dev-token", repr(self.users))
        self.assertNotIn("dev-token", str(self.users))

    def test_a_looked_up_principal_can_be_signed_and_verified(self):
        principal = self.users.authenticate("dev-token-analyst-infra")
        with mock.patch.dict("os.environ", {auth.KEY_ENV: "test-only-signing-key-not-a-secret"}):
            self.assertEqual(verify_principal(sign_principal(principal)), INFRA)


class LoaderStrictnessTests(unittest.TestCase):
    def load(self, content):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "users.json"
            path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
            return load_users(path)

    def test_a_minimal_valid_file_loads(self):
        users = self.load({"_note": "fixture", "users": [good_user(), good_user("u2", "token-for-u2")]})
        self.assertEqual(users.authenticate("token-for-u2"), Principal("u2", "team-web", "analyst"))

    def test_the_manager_may_have_no_team_but_an_analyst_may_not(self):
        manager = {"user_id": "m", "team": None, "role": "manager", "token": "token-for-m"}
        self.assertEqual(self.load({"users": [manager]}).authenticate("token-for-m"), Principal("m", None, "manager"))
        analyst = {"user_id": "a", "team": None, "role": "analyst", "token": "token-for-a"}
        with self.assertRaisesRegex(ValueError, "needs a team"):
            self.load({"users": [analyst]})

    def test_bad_files_are_rejected(self):
        cases = {
            "not json": "{nope",
            "top level is a list": [],
            "no users key": {"_note": "x"},
            "empty users": {"users": []},
            "users is not a list": {"users": {}},
            "unknown top-level key": {"users": [good_user()], "admins": []},
            "user is not an object": {"users": ["u1"]},
            "unknown user key": {"users": [good_user(is_admin=True)]},
            "missing user_id": {"users": [{"team": "t", "role": "analyst", "token": "token-12345"}]},
            "unknown role": {"users": [good_user(role="root")]},
            "team is a number": {"users": [good_user(team=5)]},
            "token too short": {"users": [good_user(token="short")]},
            "token too long": {"users": [good_user(token="x" * 300)]},
            "token is a number": {"users": [good_user(token=12345678)]},
            "duplicate user_id": {"users": [good_user(), good_user(token="another-token-1")]},
            "duplicate token": {"users": [good_user(), good_user("u2")]},
        }
        for name, content in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                self.load(content)

    def test_error_messages_never_contain_a_token(self):
        token = "super-secret-looking-token-value"
        with self.assertRaises(ValueError) as caught:
            self.load({"users": [good_user(token=token), good_user("u2", token=token)]})
        self.assertNotIn(token, str(caught.exception))

    def test_missing_file_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            load_users(ROOT / "data" / "no-such-users.json")

    def test_environment_variable_can_point_at_another_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "users.json"
            path.write_text(json.dumps({"users": [good_user("only", "token-for-only")]}), encoding="utf-8")
            with mock.patch.dict("os.environ", {auth.USERS_ENV: str(path)}):
                users = load_users()
        self.assertEqual(len(users), 1)
        self.assertIsNone(users.authenticate("dev-token-manager"))


if __name__ == "__main__":
    unittest.main()
