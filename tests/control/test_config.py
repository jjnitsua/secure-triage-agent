"""Tests for app/config.py: the loader must be strict so a typo cannot disable a protection.

Run from the repo folder:  python tests/control/test_config.py -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.config import Config, load_config  # noqa: E402


class ConfigTests(unittest.TestCase):
    def load(self, yaml_text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security.yaml"
            path.write_text(yaml_text, encoding="utf-8")
            return load_config(path)

    def test_repo_config_loads_with_protection_on(self):
        config = load_config(ROOT / "config" / "security.yaml")
        self.assertEqual(config, Config(mode="defended", token_auth=True, tool_authz=True, approval_policy="none"))

    def test_empty_file_gives_the_safe_defaults(self):
        self.assertEqual(self.load(""), Config())
        self.assertTrue(self.load("controls: {}\n").tool_authz)

    def test_tool_authz_can_be_turned_off_explicitly(self):
        self.assertFalse(self.load("controls:\n  tool_authz: false\n").tool_authz)

    def test_unknown_keys_are_rejected(self):
        for bad in ("controls:\n  tool_authz_typo: false\n", "auth:\n  tokn_auth: true\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.load(bad)

    def test_wrong_types_are_rejected(self):
        for bad in ("controls:\n  tool_authz: 'no'\n", "controls:\n  tool_authz: 0\n", "controls: [1, 2]\n", "- a\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.load(bad)

    def test_features_that_do_not_exist_yet_are_rejected(self):
        for bad in ("controls:\n  approval_policy: full\n", "controls:\n  approval_policy: naive\n",
                    "auth:\n  token_auth: false\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.load(bad)

    def test_modes_set_the_switches(self):
        vulnerable = self.load("mode: vulnerable\n")
        self.assertEqual(vulnerable, Config(mode="vulnerable", token_auth=True, tool_authz=False, approval_policy="none"))
        self.assertEqual(self.load("mode: defended\n"), Config(mode="defended"))
        self.assertEqual(self.load("").mode, "defended")

    def test_unknown_mode_is_rejected(self):
        for bad in ("mode: vulnerble\n", "mode: true\n", "mode: ''\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.load(bad)

    def test_explicit_switch_overrides_mode_and_is_labelled_custom(self):
        mixed = self.load("mode: vulnerable\ncontrols:\n  tool_authz: true\n")
        self.assertTrue(mixed.tool_authz)
        self.assertEqual(mixed.mode, "custom")
        self.assertEqual(self.load("mode: defended\ncontrols:\n  tool_authz: false\n").mode, "custom")
        # an explicit switch that matches the mode changes nothing
        self.assertEqual(self.load("mode: vulnerable\ncontrols:\n  tool_authz: false\n").mode, "vulnerable")

    def test_token_auth_stays_on_in_every_mode(self):
        self.assertTrue(self.load("mode: vulnerable\n").token_auth)
        with self.assertRaises(ValueError):
            self.load("mode: vulnerable\nauth:\n  token_auth: false\n")

    def test_vulnerable_config_file_loads_as_vulnerable(self):
        config = load_config(ROOT / "config" / "vulnerable.yaml")
        self.assertEqual((config.mode, config.tool_authz, config.token_auth), ("vulnerable", False, True))

    def test_missing_file_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            load_config(ROOT / "config" / "does-not-exist.yaml")


if __name__ == "__main__":
    unittest.main()
