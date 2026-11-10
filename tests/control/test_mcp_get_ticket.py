"""Deterministic tests for the MCP server's get_ticket tool. No model, no network.

The server is called directly through an in-process MCP client, the way an attacker (or
a buggy agent) could call it without going through the model. Each test gets a fresh
copy of the fixture database. Needs data/fixtures.db (python scripts/seed_db.py).

Run from the repo folder:  python tests/control/test_mcp_get_ticket.py -v
"""
import base64
import json
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mcp import Client  # noqa: E402

from app import auth  # noqa: E402
from app.auth import META_KEY, Principal, sign_principal  # noqa: E402
from mcp_server import store  # noqa: E402
from mcp_server.server import create_server  # noqa: E402

KEY = "test-only-signing-key-not-a-secret"
OTHER_KEY = "a-different-test-only-signing-key"
WEB = Principal("analyst-web", "team-web", "analyst")
INFRA = Principal("analyst-infra", "team-infra", "analyst")
MANAGER = Principal("manager", None, "manager")

WEB_TICKET = "T-1003"    # team-web; description holds the web canary
INFRA_TICKET = "T-2003"  # team-infra; description holds the infra canary
INFRA_CANARY = "CANARY-4b1e6-DO-NOT-LEAK"
WEB_CANARY = "CANARY-7f3a9-DO-NOT-LEAK"


def _text(result) -> str:
    return " ".join(getattr(block, "text", "") for block in result.content)


class GetTicketTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = ROOT / "data" / "fixtures.db"
        if not cls.fixtures.exists():
            raise FileNotFoundError(f"{cls.fixtures} not found; run: python scripts/seed_db.py")

    def setUp(self):
        patcher = mock.patch.dict("os.environ", {auth.KEY_ENV: KEY})
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "working.db"
        shutil.copyfile(self.fixtures, self.db)
        self.server = create_server(self.db)

    async def call(self, args, principal=None, package=None):
        """Call get_ticket; the signed principal travels in _meta, never in the arguments."""
        if package is None and principal is not None:
            package = sign_principal(principal)
        meta = {META_KEY: package} if package is not None else None
        async with Client(self.server) as client:
            return await client.call_tool("get_ticket", args, meta=meta)

    async def test_analyst_reads_own_team_ticket(self):
        result = await self.call({"ticket_id": WEB_TICKET}, WEB)
        self.assertFalse(result.is_error)
        ticket = result.structured_content
        self.assertEqual(ticket["ticket_id"], WEB_TICKET)
        self.assertEqual(ticket["team"], "team-web")
        self.assertEqual(ticket["severity_history"], ["Critical"])
        self.assertEqual(ticket["cve_ids"], ["CVE-2099-0003"])

    async def test_analyst_cannot_read_other_team_and_gets_same_error_as_missing(self):
        other = await self.call({"ticket_id": INFRA_TICKET}, WEB)
        missing = await self.call({"ticket_id": "T-9999"}, WEB)
        self.assertTrue(other.is_error)
        self.assertIn("ticket not found", _text(other))
        self.assertNotIn(INFRA_CANARY, _text(other))
        self.assertEqual(_text(other).replace(INFRA_TICKET, "X"), _text(missing).replace("T-9999", "X"))

    async def test_manager_reads_both_teams(self):
        for ticket_id, team in ((WEB_TICKET, "team-web"), (INFRA_TICKET, "team-infra")):
            with self.subTest(ticket=ticket_id):
                result = await self.call({"ticket_id": ticket_id}, MANAGER)
                self.assertFalse(result.is_error)
                self.assertEqual(result.structured_content["team"], team)

    async def test_missing_principal_is_rejected(self):
        result = await self.call({"ticket_id": WEB_TICKET})
        self.assertTrue(result.is_error)
        self.assertIn("authentication failed", _text(result))
        self.assertNotIn(WEB_CANARY, _text(result))

    async def test_forged_principal_is_rejected(self):
        body, sig = sign_principal(WEB).split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["role"], payload["team"] = "manager", None
        forged_body = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")
        with mock.patch.dict("os.environ", {auth.KEY_ENV: OTHER_KEY}):
            wrong_key = sign_principal(MANAGER)
        for name, package in (("role edited, old signature", f"{forged_body}.{sig}"),
                              ("signed with another key", wrong_key),
                              ("garbage", "not-a-package")):
            with self.subTest(forgery=name):
                result = await self.call({"ticket_id": INFRA_TICKET}, package=package)
                self.assertTrue(result.is_error)
                self.assertIn("authentication failed", _text(result))
                self.assertNotIn(INFRA_CANARY, _text(result))

    async def test_expired_principal_is_rejected(self):
        old = sign_principal(MANAGER, ttl=60, now=time.time() - 120)
        result = await self.call({"ticket_id": WEB_TICKET}, package=old)
        self.assertTrue(result.is_error)
        self.assertIn("authentication failed", _text(result))

    async def test_identity_sent_in_arguments_gains_nothing(self):
        # What a manipulated model might try: put a team or role in the tool arguments.
        args = {"ticket_id": INFRA_TICKET, "team": "team-infra", "role": "manager", "user_id": "manager"}
        result = await self.call(args, WEB)
        self.assertTrue(result.is_error)
        self.assertNotIn(INFRA_CANARY, _text(result))

    async def test_tool_schema_has_no_identity_parameter(self):
        async with Client(self.server) as client:
            tools = (await client.list_tools()).tools
        schema = {t.name: t.input_schema for t in tools}["get_ticket"]
        self.assertEqual(set(schema["properties"]), {"ticket_id"})

    async def test_sql_shaped_ticket_id_is_just_not_found(self):
        result = await self.call({"ticket_id": "T-1001' OR '1'='1"}, MANAGER)
        self.assertTrue(result.is_error)
        self.assertIn("ticket not found", _text(result))
        count = sqlite3.connect(self.db).execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
        self.assertEqual(count, 30)


class StoreTests(unittest.TestCase):
    def test_read_connection_cannot_write(self):
        fixtures = ROOT / "data" / "fixtures.db"
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "working.db"
            shutil.copyfile(fixtures, db)
            con = store.connect_readonly(db)
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("UPDATE tickets SET severity = 'Low' WHERE ticket_id = 'T-1001'")
            con.close()


if __name__ == "__main__":
    unittest.main()
