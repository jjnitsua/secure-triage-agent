"""Shared helpers for the MCP tool control tests (no tests in this file).

ToolTestCase gives each test a fresh copy of the fixture database, a server built on it
with `tool_authz` on or off (set the class attribute), and `call()` to invoke a tool
through an in-process MCP client with a signed principal in `_meta`. Needs
data/fixtures.db (python scripts/seed_db.py).
"""
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mcp import Client  # noqa: E402

from app import auth  # noqa: E402
from app.auth import META_KEY, Principal, sign_principal  # noqa: E402
from mcp_server.server import create_server  # noqa: E402

KEY = "test-only-signing-key-not-a-secret"
OTHER_KEY = "a-different-test-only-signing-key"
WEB = Principal("analyst-web", "team-web", "analyst")
INFRA = Principal("analyst-infra", "team-infra", "analyst")
MANAGER = Principal("manager", None, "manager")

WEB_CANARY = "CANARY-7f3a9-DO-NOT-LEAK"      # in T-1003 (team-web)
INFRA_CANARY = "CANARY-4b1e6-DO-NOT-LEAK"    # in T-2003 (team-infra)
FIXTURES = ROOT / "data" / "fixtures.db"


def text(result) -> str:
    return " ".join(getattr(block, "text", "") for block in result.content)


class ToolTestCase(unittest.IsolatedAsyncioTestCase):
    tool_authz = True

    @classmethod
    def setUpClass(cls):
        if not FIXTURES.exists():
            raise FileNotFoundError(f"{FIXTURES} not found; run: python scripts/seed_db.py")

    def setUp(self):
        patcher = mock.patch.dict("os.environ", {auth.KEY_ENV: KEY})
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "working.db"
        shutil.copyfile(FIXTURES, self.db)
        self.server = create_server(self.db, tool_authz=self.tool_authz)

    async def call(self, tool, args, principal=None, package=None):
        """Call a tool; the signed principal travels in _meta, never in the arguments."""
        if package is None and principal is not None:
            package = sign_principal(principal)
        meta = {META_KEY: package} if package is not None else None
        async with Client(self.server) as client:
            return await client.call_tool(tool, args, meta=meta)

    def rows(self, sql, params=()):
        """Read the working database directly (what really happened, not what a tool said)."""
        with closing(sqlite3.connect(self.db)) as con:
            return con.execute(sql, params).fetchall()
