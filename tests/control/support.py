"""Shared helpers for the MCP tool control tests (no tests in this file).

ToolTestCase gives each test a fresh copy of the fixture database, a server built on it
with `tool_authz` on or off (set the class attribute), and `call()` to invoke a tool
through an in-process MCP client with a signed principal in `_meta`. Needs
data/fixtures.db (python scripts/seed_db.py).
"""
import copy
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
PROMPT_CANARY = "CANARY-9d2c5-DO-NOT-LEAK"   # in config/system_prompt.txt
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


def say(text):
    """A scripted model message: a plain reply."""
    return {"role": "assistant", "content": text}


def tool_call(name, **arguments):
    """A scripted model message: a request to call one tool."""
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": arguments}}]}


class ScriptedModel:
    """Plays the language model: returns the scripted messages in order (the last repeats if asked).

    A scripted item that is an Exception is raised instead. Every call it receives is kept in
    `calls` (a copy of the messages and the tool list) so tests can check what the model saw.
    """

    def __init__(self, *script, repeat_last=False):
        self.script, self.repeat_last, self.calls = list(script), repeat_last, []

    async def chat(self, messages, tools):
        self.calls.append({"messages": copy.deepcopy(messages), "tools": tools})
        item = self.script[0] if (self.repeat_last and len(self.script) == 1) else self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
