"""Real-HTTP checks for the MCP tool server. No model; local only (127.0.0.1).

test_mcp_get_ticket.py calls the server in-process. This file starts the real server as a
subprocess on a free port, on a throwaway database copy, and talks to it over HTTP to
show that (1) the signed principal in `_meta` survives the real transport, and (2) the
SDK's Host/Origin/Content-Type checks reject browser-style requests. The server is
stopped at the end. Needs data/fixtures.db (python scripts/seed_db.py).

Run from the repo folder:  python tests/control/test_mcp_http.py -v
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
from mcp import Client  # noqa: E402

from app import auth  # noqa: E402
from app.auth import META_KEY, Principal, sign_principal  # noqa: E402

KEY = "test-only-signing-key-not-a-secret"
WEB = Principal("analyst-web", "team-web", "analyst")
MANAGER = Principal("manager", None, "manager")
WEB_TICKET = "T-1003"
INFRA_TICKET = "T-2003"
INFRA_CANARY = "CANARY-4b1e6-DO-NOT-LEAK"

JSON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _text(result) -> str:
    return " ".join(getattr(block, "text", "") for block in result.content)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class McpHttpTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        fixtures = ROOT / "data" / "fixtures.db"
        if not fixtures.exists():
            raise FileNotFoundError(f"{fixtures} not found; run: python scripts/seed_db.py")
        cls._key_patch = mock.patch.dict("os.environ", {auth.KEY_ENV: KEY})
        cls._key_patch.start()
        cls._tmp = tempfile.TemporaryDirectory()
        db = Path(cls._tmp.name) / "working.db"
        shutil.copyfile(fixtures, db)
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = {**os.environ, "TRIAGE_DB": str(db), "TRIAGE_MCP_PORT": str(cls.port)}
        cls._log_path = Path(cls._tmp.name) / "server.log"
        cls._log = open(cls._log_path, "wb")
        cls._proc = subprocess.Popen([sys.executable, "-m", "mcp_server.server"], cwd=ROOT, env=env,
                                     stdout=cls._log, stderr=subprocess.STDOUT)
        deadline = time.time() + 20
        while time.time() < deadline:
            if cls._proc.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.2)
        cls.tearDownClass()
        raise RuntimeError("server did not start:\n" + cls._log_path.read_text(errors="replace")[-2000:]
                           if cls._log_path.exists() else "server did not start")

    @classmethod
    def tearDownClass(cls):
        proc = getattr(cls, "_proc", None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if getattr(cls, "_log", None):
            cls._log.close()
        cls._key_patch.stop()
        cls._tmp.cleanup()

    async def call(self, ticket_id, principal=None, package=None):
        if package is None and principal is not None:
            package = sign_principal(principal)
        meta = {META_KEY: package} if package is not None else None
        async with Client(f"{self.base}/mcp") as client:
            return await client.call_tool("get_ticket", {"ticket_id": ticket_id}, meta=meta)

    # --- the signed principal survives the real transport -------------------------------

    async def test_signed_principal_works_over_http(self):
        result = await self.call(WEB_TICKET, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["ticket_id"], WEB_TICKET)

    async def test_cross_team_read_is_not_found_over_http(self):
        result = await self.call(INFRA_TICKET, WEB)
        self.assertTrue(result.is_error)
        self.assertIn("ticket not found", _text(result))
        self.assertNotIn(INFRA_CANARY, _text(result))

    async def test_manager_reads_other_team_over_http(self):
        result = await self.call(INFRA_TICKET, MANAGER)
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["team"], "team-infra")

    async def test_missing_and_forged_principal_rejected_over_http(self):
        body, sig = sign_principal(WEB).split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["role"], payload["team"] = "manager", None
        edited = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")
        for name, package in (("no stamp", None), ("role edited", f"{edited}.{sig}"), ("garbage", "x")):
            with self.subTest(case=name):
                result = await self.call(INFRA_TICKET, package=package)
                self.assertTrue(result.is_error)
                self.assertIn("authentication failed", _text(result))
                self.assertNotIn(INFRA_CANARY, _text(result))

    # --- browser-style requests are refused by the SDK's transport checks ----------------

    def post(self, headers=None, **kwargs):
        return httpx.post(f"{self.base}/mcp", headers={**JSON_HEADERS, **(headers or {})},
                          json=LIST_TOOLS, timeout=10, **kwargs)

    def test_foreign_host_header_is_refused(self):
        self.assertEqual(self.post({"Host": "evil.example"}).status_code, 421)

    def test_foreign_origin_header_is_refused(self):
        self.assertEqual(self.post({"Origin": "http://evil.example"}).status_code, 403)

    def test_wrong_content_type_is_refused(self):
        response = httpx.post(f"{self.base}/mcp", content=json.dumps(LIST_TOOLS), timeout=10,
                              headers={"Content-Type": "text/plain", "Accept": JSON_HEADERS["Accept"]})
        self.assertEqual(response.status_code, 400)

    def test_local_origin_is_not_refused_so_the_signature_is_the_defense(self):
        # Documents the limit: a page served from another localhost port passes the Origin
        # check. Such a caller still cannot get ticket data without a valid signed principal.
        ok_host = self.post()
        local_origin = self.post({"Origin": "http://localhost:3000"})
        for response in (ok_host, local_origin):
            self.assertNotIn(response.status_code, (403, 421))


if __name__ == "__main__":
    unittest.main()
