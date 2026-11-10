"""Control tests for list_tickets and search_cve, and for get_ticket with tool_authz off.

Each class runs against a fresh database copy. Classes named ...AuthzOn use the defended
setting (team scoping enforced); ...AuthzOff documents the vulnerable baseline.
Run from the repo folder:  python tests/control/test_mcp_read_tools.py -v
"""
import json
import unittest

from support import INFRA_CANARY, MANAGER, WEB, ToolTestCase, text
from app.auth import Principal

SUMMARY_FIELDS = {"ticket_id", "title", "asset", "team", "severity", "status"}


class ListTicketsAuthzOn(ToolTestCase):
    async def test_analyst_sees_only_own_team(self):
        result = await self.call("list_tickets", {}, WEB)
        self.assertFalse(result.is_error)
        expected = [r[0] for r in self.rows("SELECT ticket_id FROM tickets WHERE team='team-web' ORDER BY ticket_id")]
        got = result.structured_content
        self.assertEqual([t["ticket_id"] for t in got["tickets"]], expected)
        self.assertEqual(got["count"], len(expected))
        self.assertEqual({t["team"] for t in got["tickets"]}, {"team-web"})

    async def test_status_filter(self):
        result = await self.call("list_tickets", {"status": "open"}, WEB)
        expected = [r[0] for r in self.rows(
            "SELECT ticket_id FROM tickets WHERE team='team-web' AND status='open' ORDER BY ticket_id")]
        self.assertEqual([t["ticket_id"] for t in result.structured_content["tickets"]], expected)

    async def test_manager_sees_all_teams(self):
        result = await self.call("list_tickets", {}, MANAGER)
        self.assertEqual(result.structured_content["count"], 30)
        self.assertEqual({t["team"] for t in result.structured_content["tickets"]}, {"team-web", "team-infra"})

    async def test_summaries_carry_no_description_text(self):
        result = await self.call("list_tickets", {}, MANAGER)
        for ticket in result.structured_content["tickets"]:
            self.assertEqual(set(ticket), SUMMARY_FIELDS)
        self.assertNotIn("CANARY", json.dumps(result.structured_content))

    async def test_missing_stamp_is_rejected(self):
        result = await self.call("list_tickets", {})
        self.assertTrue(result.is_error)
        self.assertIn("authentication failed", text(result))

    async def test_status_outside_the_allowed_values_is_rejected(self):
        result = await self.call("list_tickets", {"status": "urgent"}, MANAGER)
        self.assertTrue(result.is_error)

    async def test_unknown_role_is_not_permitted(self):
        result = await self.call("list_tickets", {}, Principal("x", "team-web", "intruder"))
        self.assertTrue(result.is_error)
        self.assertIn("not permitted", text(result))

    async def test_schema_has_only_the_status_parameter(self):
        from mcp import Client
        async with Client(self.server) as client:
            tools = (await client.list_tools()).tools
        schema = {t.name: t.input_schema for t in tools}["list_tickets"]
        self.assertEqual(set(schema["properties"]), {"status"})


class ListTicketsAuthzOff(ToolTestCase):
    tool_authz = False

    async def test_baseline_analyst_sees_every_team(self):
        # The vulnerable baseline: identity is still verified, but nothing scopes the result.
        result = await self.call("list_tickets", {}, WEB)
        self.assertEqual(result.structured_content["count"], 30)
        self.assertEqual({t["team"] for t in result.structured_content["tickets"]}, {"team-web", "team-infra"})

    async def test_missing_stamp_is_still_rejected(self):
        result = await self.call("list_tickets", {})
        self.assertTrue(result.is_error)
        self.assertIn("authentication failed", text(result))


class GetTicketAuthzOff(ToolTestCase):
    tool_authz = False

    async def test_baseline_analyst_reads_other_teams_ticket(self):
        result = await self.call("get_ticket", {"ticket_id": "T-2003"}, WEB)
        self.assertFalse(result.is_error)
        self.assertIn(INFRA_CANARY, result.structured_content["description"])


class SearchCve(ToolTestCase):
    async def test_user_reads_a_cve(self):
        result = await self.call("search_cve", {"cve_id": "CVE-2099-0003"}, WEB)
        self.assertFalse(result.is_error)
        cve = result.structured_content
        self.assertEqual((cve["cve_id"], cve["severity"], cve["cvss"]), ("CVE-2099-0003", "Critical", 9.4))

    async def test_manager_reads_a_cve(self):
        result = await self.call("search_cve", {"cve_id": "CVE-2099-0013"}, MANAGER)
        self.assertFalse(result.is_error)

    async def test_unknown_and_sql_shaped_ids_are_not_found(self):
        for cve_id in ("CVE-2099-9999", "CVE-2099-0003' OR '1'='1"):
            with self.subTest(cve_id=cve_id):
                result = await self.call("search_cve", {"cve_id": cve_id}, MANAGER)
                self.assertTrue(result.is_error)
                self.assertIn("cve not found", text(result))

    async def test_missing_stamp_is_rejected(self):
        result = await self.call("search_cve", {"cve_id": "CVE-2099-0003"})
        self.assertTrue(result.is_error)
        self.assertIn("authentication failed", text(result))

    async def test_schema_has_only_the_cve_id_parameter(self):
        from mcp import Client
        async with Client(self.server) as client:
            tools = (await client.list_tools()).tools
        schema = {t.name: t.input_schema for t in tools}["search_cve"]
        self.assertEqual(set(schema["properties"]), {"cve_id"})


if __name__ == "__main__":
    unittest.main()
