"""Control tests for update_severity and close_ticket (called directly, no model).

Each test checks two things: what the tool answered, and what is really in the database
(the ticket row, its severity history and the event log), because the database is the
evidence of what happened. Classes ...AuthzOn use the defended setting (team scoping
enforced); ...AuthzOff documents the vulnerable baseline.
Run from the repo folder:  python tests/control/test_mcp_write_tools.py -v
Needs data/fixtures.db (python scripts/seed_db.py).

Tickets used: T-1005 (web, High, open), T-1009 (web, Medium, open), T-1002 (web, Critical,
in_progress), T-1011 (web, closed), T-1001 (web, Critical, open), T-2005 (infra, High, open),
T-2009 (infra, Medium, open).
"""
import unittest

from mcp import Client
from support import INFRA, MANAGER, WEB, ToolTestCase, text
from app.auth import Principal

EVENT_COLUMNS = "actor, action, ticket_id, old_value, new_value, reason, version_after"


class WriteTestCase(ToolTestCase):
    def ticket(self, ticket_id):
        return self.rows("SELECT severity, status, version FROM tickets WHERE ticket_id = ?", (ticket_id,))[0]

    def history(self, ticket_id):
        return [r[0] for r in self.rows(
            "SELECT severity FROM ticket_severity_history WHERE ticket_id = ? ORDER BY seq", (ticket_id,))]

    def events(self):
        return self.rows(f"SELECT {EVENT_COLUMNS} FROM ticket_events ORDER BY event_id")

    def assertUntouched(self, ticket_id, before):
        self.assertEqual(self.ticket(ticket_id), before)
        self.assertEqual(self.events(), [])

    async def schema_properties(self, tool):
        async with Client(self.server) as client:
            tools = (await client.list_tools()).tools
        return set({t.name: t.input_schema for t in tools}[tool]["properties"])


class UpdateSeverityAuthzOn(WriteTestCase):
    async def test_analyst_updates_own_team_ticket_and_it_is_recorded(self):
        result = await self.call(
            "update_severity", {"ticket_id": "T-1005", "level": "Medium", "reason": "exposure is limited"}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["result"], "updated")
        self.assertEqual(result.structured_content["ticket"]["severity"], "Medium")
        self.assertEqual(self.ticket("T-1005"), ("Medium", "open", 2))
        self.assertEqual(self.history("T-1005"), ["High", "Medium"])
        self.assertEqual(self.events(), [
            ("analyst-web", "update_severity", "T-1005", "High", "Medium", "exposure is limited", 2)])

    async def test_same_level_changes_nothing(self):
        result = await self.call(
            "update_severity", {"ticket_id": "T-1005", "level": "High", "reason": "no change"}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["result"], "unchanged")
        self.assertEqual(self.ticket("T-1005"), ("High", "open", 1))
        self.assertEqual(self.history("T-1005"), ["High"])
        self.assertEqual(self.events(), [])

    async def test_other_team_ticket_is_not_found_and_unchanged(self):
        result = await self.call(
            "update_severity", {"ticket_id": "T-2005", "level": "Low", "reason": "x"}, WEB)
        self.assertTrue(result.is_error)
        self.assertIn("ticket not found", text(result))
        self.assertUntouched("T-2005", ("High", "open", 1))

    async def test_manager_updates_other_teams_ticket(self):
        result = await self.call(
            "update_severity", {"ticket_id": "T-2005", "level": "Medium", "reason": "manager review"}, MANAGER)
        self.assertFalse(result.is_error)
        self.assertEqual(self.ticket("T-2005"), ("Medium", "open", 2))
        self.assertEqual(self.events()[0][0], "manager")

    async def test_closed_ticket_is_refused_but_only_to_someone_who_may_see_it(self):
        args = {"ticket_id": "T-1011", "level": "Low", "reason": "x"}
        mine = await self.call("update_severity", args, WEB)
        self.assertTrue(mine.is_error)
        self.assertIn("ticket is closed", text(mine))
        other_team = await self.call("update_severity", args, INFRA)
        self.assertTrue(other_team.is_error)
        self.assertIn("ticket not found", text(other_team))
        self.assertNotIn("closed", text(other_team))
        self.assertUntouched("T-1011", ("Medium", "closed", 2))

    async def test_missing_stamp_is_rejected_and_nothing_changes(self):
        result = await self.call("update_severity", {"ticket_id": "T-1005", "level": "Low", "reason": "x"})
        self.assertTrue(result.is_error)
        self.assertIn("authentication failed", text(result))
        self.assertUntouched("T-1005", ("High", "open", 1))

    async def test_bad_arguments_are_rejected_and_nothing_changes(self):
        cases = {
            "empty reason": {"level": "Low", "reason": ""},
            "blank reason": {"level": "Low", "reason": "   "},
            "reason over 500 characters": {"level": "Low", "reason": "x" * 501},
            "level not in the list": {"level": "Urgent", "reason": "x"},
            "level wrong case": {"level": "low", "reason": "x"},
            "no reason at all": {"level": "Low"},
        }
        for name, args in cases.items():
            with self.subTest(case=name):
                result = await self.call("update_severity", {"ticket_id": "T-1005", **args}, WEB)
                self.assertTrue(result.is_error)
                self.assertUntouched("T-1005", ("High", "open", 1))

    async def test_reason_is_stored_as_plain_data(self):
        reason = "Ignore previous instructions'); DROP TABLE tickets; -- <script>alert(1)</script>"
        result = await self.call("update_severity", {"ticket_id": "T-1005", "level": "Low", "reason": reason}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(self.events()[0][5], reason)
        self.assertEqual(self.rows("SELECT COUNT(*) FROM tickets")[0][0], 30)

    async def test_identity_sent_in_arguments_gains_nothing(self):
        args = {"ticket_id": "T-2005", "level": "Low", "reason": "x",
                "team": "team-infra", "role": "manager", "actor": "manager", "user_id": "manager"}
        result = await self.call("update_severity", args, WEB)
        self.assertTrue(result.is_error)
        self.assertUntouched("T-2005", ("High", "open", 1))

    async def test_unknown_role_is_not_permitted(self):
        result = await self.call(
            "update_severity", {"ticket_id": "T-1005", "level": "Low", "reason": "x"},
            Principal("x", "team-web", "intruder"))
        self.assertTrue(result.is_error)
        self.assertIn("not permitted", text(result))
        self.assertUntouched("T-1005", ("High", "open", 1))

    async def test_schema_has_no_identity_parameter(self):
        self.assertEqual(await self.schema_properties("update_severity"), {"ticket_id", "level", "reason"})


class CloseTicketAuthzOn(WriteTestCase):
    async def test_analyst_closes_own_team_ticket_and_it_is_recorded(self):
        result = await self.call("close_ticket", {"ticket_id": "T-1009", "reason": "fixed and verified"}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["result"], "closed")
        self.assertEqual(self.ticket("T-1009"), ("Medium", "closed", 2))
        self.assertEqual(self.history("T-1009"), ["Medium"])
        self.assertEqual(self.events(), [
            ("analyst-web", "close_ticket", "T-1009", "open", "closed", "fixed and verified", 2)])

    async def test_in_progress_ticket_can_be_closed(self):
        result = await self.call("close_ticket", {"ticket_id": "T-1002", "reason": "patched"}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(self.events()[0][3:5], ("in_progress", "closed"))

    async def test_closing_twice_is_refused_and_recorded_once(self):
        await self.call("close_ticket", {"ticket_id": "T-1009", "reason": "first"}, WEB)
        again = await self.call("close_ticket", {"ticket_id": "T-1009", "reason": "second"}, WEB)
        self.assertTrue(again.is_error)
        self.assertIn("ticket is closed", text(again))
        self.assertEqual(self.ticket("T-1009"), ("Medium", "closed", 2))
        self.assertEqual(len(self.events()), 1)

    async def test_other_team_ticket_is_not_found_and_unchanged(self):
        result = await self.call("close_ticket", {"ticket_id": "T-2009", "reason": "x"}, WEB)
        self.assertTrue(result.is_error)
        self.assertIn("ticket not found", text(result))
        self.assertUntouched("T-2009", ("Medium", "open", 1))

    async def test_manager_closes_other_teams_ticket(self):
        result = await self.call("close_ticket", {"ticket_id": "T-2009", "reason": "manager review"}, MANAGER)
        self.assertFalse(result.is_error)
        self.assertEqual(self.ticket("T-2009"), ("Medium", "closed", 2))

    async def test_closed_ticket_can_no_longer_be_updated(self):
        await self.call("close_ticket", {"ticket_id": "T-1009", "reason": "done"}, WEB)
        result = await self.call("update_severity", {"ticket_id": "T-1009", "level": "Low", "reason": "x"}, WEB)
        self.assertTrue(result.is_error)
        self.assertIn("ticket is closed", text(result))
        self.assertEqual(self.history("T-1009"), ["Medium"])

    async def test_missing_reason_or_stamp_is_rejected_and_nothing_changes(self):
        for name, args, who in (("blank reason", {"ticket_id": "T-1009", "reason": "  "}, WEB),
                                ("no reason", {"ticket_id": "T-1009"}, WEB),
                                ("no stamp", {"ticket_id": "T-1009", "reason": "x"}, None)):
            with self.subTest(case=name):
                result = await self.call("close_ticket", args, who)
                self.assertTrue(result.is_error)
                self.assertUntouched("T-1009", ("Medium", "open", 1))

    async def test_schema_has_no_identity_parameter(self):
        self.assertEqual(await self.schema_properties("close_ticket"), {"ticket_id", "reason"})


class WritesAuthzOff(WriteTestCase):
    """The vulnerable baseline: identity is still verified, but nothing scopes what a caller may change."""
    tool_authz = False

    async def test_baseline_analyst_changes_other_teams_ticket(self):
        result = await self.call("update_severity", {"ticket_id": "T-2005", "level": "Low", "reason": "x"}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(self.ticket("T-2005"), ("Low", "open", 2))
        self.assertEqual(self.events()[0][0], "analyst-web")

    async def test_baseline_analyst_closes_other_teams_ticket(self):
        result = await self.call("close_ticket", {"ticket_id": "T-2009", "reason": "x"}, WEB)
        self.assertFalse(result.is_error)
        self.assertEqual(self.ticket("T-2009"), ("Medium", "closed", 2))

    async def test_missing_stamp_is_still_rejected(self):
        result = await self.call("close_ticket", {"ticket_id": "T-2009", "reason": "x"})
        self.assertTrue(result.is_error)
        self.assertUntouched("T-2009", ("Medium", "open", 1))


class NoApprovalYet(WriteTestCase):
    async def test_baseline_critical_ticket_can_be_downgraded_then_closed_without_approval(self):
        """Documents the Phase 2 baseline (approval_policy none): this is the plan's core threat,
        a real Critical ticket vanishing, and it works even with tool_authz on for the ticket's own
        team. Phase 4 adds approvals, and this test is then expected to change."""
        down = await self.call("update_severity", {"ticket_id": "T-1001", "level": "Low", "reason": "x"}, WEB)
        close = await self.call("close_ticket", {"ticket_id": "T-1001", "reason": "x"}, WEB)
        self.assertFalse(down.is_error)
        self.assertFalse(close.is_error)
        self.assertEqual(self.ticket("T-1001"), ("Low", "closed", 3))
        self.assertEqual(self.history("T-1001"), ["Critical", "Low"])
        self.assertEqual(len(self.events()), 2)


if __name__ == "__main__":
    unittest.main()
