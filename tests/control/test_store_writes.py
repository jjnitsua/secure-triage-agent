"""Concurrency and rollback tests for the store's write functions (no MCP, no model).

Real threads, each with its own database connection, hit the same ticket at once. The
checks are invariants that hold whatever order the writes happen in: the version, the
severity history and the event log must always agree, and a closed ticket must never be
changed afterwards. Needs data/fixtures.db (python scripts/seed_db.py).

Run from the repo folder:  python tests/control/test_store_writes.py -v
"""
import shutil
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mcp_server import store  # noqa: E402

FIXTURES = ROOT / "data" / "fixtures.db"
LEVELS = ("Critical", "High", "Medium", "Low")


class StoreWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURES.exists():
            raise FileNotFoundError(f"{FIXTURES} not found; run: python scripts/seed_db.py")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.db = self.tmp / "working.db"
        shutil.copyfile(FIXTURES, self.db)

    def rows(self, sql, params=()):
        with closing(sqlite3.connect(self.db)) as con:
            return con.execute(sql, params).fetchall()

    def test_parallel_severity_updates_stay_consistent(self):
        # T-1001 starts Critical, version 1, one history row. 24 writes from 8 threads.
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(store.update_severity, self.db, "T-1001", LEVELS[i % 4], f"r{i}", f"user{i}")
                       for i in range(24)]
            outcomes = [f.result() for f in futures]  # any exception fails the test here
        changes = sum(1 for changed, _ in outcomes if changed)
        self.assertGreater(changes, 0)

        severity, version = self.rows("SELECT severity, version FROM tickets WHERE ticket_id = 'T-1001'")[0]
        history = self.rows("SELECT seq, severity FROM ticket_severity_history WHERE ticket_id = 'T-1001' ORDER BY seq")
        events = self.rows("SELECT old_value, new_value, version_after FROM ticket_events ORDER BY event_id")

        self.assertEqual(version, 1 + changes)
        self.assertEqual([s for s, _ in history], list(range(1, changes + 2)))
        self.assertEqual(len(events), changes)
        self.assertEqual(history[-1][1], severity)
        # The events form one unbroken chain, which is only possible if the writes ran one at a time.
        self.assertEqual(events[0][0], "Critical")
        for previous, current in zip(events, events[1:]):
            self.assertEqual(current[0], previous[1])
        self.assertEqual([e[2] for e in events], list(range(2, changes + 2)))

    def test_parallel_close_and_updates_never_change_a_closed_ticket(self):
        def close(i):
            try:
                store.close_ticket(self.db, "T-1005", f"close{i}", f"closer{i}")
                return "closed"
            except store.TicketClosed:
                return "refused"

        def update(i):
            try:
                store.update_severity(self.db, "T-1005", LEVELS[i % 4], f"u{i}", f"updater{i}")
                return "updated"
            except store.TicketClosed:
                return "refused"

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(close, i) for i in range(4)] + [pool.submit(update, i) for i in range(8)]
            results = [f.result() for f in futures]

        self.assertEqual(results[:4].count("closed"), 1)  # exactly one close wins
        events = self.rows("SELECT action, version_after FROM ticket_events ORDER BY event_id")
        close_at = [i for i, (action, _) in enumerate(events) if action == "close_ticket"]
        self.assertEqual(len(close_at), 1)
        self.assertEqual(close_at[0], len(events) - 1)  # nothing was recorded after the close
        status, version = self.rows("SELECT status, version FROM tickets WHERE ticket_id = 'T-1005'")[0]
        self.assertEqual(status, "closed")
        self.assertEqual(version, 1 + len(events))

    def test_a_failure_part_way_rolls_everything_back(self):
        with closing(sqlite3.connect(self.db)) as con:
            con.execute("DROP TABLE ticket_events")  # the last step of a write will now fail
        with self.assertRaises(sqlite3.OperationalError):
            store.update_severity(self.db, "T-1005", "Low", "x", "someone")
        self.assertEqual(self.rows("SELECT severity, version FROM tickets WHERE ticket_id = 'T-1005'"), [("High", 1)])
        self.assertEqual(self.rows("SELECT severity FROM ticket_severity_history WHERE ticket_id = 'T-1005'"),
                         [("High",)])

    def test_a_wrong_database_path_is_an_error_not_a_new_empty_database(self):
        missing = self.tmp / "missing.db"
        with self.assertRaises(sqlite3.OperationalError):
            store.update_severity(missing, "T-1005", "Low", "x", "someone")
        self.assertFalse(missing.exists())

    def test_team_scope_is_enforced_inside_the_transaction(self):
        with self.assertRaises(store.TicketForbidden):
            store.close_ticket(self.db, "T-2009", "x", "analyst-web", team_scope="team-web")
        with self.assertRaises(store.TicketNotFound):
            store.close_ticket(self.db, "T-9999", "x", "analyst-web", team_scope="team-web")
        self.assertEqual(self.rows("SELECT COUNT(*) FROM ticket_events"), [(0,)])


if __name__ == "__main__":
    unittest.main()
