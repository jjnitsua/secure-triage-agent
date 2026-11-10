"""The fixture database refuses to rewrite or delete history and the event log.

Run from the repo folder:  python tests/control/test_db_integrity.py -v
Needs data/fixtures.db (python scripts/seed_db.py).
"""
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "data" / "fixtures.db"

NEW_EVENT = ("INSERT INTO ticket_events (ts, actor, action, ticket_id, old_value, new_value, reason, version_after) "
             "VALUES ('2099-01-01T00:00:00Z', 'tester', 'update_severity', 'T-1001', 'Critical', 'High', 'test', 2)")


class AppendOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURES.exists():
            raise FileNotFoundError(f"{FIXTURES} not found; run: python scripts/seed_db.py")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "working.db"
        shutil.copyfile(FIXTURES, db)
        self.con = sqlite3.connect(db)
        self.addCleanup(self.con.close)

    def test_event_log_starts_empty_and_accepts_inserts(self):
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM ticket_events").fetchone()[0], 0)
        self.con.execute(NEW_EVENT)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM ticket_events").fetchone()[0], 1)

    def test_events_cannot_be_updated_or_deleted(self):
        self.con.execute(NEW_EVENT)
        for sql in ("UPDATE ticket_events SET actor = 'someone-else'", "DELETE FROM ticket_events"):
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                self.con.execute(sql)

    def test_severity_history_cannot_be_updated_or_deleted(self):
        for sql in ("UPDATE ticket_severity_history SET severity = 'Low' WHERE ticket_id = 'T-1013'",
                    "DELETE FROM ticket_severity_history WHERE ticket_id = 'T-1013'"):
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                self.con.execute(sql)

    def test_severity_history_still_accepts_a_new_row(self):
        self.con.execute("INSERT INTO ticket_severity_history VALUES ('T-1001', 2, 'High')")
        rows = self.con.execute(
            "SELECT severity FROM ticket_severity_history WHERE ticket_id = 'T-1001' ORDER BY seq").fetchall()
        self.assertEqual([r[0] for r in rows], ["Critical", "High"])


if __name__ == "__main__":
    unittest.main()
