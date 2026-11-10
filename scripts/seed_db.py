#!/usr/bin/env python3
"""Build the pristine fixture database from the synthetic JSON files (Phase 2).

Reads data/tickets.json, data/cves.json and data/users.json (all synthetic) and writes
data/fixtures.db, a SQLite database. The app never edits this file: scripts/reset_db.py
copies it to a working database before every run, so state never leaks between runs.

Users and tokens are not stored in the database; the app reads data/users.json for
authentication. The database holds tickets, each ticket's severity history, CVE records
and the ticket-to-CVE links.
(The approvals table is added when the approval flow is built.)

Rerunning replaces data/fixtures.db. Standard library only.

Usage:
  python scripts/seed_db.py [--out data/fixtures.db]
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

SEVERITIES = ("Critical", "High", "Medium", "Low")
STATUSES = ("open", "in_progress", "closed")

SCHEMA = """
CREATE TABLE cves (
    cve_id      TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    cvss        REAL NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low')),
    affected    TEXT NOT NULL,
    published   TEXT NOT NULL
);

CREATE TABLE tickets (
    ticket_id        TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    asset            TEXT NOT NULL,
    team             TEXT NOT NULL,
    description      TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low')),
    status           TEXT NOT NULL CHECK (status IN ('open','in_progress','closed')),
    version          INTEGER NOT NULL CHECK (version >= 1)
);

-- Append-only: one row per severity the ticket has had (seq 1 = oldest, last = current).
-- Lets "was this ticket ever Critical?" be a single SQL check.
CREATE TABLE ticket_severity_history (
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id),
    seq       INTEGER NOT NULL CHECK (seq >= 1),
    severity  TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low')),
    PRIMARY KEY (ticket_id, seq)
);

CREATE TABLE ticket_cves (
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id),
    cve_id    TEXT NOT NULL REFERENCES cves(cve_id),
    PRIMARY KEY (ticket_id, cve_id)
);
"""


def load(name):
    with open(DATA / name, encoding="utf-8") as f:
        return json.load(f)


def validate(tickets, cves, users):
    """Return a list of problems found in the JSON data (empty list = fine)."""
    problems = []
    cve_ids = {c["cve_id"] for c in cves}
    teams = {u["team"] for u in users if u["team"]}
    seen = set()
    for t in tickets:
        tid = t["ticket_id"]
        if tid in seen:
            problems.append(f"{tid}: duplicate ticket_id")
        seen.add(tid)
        if t["severity"] not in SEVERITIES:
            problems.append(f"{tid}: bad severity {t['severity']!r}")
        if t["status"] not in STATUSES:
            problems.append(f"{tid}: bad status {t['status']!r}")
        if t["team"] not in teams:
            problems.append(f"{tid}: team {t['team']!r} has no user")
        if not t["severity_history"] or t["severity_history"][-1] != t["severity"]:
            problems.append(f"{tid}: severity_history does not end with current severity")
        for cid in t["cve_ids"]:
            if cid not in cve_ids:
                problems.append(f"{tid}: unknown CVE {cid}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(DATA / "fixtures.db"), help="database file to create")
    args = ap.parse_args()

    tickets = load("tickets.json")["tickets"]
    cves = load("cves.json")["cves"]
    users = load("users.json")["users"]

    problems = validate(tickets, cves, users)
    if problems:
        print("Data problems, database not built:")
        for p in problems:
            print("  -", p)
        sys.exit(1)

    out = Path(args.out)
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(str(out) + suffix).unlink(missing_ok=True)

    con = sqlite3.connect(out)
    con.execute("PRAGMA foreign_keys = ON")
    with con:  # one transaction: all rows or none
        con.executescript(SCHEMA)
        con.executemany(
            "INSERT INTO cves VALUES (?,?,?,?,?,?,?)",
            [(c["cve_id"], c["title"], c["description"], c["cvss"], c["severity"],
              c["affected"], c["published"]) for c in cves],
        )
        con.executemany(
            "INSERT INTO tickets VALUES (?,?,?,?,?,?,?,?)",
            [(t["ticket_id"], t["title"], t["asset"], t["team"], t["description"],
              t["severity"], t["status"], t["version"])
             for t in tickets],
        )
        con.executemany(
            "INSERT INTO ticket_severity_history VALUES (?,?,?)",
            [(t["ticket_id"], seq, sev)
             for t in tickets for seq, sev in enumerate(t["severity_history"], start=1)],
        )
        con.executemany(
            "INSERT INTO ticket_cves VALUES (?,?)",
            [(t["ticket_id"], cid) for t in tickets for cid in t["cve_ids"]],
        )
    n = {tbl: con.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
         for tbl in ("tickets", "cves", "ticket_cves", "ticket_severity_history")}
    con.close()
    print(f"Wrote {out}: {n['tickets']} tickets, {n['cves']} CVEs, {n['ticket_cves']} links, "
          f"{n['ticket_severity_history']} history rows")


if __name__ == "__main__":
    main()
