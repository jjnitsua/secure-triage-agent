"""Database access for the MCP tool server (Phase 2).

Reads open the database read-only, so a read tool cannot change data even by mistake.
Writes (update_severity, close_ticket) each run in ONE transaction opened with
BEGIN IMMEDIATE, which takes the write lock first so two writers cannot interleave. Inside
it: look the ticket up, apply the team scope and the closed check, change the ticket and
bump its version (guarded by the version just read), append the severity-history row if
the severity changed, append the event-log row, then commit. Any failure rolls
everything back. Every query is parameterized: values such as a ticket ID or a reason
chosen by the model are never pasted into SQL text. Standard library only.
"""
import json
import os
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TICKET_COLUMNS = "ticket_id, title, asset, team, description, severity, status, version"


class TicketNotFound(Exception):
    """No such ticket."""


class TicketForbidden(TicketNotFound):
    """The ticket exists but is outside the caller's team scope (callers report it as not found)."""


class TicketClosed(Exception):
    """The ticket is closed and can no longer be changed."""


class TicketConflict(Exception):
    """The ticket's version changed under the write (should not happen inside BEGIN IMMEDIATE)."""


def default_db_path() -> Path:
    """The working database (reset before every run), or TRIAGE_DB if set."""
    return Path(os.environ.get("TRIAGE_DB") or ROOT / "data" / "working.db")


def connect_readonly(db_path) -> sqlite3.Connection:
    con = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def connect_readwrite(db_path) -> sqlite3.Connection:
    """Read-write, but never creates a missing file (a wrong path is an error, not an empty database).

    isolation_level=None so the transaction is controlled explicitly with BEGIN IMMEDIATE.
    """
    con = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=rw", uri=True,
                          timeout=5.0, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def _read_ticket(con: sqlite3.Connection, ticket_id: str) -> dict | None:
    row = con.execute(f"SELECT {TICKET_COLUMNS} FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if row is None:
        return None
    history = [r[0] for r in con.execute(
        "SELECT severity FROM ticket_severity_history WHERE ticket_id = ? ORDER BY seq", (ticket_id,))]
    cve_ids = [r[0] for r in con.execute(
        "SELECT cve_id FROM ticket_cves WHERE ticket_id = ? ORDER BY cve_id", (ticket_id,))]
    return {**dict(row), "severity_history": history, "cve_ids": cve_ids}


def get_ticket(db_path, ticket_id: str) -> dict | None:
    """Return the ticket as a dict, or None if there is no such ticket."""
    with closing(connect_readonly(db_path)) as con:
        return _read_ticket(con, ticket_id)


def list_tickets(db_path, status: str | None = None, team: str | None = None) -> list[dict]:
    """Ticket summaries (no description text), optionally filtered by status and team."""
    sql = "SELECT ticket_id, title, asset, team, severity, status FROM tickets"
    clauses, params = [], []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if team is not None:
        clauses.append("team = ?")
        params.append(team)
    if clauses:  # the clause text is fixed above; only the values come from callers
        sql += " WHERE " + " AND ".join(clauses)
    with closing(connect_readonly(db_path)) as con:
        return [dict(r) for r in con.execute(sql + " ORDER BY ticket_id", params)]


def get_cve(db_path, cve_id: str) -> dict | None:
    """Return the CVE record as a dict, or None if there is no such record."""
    with closing(connect_readonly(db_path)) as con:
        row = con.execute(
            "SELECT cve_id, title, description, cvss, severity, affected, published "
            "FROM cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
    return dict(row) if row else None


def _record_event(con, actor, action, ticket_id, old_value, new_value, reason, version_after, request_id) -> None:
    con.execute(
        "INSERT INTO ticket_events (ts, actor, action, ticket_id, old_value, new_value, reason, version_after, request_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         actor, action, ticket_id, old_value, new_value, reason, version_after, request_id),
    )


@contextmanager
def _transaction(db_path):
    """One write transaction: BEGIN IMMEDIATE, commit if the block finishes, roll back on any error."""
    with closing(connect_readwrite(db_path)) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            yield con
            con.execute("COMMIT")
        except BaseException:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise


def _write(db_path, ticket_id, team_scope, change):
    """Run `change(con, row)` in one transaction after the shared checks.

    Order matters: not found, then outside the team scope, then closed, so the closed
    state is only ever revealed to a caller who may see the ticket. Returns
    (changed, ticket) where ticket is read inside the same transaction.
    """
    with _transaction(db_path) as con:
        row = con.execute(
            "SELECT team, severity, status, version FROM tickets WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
        if row is None:
            raise TicketNotFound(ticket_id)
        if team_scope is not None and row["team"] != team_scope:
            raise TicketForbidden(ticket_id)
        if row["status"] == "closed":
            raise TicketClosed(ticket_id)
        changed = change(con, row)
        return changed, _read_ticket(con, ticket_id)


def update_severity(db_path, ticket_id, level, reason, actor, team_scope=None, request_id=None):
    """Set the ticket's severity. Returns (changed, ticket); changed is False if it already had that level.

    team_scope None means every team; a team name restricts the write to that team's tickets.
    """
    def change(con, row):
        if row["severity"] == level:
            return False
        cur = con.execute(
            "UPDATE tickets SET severity = ?, version = version + 1 WHERE ticket_id = ? AND version = ?",
            (level, ticket_id, row["version"]))
        if cur.rowcount != 1:
            raise TicketConflict(ticket_id)
        seq = con.execute(
            "SELECT MAX(seq) FROM ticket_severity_history WHERE ticket_id = ?", (ticket_id,)).fetchone()[0] + 1
        con.execute("INSERT INTO ticket_severity_history VALUES (?, ?, ?)", (ticket_id, seq, level))
        _record_event(con, actor, "update_severity", ticket_id, row["severity"], level, reason, row["version"] + 1, request_id)
        return True

    return _write(db_path, ticket_id, team_scope, change)


def close_ticket(db_path, ticket_id, reason, actor, team_scope=None, request_id=None):
    """Close the ticket. Returns (True, ticket). A ticket that is already closed raises TicketClosed."""
    def change(con, row):
        cur = con.execute(
            "UPDATE tickets SET status = 'closed', version = version + 1 WHERE ticket_id = ? AND version = ?",
            (ticket_id, row["version"]))
        if cur.rowcount != 1:
            raise TicketConflict(ticket_id)
        _record_event(con, actor, "close_ticket", ticket_id, row["status"], "closed", reason, row["version"] + 1, request_id)
        return True

    return _write(db_path, ticket_id, team_scope, change)


def draft_summary(db_path, ticket_ids, actor, team_scope=None, request_id=None) -> list[dict]:
    """Return the summary fields of every requested ticket and record a draft_summary event.

    All or nothing: if any ID does not exist (TicketNotFound) or is outside the team scope
    (TicketForbidden), nothing is returned and nothing is recorded. Closed tickets are
    included. The rows carry no description text.
    """
    with _transaction(db_path) as con:
        rows = []
        for ticket_id in ticket_ids:
            row = con.execute(
                "SELECT ticket_id, title, asset, team, severity, status FROM tickets WHERE ticket_id = ?",
                (ticket_id,)).fetchone()
            if row is None:
                raise TicketNotFound(ticket_id)
            if team_scope is not None and row["team"] != team_scope:
                raise TicketForbidden(ticket_id)
            rows.append(dict(row))
        _record_event(con, actor, "draft_summary", None, None, json.dumps(list(ticket_ids)), None, None, request_id)
        return rows
