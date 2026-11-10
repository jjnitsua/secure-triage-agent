"""Database access for the MCP tool server (Phase 2).

Only reads exist so far. Reads open the database in read-only mode, so a read tool
cannot change data even by mistake. Every query is parameterized: values such as a
ticket ID chosen by the model are never pasted into SQL text. Standard library only.
"""
import os
import sqlite3
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def default_db_path() -> Path:
    """The working database (reset before every run), or TRIAGE_DB if set."""
    return Path(os.environ.get("TRIAGE_DB") or ROOT / "data" / "working.db")


def connect_readonly(db_path) -> sqlite3.Connection:
    con = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def get_ticket(db_path, ticket_id: str) -> dict | None:
    """Return the ticket as a dict, or None if there is no such ticket."""
    with closing(connect_readonly(db_path)) as con:
        row = con.execute(
            "SELECT ticket_id, title, asset, team, description, severity, status, version "
            "FROM tickets WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
        if row is None:
            return None
        history = [r[0] for r in con.execute(
            "SELECT severity FROM ticket_severity_history WHERE ticket_id = ? ORDER BY seq",
            (ticket_id,))]
        cve_ids = [r[0] for r in con.execute(
            "SELECT cve_id FROM ticket_cves WHERE ticket_id = ? ORDER BY cve_id",
            (ticket_id,))]
    return {**dict(row), "severity_history": history, "cve_ids": cve_ids}
