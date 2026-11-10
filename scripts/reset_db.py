#!/usr/bin/env python3
"""Reset the working database to the pristine fixtures (Phase 2).

Copies data/fixtures.db (built by scripts/seed_db.py) over data/working.db, the database
the app and the tests read and write. Run this before every test run so state from an
earlier run (closed tickets, changed severities) never leaks into the next one.

The copy goes to a temporary file first and is then swapped in, so a half-finished copy
never replaces a good working database. Leftover SQLite side files (-wal, -shm, -journal)
of the old working database are removed. Do not reset while the app is running against
the working database. Standard library only.

Usage:
  python scripts/reset_db.py [--src data/fixtures.db] [--dest data/working.db]
"""
import argparse
import os
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def reset(src: Path, dest: Path) -> dict:
    """Replace dest with a copy of src; return row counts of the new dest."""
    if not src.exists():
        raise FileNotFoundError(f"{src} not found; run scripts/seed_db.py first")
    tmp = dest.with_name(dest.name + ".tmp")
    shutil.copyfile(src, tmp)
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(dest) + suffix).unlink(missing_ok=True)
    os.replace(tmp, dest)  # atomic swap on the same filesystem

    con = sqlite3.connect(dest)
    try:
        return {tbl: con.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
                for tbl in ("tickets", "cves", "ticket_cves", "ticket_severity_history")}
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src", default=str(DATA / "fixtures.db"), help="pristine database")
    ap.add_argument("--dest", default=str(DATA / "working.db"), help="working database to replace")
    args = ap.parse_args()
    try:
        n = reset(Path(args.src), Path(args.dest))
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    print(f"Reset {args.dest} from {args.src}: "
          f"{n['tickets']} tickets, {n['cves']} CVEs, {n['ticket_cves']} links, "
          f"{n['ticket_severity_history']} history rows")


if __name__ == "__main__":
    main()
