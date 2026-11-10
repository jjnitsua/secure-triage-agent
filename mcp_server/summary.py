"""Builds the manager summary text for draft_summary (Phase 2). Pure functions, no database.

The tool, not the model, writes this text, from ticket rows the caller may see. Only the
summary fields (ID, severity, status, title, asset, team) are used; descriptions never
appear. Titles and assets are untrusted ticket text, so every free-text field is forced
onto one line, stripped of control characters and truncated: a title cannot add lines to
the summary or fake another ticket's entry.
"""
from collections import Counter

SEVERITIES = ("Critical", "High", "Medium", "Low")
STATUSES = ("open", "in_progress", "closed")
MAX_TITLE = 120
MAX_ASSET = 60


def one_line(text: object, limit: int) -> str:
    """Collapse all whitespace (newlines, tabs) to single spaces, drop non-printable characters, truncate."""
    cleaned = "".join(ch for ch in " ".join(str(text).split()) if ch.isprintable())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3].rstrip() + "..."


def build_summary(rows: list[dict]) -> str:
    severities = Counter(r["severity"] for r in rows)
    statuses = Counter(r["status"] for r in rows)
    lines = [
        f"Triage summary: {len(rows)} ticket{'s' if len(rows) != 1 else ''}",
        "Severity: " + ", ".join(f"{s} {severities[s]}" for s in SEVERITIES),
        "Status: " + ", ".join(f"{s} {statuses[s]}" for s in STATUSES),
        "",
    ]
    for r in rows:
        lines.append(
            f"- {one_line(r['ticket_id'], 20)} [{one_line(r['severity'], 10)}, {one_line(r['status'], 12)}] "
            f"{one_line(r['title'], MAX_TITLE)} (asset {one_line(r['asset'], MAX_ASSET)}, "
            f"{one_line(r['team'], 20)})")
    return "\n".join(lines)
