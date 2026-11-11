"""MCP tool server (Phase 2). Tools: get_ticket, list_tickets, search_cve, update_severity,
close_ticket, draft_summary.

Identity: every tool call must carry a signed principal in the request's `_meta` (see
app/auth.py). The server verifies it on every call and takes the caller's team and role
only from the verified result. The tools have no user, team or role parameter, so the
model can neither see nor choose who is asking. Identity is checked in both security
settings.

Authorization (what a verified caller may see or do) is a separate switch,
`controls.tool_authz` in config/security.yaml. On: analysts reach only their own team's
tickets and the manager reaches all. Off: the vulnerable baseline, where any logged-in
user can reach everything and the model alone decides what is allowed.

There is no approval step yet (`approval_policy: none`): a verified, authorized caller's
severity change or close runs immediately. Approvals are Phase 4.

Failures reach the caller as generic tool errors ("authentication failed",
"ticket not found"). A ticket the caller may not reach gets the same "ticket not found"
as one that does not exist, so ticket IDs cannot be probed. The real reason is logged
here only. Tool error text reaches the model, so it must not carry useful detail. The
free-text `reason` of a write is model-supplied: it is stored as plain data in the event
log and never interpreted or logged here.

Run (from the repo folder, with TRIAGE_SIGNING_KEY set):
  python -m mcp_server.server        # Streamable HTTP on 127.0.0.1:8000
Port: TRIAGE_MCP_PORT (default 8000). The host is fixed to 127.0.0.1 on purpose: the SDK
turns on its Host/Origin checks (DNS rebinding protection) automatically only for
localhost hosts, so never bind another address without setting those checks explicitly.
"""
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.mcpserver import Context, MCPServer  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402
from pydantic import Field  # noqa: E402

from app.auth import META_KEY, AuthError, Principal, verify_principal  # noqa: E402
from app.config import load_config  # noqa: E402
from mcp_server import store  # noqa: E402
from mcp_server.summary import build_summary  # noqa: E402

log = logging.getLogger("triage.mcp_server")

Severity = Literal["Critical", "High", "Medium", "Low"]
Reason = Annotated[str, Field(min_length=1, max_length=500)]
TicketIds = Annotated[list[Annotated[str, Field(max_length=20)]], Field(min_length=1, max_length=20)]


def require_principal(ctx: Context) -> Principal:
    """Return the verified caller, or raise a generic ToolError."""
    meta = ctx.request_context.meta
    package = meta.get(META_KEY) if meta else None
    try:
        return verify_principal(package)
    except AuthError as exc:
        log.warning("auth rejected: %s", exc)
        raise ToolError("authentication failed") from None


def can_access_team(principal: Principal, team: str) -> bool:
    """Team scoping: analysts reach their own team's tickets, the manager all of them."""
    if principal.role == "manager":
        return True
    return principal.role == "analyst" and principal.team == team


def create_server(db_path=None, tool_authz: bool = True) -> MCPServer:
    path = db_path or store.default_db_path()
    server = MCPServer("secure-triage-tools")

    def may_access(principal: Principal, team: str) -> bool:
        return True if not tool_authz else can_access_team(principal, team)

    def team_scope(principal: Principal, tool: str) -> str | None:
        """None = every team; a team name = only that team's tickets; raises for roles that may not use the tool."""
        if not tool_authz or principal.role == "manager":
            return None
        if principal.role == "analyst" and principal.team:
            return principal.team
        log.warning("%s user=%s request=%s role=%r outcome=not_permitted", tool, principal.user_id, principal.request_id, principal.role)
        raise ToolError("not permitted")

    def run_write(tool: str, principal: Principal, ticket_id: str, call):
        """Run a store write and turn its failures into generic tool errors (real reason logged)."""
        try:
            return call()
        except store.TicketForbidden:
            log.warning("%s user=%s request=%s ticket=%s outcome=forbidden", tool, principal.user_id, principal.request_id, ticket_id)
            raise ToolError("ticket not found") from None
        except store.TicketNotFound:
            log.info("%s user=%s request=%s ticket=%r outcome=not_found", tool, principal.user_id, principal.request_id, ticket_id)
            raise ToolError("ticket not found") from None
        except store.TicketClosed:
            log.info("%s user=%s request=%s ticket=%s outcome=already_closed", tool, principal.user_id, principal.request_id, ticket_id)
            raise ToolError("ticket is closed") from None
        except store.TicketConflict:
            log.warning("%s user=%s request=%s ticket=%s outcome=conflict", tool, principal.user_id, principal.request_id, ticket_id)
            raise ToolError("ticket changed, try again") from None

    @server.tool()
    async def get_ticket(ticket_id: str, ctx: Context) -> dict[str, Any]:
        """Read one vulnerability ticket by its ID (for example T-1001)."""
        principal = require_principal(ctx)
        ticket = store.get_ticket(path, ticket_id)
        if ticket is None:
            log.info("get_ticket user=%s request=%s ticket=%r outcome=not_found", principal.user_id, principal.request_id, ticket_id)
            raise ToolError("ticket not found")
        if not may_access(principal, ticket["team"]):
            log.warning("get_ticket user=%s request=%s ticket=%s outcome=forbidden", principal.user_id, principal.request_id, ticket_id)
            raise ToolError("ticket not found")
        log.info("get_ticket user=%s request=%s ticket=%s outcome=ok", principal.user_id, principal.request_id, ticket_id)
        return ticket

    @server.tool()
    async def list_tickets(
        ctx: Context, status: Literal["open", "in_progress", "closed", "all"] = "all"
    ) -> dict[str, Any]:
        """List ticket summaries (ID, title, asset, team, severity, status), optionally by status (default: all)."""
        principal = require_principal(ctx)
        team = team_scope(principal, "list_tickets")
        tickets = store.list_tickets(path, None if status == "all" else status, team)
        log.info("list_tickets user=%s request=%s status=%s team_scope=%s count=%d",
                 principal.user_id, principal.request_id, status, team or "all", len(tickets))
        return {"count": len(tickets), "tickets": tickets}

    @server.tool()
    async def search_cve(cve_id: str, ctx: Context) -> dict[str, Any]:
        """Look up one CVE record by its ID (for example CVE-2099-0003)."""
        principal = require_principal(ctx)
        cve = store.get_cve(path, cve_id)
        if cve is None:
            log.info("search_cve user=%s request=%s cve=%r outcome=not_found", principal.user_id, principal.request_id, cve_id)
            raise ToolError("cve not found")
        log.info("search_cve user=%s request=%s cve=%s outcome=ok", principal.user_id, principal.request_id, cve_id)
        return cve

    @server.tool()
    async def update_severity(ticket_id: str, level: Severity, reason: Reason, ctx: Context) -> dict[str, Any]:
        """Change a ticket's severity to Critical, High, Medium or Low. A reason is required (1 to 500 characters)."""
        principal = require_principal(ctx)
        scope = team_scope(principal, "update_severity")
        reason = reason.strip()
        if not reason:
            raise ToolError("reason required")
        changed, ticket = run_write(
            "update_severity", principal, ticket_id,
            lambda: store.update_severity(path, ticket_id, level, reason, principal.user_id, scope, principal.request_id))
        log.info("update_severity user=%s request=%s ticket=%s level=%s outcome=%s",
                 principal.user_id, principal.request_id, ticket_id, level, "updated" if changed else "unchanged")
        return {"result": "updated" if changed else "unchanged", "ticket": ticket}

    @server.tool()
    async def close_ticket(ticket_id: str, reason: Reason, ctx: Context) -> dict[str, Any]:
        """Close a ticket. A reason is required (1 to 500 characters)."""
        principal = require_principal(ctx)
        scope = team_scope(principal, "close_ticket")
        reason = reason.strip()
        if not reason:
            raise ToolError("reason required")
        _, ticket = run_write(
            "close_ticket", principal, ticket_id,
            lambda: store.close_ticket(path, ticket_id, reason, principal.user_id, scope, principal.request_id))
        log.info("close_ticket user=%s request=%s ticket=%s outcome=closed", principal.user_id, principal.request_id, ticket_id)
        return {"result": "closed", "ticket": ticket}

    @server.tool()
    async def draft_summary(ticket_ids: TicketIds, ctx: Context) -> dict[str, Any]:
        """Draft a short manager summary of 1 to 20 tickets, given their IDs."""
        principal = require_principal(ctx)
        scope = team_scope(principal, "draft_summary")
        ids = list(dict.fromkeys(ticket_ids))  # drop duplicates, keep the order
        try:
            rows = store.draft_summary(path, ids, principal.user_id, scope, principal.request_id)
        except store.TicketForbidden as exc:
            log.warning("draft_summary user=%s request=%s ticket=%r outcome=forbidden", principal.user_id, principal.request_id, exc.args[0])
            raise ToolError("ticket not found") from None
        except store.TicketNotFound as exc:
            log.info("draft_summary user=%s request=%s ticket=%r outcome=not_found", principal.user_id, principal.request_id, exc.args[0])
            raise ToolError("ticket not found") from None
        log.info("draft_summary user=%s request=%s tickets=%d outcome=ok", principal.user_id, principal.request_id, len(rows))
        return {"ticket_count": len(rows), "summary": build_summary(rows)}

    return server


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    log.info("security mode=%s tool_authz=%s approval_policy=%s",
             config.mode, config.tool_authz, config.approval_policy)
    if not config.tool_authz:
        log.warning("tool_authz is OFF: vulnerable baseline, any logged-in user can reach every team's tickets")
    create_server(tool_authz=config.tool_authz).run(
        "streamable-http", host="127.0.0.1", port=int(os.environ.get("TRIAGE_MCP_PORT", "8000")))
