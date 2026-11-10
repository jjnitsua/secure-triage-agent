"""MCP tool server (Phase 2). Only `get_ticket` exists so far; the other five tools follow.

Identity: every tool call must carry a signed principal in the request's `_meta` (see
app/auth.py). The server verifies it on every call and takes the caller's team and role
only from the verified result. The tools have no user, team or role parameter, so the
model can neither see nor choose who is asking.

Failures reach the caller as generic tool errors ("authentication failed",
"ticket not found"). A ticket the caller may not read gets the same "ticket not found"
as one that does not exist, so ticket IDs cannot be probed. The real reason is logged
here only. Tool error text reaches the model, so it must not carry useful detail.

Run (from the repo folder, with TRIAGE_SIGNING_KEY set):
  python -m mcp_server.server        # Streamable HTTP on 127.0.0.1:8000
"""
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.mcpserver import Context, MCPServer  # noqa: E402
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

from app.auth import META_KEY, AuthError, Principal, verify_principal  # noqa: E402
from mcp_server import store  # noqa: E402

log = logging.getLogger("triage.mcp_server")


def require_principal(ctx: Context) -> Principal:
    """Return the verified caller, or raise a generic ToolError."""
    meta = ctx.request_context.meta
    package = meta.get(META_KEY) if meta else None
    try:
        return verify_principal(package)
    except AuthError as exc:
        log.warning("auth rejected: %s", exc)
        raise ToolError("authentication failed") from None


def can_read(principal: Principal, ticket: dict) -> bool:
    """Team scoping for reads: analysts see their own team's tickets, the manager all."""
    if principal.role == "manager":
        return True
    return principal.role == "analyst" and principal.team == ticket["team"]


def create_server(db_path=None) -> MCPServer:
    path = db_path or store.default_db_path()
    server = MCPServer("secure-triage-tools")

    @server.tool()
    async def get_ticket(ticket_id: str, ctx: Context) -> dict[str, Any]:
        """Read one vulnerability ticket by its ID (for example T-1001)."""
        principal = require_principal(ctx)
        ticket = store.get_ticket(path, ticket_id)
        if ticket is None:
            log.info("get_ticket user=%s ticket=%r outcome=not_found", principal.user_id, ticket_id)
            raise ToolError("ticket not found")
        if not can_read(principal, ticket):
            log.warning("get_ticket user=%s ticket=%s outcome=forbidden", principal.user_id, ticket_id)
            raise ToolError("ticket not found")
        log.info("get_ticket user=%s ticket=%s outcome=ok", principal.user_id, ticket_id)
        return ticket

    return server


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_server().run("streamable-http", host="127.0.0.1", port=8000)
