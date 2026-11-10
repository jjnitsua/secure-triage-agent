"""Agent service (Phase 2, plan task 3): POST /chat and the POST /approvals/{id} stub.

Run (from the repo folder; the MCP tool server and Ollama must be running, and
TRIAGE_SIGNING_KEY must be set to the same value the tool server uses):
  uvicorn app.main:create_default_app --factory --host 127.0.0.1 --port 8001
Settings: TRIAGE_MCP_URL (default http://127.0.0.1:8000/mcp), TRIAGE_MODEL (default
qwen2.5:7b), TRIAGE_USERS (users file), TRIAGE_SYSTEM_PROMPT (prompt file).

Identity: the only thing that decides who the caller is, is the bearer token, looked up in
the users file (app/auth.py). The body of /chat holds only `message`; any other field,
such as a user_id or role, is refused with 422, so identity can never be supplied in the
request. A missing, malformed or unknown token gets the same 401 whatever else is wrong with
the request, so an unauthenticated caller learns nothing about the body format. The caller's
identity then goes to the tool server only as a signed value in `_meta` (app/agent.py).

The model and the tool server are passed in, so tests can use a scripted model and an
in-process tool server. The generated API docs (/docs, /redoc, /openapi.json) are switched
off. Logs hold the user, the tools used and the outcome, never the message text.
"""
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import Depends, FastAPI, HTTPException  # noqa: E402
from fastapi import Path as PathParam  # noqa: E402
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer  # noqa: E402
from pydantic import BaseModel, ConfigDict, StringConstraints  # noqa: E402

from app.agent import (McpToolGateway, ModelClient, ModelUnavailable, OllamaModelClient,  # noqa: E402
                       ToolServerUnavailable, run_agent)
from app.auth import Principal, TokenDirectory, load_users  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PROMPT_ENV = "TRIAGE_SYSTEM_PROMPT"
MAX_MESSAGE_CHARS = 4000

log = logging.getLogger("triage.api")


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_MESSAGE_CHARS)]


class ToolCallOut(BaseModel):
    name: str
    arguments: dict[str, Any]
    ok: bool


class ChatOut(BaseModel):
    reply: str
    tool_calls: list[ToolCallOut]
    stopped_early: bool


def load_system_prompt(path=None) -> str:
    path = Path(path or os.environ.get(PROMPT_ENV) or ROOT / "config" / "system_prompt.txt")
    prompt = path.read_text(encoding="utf-8").strip()
    if not prompt:
        raise ValueError("system prompt file is empty")
    return prompt


def create_app(model: ModelClient, gateway: McpToolGateway, users: TokenDirectory, system_prompt: str) -> FastAPI:
    app = FastAPI(title="secure-triage-agent", docs_url=None, redoc_url=None, openapi_url=None)
    bearer = HTTPBearer()  # a missing header or another scheme is a 401

    def current_principal(credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)]) -> Principal:
        principal = users.authenticate(credentials.credentials)
        if principal is None:
            raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
        return principal

    @app.post("/chat", response_model=ChatOut)
    async def chat(body: ChatIn, principal: Annotated[Principal, Depends(current_principal)]) -> ChatOut:
        try:
            result = await run_agent(model, gateway, principal, body.message, system_prompt)
        except ModelUnavailable:
            log.warning("chat user=%s outcome=model_unavailable", principal.user_id)
            raise HTTPException(status_code=503, detail="The language model is unavailable") from None
        except ToolServerUnavailable:
            log.warning("chat user=%s outcome=tool_server_unavailable", principal.user_id)
            raise HTTPException(status_code=503, detail="The tool server is unavailable") from None
        log.info("chat user=%s tools=%s stopped_early=%s", principal.user_id,
                 [f"{r.name}:{'ok' if r.ok else 'error'}" for r in result.tool_calls], result.stopped_early)
        return ChatOut(reply=result.reply, stopped_early=result.stopped_early,
                       tool_calls=[ToolCallOut(name=r.name, arguments=r.arguments, ok=r.ok)
                                   for r in result.tool_calls])

    @app.post("/approvals/{approval_id}")
    async def approve(approval_id: Annotated[str, PathParam(max_length=64)],
                      principal: Annotated[Principal, Depends(current_principal)]) -> None:
        """Stub. Approvals are a separate endpoint the agent cannot reach (there is no approval tool);
        the real flow is Phase 4. For now it only enforces who may call it."""
        if principal.role != "manager":
            log.warning("approvals user=%s outcome=forbidden", principal.user_id)
            raise HTTPException(status_code=403, detail="Forbidden")
        raise HTTPException(status_code=501, detail="Approvals are not implemented yet")

    return app


def create_default_app() -> FastAPI:
    """The real service: Ollama for the model, the MCP server over HTTP, users and prompt from files."""
    logging.basicConfig(level=logging.INFO)
    return create_app(
        model=OllamaModelClient(model=os.environ.get("TRIAGE_MODEL", "qwen2.5:7b")),
        gateway=McpToolGateway(os.environ.get("TRIAGE_MCP_URL", "http://127.0.0.1:8000/mcp")),
        users=load_users(),
        system_prompt=load_system_prompt(),
    )
