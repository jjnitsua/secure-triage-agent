"""Agent loop and tool dispatcher (Phase 2, plan task 3).

run_agent() is the loop: send the system prompt and the user's message to the model, run
the tool calls it asks for, give the results back, repeat until it answers. Three rules
keep the model from becoming the security boundary:

  * Identity never enters the conversation. The caller's Principal is held here in Python
    and handed only to McpToolGateway.call(), which signs it into the MCP request's `_meta`
    (app/auth.py). The model sees neither the identity nor the signature, and nothing in the
    tool arguments can change it.
  * Only tools the MCP server itself publishes can be called. An unknown name, or arguments
    that are not an object, are never executed; the model just gets an error back.
  * The loop is bounded: at most MAX_STEPS rounds of tool calls, at most MAX_CALLS_PER_STEP
    calls in a round, and each tool result is cut to MAX_RESULT_CHARS.

Tool results go to the model unchanged. In this baseline nothing marks ticket or CVE text
as data rather than instructions; delimiting is Phase 4.

The model is reached through a one-method interface (ModelClient), so the loop can be tested
with a scripted fake. OllamaModelClient is the real one. Messages are plain dictionaries.
"""
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
import ollama
from mcp import Client

from app.auth import META_KEY, Principal, sign_principal

MAX_STEPS = 6
MAX_CALLS_PER_STEP = 4
MAX_RESULT_CHARS = 8000
MAX_RECORDED_ARG_CHARS = 200
STOP_REPLY = "I stopped because this request needed more than {} tool steps."


class ModelUnavailable(Exception):
    """The language model could not be reached or did not answer in time."""


class ToolServerUnavailable(Exception):
    """The MCP tool server could not be reached."""


class ModelClient(Protocol):
    async def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        """Return the model's next message as a dict: role, content, and optionally tool_calls."""


@dataclass
class ToolOutcome:
    text: str
    is_error: bool


@dataclass
class ToolCallRecord:
    name: str
    arguments: dict
    ok: bool


@dataclass
class AgentResult:
    reply: str
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    stopped_early: bool = False


class OllamaModelClient:
    """The real model: Ollama, temperature 0 and a fixed seed so runs can be repeated."""

    def __init__(self, model="qwen2.5:7b", host=None, timeout=120.0, temperature=0, seed=0,
                 num_predict=1024, client=None):
        self.model = model
        self.options = {"temperature": temperature, "seed": seed, "num_predict": num_predict}
        self._client = client or ollama.AsyncClient(host=host, timeout=timeout)

    async def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        try:
            response = await self._client.chat(model=self.model, messages=messages, tools=tools,
                                               options=self.options)
        except (ConnectionError, ollama.ResponseError, httpx.HTTPError) as exc:
            raise ModelUnavailable(type(exc).__name__) from None
        return response.message.model_dump(exclude_none=True)


def _cap(text: str) -> str:
    return text if len(text) <= MAX_RESULT_CHARS else text[:MAX_RESULT_CHARS] + " ...[truncated]"


def _result_text(result) -> str:
    if not result.is_error and result.structured_content is not None:
        return _cap(json.dumps(result.structured_content, ensure_ascii=False))
    return _cap(" ".join(getattr(block, "text", "") for block in result.content))


class McpToolGateway:
    """Talks to the MCP tool server. `target` is a URL, or a server object in tests."""

    def __init__(self, target):
        self._target = target

    async def list_tools(self) -> list[dict]:
        """The server's own published tools, in the format the model expects."""
        try:
            async with Client(self._target) as client:
                tools = (await client.list_tools()).tools
        except (OSError, httpx.HTTPError):
            raise ToolServerUnavailable from None
        return [{"type": "function",
                 "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema}}
                for t in tools]

    async def call(self, principal: Principal, name: str, arguments: Mapping) -> ToolOutcome:
        """Call one tool as `principal`: the signed identity goes in `_meta`, the model's arguments as given."""
        meta = {META_KEY: sign_principal(principal)}
        try:
            async with Client(self._target) as client:
                result = await client.call_tool(name, dict(arguments), meta=meta)
        except (OSError, httpx.HTTPError):
            raise ToolServerUnavailable from None
        return ToolOutcome(_result_text(result), result.is_error)


def _short(arguments: object) -> dict:
    """Arguments for the response record, with long strings cut."""
    if not isinstance(arguments, Mapping):
        return {}
    return {str(k): (v if not isinstance(v, str) or len(v) <= MAX_RECORDED_ARG_CHARS
                     else v[:MAX_RECORDED_ARG_CHARS] + "...")
            for k, v in arguments.items()}


async def run_agent(model: ModelClient, gateway: McpToolGateway, principal: Principal,
                    user_message: str, system_prompt: str, max_steps: int = MAX_STEPS) -> AgentResult:
    tools = await gateway.list_tools()
    known = {t["function"]["name"] for t in tools}
    messages: list[dict] = [{"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_message}]
    records: list[ToolCallRecord] = []
    steps = 0
    while True:
        message = await model.chat(messages, tools)
        messages.append(message)
        calls = message.get("tool_calls") or []
        if not calls:
            return AgentResult(reply=(message.get("content") or "").strip() or "(no reply)", tool_calls=records)
        if steps >= max_steps:
            return AgentResult(reply=STOP_REPLY.format(max_steps), tool_calls=records, stopped_early=True)
        steps += 1
        for index, call in enumerate(calls):
            function = call.get("function") if isinstance(call, Mapping) else None
            function = function if isinstance(function, Mapping) else {}
            name, arguments = function.get("name"), function.get("arguments")
            if index >= MAX_CALLS_PER_STEP:
                outcome = ToolOutcome("not executed: too many tool calls in one step", True)
            elif not isinstance(name, str) or name not in known:
                outcome = ToolOutcome("unknown tool", True)
            elif not isinstance(arguments, Mapping):
                outcome = ToolOutcome("arguments must be an object", True)
            else:
                outcome = await gateway.call(principal, name, arguments)
            records.append(ToolCallRecord(name=str(name), arguments=_short(arguments), ok=not outcome.is_error))
            messages.append({"role": "tool", "content": outcome.text, "tool_name": str(name)})
