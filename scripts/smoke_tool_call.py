"""Phase 0 smoke test: does a model reliably call a tool? Usage: python scripts/smoke_tool_call.py <model> [runs]"""
import json
import sys
import time
import urllib.request

MODEL = sys.argv[1]
RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 10

TOOL = {
    "type": "function",
    "function": {
        "name": "get_ticket",
        "description": "Read a vulnerability ticket by ID.",
        "parameters": {
            "type": "object",
            "properties": {"ticket_id": {"type": "string"}},
            "required": ["ticket_id"],
        },
    },
}
PROMPT = "Show me ticket T-1042."

ok = 0
times = []
for _ in range(RUNS):
    body = json.dumps({
        "model": MODEL, "stream": False, "tools": [TOOL],
        "options": {"temperature": 0},
        "messages": [{"role": "user", "content": PROMPT}],
    }).encode()
    t0 = time.time()
    req = urllib.request.Request("http://localhost:11434/api/chat", body, {"Content-Type": "application/json"})
    msg = json.load(urllib.request.urlopen(req, timeout=300))["message"]
    times.append(time.time() - t0)
    calls = msg.get("tool_calls") or []
    if calls and calls[0]["function"]["name"] == "get_ticket" and calls[0]["function"]["arguments"].get("ticket_id") == "T-1042":
        ok += 1
print(f"{MODEL}: {ok}/{RUNS} correct tool calls, avg {sum(times)/len(times):.1f}s/call (first call includes model load)")
