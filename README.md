# secure-triage-agent

Hardening and monitoring an agentic AI assistant.

This is a **defensive security** project. I build a small vulnerability-triage assistant (an LLM agent that uses tools exposed through an MCP server), then attack it, harden it, and monitor it. [NVIDIA Garak](https://github.com/NVIDIA/garak) and a custom attack harness are used as adversary emulation to test and measure the defenses, the way blue teams use Atomic Red Team to test detections. All data is synthetic, and I only test systems I own.

## Status

**Phase 0 (setup and foundations): complete.** The assistant itself is not built yet.

| Phase | Scope | Status |
|---|---|---|
| 0 | Setup, model choice, tool-calling checks | Done |
| 1 | Garak baseline assessment | Not started |
| 2 | Agent, identity and threat model | Not started |
| 3 | Adversary emulation harness | Not started |
| 4 | Hardening | Not started |
| 5 | Telemetry and detections | Not started |
| 7 | CI/CD security gate | Not started |

## What exists so far

- `scripts/smoke_tool_call.py`: checks that a local model can make a correct tool call.
- `scripts/tool_selection_test.py`: a 30-case test of tool selection across the six planned tools, with repeated runs, adjustable temperature, per-category totals and Wilson 95% confidence intervals.
- `requirements.txt`: pinned dependencies (Garak 0.17.1).
- The remaining folders are the planned layout for later phases.

## Phase 0 findings

Model chosen for v1: `qwen2.5:7b` (via Ollama), compared with `llama3.1:8b` on the 30-case tool-selection test.

| Model | Temp 0, 1 run per case | Temp 0.7, 5 runs per case |
|---|---|---|
| qwen2.5:7b | 27/30 (90%) | 133/150 (89%, 95% CI 83-93%) |
| llama3.1:8b | 23/30 (77%) | 113/150 (75%, 95% CI 68-82%) |

These measure tool-selection accuracy on a small hand-written set, not security. At temperature 0 the intervals overlap, so that run alone does not rank the models. Security results will come from the attack harness in later phases and will be reported separately from Garak findings.

### Why Qwen

- **More reliable on the basics.** Across the 5-run test at temperature 0.7, Qwen answered all 20 no-tool questions without calling a tool; Llama called `search_cve` on 18 of them, often with an invented CVE ID. Llama also passed a ticket ID to a CVE lookup on multi-step tasks (1/10 vs. Qwen's 9/10).
- **Safer on ambiguous requests.** Qwen made no unsafe writes on the three ambiguous cases. Llama closed ticket T-31 on "T-31 looks fine to me" in 5 of 5 runs at temperature 0.7.
- **A measurable vulnerable baseline.** Qwen followed instructions embedded in pasted ticket text (5 of 5 runs at temperature 0.7 on one case), while Llama resisted all 15 injection-preview runs. That favored Llama on this one category, but a model that sometimes obeys injected text is what the attack harness needs to measure before-and-after effects. The controls in this project are meant to hold whatever the model does, so Llama's resistance here is not treated as a reason to skip them.

Limits: 30 hand-written cases, only 3 injection cases, one wording each, and the injection cases paste hostile text into the user message instead of delivering it through a tool result. Repeated runs of the same case are not independent, so the intervals are optimistic. Treat this as a reasonable engineering choice, not a ranking of the two models.

## Setup

Requires macOS or Linux, Python 3.11 or newer, and [Ollama](https://ollama.com).

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

ollama pull qwen2.5:7b
ollama pull llama3.1:8b
```

Run the checks (Ollama must be running):

```bash
python scripts/smoke_tool_call.py qwen2.5:7b
python scripts/tool_selection_test.py qwen2.5:7b
python scripts/tool_selection_test.py qwen2.5:7b --temp 0.7 --runs 5
```

Garak writes its reports to `~/.local/share/garak/garak_runs/`, not into this repo.

## Scope and ethics

- All data is synthetic. Tokens and canary values are dev-only.
- Malicious test fixtures will live in `attack_fixtures/`, clearly labeled, and target only this project.
- Results will be reported with sample sizes and confidence intervals, and claims will be limited to what was tested.
