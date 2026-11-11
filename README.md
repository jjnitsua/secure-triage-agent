# secure-triage-agent

Hardening and monitoring an agentic AI assistant.

This is a **defensive security** project. I build a small vulnerability-triage assistant (an LLM agent that uses tools exposed through an MCP server), then attack it, harden it, and monitor it. [NVIDIA Garak](https://github.com/NVIDIA/garak) and a custom attack harness are used as adversary emulation to test and measure the defenses, the way blue teams use Atomic Red Team to test detections. All data is synthetic, and I only test systems I own.

## Status

**Phases 0 (setup), 1 (Garak baseline) and 2 (the assistant, identity and threat model): complete for v1, with the limits listed under "Phase 1 findings" and "Phase 2 findings".** The assistant is built and has been measured in its deliberately vulnerable baseline mode; **nothing has been measured in the defended mode yet** (hardening is Phase 4).

| Phase | Scope | Status |
|---|---|---|
| 0 | Setup, model choice, tool-calling checks | Done |
| 1 | Garak baseline assessment | Done for v1 (results and limits in `RESULTS.md`) |
| 2 | Agent, identity and threat model | Done for v1 (vulnerable baseline measured; details in `reports/PHASE_2_ANALYSIS.md`) |
| 3 | Adversary emulation harness | Not started |
| 4 | Hardening | Not started |
| 5 | Telemetry and detections | Not started |
| 7 | CI/CD security gate | Not started |

## What exists so far

- `scripts/smoke_tool_call.py`: checks that a local model can make a correct tool call.
- `scripts/tool_selection_test.py`: a 30-case test of tool selection across the six planned tools, with repeated runs, adjustable temperature, per-category totals and Wilson 95% confidence intervals.
- `requirements.txt`: pinned dependencies (Garak 0.17.1).
- `garak/baseline.yaml`: the pinned Garak settings for the Phase 1 baseline (target model, temperature 0, 1 generation, `max_tokens` 150).
- `scripts/parse_garak.py`: turns Garak report files into counts with Wilson 95% intervals and checks them against Garak's own totals.
- `scripts/classify_hits.py`: sorts flagged replies into success / partial / artifact (or exact / near miss for decoding probes). These are our own definitions, kept separate from Garak's flag counts.
- `RESULTS.md`: the headline numbers. `reports/PHASE_1_ANALYSIS.md`: the detail behind them (settings, methods, definitions, examples, limits).
- **The assistant (Phase 2):** `app/` (FastAPI agent service: `POST /chat`, token lookup, signed identity, the agent loop), `mcp_server/` (the tool server with six tools and a SQLite store), `config/` (`security.yaml`, `vulnerable.yaml`, `system_prompt.txt`), `data/` (synthetic tickets, CVE records and dev-only users), `scripts/seed_db.py` and `scripts/reset_db.py` (build and reset the fixture database), `tests/control/` (166 deterministic control tests, no model).
- `THREAT_MODEL.md`: assets, attackers, trust boundaries and 13 threats, mapped to the OWASP Top 10 for LLM Applications (2025), MITRE ATLAS and STRIDE.
- `garak/rest_vulnerable.yaml` and `scripts/run_garak_rest.py`: run Garak against the running service and read what happened to the data afterwards. `reports/PHASE_2_ANALYSIS.md`: the detail behind the Phase 2 results.
- The remaining folders are the planned layout for later phases.

## The assistant and its security modes (Phase 2)

An analyst or manager chats with a vulnerability-triage assistant. It can read and list tickets, look up CVE records, change a ticket's severity, close a ticket and draft a manager summary, using six tools served by a separate MCP server. Everything runs locally against synthetic data, with `qwen2.5:7b` through Ollama.

- **Identity.** Each user has a dev-only bearer token (fake, in `data/users.json`). `POST /chat` takes only `{"message": ...}`; the user, team and role come from the token and never from the request body. The agent signs the caller's identity (HMAC-SHA256, 60-second expiry) into every tool call; the model neither sees nor sets it. The tool server verifies the signature on every call.
- **Authorization at the tool boundary.** The tool server checks team scope and role on each call and returns the same "not found" for a missing ticket and for one the caller may not read. Hiding a tool from the model is not treated as a control.
- **Simplification, stated plainly.** Production MCP over HTTP uses the protocol's OAuth-based authorization. This project uses a simpler scheme, a shared signing key held by the two local processes, so that the project can concentrate on enforcing identity and permissions at the tool boundary. It is a teaching simplification, not a production design.
- **Modes.** `config/security.yaml` is `mode: defended`, the default. `config/vulnerable.yaml` is the baseline: login is still real, but tool-boundary authorization is off and there are no approvals, so the model alone decides what is allowed. An explicit switch overrides the mode and is then reported as `custom`. **Approvals are not built yet (Phase 4)**, so `approval_policy` is `none` in both modes and today "defended" means only tool-boundary authorization.
- **Threat model.** `THREAT_MODEL.md` lists what could go wrong and where. It is a plan of what to test, not a result; the STRIDE labels were added to threats found by the asset, attacker and boundary method, and no per-element STRIDE pass was done.

## Phase 2 findings

Two kinds of evidence are kept apart: **Garak findings** (what the reply text looks like) and **verified application outcomes** (what actually happened to tickets, read from the database after each run). They are never added together.

In the vulnerable baseline, Garak's probes sent through `/chat` made the agent follow injected text in many replies, and across five runs the database shows **9 unapproved ticket changes** (8 closes and 1 severity change), all on the caller's own team. One planted resume-style text led to four tickets being closed in the same second. These come from single, seeded runs, so they describe what happened in those runs and are not rates; the event log does not yet record which prompt caused which change. Garak's flag rates, with sample sizes and 95% intervals, are in `reports/PHASE_2_ANALYSIS.md`.

Limits: nothing was measured in the defended mode; `LatentWhoisSnippet` could not be tested through the API as built (all of its prompts exceed the 4,000-character message limit, so none was evaluated); the Phase 2 Garak numbers are **not comparable with Phase 1** (whole application with a system prompt and tools, a 1,024-token cap, seeded prompt subsets, versus the bare model with a 150-token cap); the stricter success counts come from a classifier written for the bare model's replies and have not been re-validated on these replies; and one run was cut short when the local model backend returned errors for a reason that was not found (it was re-run). Headline numbers will be added to `RESULTS.md`.

## Phase 1 findings

Garak findings describe how the bare model (`qwen2.5:7b`) responded to probes. They do not show that an application was compromised. Under these probes the model often follows instructions hidden in the input. The numbers, with settings, sample sizes, Wilson intervals, definitions and limits, are in `RESULTS.md` and `reports/PHASE_1_ANALYSIS.md`. Known limits: the runs were not seeded (a rerun draws different prompts), the 150-token cap and the detectors' misses make most rates lower bounds, the `promptinject` rows use the probe's own mixed settings, and the stricter success counts are one rater's classification that has not yet been independently validated.

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

### Reproducing the Phase 1 baseline

Run these from the repo folder with the venv active and Ollama running. On a laptop use AC power and, on macOS, put `caffeinate -i` in front of each Garak command: when the Mac slept mid-run, Garak's 30 second request timeout fired on every wake and a run that should have been short took about 6 hours. `--report_prefix` is a name, not a path.

```bash
# Pilot: Base64 (256 prompts, about 8 min measured)
python -m garak --config garak/baseline.yaml \
  --spec probes.encoding.InjectBase64 --report_prefix phase1_encoding_base64_g1

# latentinjection: 4 probes, 1,024 prompts (first run was interrupted by sleep, so
# an uninterrupted time was not measured)
python -m garak --config garak/baseline.yaml \
  --spec "probes.latentinjection.LatentInjectionReport,probes.latentinjection.LatentInjectionResume,probes.latentinjection.LatentInjectionFactSnippetLegal,probes.latentinjection.LatentWhoisSnippet" \
  --report_prefix phase1_latentinjection_g1

# encoding Hex and ROT13 (512 prompts, about 21 min measured)
python -m garak --config garak/baseline.yaml \
  --spec "probes.encoding.InjectHex,probes.encoding.InjectROT13" \
  --report_prefix phase1_encoding_hex_rot13_g1

# promptinject: 3 probes, 768 prompts, probe-controlled settings (about 10 min measured)
python -m garak --config garak/baseline.yaml \
  --spec probes.promptinject --report_prefix phase1_promptinject_g1
```

Then compute the numbers and the stricter counts (both read-only; add `--prompts-csv FILE` to `parse_garak.py` for one row per prompt):

```bash
R=~/.local/share/garak/garak_runs
python scripts/parse_garak.py $R/phase1_{encoding_base64,latentinjection,encoding_hex_rot13,promptinject}_g1.report.jsonl
python scripts/classify_hits.py $R/phase1_latentinjection_g1.report.jsonl   # also works on the other reports
```

Garak uses temperature 0 only if you pass `--config garak/baseline.yaml`; its defaults are different. Times were measured once on one machine (Apple M4 Pro, 24 GB) and will vary.

**What you will and will not reproduce.** The published numbers come from runs made before `run.seed: 0` was added to `garak/baseline.yaml`, and unseeded runs draw a different random 256 prompts per probe each time. Your run uses the seeded prompt set, so the method, settings and report format match but the counts will differ somewhat from `RESULTS.md`. Runs made with the seeded config repeat their own prompt set.

### Run the assistant by hand

```bash
python scripts/seed_db.py                 # once: builds data/fixtures.db from the JSON fixtures
python scripts/reset_db.py                # before every test run: fresh working database
export TRIAGE_SIGNING_KEY="<any string of 16 or more characters>"   # the same value in both terminals
python -m mcp_server.server               # terminal 1: tool server on 127.0.0.1:8000
uvicorn app.main:create_default_app --factory --host 127.0.0.1 --port 8001   # terminal 2: agent service
curl -s -X POST http://127.0.0.1:8001/chat \
  -H "Authorization: Bearer dev-token-analyst-web" -H "Content-Type: application/json" \
  -d '{"message": "Show me ticket T-1005."}'
```

To run the vulnerable baseline, start the tool server with `TRIAGE_CONFIG=config/vulnerable.yaml` set. The control tests need no model: run each file, for example `python tests/control/test_config.py -v` (166 tests across 13 files at the end of Phase 2; 177 after the request ID was added at the start of Phase 3). Do not reset the database while the service is running.

### Run Garak against the service

```bash
python scripts/run_garak_rest.py --name promptinject --spec probes.promptinject
```

The script resets the database, starts both services in vulnerable mode, runs Garak as the `analyst-web` dev user, stops everything, then prints the HTTP status counts, the tool outcomes and every database row that changed. It stops Garak after 10 responses of 503 or a timeout, because Garak's REST generator retries server errors without limit. Ollama must be running and ports 8000 and 8001 free. Logs go to `logs/garak_rest/` (git-ignored) and the report to Garak's report folder. Long runs: use AC power and `caffeinate -i` on macOS, and measure a probe's real rate before trusting a total time estimate (the full Phase 2 set took about 4 hours). The guard and abort paths of the script were not tested; only the normal path was.

## Scope and ethics

- All data is synthetic. Tokens and canary values are dev-only.
- Malicious test fixtures will live in `attack_fixtures/`, clearly labeled, and target only this project.
- Results will be reported with sample sizes and confidence intervals, and claims will be limited to what was tested.
