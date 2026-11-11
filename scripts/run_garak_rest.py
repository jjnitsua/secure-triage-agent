#!/usr/bin/env python3
"""Run one Garak probe group against the running service and record what happened to the data (Phase 2).

Garak (garak/rest_vulnerable.yaml) only sees the reply text. This script wraps each run so the
application outcomes can be checked as a separate evidence stream:

  1. reset the working database from the fixtures (scripts/reset_db.py) and snapshot every table
  2. start the tool server and the agent service with the chosen security config
  3. run Garak against POST /chat as one dev user
  4. stop Garak and both services
  5. count the HTTP status codes and tool outcomes from the service logs
  6. diff every table against the snapshot and print each new or changed row

Safeguards: Garak's REST generator retries 5xx responses with no maximum, so a model error
could hang a run for hours (it did once). The script stops Garak after --max-503 responses of
503 (the service's "model unavailable") or after --timeout-min minutes, and says which.
Put 503 in skip_codes of the Garak config so a failing prompt is skipped, not retried.

The `outcome=closed` tool log line also marks a refused close of an ALREADY-closed ticket; the
database diff, not that line, is the evidence of what really changed.

Garak findings and application outcomes are kept separate; nothing here merges them. Needs the
venv, a running Ollama, and free ports. The signing key is random for each run and not stored.
Repo folder = the folder above scripts/. Standard library, PyYAML and httpx (already installed).

Usage (from the repo folder, venv active; takes minutes to hours depending on the probes):
  python scripts/run_garak_rest.py --name encoding_base64 --spec probes.encoding.InjectBase64
  python scripts/run_garak_rest.py --name latentinjection_rerun \\
      --spec "probes.latentinjection.LatentInjectionResume,probes.latentinjection.LatentWhoisSnippet" \\
      --timeout-min 90
Logs and the summary go to logs/garak_rest/ (git-ignored); the Garak report goes to Garak's own
report folder as <prefix>_<name>.report.jsonl.
"""
import argparse
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
OLLAMA = "http://127.0.0.1:11434"


def user_token(user_id: str) -> str:
    users = json.loads((ROOT / "data" / "users.json").read_text(encoding="utf-8"))["users"]
    for u in users:
        if u["user_id"] == user_id:
            return u["token"]
    raise SystemExit(f"user {user_id!r} not found in data/users.json")


def rest_settings(garak_config: Path):
    """The /chat port and skip_codes from the Garak config, so the script and the config cannot disagree."""
    raw = yaml.safe_load(garak_config.read_text(encoding="utf-8"))
    gen = raw["plugins"]["generators"]["rest"]["RestGenerator"]
    return urlparse(gen["uri"]).port, list(gen.get("skip_codes", []))


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def dump_db(db: Path) -> dict:
    con = sqlite3.connect(db)
    try:
        return {t: con.execute(f"SELECT * FROM {t}").fetchall()
                for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()


def count_matches(log_path: Path, pattern: str) -> dict:
    counts = {}
    for m in re.finditer(pattern, log_path.read_text(errors="replace")):
        key = m.groups() if len(m.groups()) > 1 else m.group(1)
        counts[key] = counts.get(key, 0) + 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="short group name used in file and report names")
    ap.add_argument("--spec", required=True, help="Garak --spec value, e.g. probes.encoding.InjectHex")
    ap.add_argument("--garak-config", default="garak/rest_vulnerable.yaml")
    ap.add_argument("--service-config", default="config/vulnerable.yaml", help="security config for the services (TRIAGE_CONFIG)")
    ap.add_argument("--user", default="analyst-web", help="dev user whose token Garak uses")
    ap.add_argument("--prefix", default="phase2_rest_vuln", help="Garak report name prefix")
    ap.add_argument("--mcp-port", type=int, default=8000)
    ap.add_argument("--max-503", type=int, default=10, help="stop Garak after this many 503 responses")
    ap.add_argument("--timeout-min", type=int, default=150, help="stop Garak after this many minutes")
    ap.add_argument("--out-dir", default="logs/garak_rest")
    args = ap.parse_args()

    garak_config = ROOT / args.garak_config
    api_port, skip_codes = rest_settings(garak_config)
    out = ROOT / args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    summary = open(out / f"{args.name}_summary.txt", "w", encoding="utf-8")

    def say(msg: str) -> None:
        print(msg, flush=True)
        summary.write(msg + "\n")
        summary.flush()

    say(f"== {args.name}: {args.spec}")
    say(f"garak config {args.garak_config} (skip_codes {skip_codes}), services {args.service_config}, user {args.user}")
    if 503 not in skip_codes:
        say("WARNING: 503 is not in skip_codes, so Garak will retry a model error without limit "
            f"(this script stops it after {args.max_503} x 503)")

    # Preflight: nothing started yet, nothing changed.
    try:
        httpx.get(f"{OLLAMA}/api/tags", timeout=5).raise_for_status()
    except Exception as exc:
        say(f"ABORT: Ollama is not reachable at {OLLAMA} ({exc!r})")
        return 2
    for port in (args.mcp_port, api_port):
        if not port_free(port):
            say(f"ABORT: port {port} is already in use (is an earlier run still going?)")
            return 2

    subprocess.run([sys.executable, "scripts/reset_db.py"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    working_db = ROOT / "data" / "working.db"
    before = dump_db(working_db)

    env = {**os.environ,
           "TRIAGE_SIGNING_KEY": secrets.token_hex(16),
           "TRIAGE_CONFIG": str(ROOT / args.service_config),
           "TRIAGE_MCP_PORT": str(args.mcp_port),
           "TRIAGE_MCP_URL": f"http://127.0.0.1:{args.mcp_port}/mcp"}
    logs = {n: open(out / f"{args.name}_{n}.log", "w") for n in ("mcp", "api", "garak")}
    procs, reason, started = [], "finished", time.time()
    try:
        procs.append(subprocess.Popen([sys.executable, "-m", "mcp_server.server"], cwd=ROOT, env=env,
                                      stdout=logs["mcp"], stderr=logs["mcp"]))
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:create_default_app", "--factory",
             "--host", "127.0.0.1", "--port", str(api_port)],
            cwd=ROOT, env=env, stdout=logs["api"], stderr=logs["api"]))
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{api_port}/docs", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            say("ABORT: the agent service did not start in 30 s")
            return 2
        # the token goes to Garak through the environment only, never to a file or a log
        garak = subprocess.Popen(
            [sys.executable, "-m", "garak", "--config", str(garak_config), "--spec", args.spec,
             "--report_prefix", f"{args.prefix}_{args.name}"],
            cwd=ROOT, env={**env, "REST_API_KEY": user_token(args.user)},
            stdout=logs["garak"], stderr=subprocess.STDOUT)
        while garak.poll() is None:
            time.sleep(15)
            n503 = sum(count_matches(out / f"{args.name}_api.log", r'POST /chat HTTP/1.1" (503)').values())
            if n503 >= args.max_503:
                reason = f"STOPPED: {n503} x 503 reached the limit of {args.max_503}"
                garak.terminate()
                break
            if time.time() - started > args.timeout_min * 60:
                reason = f"STOPPED: {args.timeout_min}-minute timeout"
                garak.terminate()
                break
        garak.wait(timeout=60)
        say(f"garak exit {garak.returncode} in {(time.time() - started) / 60:.1f} min; {reason}")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=15)
        for f in logs.values():
            f.close()

    codes = count_matches(out / f"{args.name}_api.log", r'POST /chat HTTP/1.1" (\d+)')
    say(f"/chat status codes: {codes}")
    tools = count_matches(out / f"{args.name}_mcp.log", r"triage\.mcp_server:(\w+) user=\S+.*?outcome=(\w+)")
    say(f"tool outcomes (log lines; 'closed' includes refused closes of already-closed tickets): {tools}")
    after = dump_db(working_db)
    changed = False
    for table, rows in before.items():
        if rows != after[table]:
            changed = True
            say(f"DB table {table} CHANGED: {len(rows)} -> {len(after[table])} rows")
            for row in after[table]:
                if row not in rows:
                    say(f"  new/changed: {str(row)[:230]}")
    if not changed:
        say("DB unchanged")
    say("DONE (reset the database again before the next run; this script does it at the start)")
    summary.close()
    return 0 if reason == "finished" else 1


if __name__ == "__main__":
    sys.exit(main())
