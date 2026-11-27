#!/usr/bin/env python3
"""Offline re-grade of saved A5 results with the disclosure check (D-040 e). No model, no services, no database.

Reads logs/attacks/<name>_results.jsonl, rebuilds each case's user message from the payload file, and prints
the Phase 3 verdict (marker check) next to the new one for every A5 case, then both rates.
  python scripts/regrade_a5.py --name baseline_dev [--set dev]
Writes logs/attacks/<name>_a5_regrade.jsonl (git-ignored).
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "attacks"))
import run_attacks as ra  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--set", default="dev", choices=["dev"])  # held-out stays untouched (D-039)
    args = ap.parse_args()
    spec = json.loads((ra.PAYLOAD_DIR / f"payloads_{args.set}.json").read_text(encoding="utf-8"))
    cases = {c["case_id"]: c for c in ra.expand_attacks(spec, {"A5"})}
    markers = ra.infra_markers()
    recs = [json.loads(l) for l in (ROOT / "logs" / "attacks" / f"{args.name}_results.jsonl").read_text().splitlines()]
    recs = [r for r in recs if r["scenario"] == "A5" and not r.get("repeat")]
    out, rows = [], []
    for r in recs:
        old = (r["class"], r["detail"])
        new_rec = dict(r, reply=r["reply_text"])
        new = ra.classify_a5(cases[r["case_id"]], new_rec, markers)
        assert new_rec["marker_leak"] == (old == ("succeeded", "leaked_to_user")), r["case_id"]  # v1 must reproduce
        assert r["reply_chars"] <= 3000, r["case_id"]  # a capped reply could hide a disclosure
        rows.append((r["case_id"], old[1], bool(r["read_by_agent"]), new_rec["read_by_agent"], new[1], new_rec["disclosed"]))
        out.append({"case_id": r["case_id"], "old": old, "new": new, "read_by_agent": new_rec["read_by_agent"],
                    "disclosed": new_rec["disclosed"], "reply_text": r["reply_text"]})
    print(f"{'case':<14}{'old detail':<22}{'read(old)':<10}{'read(new)':<10}{'new detail':<20}disclosed by")
    for row in rows:
        print(f"{row[0]:<14}{row[1]:<22}{str(row[2]):<10}{str(row[3]):<10}{row[4]:<20}{row[5]}")
    n = len(recs)
    print(f"\nn = {n} distinct cases")
    print("read by the agent (log), Phase 3 :", ra.rate(sum(r["read_by_agent"] for r in recs), n))
    print("read by the agent (log), new     :", ra.rate(sum(o["read_by_agent"] for o in out), n))
    print("leak, marker check (Phase 3)     :", ra.rate(sum(o["old"] == ("succeeded", "leaked_to_user") for o in out), n))
    print("leak, disclosure check (new)     :", ra.rate(sum(o["new"] == ("succeeded", "leaked_to_user") for o in out), n))
    print("inconclusive (new)               :", sum(o["new"][0] == "inconclusive" for o in out))
    with open(ROOT / "logs" / "attacks" / f"{args.name}_a5_regrade.jsonl", "w", encoding="utf-8") as f:
        f.writelines(json.dumps(o) + "\n" for o in out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
