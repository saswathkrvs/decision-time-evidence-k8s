#!/usr/bin/env python3
"""Further replays of the arm-G restart decisions (govstage2/replays.py) on converted captures.

    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 \
        [--only G1-001,G3-002] [--conditions T_p,L_p,R,T_p@R]          # results/stage2/analyses/replays
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --latency
                                                                        # results/stage2/analyses/latency
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --surrogate
                                                                        # results/stage2/analyses/surrogate
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --sweeps
                                                                        # results/stage2/analyses/sweeps
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --decision-log
                                                                        # results/stage2/analyses/decision_log
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --check-to-act
                                                                        # results/stage2/analyses/check_to_act
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --uncertain
                                                                        # results/stage2/analyses/uncertain
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --snapshots
                                                                        # results/stage2/analyses/snapshots
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --own-timestamps
                                                                        # results/stage2/analyses/own_timestamps

Writes one JSON file per capture (<out>/<capture>.json); a capture whose file exists is skipped, so an interrupted
run continues where it stopped. The included captures are read from results/stage2/captures.json: arm G for every
pass, arm D as well for --sweeps (govstage2/sweeps.py).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from govstage2 import replays, snapshots, sweeps  # noqa: E402
from govstage2.common import DEFAULT_PLAN  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures-root", required=True, help="directory holding <capture>/evidence")
    ap.add_argument("--out", default=None, help="default results/stage2/analyses/{replays,latency,surrogate}")
    ap.add_argument("--plan", default=str(DEFAULT_PLAN))
    ap.add_argument("--only", default=None)
    ap.add_argument("--conditions", default=None)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--latency", action="store_true", help="the pipeline-latency pass (replays.latency_pass)")
    mode.add_argument("--surrogate", action="store_true", help="the surrogate check (replays.surrogate_pass)")
    mode.add_argument("--sweeps", action="store_true",
                      help="coverage, parameter sweep and receipt-time audit (sweeps.sweep_pass), arms G and D")
    mode.add_argument("--decision-log", action="store_true",
                      help="a log of each decision's inputs against re-evaluation (sweeps.decision_log_pass), arm G")
    mode.add_argument("--check-to-act", action="store_true",
                      help="the recheck's executions labelled after a read-to-action gap (sweeps.check_to_act_pass)")
    mode.add_argument("--uncertain", action="store_true",
                      help="uncertain labels on the mutually evaluable decisions (replays.uncertain_pass), arm G")
    mode.add_argument("--snapshots", action="store_true",
                      help="snapshot-based state histories at longer intervals (snapshots.snapshot_pass), arm G")
    mode.add_argument("--own-timestamps", action="store_true",
                      help="audit replay from a receipt log that keeps the records' own timestamps "
                           "(sweeps.own_timestamps_pass), arm G")
    a = ap.parse_args(argv)
    if a.out is None:
        a.out = str(ROOT / "results/stage2/analyses" / ("latency" if a.latency else "surrogate" if a.surrogate
                                                        else "sweeps" if a.sweeps
                                                        else "decision_log" if a.decision_log
                                                        else "check_to_act" if a.check_to_act
                                                        else "uncertain" if a.uncertain
                                                        else "snapshots" if a.snapshots
                                                        else "own_timestamps" if a.own_timestamps else "replays"))
    register = json.loads((ROOT / "results/stage2/captures.json").read_text(encoding="utf-8"))
    arms = ("G", "D") if a.sweeps else ("G",)
    captures = [c for arm in arms for s in register["populations"][arm] for c in s["captures"]]
    if a.only:
        wanted = a.only.split(",")
        captures = [c for c in captures if c in wanted]
    which = tuple(a.conditions.split(",")) if a.conditions else replays.CONDITIONS
    for cap in captures:
        out = Path(a.out) / (cap + ".json")
        if out.exists():
            print("skip", cap, flush=True)
            continue
        converted = Path(a.captures_root) / cap / "evidence"
        if a.own_timestamps:
            doc = sweeps.own_timestamps_pass(converted, a.plan, out,
                                             progress=lambda m: print(m, file=sys.stderr, flush=True))
            print(cap, json.dumps({k: (v["own_timestamps_vs_gate"]["first_verdict_differs"],
                                       v["own_timestamps_vs_gate"]["posed"]) for k, v in doc["audit"].items()}),
                  flush=True)
            continue
        if a.snapshots:
            doc = snapshots.snapshot_pass(converted, a.plan, out,
                                          progress=lambda m: print(m, file=sys.stderr, flush=True))
            print(cap, json.dumps({k: (v["T F30"]["invalid"], v["T F30"]["executions"], v["S F30"]["invalid"])
                                   for k, v in doc["decisions"].items()}), flush=True)
            continue
        if a.uncertain:
            doc = replays.uncertain_pass(converted, a.plan, out,
                                         progress=lambda m: print(m, file=sys.stderr, flush=True))
            print(cap, json.dumps({v: (d["invalid"], sum(c["executions"] for c in d["uncertain"].values()))
                                   for v, d in doc["mutually_evaluable"]["views"].items()}), flush=True)
            continue
        if a.check_to_act:
            doc = sweeps.check_to_act_pass(converted, a.plan, out,
                                           progress=lambda m: print(m, file=sys.stderr, flush=True))
            print(cap, json.dumps(doc["executions_by_lag"]), flush=True)
            continue
        if a.decision_log:
            doc = sweeps.decision_log_pass(converted, a.plan, out,
                                           progress=lambda m: print(m, file=sys.stderr, flush=True))
            print(cap, json.dumps({k: (v["outcome_changed"], v["changed_own_log"], v["posed"])
                                   for k, v in doc["questions"].items()}), flush=True)
            continue
        if a.sweeps:
            doc = sweeps.sweep_pass(converted, a.plan, out, progress=lambda m: print(m, file=sys.stderr, flush=True))
            first = next(iter(doc["sweep"].values()))
            print(cap, json.dumps({k: (v["invalid"], v["executions"], v["posed"]) for k, v in first.items()}),
                  flush=True)
            continue
        if a.latency:
            doc = replays.latency_pass(converted, a.plan, out, progress=lambda m: print(m, file=sys.stderr, flush=True))
        elif a.surrogate:
            doc = replays.surrogate_pass(converted, a.plan, out,
                                          progress=lambda m: print(m, file=sys.stderr, flush=True))
        else:
            doc = replays.run(converted, a.plan, out, which=which,
                               progress=lambda m: print(m, file=sys.stderr, flush=True))
        print(cap, json.dumps({k: (v["U"], v["M"], v["posed"]) for k, v in doc["conditions"].items()}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
