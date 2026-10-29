#!/usr/bin/env python3
"""Further replays of the arm-G restart decisions (govstage2/replays.py) on converted captures.

    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 \
        [--only G1-001,G3-002] [--conditions T_p,L_p,R,T_p@R]          # results/stage2/analyses/replays
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --latency
                                                                        # results/stage2/analyses/latency
    python3 experiments/governance-stage2/run_replays.py --captures-root phase3/captures_stage2 --surrogate
                                                                        # results/stage2/analyses/surrogate

Writes one JSON file per capture (<out>/<capture>.json); a capture whose file exists is skipped, so an interrupted
run continues where it stopped. The included arm-G captures are read from results/stage2/captures.json.
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

from govstage2 import replays  # noqa: E402
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
    a = ap.parse_args(argv)
    if a.out is None:
        a.out = str(ROOT / "results/stage2/analyses" / ("latency" if a.latency else "surrogate" if a.surrogate
                                                        else "replays"))
    register = json.loads((ROOT / "results/stage2/captures.json").read_text(encoding="utf-8"))
    captures = [c for s in register["populations"]["G"] for c in s["captures"]]
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
