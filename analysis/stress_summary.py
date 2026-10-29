"""Where snapshot-based attribution starts to fail, from results/stage2/analyses/diagnosis_stress.json.

    python -m analysis.stress_summary        # writes results/stage2/analyses/diagnosis_stress_summary.json

Curves count captures that have the family's streams (a capture without a switch poll has no switch streams; its
complete stream is then left out of that family's curve too). For every capture, perturbation family, cutoff and
policy: the smallest record delay at which the faulty Pod is no longer ranked first (``first_failing_delay_s``; None if it stays first at every delay), next to the time between the
switch poll's observation and the cutoff. A record delayed beyond that time is not available at the cutoff. The
poller's Pod-list intervals of each capture are carried over (``pod_list_intervals``). Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
POLICIES = ("latest_state", "temporal_join", "bitemporal_abstain_F600", "bitemporal_abstain_F30")
FAMILIES = ("delayed_switch", "corrected_late", "delayed_api")


def thresholds(cap: dict, delays) -> list:
    rows = {(r["stream"], r["delta_s"], r["policy"]): r for r in cap["rows"]}
    hind = {r["delta_s"]: r["top1"] for r in cap["rows"] if r["policy"] == "hindsight"}
    out = []
    deltas = sorted({r["delta_s"] for r in cap["rows"]})
    for fam in FAMILIES:
        for delta in deltas:
            for pol in POLICIES:
                complete = rows.get(("complete", delta, pol))
                if complete is None:
                    continue
                first_fail = None
                if complete["top1"]:
                    for d in delays:
                        r = rows.get(("%s_%ds" % (fam, d), delta, pol))
                        if r is not None and not r["top1"]:
                            first_fail = d
                            break
                out.append(OrderedDict([("family", fam), ("delta_s", delta), ("policy", pol),
                                        ("complete_top1", complete["top1"]), ("hindsight_top1", hind.get(delta)),
                                        ("first_failing_delay_s", first_fail),
                                        ("cutoff_minus_switch_s", complete["cutoff_minus_switch_s"])]))
    return out


def compute(path) -> OrderedDict:
    return compute_from_doc(json.loads(Path(path).read_text(encoding="utf-8")))


def compute_from_doc(doc: dict) -> OrderedDict:
    delays = doc["delays_s"]
    out = OrderedDict([("delays_s", delays), ("deltas_s", doc["deltas_s"])])
    for stage, key in (("follow_up", "per_capture"), ("development", "development_per_capture")):
        caps = doc.get(key) or []
        per = OrderedDict()
        for cap in caps:
            per[cap["capture"]] = {"onset_minus_switch_s": cap["onset_minus_switch_s"],
                                   "pod_list_intervals": cap.get("pod_list_intervals"),
                                   "thresholds": thresholds(cap, delays)}
        # how often the failure begins exactly when the delayed record misses the cutoff
        consistent = defaultdict(lambda: [0, 0, 0])   # (fails at all, fails only once delay > cutoff-switch, n)
        for name, v in per.items():
            for t in v["thresholds"]:
                if not t["complete_top1"] or t["cutoff_minus_switch_s"] is None:
                    continue
                k = (t["family"], t["policy"])
                consistent[k][2] += 1
                if t["first_failing_delay_s"] is not None:
                    consistent[k][0] += 1
                    consistent[k][1] += t["first_failing_delay_s"] > t["cutoff_minus_switch_s"]
        curves = OrderedDict()
        for fam in FAMILIES:
            for pol in POLICIES + ("hindsight",):
                members = [cap for cap in caps if any(r["stream"].startswith(fam + "_") for r in cap["rows"])]
                for delta in doc["deltas_s"]:
                    pts = []
                    for d in [0] + list(delays):
                        stream = "complete" if d == 0 else "%s_%ds" % (fam, d)
                        if pol == "hindsight":
                            stream = "-"
                        n = top = 0
                        for cap in members:
                            for r in cap["rows"]:
                                if r["stream"] == stream and r["delta_s"] == delta and r["policy"] == pol:
                                    n += 1
                                    top += r["top1"]
                        pts.append([d, top, n])
                    curves["%s | %s | %d s" % (fam, pol, delta)] = pts
        out[stage] = OrderedDict([("captures", list(per)), ("per_capture", per),
                                  ("failures_vs_cutoff", {"%s | %s" % k: {"cells_failing": v[0],
                                                                          "of_which_delay_exceeds_cutoff_gap": v[1],
                                                                          "cells": v[2]}
                                                          for k, v in sorted(consistent.items())}),
                                  ("curves_top1_of_n", curves)])
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stress", default=str(ROOT / "results/stage2/analyses/diagnosis_stress.json"))
    ap.add_argument("--out", default=str(ROOT / "results/stage2/analyses/diagnosis_stress_summary.json"))
    a = ap.parse_args(argv)
    o = compute(a.stress)
    Path(a.out).write_text(json.dumps(o, indent=1) + "\n", encoding="utf-8")
    for stage in ("follow_up", "development"):
        s = o.get(stage)
        if not s:
            continue
        print("==", stage, s["captures"])
        for k, v in s["failures_vs_cutoff"].items():
            print("  %-45s failing %d of %d cells; delay beyond the cutoff gap in %d" % (
                k, v["cells_failing"], v["cells"], v["of_which_delay_exceeds_cutoff_gap"]))
        for name, v in s["per_capture"].items():
            fails = [(t["family"][:8], t["delta_s"], t["policy"][:12], t["first_failing_delay_s"],
                      t["cutoff_minus_switch_s"]) for t in v["thresholds"]
                     if t["first_failing_delay_s"] is not None and t["policy"] in ("temporal_join", "latest_state")]
            print("  %s switch-to-onset %s s; first failures (family, Delta, policy, delay, cutoff-switch): %s" % (
                name, v["onset_minus_switch_s"], fails[:12]))
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
