#!/usr/bin/env python3
"""Where snapshot-based attribution starts to fail: the diagnosis control (arm D) under a sweep of record delays.

    python3 experiments/diagnosis-control-v1/run_diagnosis_stress.py --captures-root phase3/captures_stage2 \
        --out results/stage2/analyses/diagnosis_stress.json

For every included arm-D capture (results/stage2/diagnosis/<capture>.json, category primary_*), the context bridge
of ``run_diagnosis_control_v1.py`` (unchanged: policies, windows, ranker, hindsight reference) is run on the poller's
records under three perturbation families, each at delays d = 2, 5, 10, 20, 30, 45, 60, 90 s:

* ``delayed_switch_{d}s``: only the switch poll's records (the first poll that shows a Pod of the changed service
  leaving ready, i.e. the replacement becoming the serving Pod) arrive d s later; everything else as captured;
* ``corrected_late_{d}s``: those records first arrive with the preceding state and their corrected versions d s
  later (the bridge's own corrected_late streams, here at more delays);
* ``delayed_api_{d}s``: every API record arrives d s later (the bridge's delayed_api streams, at more delays);

plus the ``complete`` stream, at knowledge cutoffs Delta = 0, 5, 10, 20, 30, 60 s after the onset, for the
policies latest_state, temporal_join, bitemporal_abstain (F = 600 s and 30 s) and the span-identity hindsight
reference. Per cell: whether the faulty Pod is ranked first, and the time from the switch poll's observation to the
cutoff. Per capture, the poller's Pod-list intervals (``pod_list_intervals``). Counts of captures only.
"""
from __future__ import annotations

import argparse
import bisect
import json
import statistics
import sys
from collections import OrderedDict
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _path in (ROOT / "src", HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import run_diagnosis_control_v1 as DC  # noqa: E402
from aiops_kg import context_bridge as B  # noqa: E402
from aiops_kg import replay as R  # noqa: E402

DELAYS = (2, 5, 10, 20, 30, 45, 60, 90)
DELTAS = tuple((f"{d} s", d) for d in (0, 5, 10, 20, 30, 60))


def switch_targets(bridge):
    """The switch poll's revealing records, found exactly as ``bridge_streams`` finds them."""
    task = bridge.primary_task
    keys = {c.key for c in task.candidates} if task else set()
    switch = sorted((r for r, prev in R.revealing_records(bridge.records, mode="change")
                     if r.subject in keys and prev == "ready" and r.value in B.RETIRED),
                    key=lambda r: (r.observed_at, r.record_id))
    if not switch:
        return None, frozenset()
    at = switch[0].observed_at
    _, manifest = R.drop_transition(bridge.records, mode="change", where=lambda r: r.observed_at == at)
    return at, frozenset(e["record_id"] for e in manifest["records"])


LIST_GAP_US = 500_000   # Pod observations closer than this belong to one Pod list


def pod_list_intervals(bridge, at) -> OrderedDict:
    """The poller's Pod lists in the bridge's records (Pod observations less than 0.5 s apart form one list; a list
    is dated by its first observation): their number, the median and the longest interval between successive lists,
    the interval that ends with the switch poll (from the preceding list to the switch observation) and the one that
    follows it (from the switch observation to the next list)."""
    stamps = sorted({r.observed_at for r in bridge.records
                     if r.kind in DC.API_KINDS and r.subject.startswith("Pod/")})
    lists = []
    for t in stamps:
        if not lists or t - lists[-1][1] > LIST_GAP_US:
            lists.append([t, t])
        else:
            lists[-1][1] = t
    firsts = [first for first, _ in lists]
    gaps = [(b - a) / R.US for a, b in zip(firsts, firsts[1:])]
    before = after = None
    if at is not None:
        k = bisect.bisect_right(firsts, at)
        if k >= 2:
            before = round((at - firsts[k - 2]) / R.US, 3)
        if k < len(firsts):
            after = round((firsts[k] - at) / R.US, 3)
    return OrderedDict([("lists", len(firsts)),
                        ("median_s", round(statistics.median(gaps), 3) if gaps else None),
                        ("max_s", round(max(gaps), 3) if gaps else None),
                        ("ending_with_switch_s", before), ("following_switch_s", after)])


def stress_streams(bridge):
    base = bridge.records
    at, targets = switch_targets(bridge)
    out = [{"name": "complete", "family": "complete", "records": base, "description": "as captured",
            "manifest": {"perturbation": "none"}}]
    for d in DELAYS:
        if targets:
            records, manifest = R.delay(base, d, where=lambda r: r.record_id in targets)
            out.append({"name": f"delayed_switch_{d}s", "family": "delayed_switch", "records": records,
                        "description": f"the switch poll's {len(targets)} records available {d} s later",
                        "manifest": {"perturbation": "delay", "seconds": d, "changed": manifest["changed"]}})
            records, manifest = R.correct_late(base, d, where=lambda r: r.record_id in targets)
            out.append({"name": f"corrected_late_{d}s", "family": "corrected_late", "records": records,
                        "description": f"the switch poll's records first with the preceding state, corrected {d} s "
                                       "later", "manifest": manifest})
        records, manifest = R.delay(base, d, kinds=DC.API_KINDS)
        out.append({"name": f"delayed_api_{d}s", "family": "delayed_api", "records": records,
                    "description": f"every API record available {d} s later",
                    "manifest": {"perturbation": "delay", "seconds": d, "changed": manifest["changed"]}})
    return out, at, targets


class _NoLoader:
    report = {"loader": "context_bridge.load_capture_input (development capture)"}


def analyse(capture: Path, *, development: bool = False) -> dict:
    """Every stress stream of one capture at the cutoffs ``DELTAS`` (the diagnosis control's own grid is restored
    afterwards)."""
    policies = DC.make_policies()
    truth = B.load_capture_truth(capture)
    if development:
        bridge, store = B.load_capture_input(capture, root=ROOT), _NoLoader()
    else:
        bridge, store = DC.load_bridge_input(capture, DC.POLLER)
    streams, at, targets = stress_streams(bridge)
    grid, DC.DELTAS = DC.DELTAS, DELTAS
    try:
        block = DC.observer_block(bridge, store, streams, [], policies, truth)
    finally:
        DC.DELTAS = grid
    onset = truth["onset"]
    rows = []
    for r in block["rows"]:
        c = B.decision_cutoff(onset, r["delta_seconds"])
        rows.append(OrderedDict([("stream", r["stream"]), ("delta_s", r["delta_seconds"]), ("policy", r["policy"]),
                                 ("top1", bool(r["top1"])), ("outcome", r["outcome"]), ("rank", r["rank"]),
                                 ("candidates", r["candidates"]),
                                 ("cutoff_minus_switch_s", None if at is None else round((c - at) / 1e6, 3))]))
    return OrderedDict([("capture", capture.name), ("stage", "development" if development else "follow-up"),
                        ("onset", R.iso(onset)),
                        ("switch_observed", R.iso(at) if at is not None else None),
                        ("switch_records", len(targets)),
                        ("onset_minus_switch_s", None if at is None else round((onset - at) / 1e6, 3)),
                        ("pod_list_intervals", pod_list_intervals(bridge, at)),
                        ("rows", rows)])


def summarise(captures: list) -> dict:
    """Per stream x Delta x policy: in how many captures the faulty Pod is ranked first."""
    table = OrderedDict()
    for cap in captures:
        for r in cap["rows"]:
            key = "%s | %d s | %s" % (r["stream"], r["delta_s"], r["policy"])
            entry = table.setdefault(key, {"top1": 0, "n": 0, "failing": []})
            entry["n"] += 1
            entry["top1"] += r["top1"]
            if not r["top1"]:
                entry["failing"].append(cap["capture"])
    return table


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures-root", required=True)
    ap.add_argument("--out", default=str(ROOT / "results/stage2/analyses/diagnosis_stress.json"))
    ap.add_argument("--dev-captures-root", default=None,
                    help="also the five development diagnosis captures (I2-002, I3-004, I6-002, I6-003, I7-001)")
    a = ap.parse_args(argv)
    included = []
    for path in sorted((ROOT / "results/stage2/diagnosis").glob("D*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if str(doc.get("category", "")).startswith("primary_"):
            included.append(path.stem)
    out = []
    for name in included:
        res = analyse(Path(a.captures_root) / name)
        out.append(res)
        print(name, "switch-to-onset %.1f s" % res["onset_minus_switch_s"] if res["onset_minus_switch_s"] is not None
              else "no switch", flush=True)
    dev = []
    if a.dev_captures_root:
        for name in ("I2-002", "I3-004", "I6-002", "I6-003", "I7-001"):
            res = analyse(Path(a.dev_captures_root) / name, development=True)
            dev.append(res)
            print(name, "switch-to-onset %.1f s" % res["onset_minus_switch_s"]
                  if res["onset_minus_switch_s"] is not None else "no switch", flush=True)
    doc = OrderedDict([("captures", included), ("development_captures", [d["capture"] for d in dev]),
                       ("delays_s", list(DELAYS)), ("deltas_s", [d for _, d in DELTAS]),
                       ("per_capture", out), ("summary", summarise(out)),
                       ("development_per_capture", dev), ("development_summary", summarise(dev))])
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
