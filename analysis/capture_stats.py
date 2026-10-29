"""Per-capture distributions and robustness of the follow-up comparisons, from the per-capture adapter outputs.

    python -m analysis.capture_stats                 # writes results/stage2/analyses/per_capture_stats.json

For every comparison of Table 3 (and the secondary ones) this computes, from ``results/stage2/adapter/*.json``:

* the per-capture unsafe executions and missed opportunities of both views (the rows behind Table 3; the totals are
  checked against ``analysis.tables`` before anything else is written);
* leave-one-capture-out: the totals and the stratified capture-bootstrap interval of the difference with each
  capture removed in turn;
* per scenario: totals and a capture-bootstrap interval within the scenario;
* the comparison without the three captures of scenario G3 (catalog rollout, container termination), which hold
  most unsafe executions;
* for restart in arm G, the per-capture counts of every gate condition in the same primary cells (including the
  matched latest-snapshot view L_p, the freshness sensitivity F = 600 s and the hindsight view), and the counts by
  dispatch delay and by knowledge cutoff.

The bootstrap is ``analysis.stats``'s: 10,000 resamples of captures within scenario strata, seed 0, R type 7
percentiles. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import stats as ST, tables as TB  # noqa: E402

SCENARIO_G3 = "G3"
SCENARIO_NAMES = OrderedDict([
    ("G1", "recommendation rollout, CPU fault"), ("G2", "recommendation rollout, container termination"),
    ("G3", "catalog rollout, container termination"), ("G4", "benign rollout"),
    ("D1", "recommendation rollout, CPU fault (one replica)"), ("D2", "settled catalog rollout, CPU fault")])
RESTART_CELLS = {"action": "B", "stream": "S0", "Delta_s": (0, 5, 30), "delta_s": (0, 10, 30, 80)}
CONDITIONS_G = ("T_p", "L_p", "T_w", "L_w", "R", "L-kappa", "c-hind", "T@F600", "L@F600")


def cell_sums(adapter: dict, condition: str, action: str, stream: str, Deltas, deltas) -> dict:
    """Sums over the T1 cells of one condition: unsafe executions, missed opportunities, eligible requests, posed."""
    out = {"U": 0, "M": 0, "GT2": 0, "posed": 0, "cells": 0}
    for c in adapter["T1_cells"]:
        if (c["condition"] == condition and c["action"] == action and c["stream"] == stream
                and c["Delta_s"] in Deltas and c["delta_s"] in deltas):
            out["U"] += int(c["unsafe_executions"]["count"])
            out["M"] += int(c["missed_opportunities"]["total"])
            out["GT2"] += int(c["missed_opportunities"]["of_requests_labelled_GT2"])
            out["posed"] += int(c["posed"])
            out["cells"] += 1
    return out


def strata_without(strata, drop_captures=(), drop_scenarios=()):
    return [(s, [c for c in caps if c not in drop_captures]) for s, caps in strata if s not in drop_scenarios]


def boot(strata, values_by_capture: dict) -> dict:
    """Stratified capture bootstrap of the sum of a per-capture value over the captures listed in ``strata``."""
    caps = TB.flatten(strata)
    positions = TB.strata_positions([(s, cs) for s, cs in strata if cs])
    resamples = ST.draw_resamples(positions)
    return ST.bootstrap(resamples, [values_by_capture[c] for c in caps])


def robustness(rows: list, strata) -> OrderedDict:
    """Leave-one-capture-out, per-scenario and without-G3 summaries of one comparison."""
    by_cap = {r["capture"]: r for r in rows}
    d_u = {c: r["d_U"] for c, r in by_cap.items()}
    d_m = {c: r["d_M"] for c, r in by_cap.items()}
    out = OrderedDict()
    loco = []
    for cap in TB.flatten(strata):
        rest = strata_without(strata, drop_captures=(cap,))
        keep = TB.flatten(rest)
        bu, bm = boot(rest, d_u), boot(rest, d_m)
        loco.append(OrderedDict([
            ("removed", cap), ("scenario", by_cap[cap]["scenario"]),
            ("U_X", sum(by_cap[c]["U_X"] for c in keep)), ("U_Y", sum(by_cap[c]["U_Y"] for c in keep)),
            ("M_X", sum(by_cap[c]["M_X"] for c in keep)), ("M_Y", sum(by_cap[c]["M_Y"] for c in keep)),
            ("posed", sum(by_cap[c]["posed"] for c in keep)),
            ("D_U", bu["point"]), ("D_U_95", bu["interval_95"]), ("D_U_excludes_0", bu["excludes_0_95"]),
            ("D_M", bm["point"]), ("D_M_95", bm["interval_95"])]))
    out["leave_one_capture_out"] = loco
    out["leave_one_capture_out_summary"] = {
        "D_U_range": [min(r["D_U"] for r in loco), max(r["D_U"] for r in loco)],
        "D_U_interval_excludes_0_in": sum(1 for r in loco if r["D_U_excludes_0"]), "of": len(loco)}
    per_s = OrderedDict()
    for s, caps in strata:
        if not caps:
            continue
        sub = [(s, caps)]
        bu, bm = boot(sub, d_u), boot(sub, d_m)
        per_s[s] = OrderedDict([
            ("scenario", SCENARIO_NAMES.get(s, s)), ("captures", len(caps)),
            ("U_X", sum(by_cap[c]["U_X"] for c in caps)), ("U_Y", sum(by_cap[c]["U_Y"] for c in caps)),
            ("M_X", sum(by_cap[c]["M_X"] for c in caps)), ("M_Y", sum(by_cap[c]["M_Y"] for c in caps)),
            ("posed", sum(by_cap[c]["posed"] for c in caps)),
            ("D_U", bu["point"]), ("D_U_95", bu["interval_95"]), ("D_M", bm["point"]), ("D_M_95", bm["interval_95"]),
            ("captures_X_more_equal_fewer", [sum(1 for c in caps if by_cap[c]["U_X"] > by_cap[c]["U_Y"]),
                                             sum(1 for c in caps if by_cap[c]["U_X"] == by_cap[c]["U_Y"]),
                                             sum(1 for c in caps if by_cap[c]["U_X"] < by_cap[c]["U_Y"])])])
    out["per_scenario"] = per_s
    if any(s == SCENARIO_G3 for s, _ in strata):
        rest = strata_without(strata, drop_scenarios=(SCENARIO_G3,))
        keep = TB.flatten(rest)
        bu, bm = boot(rest, d_u), boot(rest, d_m)
        out["without_G3"] = OrderedDict([
            ("captures", len(keep)), ("U_X", sum(by_cap[c]["U_X"] for c in keep)),
            ("U_Y", sum(by_cap[c]["U_Y"] for c in keep)), ("M_X", sum(by_cap[c]["M_X"] for c in keep)),
            ("M_Y", sum(by_cap[c]["M_Y"] for c in keep)), ("posed", sum(by_cap[c]["posed"] for c in keep)),
            ("D_U", bu["point"]), ("D_U_95", bu["interval_95"]), ("D_U_98_33", bu["interval_98_33"]),
            ("D_M", bm["point"]), ("D_M_95", bm["interval_95"]),
            ("captures_X_more_equal_fewer", [sum(1 for c in keep if by_cap[c]["U_X"] > by_cap[c]["U_Y"]),
                                             sum(1 for c in keep if by_cap[c]["U_X"] == by_cap[c]["U_Y"]),
                                             sum(1 for c in keep if by_cap[c]["U_X"] < by_cap[c]["U_Y"])])])
    return out


def restart_conditions(D: dict, strata) -> OrderedDict:
    """Per capture and condition, restart in arm G over the H-G3 primary cells (all dispatch delays) and over the
    approval-reuse cells (positive delays); totals by dispatch delay and by cutoff."""
    caps = TB.flatten(strata)
    scen = {c: s for s, cs in strata for c in cs}
    rc = RESTART_CELLS
    per = OrderedDict()
    for cap in caps:
        a = D["adapter"][cap]
        row = OrderedDict([("scenario", scen[cap])])
        for cond in CONDITIONS_G:
            row[cond] = cell_sums(a, cond, rc["action"], rc["stream"], rc["Delta_s"], rc["delta_s"])
            row[cond + " (delta > 0)"] = cell_sums(a, cond, rc["action"], rc["stream"], rc["Delta_s"], (10, 30, 80))
        per[cap] = row
    totals = OrderedDict()
    for cond in CONDITIONS_G:
        for key in (cond, cond + " (delta > 0)"):
            totals[key] = {k: sum(per[c][key][k] for c in caps) for k in ("U", "M", "GT2", "posed", "cells")}
    by_delay = OrderedDict()
    for cond in CONDITIONS_G:
        by_delay[cond] = OrderedDict()
        for d in rc["delta_s"]:
            by_delay[cond]["delta %d s" % d] = {
                k: sum(cell_sums(D["adapter"][c], cond, rc["action"], rc["stream"], rc["Delta_s"], (d,))[k]
                       for c in caps) for k in ("U", "M", "posed")}
        for k0 in rc["Delta_s"]:
            by_delay[cond]["cutoff +%d s" % k0] = {
                k: sum(cell_sums(D["adapter"][c], cond, rc["action"], rc["stream"], (k0,), rc["delta_s"])[k]
                       for c in caps) for k in ("U", "M", "posed")}
    return OrderedDict([("cells", {k: list(v) if isinstance(v, tuple) else v for k, v in rc.items()}),
                        ("per_capture", per), ("totals", totals), ("by_delay_and_cutoff", by_delay)])


def compute(results) -> OrderedDict:
    D = TB.load(results)
    reg = D["register"]
    published = TB.compute(results)
    bad = TB.check(published, TB.EXPECTED)
    if bad:
        raise SystemExit("the published tables do not reproduce: %s" % bad[:3])
    out = OrderedDict([("source", "results/stage2/adapter/*.json; analysis.tables reproduces every published value")])
    comps = OrderedDict()
    for c in TB.COMPARISONS:
        cmp_ = published["comparisons"][c["id"]]
        strata = TB.population(reg, c["population"])
        rows = [OrderedDict((k, r[k]) for k in ("capture", "scenario", "U_X", "U_Y", "M_X", "M_Y", "posed", "GT2",
                                                  "d_U", "d_M")) for r in cmp_["per_capture"]]
        entry = OrderedDict([("title", c["title"]), ("X", c["X"]), ("Y", c["Y"]), ("population", c["population"]),
                             ("totals", cmp_["totals"]), ("D_U", cmp_["D_U"]), ("D_M", cmp_["D_M"]),
                             ("per_capture", rows)])
        entry.update(robustness(rows, strata))
        comps[c["id"]] = entry
    out["comparisons"] = comps
    out["restart_arm_G_conditions"] = restart_conditions(D, TB.population(reg, "G"))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "results/stage2/analyses/per_capture_stats.json"))
    a = ap.parse_args(argv)
    o = compute(a.results)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(o, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    for cid, c in o["comparisons"].items():
        lo = c["leave_one_capture_out_summary"]
        wc = c.get("without_G3")
        print("%-24s U %d vs %d; LOCO D_U %s, interval excludes 0 in %d/%d%s" % (
            cid, c["totals"]["U_X"], c["totals"]["U_Y"], lo["D_U_range"], lo["D_U_interval_excludes_0_in"], lo["of"],
            "; without G3: %d vs %d, D_U %s %s" % (wc["U_X"], wc["U_Y"], wc["D_U"], wc["D_U_95"]) if wc else ""))
        for s, v in c["per_scenario"].items():
            print("    %s: %d vs %d (%d posed), D_U %s %s; missed %d vs %d" % (
                s, v["U_X"], v["U_Y"], v["posed"], v["D_U"], v["D_U_95"], v["M_X"], v["M_Y"]))
    t = o["restart_arm_G_conditions"]["totals"]
    print("restart, arm G, primary cells:", {k: (v["U"], v["M"], v["posed"]) for k, v in t.items()})
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
