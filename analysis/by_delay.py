"""Executions, unsafe executions and missed opportunities by dispatch delay and by cutoff, restart in arm G.

    python -m analysis.by_delay        # writes results/stage2/analyses/by_delay.json

Views: the adapter's published conditions, from the T1 cells of results/stage2/adapter/*.json (T_p, L_p, T_w, L_w,
R, L-kappa, c-hind, T@F600, L@F600), and the further replays, from the per-cell counts (``by_cell``) of
results/stage2/analyses/replays/*.json (T_p@R, L_p@R, T_p+lag, T_p[event-time], T_p[thin k], L_p[thin k]) and
results/stage2/analyses/latency/*.json (T_p[late 5], T_p[late 30]). Scope: action B, stream S0, the twelve primary
cells (cutoffs 0, 5, 30 s; dispatch delays 0, 10, 30, 80 s) of the 16 included arm-G captures.

Output: {view: {"delta 0 s": counts, ..., "cutoff +0 s": counts, ..., "total": counts}} with counts =
{"posed", "executions", "U", "M", "GT2"}: posed decisions, executed ALLOW verdicts, unsafe executions, missed
opportunities and opportunities at posing. Two further keys give, for the captures with a kill (scenarios G2 and
G3), how long the fault's target Pod stayed not ready after the kill, from the labeller's kubelet history
(results/stage2/analyses/surrogate/*.json, ``fault_not_ready``): "fault_not_ready_s" {capture: seconds} and
"fault_not_ready_s_by_scenario" {scenario: {"captures", "with_interval", "min", "max"}}. Kubelet stamps are whole
seconds, so each interval is exact to about 1 s.

Checks (the script stops on any failure): the replayed T_p, L_p, R and L-kappa equal the published T1 cells in every
cell of every capture; T_p and T_p[event-time] of the latency pass equal those of the replays in every cell; the
totals equal per_capture_stats.json (published views, also by delay and by cutoff) and replays_summary.json
(replayed views). Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import tables as TB  # noqa: E402

ACTION, STREAM = "B", "S0"
CUTOFFS, DELAYS = (0, 5, 30), (0, 10, 30, 80)
FIELDS = ("posed", "executions", "U", "M", "GT2")
PUBLISHED = ("T_p", "L_p", "T_w", "L_w", "R", "L-kappa", "c-hind", "T@F600", "L@F600")
REPLAYED = ("T_p@R", "L_p@R", "T_p+lag", "T_p[thin 2]", "L_p[thin 2]", "T_p[thin 4]", "L_p[thin 4]",
            "T_p[event-time]")
LATENCY = ("T_p[late 5]", "T_p[late 30]")
KILL_SCENARIOS = ("G2", "G3")
ORDER = ("T_p", "L_p", "T_w", "L_w", "R", "L-kappa", "c-hind", "T@F600", "L@F600", "T_p@R", "L_p@R", "T_p+lag",
         "T_p[thin 2]", "L_p[thin 2]", "T_p[thin 4]", "L_p[thin 4]", "T_p[late 5]", "T_p[late 30]", "T_p[event-time]")
CELL_KEY = re.compile(r"^cutoff \+(\S+) s \| delta (\S+) s$")


def _num(text: str):
    value = float(text)
    return int(value) if value.is_integer() else value


def published_cells(doc: dict, view: str) -> dict:
    """{(cutoff s, delay s): counts} from one capture's published T1 cells."""
    out = {}
    for c in doc["T1_cells"]:
        if (c["condition"] == view and c["action"] == ACTION and c["stream"] == STREAM
                and c["Delta_s"] in CUTOFFS and c["delta_s"] in DELAYS):
            key = (c["Delta_s"], c["delta_s"])
            if key in out:
                raise SystemExit("duplicate published cell %s %s" % (view, key))
            out[key] = {"posed": int(c["posed"]),
                        "executions": sum(int(n) for n in c["executions_by_label"]["counts"].values()),
                        "U": int(c["unsafe_executions"]["count"]),
                        "M": int(c["missed_opportunities"]["total"]),
                        "GT2": int(c["missed_opportunities"]["of_requests_labelled_GT2"])}
    return out


def replayed_cells(doc: dict, view: str) -> dict:
    """{(cutoff s, delay s): counts} from one capture's replay output (``by_cell``)."""
    out = {}
    for key, counts in doc["conditions"][view]["by_cell"].items():
        m = CELL_KEY.match(key)
        if not m:
            raise SystemExit("unexpected cell key %r" % key)
        out[(_num(m.group(1)), _num(m.group(2)))] = {f: counts[f] for f in FIELDS}
    return out


def breakdown(cells_by_capture: dict) -> OrderedDict:
    """Sums over captures by dispatch delay, by cutoff and in total."""
    def total(keep):
        acc = OrderedDict((f, 0) for f in FIELDS)
        for cells in cells_by_capture.values():
            for (cutoff, delay), counts in cells.items():
                if keep(cutoff, delay):
                    for f in FIELDS:
                        acc[f] += counts[f]
        return acc
    out = OrderedDict()
    for d in DELAYS:
        out["delta %d s" % d] = total(lambda cutoff, delay, d=d: delay == d)
    for c0 in CUTOFFS:
        out["cutoff +%d s" % c0] = total(lambda cutoff, delay, c0=c0: cutoff == c0)
    out["total"] = total(lambda cutoff, delay: True)
    return out


def compute(results) -> tuple:
    results = Path(results)
    reg = json.loads((results / "stage2/captures.json").read_text(encoding="utf-8"))
    caps = TB.flatten(TB.population(reg, "G"))

    def load(folder, cap):
        return json.loads((results / folder / (cap + ".json")).read_text(encoding="utf-8"))

    published = {c: load("stage2/adapter", c) for c in caps}
    replays = {c: load("stage2/analyses/replays", c) for c in caps}
    latency = {c: load("stage2/analyses/latency", c) for c in caps}
    cells = OrderedDict()
    for view in PUBLISHED:
        cells[view] = {c: published_cells(published[c], view) for c in caps}
    for view in REPLAYED:
        cells[view] = {c: replayed_cells(replays[c], view) for c in caps}
    for view in LATENCY:
        cells[view] = {c: replayed_cells(latency[c], view) for c in caps}
    problems = []
    for view, by_cap in cells.items():
        for c, cs in by_cap.items():
            if sorted(cs) != sorted((a, b) for a in CUTOFFS for b in DELAYS):
                problems.append("%s %s: cells %s" % (view, c, sorted(cs)))
    for view in ("T_p", "L_p", "R", "L-kappa"):
        for c in caps:
            if replayed_cells(replays[c], view) != cells[view][c]:
                problems.append("replayed %s differs from the published cells in %s" % (view, c))
    for view in ("T_p", "T_p[event-time]"):
        for c in caps:
            if replayed_cells(latency[c], view) != replayed_cells(replays[c], view):
                problems.append("latency pass %s differs from the replay in %s" % (view, c))
    out = OrderedDict((view, breakdown(cells[view])) for view in ORDER)
    not_ready, by_scenario = OrderedDict(), OrderedDict()
    for scenario, members in TB.population(reg, "G"):
        if scenario not in KILL_SCENARIOS:
            continue
        values = []
        for c in members:
            seconds = load("stage2/analyses/surrogate", c)["fault_not_ready"]["seconds"]
            not_ready[c] = seconds
            if seconds is not None:
                values.append(seconds)
        by_scenario[scenario] = OrderedDict([("captures", len(members)), ("with_interval", len(values)),
                                             ("min", min(values) if values else None),
                                             ("max", max(values) if values else None)])
    out["fault_not_ready_s"] = not_ready
    out["fault_not_ready_s_by_scenario"] = by_scenario
    stats = json.loads((results / "stage2/analyses/per_capture_stats.json").read_text(encoding="utf-8"))
    summary = json.loads((results / "stage2/analyses/replays_summary.json").read_text(encoding="utf-8"))
    checked = OrderedDict()
    for view in PUBLISHED:
        ref = stats["restart_arm_G_conditions"]["totals"][view]
        ref_split = stats["restart_arm_G_conditions"]["by_delay_and_cutoff"][view]
        for f in ("U", "M", "GT2", "posed"):
            if out[view]["total"][f] != ref[f]:
                problems.append("%s %s: %s here, %s in per_capture_stats.json" % (view, f, out[view]["total"][f],
                                                                                 ref[f]))
        for key, counts in ref_split.items():
            for f, v in counts.items():
                if out[view][key][f] != v:
                    problems.append("%s %s %s: %s here, %s in per_capture_stats.json" % (view, key, f,
                                                                                        out[view][key][f], v))
        checked[view] = "per_capture_stats.json"
    for view in REPLAYED + ("T_p", "L_p", "R", "L-kappa"):
        ref = summary["totals"][view]
        for f in FIELDS:
            if out[view]["total"][f] != ref[f]:
                problems.append("%s %s: %s here, %s in replays_summary.json" % (view, f, out[view]["total"][f],
                                                                               ref[f]))
        checked[view] = (checked.get(view, "") + " and " if view in checked else "") + "replays_summary.json"
    for view in LATENCY:
        ref = summary["latency"]["totals"][view]
        for f in FIELDS:
            if out[view]["total"][f] != ref[f]:
                problems.append("%s %s: %s here, %s in replays_summary.json" % (view, f, out[view]["total"][f],
                                                                               ref[f]))
        checked[view] = "replays_summary.json (latency)"
    return out, problems, checked, len(caps)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "results/stage2/analyses/by_delay.json"))
    a = ap.parse_args(argv)
    out, problems, checked, n = compute(a.results)
    if problems:
        print("\n".join(problems[:20]))
        raise SystemExit("checks failed (%d problems); nothing written" % len(problems))
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print("%d captures; totals checked against: %s" % (n, "; ".join("%s %s" % kv for kv in checked.items())))
    head = "%-16s %7s %7s %5s %4s | executions by delay 0/10/30/80 s | by cutoff +0/+5/+30 s"
    print(head % ("view", "posed", "exec", "U", "M"))
    for view in ORDER:
        b = out[view]
        t = b["total"]
        print("%-16s %7d %7d %5d %4d | %s | %s" % (
            view, t["posed"], t["executions"], t["U"], t["M"],
            " ".join("%d" % b["delta %d s" % d]["executions"] for d in DELAYS),
            " ".join("%d" % b["cutoff +%d s" % c]["executions"] for c in CUTOFFS)))
    print("fault target not ready after the kill (s):", dict(out["fault_not_ready_s"]))
    print("by scenario:", json.dumps(out["fault_not_ready_s_by_scenario"]))
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
