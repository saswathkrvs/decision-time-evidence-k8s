"""Totals, paired comparisons and checks of the further replays of the arm-G restart decisions.

    python -m analysis.replay_summary          # writes results/stage2/analyses/replays_summary.json

Reads results/stage2/analyses/replays/*.json and, when present, latency/*.json and surrogate/*.json beside it.

* The recomputed T_p, L_p, R and L-kappa counts (the twelve restart cells of every included arm-G capture), in the
  replays and in the surrogate check, must equal the published per-capture counts in results/stage2/adapter/*.json;
  the script stops otherwise.
* Paired comparisons use analysis.stats's stratified capture bootstrap (10,000 resamples, seed 0).
Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import stats as ST, tables as TB  # noqa: E402
from analysis.capture_stats import cell_sums  # noqa: E402

PAIRS = (("T_p", "R"), ("T_p@R", "R"), ("T_p", "T_p@R"), ("T_p", "T_p+lag"), ("L_p@R", "R"),
         ("T_p", "T_p[thin 2]"), ("T_p", "T_p[thin 4]"), ("T_p", "T_p[event-time]"), ("T_p", "L-kappa"))


def load(results) -> dict:
    folder = Path(results) / "stage2/analyses/replays"
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))}


def verify(docs: dict, results) -> list:
    """Recomputed T_p, L_p, R and L-kappa against the published adapter outputs (same twelve restart cells)."""
    bad = []
    for cap, doc in docs.items():
        pub = json.loads((Path(results) / "stage2/adapter" / (cap + ".json")).read_text(encoding="utf-8"))
        for cond in ("T_p", "L_p", "R", "L-kappa"):
            if cond not in doc["conditions"]:
                continue
            ref = cell_sums(pub, cond, "B", "S0", (0, 5, 30), (0, 10, 30, 80))
            mine = doc["conditions"][cond]
            for key in ("U", "M", "posed", "GT2"):
                if ref[key] != mine[key]:
                    bad.append("%s %s %s: published %s, recomputed %s" % (cap, cond, key, ref[key], mine[key]))
    return bad


def compute(results) -> OrderedDict:
    docs = load(results)
    if not docs:
        raise SystemExit("no replay outputs under results/stage2/analyses/replays")
    bad = verify(docs, results)
    if bad:
        raise SystemExit("the replayed counts differ from the published ones: %s" % bad[:5])
    reg = json.loads((Path(results) / "stage2/captures.json").read_text(encoding="utf-8"))
    strata = [(s, [c for c in caps if c in docs]) for s, caps in TB.population(reg, "G")]
    caps = TB.flatten(strata)
    resamples = ST.draw_resamples(TB.strata_positions(strata))
    out = OrderedDict([("captures", len(caps)), ("verification", {"mismatches": bad, "checked": [
        "T_p", "L_p", "R", "L-kappa"]})])
    conds = [c for c in docs[caps[0]]["conditions"]]
    totals = OrderedDict()
    for cond in conds:
        totals[cond] = {k: sum(docs[c]["conditions"][cond][k] for c in caps) for k in ("posed", "U", "M", "GT2",
                                                                                       "executions")}
        labels = defaultdict(int)
        for c in caps:
            for lab, n in docs[c]["conditions"][cond]["executions_by_label"].items():
                labels[lab] += n
        totals[cond]["executions_by_label"] = dict(sorted(labels.items()))
    out["totals"] = totals
    per_scenario = OrderedDict()
    for s, members in strata:
        per_scenario[s] = {cond: [sum(docs[c]["conditions"][cond]["U"] for c in members),
                                  sum(docs[c]["conditions"][cond]["M"] for c in members)] for cond in conds}
    out["per_scenario_U_M"] = per_scenario
    out["per_capture_U"] = {c: {cond: docs[c]["conditions"][cond]["U"] for cond in conds} for c in caps}
    pairs = OrderedDict()
    for a, b in PAIRS:
        if a not in conds or b not in conds:
            continue
        du = [docs[c]["conditions"][a]["U"] - docs[c]["conditions"][b]["U"] for c in caps]
        dm = [docs[c]["conditions"][a]["M"] - docs[c]["conditions"][b]["M"] for c in caps]
        bu, bm = ST.bootstrap(resamples, du), ST.bootstrap(resamples, dm)
        pairs["%s minus %s" % (a, b)] = {"U": [totals[a]["U"], totals[b]["U"]], "M": [totals[a]["M"], totals[b]["M"]],
                                          "D_U": bu["point"], "D_U_95": bu["interval_95"],
                                          "D_M": bm["point"], "D_M_95": bm["interval_95"],
                                          "captures_a_more_equal_fewer": [sum(1 for x in du if x > 0),
                                                                          sum(1 for x in du if x == 0),
                                                                          sum(1 for x in du if x < 0)]}
    out["paired"] = pairs
    agree = OrderedDict()
    for c in caps:
        for name, v in docs[c]["agreement"].items():
            acc = agree.setdefault(name, defaultdict(int))
            for k, n in v.items():
                acc[k] += n
    out["agreement"] = {k: dict(v) for k, v in agree.items()}
    audit = OrderedDict()
    late = defaultdict(int)
    endstate = defaultdict(int)
    final = defaultdict(int)
    posed = 0
    waits = defaultdict(list)
    for c in caps:
        a = docs[c]["audit"]
        posed += a["posed"]
        for k, n in a["records_valid_before_cutoff_available_after"].items():
            late[k] += n
        for k, v in a["largest_wait_for_such_a_record_s"].items():
            if v["max"] is not None:
                waits[k].append(v["max"])
        for k in ("target_status_differs", "other_ready_pods_differ", "either_differs"):
            endstate[k] += a["end_of_capture_state"][k]
        for k in ("first_verdict_differs", "disposition_differs"):
            final[k] += a["final_store_verdict"][k]
    audit["posed"] = posed
    audit["decisions_with_records_valid_before_cutoff_available_after"] = dict(late)
    audit["largest_such_wait_s_max_over_captures"] = {k: max(v) for k, v in waits.items() if v}
    audit["event_time_reconstruction"] = out["agreement"].get("T_p vs T_p[event-time]")
    audit["event_time_unsafe_and_missed"] = [totals.get("T_p[event-time]", {}).get("U"),
                                             totals.get("T_p[event-time]", {}).get("M")] if "T_p[event-time]" in totals \
        else None
    audit["end_of_capture_state"] = dict(endstate)
    audit["final_store_verdict"] = dict(final)
    audit["per_capture"] = {c: {"late_either": docs[c]["audit"]["records_valid_before_cutoff_available_after"]["either"],
                                "event_time_first_verdict_differs":
                                    (docs[c]["audit"]["event_time_reconstruction"] or {}).get("first_verdict_differs"),
                                "end_state_differs": docs[c]["audit"]["end_of_capture_state"]["either_differs"],
                                "final_store_first_verdict_differs":
                                    docs[c]["audit"]["final_store_verdict"]["first_verdict_differs"],
                                "posed": docs[c]["audit"]["posed"]} for c in caps}
    out["audit"] = audit
    out["surrogate"] = surrogate_summary(results, strata)
    out["latency"] = latency_summary(results, strata)
    meta = OrderedDict()
    for c in caps:
        m = docs[c]["meta"]
        meta[c] = {"poll_intervals": m["poll_intervals"], "recheck_lag_s": m["recheck_lag_s"], "seconds": m["seconds"]}
    out["meta"] = meta
    return out


SURROGATE = ("T_p", "L-kappa", "R")
PER_CAPTURE_FIELDS = ("executions", "with_target_span_after", "with_probes_service", "with_probe_failure_service",
                      "distinct_failing_probe_calls_service", "with_probes_target_pod",
                      "with_probe_failure_target_pod", "distinct_failing_probe_calls_target_pod")


def surrogate_summary(results, strata) -> OrderedDict | None:
    """The surrogate check (results/stage2/analyses/surrogate/*.json), if present: sums over captures per condition
    and label group, and the unsafe executions per capture. The recomputed T_p, L-kappa and R counts must equal the
    published per-capture sums (``verification``)."""
    folder = Path(results) / "stage2/analyses/surrogate"
    docs = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))}
    if not docs:
        return None
    caps = [c for c in TB.flatten(strata) if c in docs]
    bad = verify({c: docs[c] for c in caps}, results)
    if bad:
        raise SystemExit("the surrogate check's counts differ from the published ones: %s" % bad[:5])
    out = OrderedDict([("captures", len(caps)), ("verification", {"mismatches": bad, "checked": list(SURROGATE)})])
    in_capture, statuses = defaultdict(int), defaultdict(int)
    for c in caps:
        for k, v in docs[c]["surrogate"]["probe_calls_in_capture"].items():
            in_capture[k] += v
        for k, v in docs[c]["surrogate"]["server_spans_in_capture_by_status"].items():
            statuses[k] += v
    out["probe_calls_in_captures"] = dict(in_capture)
    out["server_spans_in_captures_by_status"] = dict(statuses)
    groups = OrderedDict()
    for cond in SURROGATE:
        for c in caps:
            for group, g in (docs[c]["surrogate"].get(cond) or {}).items():
                acc = groups.setdefault(cond, OrderedDict()).setdefault(group, defaultdict(int))
                for k, v in g.items():
                    if isinstance(v, (int, float)) and not k.endswith(("_median", "_p90")):
                        acc[k] += v
                acc["captures"] += 1
    out["by_condition_and_label"] = {cond: {g: dict(v) for g, v in gs.items()} for cond, gs in groups.items()}
    per = OrderedDict()
    for cond in ("T_p", "L-kappa"):
        rows = OrderedDict()
        for c in caps:
            g = docs[c]["surrogate"].get(cond, {}).get("unsafe (V-target)")
            if g:
                rows[c] = {k: g[k] for k in PER_CAPTURE_FIELDS}
        per[cond] = rows
    out["unsafe_per_capture"] = per
    out["seconds"] = {c: docs[c]["seconds"] for c in caps}
    return out


def latency_summary(results, strata) -> OrderedDict | None:
    """The pipeline-latency pass (results/stage2/analyses/latency/*.json), if present."""
    folder = Path(results) / "stage2/analyses/latency"
    docs = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))}
    if not docs:
        return None
    strata = [(s, [c for c in caps if c in docs]) for s, caps in strata]
    caps = TB.flatten(strata)
    resamples = ST.draw_resamples(TB.strata_positions(strata))
    names = list(docs[caps[0]]["conditions"])
    out = OrderedDict([("captures", len(caps)), ("latencies_s", docs[caps[0]]["latencies_s"])])
    out["totals"] = {n: {k: sum(docs[c]["conditions"][n][k] for c in caps) for k in ("posed", "U", "M", "GT2",
                                                                                     "executions")} for n in names}
    out["event_time_reconstruction_differs"] = {
        n: {k: sum(docs[c]["event_time_vs"][n][k] for c in caps)
            for k in ("posed", "first_verdict_differs", "disposition_differs", "execution_differs")}
        for n in docs[caps[0]]["event_time_vs"]}
    paired = OrderedDict()
    for n in names:
        if n == "T_p" or not n.startswith("T_p[late"):
            continue
        du = [docs[c]["conditions"]["T_p"]["U"] - docs[c]["conditions"][n]["U"] for c in caps]
        dm = [docs[c]["conditions"]["T_p"]["M"] - docs[c]["conditions"][n]["M"] for c in caps]
        bu, bm = ST.bootstrap(resamples, du), ST.bootstrap(resamples, dm)
        paired["T_p minus " + n] = {"D_U": bu["point"], "D_U_95": bu["interval_95"], "D_M": bm["point"],
                                    "D_M_95": bm["interval_95"]}
    out["paired"] = paired
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "results/stage2/analyses/replays_summary.json"))
    a = ap.parse_args(argv)
    o = compute(a.results)
    Path(a.out).write_text(json.dumps(o, indent=1) + "\n", encoding="utf-8")
    print("verification:", "ok" if not o["verification"]["mismatches"] else o["verification"]["mismatches"][:5])
    for cond, t in o["totals"].items():
        print("%-16s U %5d  M %4d  posed %6d  executions %6d" % (cond, t["U"], t["M"], t["posed"], t["executions"]))
    for name, p in o["paired"].items():
        print("%-28s U %s D %s %s | M %s D %s %s | more/equal/fewer %s" % (name, p["U"], p["D_U"], p["D_U_95"], p["M"],
                                                                          p["D_M"], p["D_M_95"],
                                                                          p["captures_a_more_equal_fewer"]))
    print(json.dumps(o["audit"], indent=0)[:1500])
    if o.get("latency"):
        print(json.dumps({k: v for k, v in o["latency"].items()}, indent=0))
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
