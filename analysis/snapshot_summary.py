"""Totals of the snapshot-history pass (experiments/governance-stage2/govstage2/snapshots.py) over the arm-G captures.

    python -m analysis.snapshot_summary     # writes results/stage2/analyses/snapshots_summary.json

Reads results/stage2/analyses/snapshots/<capture>.json (experiments/governance-stage2/run_replays.py --snapshots).
Per interval (k polls per kept list; k = 1 is the captured stream) it sums over the included captures
(results/stage2/captures.json):

* the realised list intervals (the median over captures of each capture's median over phases);
* episodes of the changed service's Pods by type, and how many each history records (S, T: the mean over the phases;
  W: the watch), with the instants at which S and T place their starts (pooled over captures and phases), the number
  the uniform-phase approximation min(1, d / interval) expects S to record for every episode that ends inside the
  window, at the realised intervals and at 60 and 300 s, and the span of each replacement (from the first new Pod's
  creation to the last old Pod's removal);
* the watch's object states and how many the kept lists show;
* the status answers per Pod-second (wrong, unknown);
* the gate's restart decisions on T (F = 30 and 600 s) and on S, and the audit of the gate's decisions from T and S,
  per decision phase and as the mean over the phases (with the smallest and largest phase); for T, the decisions
  declined by verdict and rule and the executions at dispatch delays of 0 and 10 s (means over the phases), and the
  invalid executions at the 10 s delay and the missed opportunities per phase;
* the records kept per hour and the watch's events per hour.

Capture-bootstrap intervals (analysis.stats: 10,000 resamples within scenario strata, seed 0) are given for the
per-capture differences that the text compares: short episodes (starting, not ready, terminating) recorded by T
minus S, wrong Pod-seconds of S minus T, and the gate's invalid executions and executions on T (F = 30 s) minus
the captured stream, each at the three longer intervals (phase means); and for two shares as ratios of sums: the
gate's first verdicts that the S and T audits report differently. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import stats as ST, tables as TB  # noqa: E402

ANALYSES = ROOT / "results/stage2/analyses"
INTERVALS = ("1", "6", "12", "24")
LONGER = ("6", "12", "24")
TYPES = ("starting", "ready", "not_ready", "terminating")
SHORT = ("starting", "not_ready", "terminating")
KINDS = ("Pod", "ReplicaSet", "Deployment")
TALLY = ("posed", "executions", "invalid", "uncertain", "opportunities", "missed", "expired", "censored")
AGREE = ("posed", "first_verdict_differs", "disposition_differs", "execution_differs")
EXTRA_INTERVALS_S = (60.0, 300.0)


def instant(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def register() -> dict:
    return json.loads((ROOT / "results/stage2/captures.json").read_text(encoding="utf-8"))


def quantile(values, q: float):
    values = sorted(values)
    if not values:
        return None
    h = (len(values) - 1) * q
    low = int(h)
    if low >= len(values) - 1:
        return values[-1]
    return round(values[low] + (h - low) * (values[low + 1] - values[low]), 3)


def phase_mean(by_phase: dict, k: str, pick) -> float:
    keys = [p for p in by_phase if p.split("/")[0] == k]
    return sum(pick(by_phase[p]) for p in keys) / len(keys)


def fixed(x):
    """A number rounded to 4 decimals, whole numbers as integers (the same output on every Python version, whose
    float sums may differ in the last bit)."""
    x = round(float(x), 4)
    return int(x) if x == int(x) else x


def boot_sum(strata, values_by_capture: dict) -> OrderedDict:
    """``analysis.stats.bootstrap`` of a per-capture value (a phase mean), rounded to 4 decimals."""
    caps = TB.flatten(strata)
    got = ST.bootstrap(ST.draw_resamples(TB.strata_positions([(s, cs) for s, cs in strata if cs])),
                       [round(values_by_capture[c], 6) for c in caps])
    return OrderedDict([("point", fixed(got["point"])),
                        ("interval_95", [fixed(x) for x in got["interval_95"]]),
                        ("interval_98_33", [fixed(x) for x in got["interval_98_33"]]),
                        ("excludes_0_95", got["excludes_0_95"])])


def ratio_boot(strata, num: dict, den: dict) -> OrderedDict:
    """Ratio of sums with the stratified capture bootstrap's resamples (percentile intervals)."""
    caps = TB.flatten(strata)
    resamples = ST.draw_resamples(TB.strata_positions([(s, cs) for s, cs in strata if cs]))
    n = [num[c] for c in caps]
    d = [den[c] for c in caps]
    ratios = sorted(sum(n[i] for i in draw) / sum(d[i] for i in draw) for draw in resamples
                    if sum(d[i] for i in draw))
    lo95, hi95 = ST.interval(ratios, ST.Q95)
    return OrderedDict([("point", round(sum(n) / sum(d), 4)),
                        ("interval_95", [round(float(lo95), 4), round(float(hi95), 4)])])


def compute(results=ANALYSES) -> OrderedDict:
    results = Path(results)
    reg = register()
    strata_all = TB.population(reg, "G")
    G = [c for c in TB.flatten(strata_all) if (results / "snapshots" / (c + ".json")).exists()]
    strata = [(s, [c for c in caps if c in G]) for s, caps in strata_all]
    docs = {c: json.loads((results / "snapshots" / (c + ".json")).read_text(encoding="utf-8")) for c in G}
    out = OrderedDict([("captures", len(G)), ("pods", sum(docs[c]["window"]["pods"] for c in G)),
                       ("window_seconds", round(sum(docs[c]["window"]["seconds"] for c in G), 3))])

    # intervals
    realised = OrderedDict()
    for k in INTERVALS:
        values = [docs[c]["intervals"][k]["median_interval_s"] for c in G]
        realised[k] = OrderedDict([("median_s", statistics.median(values)), ("min_s", min(values)),
                                   ("max_s", max(values))])
    out["intervals"] = realised

    # 1. episodes
    by_type = OrderedDict((t, sum(docs[c]["episodes"]["by_type"][t] for c in G)) for t in TYPES)
    recorded = OrderedDict()
    for h in ("S", "T"):
        recorded[h] = OrderedDict()
        for k in INTERVALS:
            recorded[h][k] = OrderedDict((t, round(sum(docs[c]["episodes"]["recorded"][h][k][t] for c in G), 3))
                                         for t in TYPES)
    recorded["W"] = OrderedDict((t, sum(docs[c]["episodes"]["recorded"]["W"]["events"][t] for c in G)) for t in TYPES)
    lags = OrderedDict()
    for h in ("S", "T"):
        lags[h] = OrderedDict()
        for k in INTERVALS:
            pooled = [x for c in G for x in docs[c]["episodes"]["start_lag_s"][h][k]]
            lags[h][k] = OrderedDict([("n", len(pooled)), ("median_s", quantile(pooled, 0.5)),
                                      ("p90_s", quantile(pooled, 0.9)), ("max_s", max(pooled) if pooled else None),
                                      ("share_within_1s", round(sum(1 for x in pooled if abs(x) <= 1.0) / len(pooled), 4)
                                       if pooled else None)])
    closed = [e for c in G for e in docs[c]["episodes"]["reference"] if not e["open_at_end"]]
    durations = OrderedDict((t, sorted(e["seconds"] for e in closed if e["type"] == t)) for t in TYPES)
    expected = OrderedDict()
    for label, seconds in [("k=%s" % k, realised[k]["median_s"]) for k in LONGER] + \
                          [("%g s" % s, s) for s in EXTRA_INTERVALS_S]:
        expected[label] = OrderedDict([("interval_s", seconds)] + [
            (t, round(sum(min(1.0, d / seconds) for d in durations[t]), 3)) for t in TYPES])
    spans = []
    for c in G:
        ref = docs[c]["episodes"]["reference"]
        starts = [instant(e["begin"]) for e in ref if e["type"] == "starting"]
        ends = [instant(e["end"]) for e in ref if e["type"] == "terminating" and e["end"]]
        if starts and ends:
            spans.append(round((max(ends) - min(starts)).total_seconds(), 3))
    spans.sort()
    out["episodes"] = OrderedDict([
        ("by_type", by_type), ("recorded", recorded), ("start_lag_s", lags),
        ("replacement_span_s", OrderedDict([("captures", len(spans)), ("min", spans[0] if spans else None),
                                            ("median", quantile(spans, 0.5)), ("max", spans[-1] if spans else None)])),
        ("closed_durations_s", OrderedDict((t, OrderedDict([("n", len(v)), ("median", quantile(v, 0.5)),
                                                            ("min", v[0] if v else None),
                                                            ("max", v[-1] if v else None)]))
                                           for t, v in durations.items())),
        ("uniform_phase_expectation_closed", expected)])

    # 2. object states
    watch_states = OrderedDict((kind, sum(docs[c]["object_states"]["watch"][kind] for c in G)) for kind in KINDS)
    shown = OrderedDict((k, OrderedDict((kind, round(sum(docs[c]["object_states"]["recorded"][k][kind] for c in G), 3))
                                        for kind in KINDS)) for k in INTERVALS)
    out["object_states"] = OrderedDict([("watch", watch_states), ("shown_by_kept_lists", shown)])

    # 3. status
    status = OrderedDict()
    for h in ("S", "T"):
        status[h] = OrderedDict()
        for k in INTERVALS:
            status[h][k] = OrderedDict((m, round(sum(docs[c]["status"][h][k][m] for c in G), 3))
                                       for m in ("seconds", "wrong", "unknown"))
    status["W"] = OrderedDict((m, sum(docs[c]["status"]["W"]["events"][m] for c in G))
                              for m in ("seconds", "wrong", "unknown"))
    out["status"] = status

    # 4-5. decisions and audit
    phases = sorted(docs[G[0]]["decisions"], key=lambda p: tuple(int(x) for x in p.split("/")))
    decisions = OrderedDict()
    for p in phases:
        decisions[p] = OrderedDict((v, OrderedDict((m, sum(docs[c]["decisions"][p][v][m] for c in G)) for m in TALLY))
                                   for v in ("T F30", "T F600", "S F30"))
    audit = OrderedDict()
    for p in phases:
        audit[p] = OrderedDict((v, OrderedDict((m, sum(docs[c]["audit"][p][v][m] for c in G)) for m in AGREE))
                               for v in ("T", "S"))
    by_interval = OrderedDict()
    for k in INTERVALS:
        keys = [p for p in phases if p.split("/")[0] == k]
        row = OrderedDict([("phases", keys)])
        for v in ("T F30", "T F600", "S F30"):
            row[v] = OrderedDict((m, OrderedDict([("mean", round(sum(decisions[p][v][m] for p in keys) / len(keys), 3)),
                                                  ("min", min(decisions[p][v][m] for p in keys)),
                                                  ("max", max(decisions[p][v][m] for p in keys))]))
                                 for m in ("executions", "invalid", "uncertain", "missed", "opportunities"))
        for v in ("T", "S"):
            row["audit " + v] = OrderedDict((m, OrderedDict([("mean", round(sum(audit[p][v][m] for p in keys) / len(keys), 3)),
                                                             ("min", min(audit[p][v][m] for p in keys)),
                                                             ("max", max(audit[p][v][m] for p in keys))]))
                                            for m in AGREE[1:])
        row["posed"] = decisions[keys[0]]["T F30"]["posed"]
        for v in ("T F30", "T F600"):
            declined = {}
            for p in keys:
                for c in G:
                    for rule, cnt in docs[c]["decisions"][p][v]["declined"].items():
                        declined[rule] = declined.get(rule, 0) + cnt
            row[v + " declined (mean over phases)"] = OrderedDict(
                (rule, round(declined[rule] / len(keys), 3)) for rule in sorted(declined))
            row[v + " executions at dispatch delays of 0 and 10 s (mean over phases)"] = round(sum(
                docs[c]["decisions"][p][v]["by_dispatch_delay"].get(d, {}).get("executions", 0)
                for p in keys for c in G for d in ("0 s", "10 s")) / len(keys), 3)
            row[v + " invalid at the 10 s dispatch delay (per phase)"] = [sum(
                docs[c]["decisions"][p][v]["by_dispatch_delay"].get("10 s", {}).get("invalid", 0) for c in G)
                for p in keys]
            row[v + " missed (per phase)"] = [decisions[p][v]["missed"] for p in keys]
        by_interval[k] = row
    out["decisions"] = OrderedDict([("by_phase", decisions), ("audit_by_phase", audit), ("by_interval", by_interval)])

    # 6. volume
    hours = sum(docs[c]["window"]["seconds"] for c in G) / 3600.0
    poller = OrderedDict()
    for k in INTERVALS:
        recs = sum(docs[c]["volume"]["poller"]["intervals"][k]["records"] for c in G)
        merged = sum(docs[c]["volume"]["poller"]["intervals"][k]["merged_records"] for c in G)
        size = sum(docs[c]["volume"]["poller"]["intervals"][k]["projected_bytes"] for c in G)
        msize = sum(docs[c]["volume"]["poller"]["intervals"][k]["merged_projected_bytes"] for c in G)
        poller[k] = OrderedDict([("records", round(recs, 3)), ("merged_records", round(merged, 3)),
                                 ("projected_bytes", round(size)), ("merged_projected_bytes", round(msize)),
                                 ("records_per_hour", round(recs / hours)),
                                 ("merged_records_per_hour", round(merged / hours))])
    watch = OrderedDict((m, sum(docs[c]["volume"]["watch"][m] for c in G))
                        for m in ("events", "list_objects", "projected_bytes", "event_line_bytes"))
    watch["events_per_hour"] = round(watch["events"] / hours)
    out["volume"] = OrderedDict([("hours", round(hours, 4)),
                                 ("records_per_poll_median", statistics.median(
                                     docs[c]["volume"]["poller"]["records_per_poll"] for c in G)),
                                 ("poller", poller), ("watch", watch)])

    # intervals of the compared differences
    cis = OrderedDict()
    for k in LONGER:
        cis["short episodes recorded, T - S, k=%s" % k] = boot_sum(strata, {
            c: sum(docs[c]["episodes"]["recorded"]["T"][k][t] - docs[c]["episodes"]["recorded"]["S"][k][t]
                   for t in SHORT) for c in G})
        cis["wrong Pod-seconds, S - T, k=%s" % k] = boot_sum(strata, {
            c: docs[c]["status"]["S"][k]["wrong"] - docs[c]["status"]["T"][k]["wrong"] for c in G})
        for m in ("invalid", "executions"):
            cis["gate %s on T (F = 30 s) minus captured, k=%s" % (m, k)] = boot_sum(strata, {
                c: phase_mean(docs[c]["decisions"], k, lambda d, m=m: d["T F30"][m])
                - docs[c]["decisions"]["1/0"]["T F30"][m] for c in G})
        for v in ("S", "T"):
            num = {c: phase_mean(docs[c]["audit"], k, lambda d, v=v: d[v]["first_verdict_differs"]) for c in G}
            den = {c: docs[c]["audit"]["1/0"][v]["posed"] for c in G}
            cis["audit from %s: first verdicts reported differently (share), k=%s" % (v, k)] = ratio_boot(strata, num, den)
    num = {c: docs[c]["audit"]["1/0"]["S"]["first_verdict_differs"] for c in G}
    den = {c: docs[c]["audit"]["1/0"]["S"]["posed"] for c in G}
    cis["audit from S: first verdicts reported differently (share), k=1"] = ratio_boot(strata, num, den)
    out["intervals_of_differences"] = cis
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--results", default=str(ANALYSES))
    ap.add_argument("--out", default=str(ANALYSES / "snapshots_summary.json"))
    a = ap.parse_args(argv)
    doc = compute(a.results)
    Path(a.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
