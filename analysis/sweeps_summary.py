"""Totals of the coverage, parameter-sweep and receipt-time-audit replays, the audit from a receipt log that keeps the
records' own timestamps, the decision log, the check-to-act gap, the uncertain labels on the mutually evaluable
decisions and the diagnosis robustness test.

    python -m analysis.sweeps_summary      # writes results/stage2/analyses/sweeps_summary.json

Reads results/stage2/analyses/sweeps/<capture>.json (experiments/governance-stage2/run_replays.py --sweeps),
own_timestamps/<capture>.json (--own-timestamps), decision_log/<capture>.json (--decision-log),
check_to_act/<capture>.json (--check-to-act),
uncertain/<capture>.json (--uncertain) and
results/stage2/analyses/diagnosis_robustness.json (experiments/diagnosis-control-v1/run_diagnosis_stress.py
--robustness). Sums over the included captures (results/stage2/captures.json); every count keeps the number of
captures it covers. ``store``: the poller store's versions and keys per arm-G capture, and the wall time of one
restart decision of the swept gate (all its evaluations and retries; the replay's own timing, on the machine that ran
it). ``uncertain_mutually_evaluable``: on the decisions that neither T_p nor R left censored, both views' invalid
executions and uncertain ones by reason; a reason other than "GT-2-B conditions without an established effect" could
hide an invalid execution; with stratified capture-bootstrap intervals (analysis.capture_stats) of the gate's excess
over the recheck counting the scored labels only, every possibly invalid uncertain execution of the recheck as invalid,
and only those whose target served no request in the 2 s after the execution. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ANALYSES = ROOT / "results/stage2/analyses"
SCALARS = ("posed", "executions", "invalid", "uncertain", "valid", "opportunities", "missed", "expired", "censored",
           "evaluations")
DICTS = ("declined", "invalid_by_target_state", "uncertain_by_reason", "opportunity_executions")


NO_EFFECT = "GT-2-B conditions without an established effect"   # uncertain for the opportunity count only


def captures(arm: str) -> list:
    register = json.loads((ROOT / "results/stage2/captures.json").read_text(encoding="utf-8"))
    return [c for s in register["populations"][arm] for c in s["captures"]]


def add(total: OrderedDict, tally: dict) -> None:
    for k in SCALARS:
        total[k] = total.get(k, 0) + tally.get(k, 0)
    for k in DICTS:
        bucket = total.setdefault(k, Counter())
        bucket.update(tally.get(k) or {})
    by = total.setdefault("by_dispatch_delay", OrderedDict())
    for d, v in (tally.get("by_dispatch_delay") or {}).items():
        by.setdefault(d, Counter()).update(v)


def finish(total: OrderedDict) -> OrderedDict:
    for k in DICTS:
        total[k] = dict(sorted(total.get(k, Counter()).items()))
    total["by_dispatch_delay"] = OrderedDict((d, dict(sorted(v.items())))
                                             for d, v in total.get("by_dispatch_delay", {}).items())
    if total.get("executions"):
        total["invalid_per_execution"] = round(total["invalid"] / total["executions"], 5)
    return total


OUTCOME_VIEWS = ("T_p", "T_w", "L-kappa", "R", "T@F600")


def adapter_outcomes(adapter_dir: Path) -> OrderedDict:
    """Every posed restart decision of arm G by outcome, per view, from the governance adapter's cells (stream S0):
    executions (invalid, valid, uncertain), and decisions not executed (approval requested, denied, expired,
    censored); the target state of every invalid execution."""
    out = OrderedDict()
    for view in OUTCOME_VIEWS:
        t = OrderedDict((k, 0) for k in ("posed", "executions", "invalid", "valid", "uncertain", "approval",
                                          "denied", "expired", "censored"))
        targets = Counter()
        for c in captures("G"):
            for cell in json.loads((adapter_dir / (c + ".json")).read_text(encoding="utf-8"))["T1_cells"]:
                if (cell["action"], cell["stream"], cell["condition"]) != ("B", "S0", view):
                    continue
                t["posed"] += cell["posed"]
                labels = cell["executions_by_label"]["counts"]
                executions = sum(labels.values())
                invalid = cell["unsafe_executions"]["count"]
                t["executions"] += executions
                t["invalid"] += invalid
                t["uncertain"] += labels.get("U", 0)
                t["valid"] += executions - invalid - labels.get("U", 0)
                for key, n in cell["dispositions"]["counts"].items():
                    verdict = key.split("[")[0]
                    if verdict == "NEEDS_APPROVAL":
                        t["approval"] += n
                    elif verdict == "DENY":
                        t["denied"] += n
                    elif verdict == "EXPIRED":
                        t["expired"] += n
                    elif verdict == "CENSORED":
                        t["censored"] += n
                reasons = cell["executions_by_label"].get("reasons") or {}
                targets.update(reasons.get("V-target") or {})
                if labels.get("V-floor"):
                    targets["below_floor"] += labels["V-floor"]
        t["invalid_by_target_state"] = dict(sorted(targets.items()))
        t["invalid_per_execution"] = round(t["invalid"] / t["executions"], 5) if t["executions"] else None
        out[view] = t
    return out


def compute(results=ANALYSES) -> OrderedDict:
    results = Path(results)
    docs = {c: json.loads((results / "sweeps" / (c + ".json")).read_text(encoding="utf-8"))
            for arm in ("G", "D") for c in captures(arm)}
    G, D = captures("G"), captures("D")
    out = OrderedDict([("captures", {"G": len(G), "D": len(D)})])
    out["outcomes"] = adapter_outcomes(results.parent / "adapter")
    # coverage
    cov = OrderedDict()
    for view in ("T_p", "L-kappa", "R", "T_p+lag"):
        if not all(view in docs[c]["coverage"] for c in G):
            continue
        total = OrderedDict()
        for c in G:
            add(total, docs[c]["coverage"][view])
        total["captures_with_invalid"] = sum(1 for c in G if docs[c]["coverage"][view]["invalid"])
        cov[view] = finish(total)
    out["coverage"] = cov
    mut = OrderedDict()
    for pair in ("T_p vs R", "L-kappa vs R"):
        m = OrderedDict([("posed", 0), ("excluded_censored", 0), ("decisions", 0)])
        sides = {"a": Counter(), "b": Counter()}
        by = defaultdict(lambda: {"decisions": 0, "a": Counter(), "b": Counter()})
        for c in G:
            doc = docs[c]["mutually_evaluable"][pair]
            for k in ("posed", "excluded_censored", "decisions"):
                m[k] += doc[k]
            for side in ("a", "b"):
                sides[side].update(doc["outcomes"][side])
            for d, v in doc["by_dispatch_delay"].items():
                by[d]["decisions"] += v["decisions"]
                by[d]["a"].update(v["a"])
                by[d]["b"].update(v["b"])
        m["outcomes"] = {s: dict(sorted(v.items())) for s, v in sides.items()}
        m["by_dispatch_delay"] = OrderedDict((d, {"decisions": v["decisions"], "a": dict(sorted(v["a"].items())),
                                                  "b": dict(sorted(v["b"].items()))})
                                             for d, v in sorted(by.items(), key=lambda kv: float(kv[0].split()[0])))
        mut[pair] = m
    out["mutually_evaluable"] = mut
    # sweep
    sweep = OrderedDict()
    blocks = sorted({b for c in G + D for b in docs[c]["sweep"]})
    for block in blocks:
        family, stream = [x.strip() for x in block.split("|")]
        arms = [arm for arm, caps in (("G", G), ("D", D)) if any(block in docs[c]["sweep"] for c in caps)]
        for arm in arms:
            caps = G if arm == "G" else D
            cells = OrderedDict()
            names = list(docs[caps[0]]["sweep"][block])
            for name in names:
                total = OrderedDict()
                for c in caps:
                    add(total, docs[c]["sweep"][block][name])
                total["captures_with_invalid"] = sum(1 for c in caps if docs[c]["sweep"][block][name]["invalid"])
                cells[name] = finish(total)
            sweep["arm %s | %s | %s" % (arm, family, stream)] = cells
    out["sweep"] = sweep
    # audit
    audit = OrderedDict()
    for latency in docs[G[0]]["audit"]:
        gate, replay = OrderedDict(), OrderedDict()
        agree = Counter()
        for c in G:
            a = docs[c]["audit"][latency]
            add(gate, a["gate"])
            add(replay, a["receipt_time_replay"])
            agree.update(a["receipt_time_vs_gate"])
        audit[latency] = OrderedDict([("gate", finish(gate)), ("receipt_time_replay", finish(replay)),
                                      ("receipt_time_vs_gate", dict(agree))])
    out["audit"] = audit
    # the audit from a receipt log that keeps the records' own timestamps (arm G)
    if all((results / "own_timestamps" / (c + ".json")).exists() for c in G):
        own = {c: json.loads((results / "own_timestamps" / (c + ".json")).read_text(encoding="utf-8")) for c in G}
        section = OrderedDict()
        for latency in own[G[0]]["audit"]:
            gate, replay = OrderedDict(), OrderedDict()
            agree = Counter()
            per_capture = OrderedDict()
            for c in G:
                a = own[c]["audit"][latency]
                add(gate, a["gate"])
                add(replay, a["own_timestamps_replay"])
                agree.update(a["own_timestamps_vs_gate"])
                per_capture[c] = OrderedDict([
                    ("posed", a["own_timestamps_vs_gate"]["posed"]),
                    ("first_verdict_differs", a["own_timestamps_vs_gate"]["first_verdict_differs"]),
                    ("receipt_time_first_verdict_differs",
                     docs[c]["audit"][latency]["receipt_time_vs_gate"]["first_verdict_differs"])])
            section[latency] = OrderedDict([("gate", finish(gate)), ("own_timestamps_replay", finish(replay)),
                                            ("own_timestamps_vs_gate", dict(agree)), ("per_capture", per_capture)])
        out["own_timestamps_audit"] = section
    # store and evaluation cost
    obs = [docs[c]["store"]["observations"] for c in G]
    keys = [docs[c]["store"]["keys"] for c in G]
    per_key = [o / k for o, k in zip(obs, keys)]
    cost = []
    for c in G:
        seconds = docs[c]["seconds"].get("sweep B S0")
        cells = docs[c]["sweep"]["B | S0"]
        computed = [v for name, v in cells.items() if name != "F=30,N=30"]   # the base setting is reused
        decisions = sum(v["posed"] for v in computed)
        if seconds and decisions:
            cost.append(1000.0 * seconds / decisions)
    out["store"] = OrderedDict([
        ("observations", {"median": statistics.median(obs), "min": min(obs), "max": max(obs)}),
        ("keys", {"median": statistics.median(keys), "min": min(keys), "max": max(keys)}),
        ("versions_per_key", {"median": round(statistics.median(per_key), 1), "min": round(min(per_key), 1),
                              "max": round(max(per_key), 1)}),
        ("ms_per_decision", {"median": round(statistics.median(cost), 1), "min": round(min(cost), 1),
                             "max": round(max(cost), 1)} if cost else None)])
    # diagnosis robustness
    rob_path = results / "diagnosis_robustness.json"
    if rob_path.exists():
        rob = json.loads(rob_path.read_text(encoding="utf-8"))
        r_out = OrderedDict()
        for stage, key in (("follow_up", "per_capture"), ("development", "development_per_capture")):
            caps = rob.get(key) or []
            table = OrderedDict()
            for cap in caps:
                for variant, rows in cap["variants"].items():
                    for row in rows:
                        k = "%s | %d s | %s" % (variant, row["delta_s"], row["policy"])
                        entry = table.setdefault(k, OrderedDict([("captures", 0), ("all_draws_top1", 0),
                                                                 ("draws", 0), ("top1_draws", 0)]))
                        entry["captures"] += 1
                        entry["all_draws_top1"] += row["top1"] == row["draws"]
                        entry["draws"] += row["draws"]
                        entry["top1_draws"] += row["top1"]
            r_out[stage] = table
        out["diagnosis_robustness"] = r_out
    # a log of each decision's inputs (arm G)
    if all((results / "decision_log" / (c + ".json")).exists() for c in G):
        logs = {c: json.loads((results / "decision_log" / (c + ".json")).read_text(encoding="utf-8")) for c in G}
        questions = OrderedDict()
        for name in logs[G[0]]["questions"]:
            total = Counter()
            for c in G:
                total.update(logs[c]["questions"][name])
            questions[name] = OrderedDict((k, total[k]) for k in logs[G[0]]["questions"][name])
        per_decision = [logs[c]["log"]["records_per_decision"]["median"] for c in G]
        share = [logs[c]["log"]["distinct_records"] / logs[c]["store"]["records"] for c in G]
        out["decision_log"] = OrderedDict([
            ("captures", len(G)), ("posed", sum(logs[c]["posed"] for c in G)),
            ("records_per_decision_median", {"median": statistics.median(per_decision), "min": min(per_decision),
                                             "max": max(per_decision)}),
            ("record_references", sum(logs[c]["log"]["record_references"] for c in G)),
            ("distinct_records", sum(logs[c]["log"]["distinct_records"] for c in G)),
            ("store_records", sum(logs[c]["store"]["records"] for c in G)),
            ("store_versions", sum(logs[c]["store"]["versions"] for c in G)),
            ("distinct_records_share_of_store_records", {"median": round(statistics.median(share), 3),
                                                         "min": round(min(share), 3), "max": round(max(share), 3)}),
            ("questions", questions)])
    # the recheck's executions labelled after a read-to-action gap (arm G)
    if all((results / "check_to_act" / (c + ".json")).exists() for c in G):
        acts = {c: json.loads((results / "check_to_act" / (c + ".json")).read_text(encoding="utf-8")) for c in G}
        lags = OrderedDict()
        for lag in acts[G[0]]["executions_by_lag"]:
            total = Counter()
            for c in G:
                total.update(acts[c]["executions_by_lag"][lag])
            lags[lag] = OrderedDict((k, total[k]) for k in ("invalid", "uncertain", "valid"))
        out["check_to_act"] = OrderedDict([("captures", len(G)), ("executions_by_lag", lags)])
    # uncertain labels on the mutually evaluable decisions (arm G)
    if all((results / "uncertain" / (c + ".json")).exists() for c in G):
        from analysis import capture_stats as CS, tables as TB
        unc = {c: json.loads((results / "uncertain" / (c + ".json")).read_text(encoding="utf-8"))["mutually_evaluable"]
               for c in G}
        views = OrderedDict()
        per = OrderedDict()
        for v in ("T_p", "R"):
            reasons = defaultdict(Counter)
            for c in G:
                for reason, cnt in unc[c]["views"][v]["uncertain"].items():
                    reasons[reason].update(cnt)
            views[v] = OrderedDict([("invalid", sum(unc[c]["views"][v]["invalid"] for c in G)),
                                    ("uncertain", OrderedDict((r, dict(reasons[r])) for r in sorted(reasons)))])
            per[v] = OrderedDict()
            for c in G:
                d = unc[c]["views"][v]
                possible = [x for r, x in d["uncertain"].items() if r != NO_EFFECT]
                per[v][c] = OrderedDict([
                    ("invalid", d["invalid"]),
                    ("possibly_invalid", sum(x["executions"] for x in possible)),
                    ("possibly_invalid_no_target_request_after", sum(x["executions"] - x["target_served_after"]
                                                                     for x in possible))])
        strata = TB.population(json.loads((ROOT / "results/stage2/captures.json").read_text(encoding="utf-8")), "G")
        tp, r = per["T_p"], per["R"]
        cis = OrderedDict([
            ("scored", CS.boot(strata, {c: tp[c]["invalid"] - r[c]["invalid"] for c in G})),
            ("recheck_possibly_invalid_counted", CS.boot(strata, {c: tp[c]["invalid"] - r[c]["invalid"]
                                                                 - r[c]["possibly_invalid"] for c in G})),
            ("recheck_possibly_invalid_without_target_request_after_counted",
             CS.boot(strata, {c: tp[c]["invalid"] - r[c]["invalid"]
                              - r[c]["possibly_invalid_no_target_request_after"] for c in G}))])
        out["uncertain_mutually_evaluable"] = OrderedDict([
            ("captures", len(G)), ("decisions", sum(unc[c]["decisions"] for c in G)),
            ("window_s", unc[G[0]]["window_s"]), ("views", views), ("per_capture", per),
            ("gate_minus_recheck", cis)])
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--results", default=str(ANALYSES))
    ap.add_argument("--out", default=str(ANALYSES / "sweeps_summary.json"))
    a = ap.parse_args(argv)
    doc = compute(a.results)
    Path(a.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
