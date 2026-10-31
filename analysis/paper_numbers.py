"""Every number of the paper, recomputed from the per-capture outputs and compared with the published value.

    python -m analysis.paper_numbers            # print the numbers as JSON
    python -m analysis.paper_numbers --check    # also run the table check and compare every value

Runs the check of :mod:`analysis.tables` (captures, observers, principal comparisons, development diagnosis) and
reads the replay analyses in ``results/stage2/analyses/`` (written by the commands in the README):
``per_capture_stats.json``, ``replays_summary.json``, ``by_delay.json``, ``diagnosis_stress_summary.json`` and the
per-capture ``replays/`` and ``surrogate/`` files, ``diagnosis_stress.json``, ``diagnosis_attribution.json``,
``sweeps_summary.json`` (coverage, parameter sweep, receipt-time audit, store size, decision log, check-to-act labels,
uncertain labels on the mutually evaluable decisions, diagnosis robustness), ``snapshots_summary.json`` (state
histories kept as periodic snapshots), plus the governance adapter's outputs
(``results/stage2/adapter/``: cells, labels and rollout timing), the diagnosis control's outputs
(``results/stage2/diagnosis/``) and the capture summaries. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import tables  # noqa: E402

ANALYSES = Path("stage2/analyses")
SCENARIOS_G = ("G1", "G2", "G3", "G4")
DELAYS = (0, 10, 30, 80)
CUTOFFS = (0, 5, 30)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _t(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _range(values, digits=0):
    lo, hi = min(values), max(values)
    return [round(lo, digits), round(hi, digits)] if digits else [int(round(lo)), int(round(hi))]


def cells(results: Path, captures, action: str, streams=("S0",)):
    """(capture, T1 cell) of the governance adapter's output for one action and the given streams."""
    for c in captures:
        for cell in _load(results / "stage2/adapter" / (c + ".json"))["T1_cells"]:
            if cell["action"] == action and cell["stream"] in streams:
                yield c, cell


def timing(results: Path, populations: dict) -> OrderedDict:
    """Seconds after the rollout started at which the new Pods were all Ready, the physical rollout interval ended
    (the later of the old revision's last request and the readiness of all new Pods), and the fault started (kill
    receipt for a termination, worker start for a CPU fault)."""
    out = OrderedDict()
    for scen, ids in populations.items():
        ready, last, fault = [], [], []
        for c in ids:
            lab = _load(results / "stage2/adapter" / (c + ".json"))["labels"]
            pr, fa = lab["physical_rollout_interval"], lab.get("fault") or {}
            r0 = _t(pr["R_us"])
            ready.append(_t(pr["new_ready_complete_us"]) - r0)
            last.append(_t(pr["end_us"]) - r0)
            if fa.get("kill_receipts"):
                fault.append(_t(fa["kill_receipts"][0]["start"]) - r0)
            elif fa.get("active_start"):
                fault.append(_t(fa["active_start"]) - r0)
        out[scen] = [_range(ready), _range(last), _range(fault) if fault else None]
    return out


def numbers(results: Path) -> OrderedDict:
    a = results / ANALYSES
    stats = _load(a / "per_capture_stats.json")
    summ = _load(a / "replays_summary.json")
    delay = _load(a / "by_delay.json")
    stress = _load(a / "diagnosis_stress_summary.json")
    pops = {p["scenario"]: p["captures"] for arm in ("D", "G")
            for p in _load(results / "stage2/captures.json")["populations"][arm]}
    cond = stats["restart_arm_G_conditions"]["per_capture"]
    comp = stats["comparisons"]
    n = OrderedDict()

    g_caps = [c for s in SCENARIOS_G for c in pops[s]]
    d_caps = [c for s in ("D1", "D2") for c in pops[s]]

    # Table 2 and Section 4.2
    n["Table 2: new Pods ready, rollout end, fault start (s after the rollout started)"] = timing(results, pops)
    n["arm-G requests without a server span of the changed service (not posed), requests"] = [
        sum(_load(results / "stage2/adapter" / (c + ".json"))["capture"]["requests"]
            - _load(results / "stage2/adapter" / (c + ".json"))["capture"]["b_targets_posable"] for c in g_caps),
        sum(_load(results / "stage2/adapter" / (c + ".json"))["capture"]["requests"] for c in g_caps)]
    summaries = _load(results / "stage2/capture_summaries.json")
    n["arm D: longest Pod-list gap in the observer-validity check (s)"] = round(max(
        summaries[c]["observer_checks"]["poller_max_pod_list_gap_in_window_seconds"] for c in d_caps), 1)
    n["Table 2: terminated target out of service (s), G2 and G3"] = OrderedDict(
        (s, [v["min"], v["max"]]) for s, v in delay["fault_not_ready_s_by_scenario"].items())

    # Table 3: invalid executions by scenario, missed opportunities, executions
    def unsafe(view, capture):
        if view in summ["per_capture_U"][capture]:
            return summ["per_capture_U"][capture][view]
        return cond[capture][view]["U"]
    views = ("T_p", "L_p", "T_w", "T_p+lag", "T_p@R", "R", "L-kappa")
    n["Table 3 invalid (G1, G2, G3, G4, all)"] = OrderedDict(
        (v, [sum(unsafe(v, c) for c in pops[s]) for s in SCENARIOS_G] + [delay[v]["total"]["U"]]) for v in views)
    n["Table 3 missed / executions"] = OrderedDict(
        (v, [delay[v]["total"]["M"], delay[v]["total"]["executions"]]) for v in views)
    n["Table 3 posed (G1, G2, G3, G4, all); opportunities"] = [
        sum(cond[c]["T_p"]["posed"] for c in pops[s]) for s in SCENARIOS_G] + [delay["T_p"]["total"]["posed"],
                                                                                  delay["T_p"]["total"]["GT2"]]
    n["T_p and L_p: decisions that differ (first verdict, disposition, execution)"] = [
        summ["agreement"]["T_p vs L_p"][k] for k in ("first_verdict_differs", "disposition_differs",
                                                     "execution_differs")]
    n["T_w and T_p: same invalid count in every capture"] = all(
        cond[c]["T_w"]["U"] == cond[c]["T_p"]["U"] for s in SCENARIOS_G for c in pops[s])
    n["posed restart decisions per arm-G capture (range)"] = _range([cond[c]["T_p"]["posed"] for c in g_caps])
    replays = {c: _load(a / "replays" / (c + ".json"))["conditions"] for c in g_caps}
    uncertain = OrderedDict((v, 0) for v in views)
    could_be_unsafe = OrderedDict((v, 0) for v in ("T_p", "R", "L-kappa"))
    floor_violations = 0
    for c, cell in cells(results, g_caps, "B"):
        counts = cell["executions_by_label"]["counts"]
        floor_violations += counts.get("V-floor", 0)
        if cell["condition"] in uncertain:
            uncertain[cell["condition"]] += counts.get("U", 0)
        if cell["condition"] in could_be_unsafe:
            reasons = (cell["executions_by_label"].get("reasons") or {}).get("U") or {}
            could_be_unsafe[cell["condition"]] += sum(
                x for k, x in reasons.items() if k != "GT-2-B conditions without an established effect")
    for v in ("T_p+lag", "T_p@R"):
        uncertain[v] = sum(replays[c][v]["executions_by_label"].get("U", 0) for c in g_caps)
    floor_violations += sum(r["executions_by_label"].get("V-floor", 0) for c in g_caps for r in replays[c].values())
    n["Table 3 uncertain executions"] = uncertain
    n["uncertain executions that could be invalid"] = could_be_unsafe
    n["restart executions labelled V-floor, every view"] = floor_violations
    reasons, after_start, fault_pod, deleted_old = {}, [], 0, 0
    for c in g_caps:
        lab = _load(results / "stage2/adapter" / (c + ".json"))["labels"]
        pr = lab["physical_rollout_interval"]
        pods = {q["uid"]: q for q in lab["pods"]}
        for e in _load(a / "surrogate" / (c + ".json"))["executions_not_neutral"]["T_p"]:
            if e["label"] not in ("V-target", "V-floor"):
                continue
            reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
            after_start.append(_t(e["x"]) - _t(pr["R_us"]))
            q = pods.get(e["target_uid"]) or {}
            fault_pod += e["target_uid"] == (lab.get("fault") or {}).get("pod_uid")
            deleted_old += bool(q.get("deletion_request")) and q.get("template_hash") == pr["old_hash"]
    n["invalid two-clock restarts: terminating, gone; fault's Pod; rollout-deleted old Pods; last (s)"] = [
        [reasons.get("terminating", 0), reasons.get("gone", 0)], fault_pod, deleted_old, round(max(after_start), 1)]
    effect = [c for c in pops["G1"] if (_load(results / "stage2/adapter" / (c + ".json"))["labels"].get("fault")
                                        or {}).get("latency_effect_established")]
    n["mitigation opportunities: G1 captures with an established effect; opportunities per capture"] = [
        sorted(effect), OrderedDict(sorted((r["capture"], r["GT2"]) for r in comp["recheck"]["per_capture"]
                                           if r["GT2"]))]

    # Table 5 and Section 5.1
    rc = comp["recheck"]

    def flip(iv):
        return sorted(-x for x in iv)
    n["recheck: difference [95%], 98.33%"] = [-rc["D_U"]["point"], flip(rc["D_U"]["interval_95"]),
                                              flip(rc["D_U"]["interval_98_33"])]
    n["recheck: captures more / equal / fewer"] = [
        sum(1 for r in rc["per_capture"] if r["U_X"] > r["U_Y"]),
        sum(1 for r in rc["per_capture"] if r["U_X"] == r["U_Y"]),
        sum(1 for r in rc["per_capture"] if r["U_X"] < r["U_Y"])]
    n["recheck per scenario: difference [95%]"] = OrderedDict(
        (s, [-v["D_U"], flip(v["D_U_95"])]) for s, v in rc["per_scenario"].items())
    lo = rc["leave_one_capture_out_summary"]
    n["recheck leave-one-out: range, intervals excluding 0"] = [flip(lo["D_U_range"]),
                                                               [lo["D_U_interval_excludes_0_in"], lo["of"]]]
    wo = rc["without_G3"]
    n["recheck without G3: invalid, captures, difference [95%], more/equal/fewer"] = [
        [wo["U_X"], wo["U_Y"]], wo["captures"], [-wo["D_U"], flip(wo["D_U_95"])], wo["captures_X_more_equal_fewer"]]
    n["recheck missed: difference [95%]"] = [rc["D_M"]["point"], rc["D_M"]["interval_95"]]
    pair = summ["paired"]
    n["T_p vs T_p@R: invalid, missed, difference [95%], captures"] = [
        pair["T_p minus T_p@R"][k] for k in ("U", "M")] + [[pair["T_p minus T_p@R"]["D_U"],
                                                           pair["T_p minus T_p@R"]["D_U_95"]],
                                                          pair["T_p minus T_p@R"]["captures_a_more_equal_fewer"]]
    p = pair["T_p@R minus R"]
    n["T_p@R vs R: invalid, missed, difference [95%], missed difference [95%], captures"] = [
        p["U"], p["M"], [p["D_U"], p["D_U_95"]], [p["D_M"], p["D_M_95"]], p["captures_a_more_equal_fewer"]]
    p = pair["T_p minus T_p+lag"]
    n["T_p+lag vs T_p: invalid, missed, difference [95%], captures (T_p+lag more/equal/fewer)"] = [
        p["U"][::-1], p["M"][::-1], [-p["D_U"], flip(p["D_U_95"])], p["captures_a_more_equal_fewer"][::-1]]
    ar = comp["approval_reuse"]
    n["approval reuse vs T_p (delays > 0): invalid, posed, difference [95%], 98.33% excludes 0, captures, missed"] = [
        [ar["totals"]["U_Y"], ar["totals"]["U_X"]], ar["totals"]["posed"],
        [ar["D_U"]["point"], ar["D_U"]["interval_95"]], ar["D_U"]["excludes_0_98_33"],
        sum(1 for r in ar["per_capture"] if r["U_Y"] > r["U_X"]), [ar["totals"]["M_Y"], ar["totals"]["M_X"]]]
    for key, label in (("watch_G", "restart, arm G"), ("watch_D", "rollback, arm D"),
                       ("watch_G_rollback", "rollback, arm G")):
        c = comp[key]
        n["T_w vs T_p, %s: invalid, posed, difference [95%%], captures, missed" % label] = [
            [c["totals"]["U_X"], c["totals"]["U_Y"]], c["totals"]["posed"],
            [-c["D_U"]["point"], flip(c["D_U"]["interval_95"])],
            [sum(1 for r in c["per_capture"] if r["U_X"] > r["U_Y"]),
             sum(1 for r in c["per_capture"] if r["U_X"] == r["U_Y"]),
             sum(1 for r in c["per_capture"] if r["U_X"] < r["U_Y"])],
            [c["totals"]["M_X"], c["totals"]["M_Y"]]]
    n["watch rollback arm D: missed difference [95%]"] = [comp["watch_D"]["D_M"]["point"],
                                                          comp["watch_D"]["D_M"]["interval_95"]]
    n["rollout end of G2-003 (s after the rollout started)"] = round(
        _t(_load(results / "stage2/adapter/G2-003.json")["labels"]["physical_rollout_interval"]["end_us"])
        - _t(_load(results / "stage2/adapter/G2-003.json")["labels"]["physical_rollout_interval"]["R_us"]))
    n["watch rollback arm D: captures holding the difference (D1)"] = sorted(
        r["capture"] for r in comp["watch_D"]["per_capture"] if r["U_Y"] != r["U_X"])
    n["watch rollback arm G: difference in G2"] = sum(
        r["U_X"] - r["U_Y"] for r in comp["watch_G_rollback"]["per_capture"] if r["scenario"] == "G2")
    n["98.33% intervals: recheck, approval reuse, watch rollback arm D"] = [
        flip(rc["D_U"]["interval_98_33"]), ar["D_U"]["interval_98_33"], flip(comp["watch_D"]["D_U"]["interval_98_33"])]

    # Section 5.1: rollbacks
    unsafe_rb = OrderedDict((v, 0) for v in ("T_p", "T_w", "R", "L-kappa", "c-hind"))
    allowed = OrderedDict((v, {}) for v in ("T_p", "R"))
    posed_rb = 0
    for c, cell in cells(results, g_caps, "A"):
        if cell["condition"] in unsafe_rb:
            unsafe_rb[cell["condition"]] += cell["unsafe_executions"]["count"]
        if cell["condition"] == "T_p":
            posed_rb += cell["posed"]
        if cell["condition"] in allowed:
            for k, x in cell["dispositions"]["counts"].items():
                if k.startswith("ALLOW"):
                    allowed[cell["condition"]][k] = allowed[cell["condition"]].get(k, 0) + x
    n["rollbacks, arm G: invalid by view; posed"] = [unsafe_rb, posed_rb]
    n["rollbacks, arm G: allowed as rollout complete, all allowed"] = OrderedDict(
        (v, [x.get("ALLOW[R7:rollout_complete]", 0), sum(x.values())]) for v, x in allowed.items())
    by_stream = OrderedDict()
    for stream in ("S0", "S30", "Snever"):
        unsafe_s, unseen = {}, {}
        for c, cell in cells(results, d_caps, "A", streams=(stream,)):
            v = cell["condition"]
            unsafe_s[v] = unsafe_s.get(v, 0) + cell["unsafe_executions"]["count"]
            unseen[v] = unseen.get(v, 0) + sum(x for k, x in cell["dispositions"]["counts"].items()
                                               if "no_visible_change" in k)
        by_stream[stream] = [[unsafe_s["T_p"], unsafe_s["T_w"]], all(x == 0 for x in unsafe_s.values()),
                             [unseen["T_p"], unseen["T_w"]]]
    n["arm-D rollbacks by receipt stream: invalid (T_p, T_w), no view invalid, allowed unseen (T_p, T_w)"] = by_stream
    last_request = []
    for s in ("D1", "G1", "G2", "G4"):
        for c in pops[s]:
            pr = _load(results / "stage2/adapter" / (c + ".json"))["labels"]["physical_rollout_interval"]
            last_request.append(_t(pr["last_old_served_end_us"]) - _t(pr["new_ready_complete_us"]))
    n["recommendation rollouts: old revision's last workload request after all new Pods were Ready (s)"] = _range(
        last_request, 1)
    unsafe_g = OrderedDict()
    for c, cell in cells(results, g_caps, "A"):
        if cell["condition"] in ("T_p", "T_w", "R", "L-kappa", "c-hind") and cell["unsafe_executions"]["count"]:
            unsafe_g.setdefault(c, OrderedDict())
            unsafe_g[c][cell["condition"]] = unsafe_g[c].get(cell["condition"], 0) + cell["unsafe_executions"]["count"]
    n["rollbacks, arm G: invalid by capture and view"] = OrderedDict(sorted(unsafe_g.items()))

    # Section 5.2
    n["T_p vs T_p@R: first verdicts that differ"] = summ["agreement"]["T_p vs T_p@R"]["first_verdict_differs"]
    n["recheck lag: per-capture medians, maximum (s)"] = [
        _range([m["recheck_lag_s"]["median"] for m in summ["meta"].values()], 1),
        round(max(m["recheck_lag_s"]["max"] for m in summ["meta"].values()), 2)]
    n["T_p@R vs R: missed by delay (0, 10, 30, 80 s)"] = [[delay[v]["delta %d s" % d]["M"] for d in DELAYS]
                                                          for v in ("T_p@R", "R")]
    lpr = [_load(path)["conditions"]["L_p@R"]["U"] for path in sorted((a / "replays").glob("*.json"))]
    n["latest snapshot at the recheck's instants: invalid executions, captures"] = [sum(lpr), len(lpr)]

    # Section 5.3 and Fig. 4
    n["posed per delay"] = delay["T_p"]["delta 0 s"]["posed"]
    n["invalid by delay (0, 10, 30, 80 s)"] = OrderedDict(
        (v, [delay[v]["delta %d s" % d]["U"] for d in DELAYS]) for v in ("T_p", "T@F600", "L-kappa", "R", "T_p@R"))
    n["executions by delay (0, 10, 30, 80 s)"] = OrderedDict(
        (v, [delay[v]["delta %d s" % d]["executions"] for d in DELAYS]) for v in ("T_p", "T@F600", "L-kappa", "R",
                                                                                 "T_p@R"))
    n["T_p invalid by cutoff (0, 5, 30 s)"] = [delay["T_p"]["cutoff +%d s" % c]["U"] for c in CUTOFFS]
    ends = OrderedDict()
    for v in ("T_p", "R"):
        ends[v] = OrderedDict()
        for d in (30, 80):
            disp = {}
            for c, cell in cells(results, g_caps, "B"):
                if cell["condition"] == v and cell["delta_s"] == d:
                    for k, x in cell["dispositions"]["counts"].items():
                        disp[k.split("[")[0]] = disp.get(k.split("[")[0], 0) + x
            ends[v]["%d s" % d] = [disp.get("EXPIRED", 0), disp.get("CENSORED", 0)]
    n["delays 30 and 80 s: decisions expired, censored at the end of the records"] = ends
    n["T@F600: invalid"] = delay["T@F600"]["total"]["U"]
    n["poller thinned x2, x4: invalid, missed, executions"] = [
        [delay[v]["total"][k] for k in ("U", "M", "executions")] for v in ("T_p[thin 2]", "T_p[thin 4]")]
    n["poller thinned: invalid unchanged in every capture"] = all(
        summ["per_capture_U"][c][v] == summ["per_capture_U"][c]["T_p"] for c in summ["per_capture_U"]
        for v in ("T_p[thin 2]", "T_p[thin 4]"))
    n["poller thinned: captures whose missed opportunities changed"] = sorted(
        c for c in g_caps if any(replays[c][v]["M"] != replays[c]["T_p"]["M"] for v in ("T_p[thin 2]", "T_p[thin 4]")))
    iv = [m["poll_intervals"] for m in summ["meta"].values()]
    n["Pod-list median intervals (s): captured, x2, x4"] = [_range([x[k]["median_s"] for x in iv], 1)
                                                            for k in ("published", "thin 2", "thin 4")]
    n["added latency 5 s, 30 s: invalid, missed, executions"] = [
        [delay[v]["total"][k] for k in ("U", "M", "executions")] for v in ("T_p[late 5]", "T_p[late 30]")]

    # Section 5.4 and Table 7
    sur = summ["surrogate"]["by_condition_and_label"]
    n["Table 7: executions, EndpointSlice not ready, with service traffic, target served a request"] = OrderedDict(
        (v, OrderedDict((lab, [sur[v][lab][k] for k in ("executions", "es_target_not_ready", "with_spans",
                                                         "with_target_span_after")])
                        for lab in ("unsafe (V-target)", "neutral", "GT-2-B") if lab in sur[v]))
        for v in ("T_p", "L-kappa", "R"))
    n["invalid executions near a call to the target's own address"] = [
        sur[v]["unsafe (V-target)"]["with_probes_target_pod"] for v in ("T_p", "L-kappa")]
    pc = summ["surrogate"]["probe_calls_in_captures"]
    n["service-addressed probe calls: failing, all"] = [pc["service_failing"], pc["service"]]
    n["server spans with an error status"] = sum(v for k, v in summ["surrogate"]["server_spans_in_captures_by_status"]
                                                 .items() if k not in ("UNSET", "OK"))
    failing = OrderedDict((s, sum(_load(a / "surrogate" / (c + ".json"))["surrogate"]["probe_calls_in_capture"]
                                  ["pod_address_failing"] for c in pops[s])) for s in SCENARIOS_G)
    n["failing Pod-address probes by scenario; R executions near one (neutral, U); T_p executions near one"] = [
        failing, [sur["R"][lab]["with_probe_failure_target_pod"] for lab in ("neutral", "U")],
        sum(g["with_probe_failure_target_pod"] for g in sur["T_p"].values())]

    # Section 5.5
    fu, dev = stress["follow_up"], stress["development"]
    n["switch to onset (s): follow-up range; development capture with the original failure"] = [
        _range([v["onset_minus_switch_s"] for v in fu["per_capture"].values()], 1),
        round(-dev["per_capture"]["I2-002"]["onset_minus_switch_s"], 1)]
    curves = fu["curves_top1_of_n"]
    n["every API record delayed, cutoff +5 s: captures first at d = 10 s and 20 s (three policies)"] = [
        [p[1] for p in curves["delayed_api | %s | 5 s" % pol] if p[0] in (10, 20)]
        for pol in ("latest_state", "temporal_join", "bitemporal_abstain_F600")]
    ok = []
    for stage in (fu, dev):
        for key, v in stage["failures_vs_cutoff"].items():
            if key.split(" | ")[1] in ("latest_state", "temporal_join", "bitemporal_abstain_F600"):
                ok.append(v["cells_failing"] == v["of_which_delay_exceeds_cutoff_gap"])
    n["every failing cell of the three policies has a delay beyond the switch-to-cutoff gap"] = all(ok)
    n["switch records delayed or corrected late: follow-up failures (three policies)"] = sum(
        v["cells_failing"] for k, v in fu["failures_vs_cutoff"].items()
        if k.split(" | ")[0] in ("delayed_switch", "corrected_late")
        and k.split(" | ")[1] in ("latest_state", "temporal_join", "bitemporal_abstain_F600"))
    n["span identity ranks the faulty Pod first in every cell after the onset"] = all(
        p[1] == p[2] for stage in (fu, dev) for k, pts in stage["curves_top1_of_n"].items()
        if "| hindsight |" in k and not k.endswith("| 0 s") for p in pts if p[2] > 0)
    paired = [r for c in d_caps for obs in ("poller", "watch")
              for r in _load(results / "stage2/diagnosis" / (c + ".json"))["paired_receipt"][obs]]
    n["follow-up, unperturbed: every policy first after the onset, none at it"] = [
        all(r["outcome_span_end"] == "top1" for r in paired if r["delta"] != "0 s"),
        all(r["outcome_span_end"] != "top1" for r in paired if r["delta"] == "0 s")]
    n["spans at their measured receipt: cells with an unchanged outcome, cells"] = [
        sum(1 for r in paired if r["comparison"] == "equal"), len(paired)]
    n["follow-up arm D: Pod-list median intervals (s)"] = _range(
        [v["pod_list_intervals"]["median_s"] for v in fu["per_capture"].values()], 1)
    n["follow-up arm D: interval from the switch poll to the next poll (s)"] = _range(
        [v["pod_list_intervals"]["following_switch_s"] for v in fu["per_capture"].values()], 1)
    raw = _load(a / "diagnosis_stress.json")
    three = ("latest_state", "temporal_join", "bitemporal_abstain_F600")
    modes = {}
    for stage, key in (("follow-up", "per_capture"), ("development", "development_per_capture")):
        for cap in raw[key]:
            base = {(r["delta_s"], r["policy"]): r for r in cap["rows"] if r["stream"] == "complete"}
            for r in cap["rows"]:
                if r["stream"] in ("complete", "-") or r["delta_s"] == 0 or r["policy"] not in three:
                    continue
                b = base.get((r["delta_s"], r["policy"]))
                if b is None or not b["top1"] or r["top1"]:
                    continue
                family = "every API record" if r["stream"].startswith("delayed_api") else "switch records"
                mode = "absent" if r["outcome"] == "absent" else ("last" if r["rank"] == r["candidates"] else "other")
                k = "%s | %s | %s" % (stage, family, r["policy"])
                modes.setdefault(k, {})
                modes[k][mode] = modes[k].get(mode, 0) + 1
    n["stress test: failing cells of the three policies by mode (faulty Pod absent, ranked last)"] = OrderedDict(
        sorted(modes.items()))
    i2 = next(c for c in raw["development_per_capture"] if c["capture"] == "I2-002")
    after_onset = [r for r in i2["rows"] if r["stream"] == "complete" and r["delta_s"] > 0]
    n["I2-002 unperturbed after the onset: (rank, candidates) of temporal join and two-clock; latest state first"] = [
        sorted({(r["rank"], r["candidates"]) for r in after_onset
                if r["policy"] in ("temporal_join", "bitemporal_abstain_F600")}),
        all(r["top1"] for r in after_onset if r["policy"] == "latest_state")]
    dpi = [v["pod_list_intervals"] for v in dev["per_capture"].values()]
    n["development Pod-list intervals: medians, longest; the one ending with I2-002's switch (s)"] = [
        _range([x["median_s"] for x in dpi], 1), round(max(x["max_s"] for x in dpi), 1),
        round(dev["per_capture"]["I2-002"]["pod_list_intervals"]["ending_with_switch_s"], 1)]

    # Section 5.6 and Fig. 6
    au = summ["audit"]
    late = au["decisions_with_records_valid_before_cutoff_available_after"]
    n["records valid before the cutoff, available after: decisions, kubelet, API; longest kubelet wait (s)"] = [
        late["either"], late["k1"], late["api"], round(au["largest_such_wait_s_max_over_captures"]["k1"], 1)]
    ev = au["event_time_reconstruction"]
    n["valid-time replay, captured latency: first verdicts, dispositions, executions; its invalid count"] = [
        ev["first_verdict_differs"], ev["disposition_differs"], ev["execution_differs"],
        au["event_time_unsafe_and_missed"][0]]
    lr = summ["latency"]["event_time_reconstruction_differs"]
    n["valid-time replay with 5 s, 30 s latency: first verdicts, executions"] = [
        [lr[v]["first_verdict_differs"], lr[v]["execution_differs"]] for v in ("T_p[late 5]", "T_p[late 30]")]
    n["end-of-capture replay: first verdicts; decisions whose context changed"] = [
        au["final_store_verdict"]["first_verdict_differs"], au["end_of_capture_state"]["either_differs"]]
    first = {}
    for c, cell in cells(results, g_caps, "B"):
        if cell["condition"] == "T_p":
            for k, x in cell["first_verdicts"]["counts"].items():
                first[k.split("[")[0]] = first.get(k.split("[")[0], 0) + x
    finals = {}
    for c in g_caps:
        for k, x in _load(a / "replays" / (c + ".json"))["audit"]["final_store_verdict"]["verdicts"].items():
            finals[k] = finals.get(k, 0) + x
    differs = au["final_store_verdict"]["first_verdict_differs"]
    unreachable = first.get("ABSTAIN", 0) + first.get("NEEDS_APPROVAL", 0) if set(finals) <= {"ALLOW", "DENY"} else None
    n["two-clock first verdicts: abstain, allow, deny, needs approval"] = [
        first.get(k, 0) for k in ("ABSTAIN", "ALLOW", "DENY", "NEEDS_APPROVAL")]
    n["end-of-capture replay: target verdicts (allow, deny); abstain/approval misreports; inversions"] = [
        [finals.get("ALLOW", 0), finals.get("DENY", 0)], unreachable,
        None if unreachable is None else differs - unreachable]
    posed = au["posed"]
    n["audit figure percentages (valid times 0, 5, 30 s; end of capture)"] = [round(100.0 * x / posed, 1) for x in (
        ev["first_verdict_differs"], lr["T_p[late 5]"]["first_verdict_differs"],
        lr["T_p[late 30]"]["first_verdict_differs"], au["final_store_verdict"]["first_verdict_differs"])]
    n.update(followup_numbers(a, posed))
    n.update(attribution_numbers(a))
    n.update(snapshot_numbers(a))
    return n


def snapshot_numbers(a: Path) -> OrderedDict:
    """State histories kept as periodic snapshots of the poller's lists (results/stage2/analyses/snapshots_summary.json):
    k = 1, 6, 12, 24 polls per kept list; S read with one clock, T with the objects' own timestamps, W the watch."""
    path = a / "snapshots_summary.json"
    n = OrderedDict()
    if not path.exists():
        return n
    sn = _load(path)
    K = ("1", "6", "12", "24")
    short = ("starting", "not_ready", "terminating")
    ep = sn["episodes"]
    n["snapshots: realised list intervals (s; median over captures)"] = [
        round(sn["intervals"][k]["median_s"], 2 if k == "1" else 1) for k in K]
    n["snapshots: Pods; episodes starting, ready, not ready, terminating; short episodes"] = [
        sn["pods"], [ep["by_type"][t] for t in ("starting", "ready", "not_ready", "terminating")],
        sum(ep["by_type"][t] for t in short)]
    n["snapshots: short episodes recorded, one clock and objects' timestamps (per interval); watch"] = [
        [round(sum(ep["recorded"]["S"][k][t] for t in short), 1) for k in K],
        [round(sum(ep["recorded"]["T"][k][t] for t in short), 1) for k in K],
        sum(ep["recorded"]["W"][t] for t in short)]
    n["snapshots: start-ups, restarts, terminations recorded (one clock; objects' timestamps; per interval)"] = \
        OrderedDict((h, OrderedDict((k, [round(ep["recorded"][h][k][t], 1) for t in short]) for k in K))
                    for h in ("S", "T"))
    exp = ep["uniform_phase_expectation_closed"]
    n["snapshots: short episodes expected by min(1, d / interval) at the realised 15, 30, 60 s and at 300 s"] = [
        round(sum(exp[k][t] for t in short), 1) for k in ("k=6", "k=12", "k=24", "300 s")]
    span = ep["replacement_span_s"]
    n["snapshots: replacement from the first new Pod's creation to the last old Pod's removal (s; min, median, "
      "max)"] = [round(span["min"], 1), round(span["median"], 1), round(span["max"], 1)]
    n["snapshots: recorded starts, one clock: median delay (s) per interval; objects' timestamps: placed within 1 s "
      "(%) per interval"] = [
        [round(ep["start_lag_s"]["S"][k]["median_s"], 1) for k in K],
        [round(100 * ep["start_lag_s"]["T"][k]["share_within_1s"], 1) for k in K]]
    st = sn["status"]

    def wrong(h, k):
        v = st[h][k]
        return round(100.0 * v["wrong"] / (v["seconds"] - v["unknown"]), 2)
    n["snapshots: wrong Pod status, % of answered Pod-seconds (one clock; objects' timestamps; per interval); "
      "Pod-seconds; watch wrong"] = [[wrong("S", k) for k in K], [wrong("T", k) for k in K],
                                     int(round(st["S"]["1"]["seconds"])), st["W"]["wrong"]]
    obj = sn["object_states"]
    total = sum(obj["watch"].values())
    n["snapshots: object states the watch delivered; shown by the kept lists (%, per interval)"] = [
        total, [round(100.0 * sum(obj["shown_by_kept_lists"][k].values()) / total, 1) for k in K]]
    by = sn["decisions"]["by_interval"]
    n["snapshots: gate F = 30 s per interval: executions (mean over phases), invalid (mean; range), missed (mean)"] = \
        OrderedDict((k, [round(by[k]["T F30"]["executions"]["mean"], 1), round(by[k]["T F30"]["invalid"]["mean"], 1),
                         [by[k]["T F30"]["invalid"]["min"], by[k]["T F30"]["invalid"]["max"]],
                         round(by[k]["T F30"]["missed"]["mean"], 1)]) for k in K)
    n["snapshots: gate F = 600 s invalid per interval (mean over phases)"] = [
        round(by[k]["T F600"]["invalid"]["mean"], 1) for k in K]
    ci = sn["intervals_of_differences"]

    def pi(v):
        return [round(v["point"], 1), [round(x, 1) for x in v["interval_95"]]]
    n["snapshots: gate F = 30 s minus captured, invalid and executions (point, 95%; 15, 30, 60 s)"] = OrderedDict(
        (k, [pi(ci["gate invalid on T (F = 30 s) minus captured, k=%s" % k]),
             pi(ci["gate executions on T (F = 30 s) minus captured, k=%s" % k])]) for k in K[1:])

    def share(v):
        return [round(100 * v["point"], 2), [round(100 * x, 2) for x in v["interval_95"]]]
    n["snapshots: audit, first verdicts misreported (%; point, 95%) from one clock (2.45, 15, 30, 60 s) and from the "
      "objects' timestamps (15, 30, 60 s)"] = OrderedDict([
        ("S", [share(ci["audit from S: first verdicts reported differently (share), k=%s" % k]) for k in K]),
        ("T", [share(ci["audit from T: first verdicts reported differently (share), k=%s" % k]) for k in K[1:]])])
    n["snapshots: short episodes recorded, objects' timestamps minus one clock (point, 95%; 15, 30, 60 s)"] = [
        pi(ci["short episodes recorded, T - S, k=%s" % k]) for k in K[1:]]
    n["snapshots: wrong Pod-seconds, one clock minus objects' timestamps (point, 95%; 15, 30, 60 s)"] = [
        pi(ci["wrong Pod-seconds, S - T, k=%s" % k]) for k in K[1:]]
    n["snapshots: gate F = 30 s, decisions declined for target identity (R1), recent change (R2), replica floor (R3) "
      "(mean over phases; per interval)"] = OrderedDict(
        (k, [round(by[k]["T F30 declined (mean over phases)"].get(r, 0), 1)
             for r in ("DENY[R1]", "NEEDS_APPROVAL[R2]", "DENY[R3]")]) for k in K)
    n["snapshots: executions at dispatch delays of 0 and 10 s, F = 30 s and 600 s (mean over phases; per interval)"] = \
        OrderedDict((k, [round(by[k]["T F30 executions at dispatch delays of 0 and 10 s (mean over phases)"], 1),
                         round(by[k]["T F600 executions at dispatch delays of 0 and 10 s (mean over phases)"], 1)])
                    for k in K)
    n["snapshots: lists every 60 s, invalid executions at the 10 s delay per phase, F = 30 s and 600 s"] = [
        by["24"]["T F30 invalid at the 10 s dispatch delay (per phase)"],
        by["24"]["T F600 invalid at the 10 s dispatch delay (per phase)"]]
    n["snapshots: lists every 30 s, invalid executions at the 10 s delay per phase, F = 30 s and 600 s"] = [
        by["12"]["T F30 invalid at the 10 s dispatch delay (per phase)"],
        by["12"]["T F600 invalid at the 10 s dispatch delay (per phase)"]]
    n["snapshots: missed opportunities, F = 30 s and 600 s (mean over phases; per interval)"] = [
        [round(sum(by[k][v + " missed (per phase)"]) / len(by[k][v + " missed (per phase)"]), 1) for k in K]
        for v in ("T F30", "T F600")]
    dur = ep["closed_durations_s"]
    n["snapshots: episode durations, median s (start-ups, not ready after a container restart, terminations)"] = [
        int(round(dur[t]["median"])) for t in short]
    n["snapshots: expected by min(1, d / interval), start-ups, restarts, terminations (realised 15, 30, 60 s)"] = [
        [round(exp[k][t], 1) for t in short] for k in ("k=6", "k=12", "k=24")]
    vol = sn["volume"]
    n["snapshots: records per hour, lists (per interval); after merging duplicates (15, 60 s); watch events per "
      "hour; hours"] = [[vol["poller"][k]["records_per_hour"] for k in K],
                        [vol["poller"][k]["merged_records_per_hour"] for k in ("6", "24")],
                        vol["watch"]["events_per_hour"], round(vol["hours"], 2)]
    return n


ATTRIBUTION_POLICIES = ("hindsight", "latest_state", "temporal_join", "bitemporal_abstain_F600", "bitemporal_abstain_F30")


def attribution_numbers(a: Path) -> OrderedDict:
    """Diagnosis by attribution (results/stage2/analyses/diagnosis_attribution.json): the faulty Pod's requests per
    window, [attributed to it and served by it, served by it, attributed to it], summed over captures."""
    n = OrderedDict()
    path = a / "diagnosis_attribution.json"
    if not path.exists():
        return n
    doc = _load(path)
    caps_all = doc["per_capture"] + doc["development_per_capture"]

    def row(cap, stream, delta, policy):
        return next(r for r in cap["rows"] if r["stream"] == stream and r["delta_s"] == delta and r["policy"] == policy)

    def summed(caps, delta, policy, window):
        tot = [0, 0, 0]
        for cap in caps:
            tot = [t + v for t, v in zip(tot, row(cap, "complete", delta, policy)["faulty_pod"][window])]
        return tot
    n["diagnosis: captures whose faulty Pod is the recommendation service's serving Pod / captures"] = [
        sum(1 for c in caps_all if c["faulty_pod_is_the_recommendation_service_s_serving_pod"]), len(caps_all)]
    for stage, caps in (("follow-up", doc["per_capture"]), ("development", doc["development_per_capture"])):
        for delta in (5, 30):
            n["attribution, %s, captured records, %d s cutoff: faulty Pod's [attributed and served, served, attributed] "
              "before and after the onset (span identity, latest state, temporal join, two-clock 600 s, 30 s)"
              % (stage, delta)] = [[summed(caps, delta, p, w) for w in ("normal", "anomalous")]
                                   for p in ATTRIBUTION_POLICIES]
    snap = ("latest_state", "temporal_join", "bitemporal_abstain_F600")
    delayed = [r for c in doc["per_capture"] for r in c["rows"]
               if r["stream"].startswith("delayed_api_") and r["policy"] in snap]
    beyond = [r for r in delayed if int(r["stream"].split("_")[-1][:-1]) >= r["cutoff_minus_switch_s"]]
    within = [r for r in delayed if int(r["stream"].split("_")[-1][:-1]) < r["cutoff_minus_switch_s"]]
    n["attribution, follow-up, every API record delayed (5 and 30 s cutoffs; latest state, temporal join, two-clock "
      "600 s): cells delayed at least the switch-to-cutoff time, of these with no fault-window request attributed to "
      "the faulty Pod and the Pod not a candidate; other cells, of these with every fault-window request attributed to "
      "it, none wrongly, and the Pod ranked first"] = [
        len(beyond), sum(1 for r in beyond if r["faulty_pod"]["anomalous"][0] == 0 and not r["candidate"]),
        len(within), sum(1 for r in within if r["top1"]
                         and r["faulty_pod"]["anomalous"][0] == r["faulty_pod"]["anomalous"][1]
                         == r["faulty_pod"]["anomalous"][2])]
    i2 = next(c for c in doc["development_per_capture"] if c["capture"] == "I2-002")
    n["attribution, development capture I2-002, 5 s cutoff, before the onset (span identity, latest state, temporal "
      "join); ranked first"] = [[row(i2, "complete", 5, p)["faulty_pod"]["normal"] for p in (
        "hindsight", "latest_state", "temporal_join")], [row(i2, "complete", 5, p)["top1"] for p in (
        "hindsight", "latest_state", "temporal_join")]]
    return n


def followup_numbers(a: Path, posed: int) -> OrderedDict:
    """Outcome coverage, invalid-restart targets, parameter sweep, receipt-time audit, store size and diagnosis
    robustness (results/stage2/analyses/sweeps_summary.json)."""
    sw = _load(a / "sweeps_summary.json")
    n = OrderedDict()
    out = sw["outcomes"]
    n["Table 4: invalid, valid, uncertain, approval, denied, expired, censored (per view)"] = OrderedDict(
        (v, [out[v][k] for k in ("invalid", "valid", "uncertain", "approval", "denied", "expired", "censored")])
        for v in out)
    n["invalid per execution (%), per view"] = OrderedDict(
        (v, round(100.0 * out[v]["invalid"] / out[v]["executions"], 2)) for v in out)
    n["invalid restart targets: gone, terminating, other states (per view)"] = OrderedDict(
        (v, [out[v]["invalid_by_target_state"].get("gone", 0), out[v]["invalid_by_target_state"].get("terminating", 0),
             sum(x for k, x in out[v]["invalid_by_target_state"].items() if k not in ("gone", "terminating"))])
        for v in out)
    lag = sw["coverage"]["T_p+lag"]
    n["two-clock gate with the recheck's lag: invalid, executions; targets gone, terminating, other states"] = [
        lag["invalid"], lag["executions"],
        [lag["invalid_by_target_state"].get("gone", 0), lag["invalid_by_target_state"].get("terminating", 0),
         sum(x for k, x in lag["invalid_by_target_state"].items() if k not in ("gone", "terminating"))]]
    m = sw["mutually_evaluable"]["T_p vs R"]
    n["T_p vs R on decisions neither left censored: decisions; T_p invalid, executions; R invalid, executions"] = [
        m["decisions"], m["outcomes"]["a"].get("invalid", 0), sum(m["outcomes"]["a"].get(k, 0) for k in (
            "invalid", "valid", "uncertain")), m["outcomes"]["b"].get("invalid", 0),
        sum(m["outcomes"]["b"].get(k, 0) for k in ("invalid", "valid", "uncertain"))]
    n["recheck executions inside a mitigation window: posed as an opportunity, posed before it"] = [
        sw["coverage"]["R"]["opportunity_executions"].get("posed as an opportunity", 0),
        sw["coverage"]["R"]["opportunity_executions"].get("posed before the opportunity", 0)]
    sweep = OrderedDict()
    for block, cells in sw["sweep"].items():
        sweep[block] = OrderedDict((name, [c["invalid"], c["executions"], c["missed"], c["opportunities"]])
                                   for name, c in cells.items())
    n["sweep: invalid, executions, missed, opportunities per setting"] = sweep
    restarts = sw["sweep"]["arm G | B | S0"]
    n["sweep, restarts: invalid targets below floor, not Ready, terminating, gone (per setting)"] = OrderedDict(
        (name, [c["invalid_by_target_state"].get(k, 0) for k in ("below_floor", "not_ready", "terminating", "gone")])
        for name, c in restarts.items())
    n["sweep, restarts: invalid by dispatch delay 0 and 10 s (N = 0, 10, 30 s)"] = [
        [restarts[name]["by_dispatch_delay"][d].get("invalid", 0) for d in ("0 s", "10 s")]
        for name in ("F=30,N=0", "F=30,N=10", "F=30,N=30")]
    n["sweep, restarts: executions added without the window; approvals of the window at 30 s"] = [
        restarts["F=30,N=0"]["executions"] - restarts["F=30,N=30"]["executions"],
        restarts["F=30,N=30"]["declined"].get("NEEDS_APPROVAL[R2]", 0)]
    n["restart decisions of the two-clock gate declined, by rule"] = sw["coverage"]["T_p"]["declined"]
    n["arm-D rollbacks posed per receipt stream (S0, S30, Snever)"] = [
        sw["sweep"]["arm D | A | %s" % s]["F=30,N=30"]["posed"] for s in ("S0", "S30", "Snever")]
    comp = _load(a / "per_capture_stats.json")["comparisons"]
    rc = [r["U_X"] - r["U_Y"] for r in comp["recheck"]["per_capture"]]
    ar = [r["U_Y"] - r["U_X"] for r in comp["approval_reuse"]["per_capture"]]
    n["capture-level effect: gate minus recheck, approval reuse minus gate (median; range)"] = [
        [statistics.median(rc), [min(rc), max(rc)]], [statistics.median(ar), [min(ar), max(ar)]]]
    probe = OrderedDict()
    for path in sorted((a / "surrogate").glob("*.json")):
        doc = _load(path)
        if not doc["surrogate"]["probe_calls_in_capture"]["service_failing"]:
            continue
        probe[doc["capture"]] = OrderedDict(
            (view, OrderedDict((label, v["with_probe_failure_service"]) for label, v in doc["surrogate"][view].items()
                               if v["with_probe_failure_service"]))
            for view in ("T_p", "L-kappa", "R"))
    n["failing service-address probe: capture; executions within 2 s by view and label"] = probe
    times = {}
    for path in sorted((a.parent / "adapter").glob("*.json")):
        for p in _load(path)["labels"]["pods"]:
            if p.get("deletion_request") and p.get("gone_after"):
                times.setdefault(p["service"], []).append(_t(p["gone_after"]) - _t(p["deletion_request"]))
    n["deleted Pods: deletion request to first evidence of removal (s), recommendation, catalog (range)"] = [
        _range(times.get("recommendationservice", []), 1), _range(times.get("productcatalogservice", []), 1)]
    rules = set()
    for path in sorted((a.parent / "adapter").glob("*.json")):
        for cell in _load(path)["T1_cells"]:
            for key in cell["dispositions"]["counts"]:
                if key.split("[")[0] in ("DENY", "NEEDS_APPROVAL"):
                    rules.update(re.findall(r"R\d+", key))
    n["rules that declined a decision (every view, stream and action)"] = sorted(rules)
    stress = _load(a / "diagnosis_stress.json")
    counts = sorted({r["candidates"] for cap in stress["per_capture"] + stress["development_per_capture"]
                     for r in cap["rows"] if r["stream"] == "complete" and r["delta_s"] > 0})
    n["diagnosis: candidates per capture, policy and cutoff after the onset (range)"] = [counts[0], counts[-1]]
    n["receipt-time audit: first verdicts, dispositions, executions misreported; invalid reported (0, 5, 30 s)"] = \
        OrderedDict((lat, [v["receipt_time_vs_gate"]["first_verdict_differs"],
                           v["receipt_time_vs_gate"]["disposition_differs"],
                           v["receipt_time_vs_gate"]["execution_differs"], v["receipt_time_replay"]["invalid"]])
                    for lat, v in sw["audit"].items())
    n["receipt-time audit percentages (0, 5, 30 s)"] = [
        round(100.0 * v["receipt_time_vs_gate"]["first_verdict_differs"] / posed, 1) for v in sw["audit"].values()]
    if "own_timestamps_audit" in sw:
        own = sw["own_timestamps_audit"]
        n["audit from a receipt log with the records' own timestamps: first verdicts, dispositions, executions "
          "misreported; executions and invalid ones reported (0, 5, 30 s)"] = OrderedDict(
            (lat, [v["own_timestamps_vs_gate"]["first_verdict_differs"], v["own_timestamps_vs_gate"]["disposition_differs"],
                   v["own_timestamps_vs_gate"]["execution_differs"], v["own_timestamps_replay"]["executions"],
                   v["own_timestamps_replay"]["invalid"]]) for lat, v in own.items())
        n["audit from a receipt log with the records' own timestamps: percentages (0, 5, 30 s)"] = [
            round(100.0 * v["own_timestamps_vs_gate"]["first_verdict_differs"] / posed, 1) for v in own.values()]
        n["gate's executions with the poller's records 0, 5, 30 s later"] = [
            v["gate"]["executions"] for v in own.values()]
        n["audit replays' approval requests by the recent-change rule (receipt time, own timestamps; 5 and 30 s)"] = [
            [sw["audit"][lat]["receipt_time_replay"]["declined"].get("NEEDS_APPROVAL[R2]", 0),
             own[lat]["own_timestamps_replay"]["declined"].get("NEEDS_APPROVAL[R2]", 0)] for lat in ("5 s", "30 s")]
    st = sw["store"]
    n["poller store per arm-G capture: versions, keys (median); versions per key (range)"] = [
        st["observations"]["median"], st["keys"]["median"],
        [st["versions_per_key"]["min"], st["versions_per_key"]["max"]]]
    dl = sw["decision_log"]
    n["decision log: input records per decision (median of capture medians; range); references; distinct records; "
      "store records, versions"] = [
        dl["records_per_decision_median"]["median"],
        [dl["records_per_decision_median"]["min"], dl["records_per_decision_median"]["max"]],
        dl["record_references"], dl["distinct_records"], dl["store_records"], dl["store_versions"]]
    n["decision log: distinct records per store records (%, range over captures)"] = [
        round(100 * dl["distinct_records_share_of_store_records"]["min"], 1),
        round(100 * dl["distinct_records_share_of_store_records"]["max"], 1)]
    n["Table 8: decisions changed; re-evaluable from their own entry, from all entries (per re-evaluation)"] = \
        OrderedDict((q, [v["outcome_changed"], v["changed_own_log"], v["changed_all_logs"]])
                    for q, v in dl["questions"].items())
    n["check to act: recheck executions invalid, uncertain, valid per lag (0, 0.1, 0.5, 1 s)"] = OrderedDict(
        (lag, [v["invalid"], v["uncertain"], v["valid"]]) for lag, v in sw["check_to_act"]["executions_by_lag"].items())
    um = sw["uncertain_mutually_evaluable"]
    no_effect = "GT-2-B conditions without an established effect"

    def possible(view, key="executions"):
        return sum(c[key] for r, c in um["views"][view]["uncertain"].items() if r != no_effect)
    n["mutually evaluable decisions: decisions; T_p invalid, uncertain, possibly invalid; R invalid, uncertain, "
      "possibly invalid, possibly invalid with a target request in the next 2 s"] = [
        um["decisions"],
        [um["views"]["T_p"]["invalid"], sum(c["executions"] for c in um["views"]["T_p"]["uncertain"].values()),
         possible("T_p")],
        [um["views"]["R"]["invalid"], sum(c["executions"] for c in um["views"]["R"]["uncertain"].values()),
         possible("R"), possible("R", "target_served_after")]]
    n["mutually evaluable decisions: gate minus recheck, scored / every possibly invalid uncertain recheck execution "
      "invalid / only those without a target request after (point, 95%, 98.33%)"] = OrderedDict(
        (k, [v["point"], v["interval_95"], v["interval_98_33"]]) for k, v in um["gate_minus_recheck"].items())
    rob = sw.get("diagnosis_robustness", {}).get("follow_up", {})

    def draws(variant, delta, policies):
        return [rob["%s | %d s | %s" % (variant, delta, p)]["top1_draws"] for p in policies]
    snap = ("latest_state", "temporal_join", "bitemporal_abstain_F600")
    if rob:
        n["robustness: captures first with the onset 10 s early (temporal join, two-clock, span identity; +5, +30 s)"] = [
            [rob["onset_shift_-10s | %d s | %s" % (d, p)]["all_draws_top1"] for p in (
                "temporal_join", "bitemporal_abstain_F600", "hindsight")] for d in (5, 30)]
        n["robustness: every policy first in every capture for onset shifts of -5..+10 s"] = all(
            v["all_draws_top1"] == v["captures"] for k, v in rob.items()
            if k.startswith("onset_shift_") and not k.startswith("onset_shift_-10s")
            and not k.endswith("bitemporal_abstain_F30"))
        n["robustness: onset 10 s early, latest state first (+5, +30 s); onset 5 s early, +5 s: captures with every "
          "policy first"] = [
            [rob["onset_shift_-10s | %d s | latest_state" % d]["all_draws_top1"] for d in (5, 30)],
            min(rob["onset_shift_-5s | 5 s | %s" % p]["all_draws_top1"] for p in (
                "latest_state", "temporal_join", "bitemporal_abstain_F600", "bitemporal_abstain_F30", "hindsight"))]
        dev = sw["diagnosis_robustness"].get("development", {})
        if dev:
            n["robustness, development: temporal join and two-clock first (complete, onset 2 s early; +5 s); span "
              "identity first (complete, onset 10 s late; +5 s); span identity draws first, half the traces (+5 s)"] = [
                [[dev["%s | 5 s | %s" % (v, p)]["all_draws_top1"] for v in ("complete", "onset_shift_-2s")]
                 for p in ("temporal_join", "bitemporal_abstain_F600")],
                [dev["%s | 5 s | hindsight" % v]["all_draws_top1"] for v in ("complete", "onset_shift_+10s")],
                [dev["sampled_0.5 | 5 s | hindsight"]["top1_draws"], dev["sampled_0.5 | 5 s | hindsight"]["draws"]]]
            n["robustness, development: draws first with half the traces (+5 s): temporal join, two-clock, span "
              "identity"] = [dev["sampled_0.5 | 5 s | %s" % p]["top1_draws"] for p in (
                "temporal_join", "bitemporal_abstain_F600", "hindsight")]
        n["robustness: sampled traces, draws with the faulty Pod first (snapshot policies, span identity; 0.5, 0.25, "
          "0.1; +5 and +30 s)"] = OrderedDict(
            (p, [[min(draws("sampled_%s" % p, d, snap)), max(draws("sampled_%s" % p, d, snap)),
                  draws("sampled_%s" % p, d, ("hindsight",))[0]] for d in (5, 30)]) for p in ("0.5", "0.25", "0.1"))
        n["robustness: spans without Pod identity, span identity draws first (0.5, 0.75, 0.9; +5 and +30 s); "
          "snapshot policies unaffected"] = [
            [[draws("identity_missing_%s" % p, d, ("hindsight",))[0] for d in (5, 30)] for p in ("0.5", "0.75", "0.9")],
            all(rob["identity_missing_%s | %d s | %s" % (p, d, q)]["top1_draws"]
                == rob["identity_missing_%s | %d s | %s" % (p, d, q)]["draws"]
                for p in ("0.5", "0.75", "0.9") for d in (5, 30) for q in snap)]
    return n


EXPECTED = OrderedDict([
    ("Table 2: new Pods ready, rollout end, fault start (s after the rollout started)",
     {"D1": [[6, 12], [7, 13], [20, 21]], "D2": [[0, 0], [0, 0], [91, 93]], "G1": [[20, 26], [22, 27], [27, 33]],
      "G2": [[20, 35], [20, 35], [27, 27]], "G3": [[1, 2], [1, 2], [10, 10]], "G4": [[21, 21], [21, 21], [20, 20]]}),
    ("arm-G requests without a server span of the changed service (not posed), requests", [14, 2880]),
    ("arm D: longest Pod-list gap in the observer-validity check (s)", 4.1),
    ("Table 2: terminated target out of service (s), G2 and G3", {"G2": [7.0, 8.0], "G3": [1.0, 2.0]}),
    ("Table 3 invalid (G1, G2, G3, G4, all)",
     {"T_p": [9, 10, 85, 6, 110], "L_p": [9, 10, 85, 6, 110], "T_w": [9, 10, 85, 6, 110],
      "T_p+lag": [10, 12, 90, 7, 119], "T_p@R": [0, 0, 0, 0, 0], "R": [0, 0, 0, 0, 0],
      "L-kappa": [422, 415, 361, 264, 1462]}),
    ("Table 3 missed / executions",
     {"T_p": [115, 10478], "L_p": [115, 10478], "T_w": [113, 10654], "T_p+lag": [118, 10478], "T_p@R": [115, 18610],
      "R": [85, 20227], "L-kappa": [116, 19604]}),
    ("Table 3 posed (G1, G2, G3, G4, all); opportunities", [10800, 10728, 6384, 6480, 34392, 124]),
    ("T_p and L_p: decisions that differ (first verdict, disposition, execution)", [0, 0, 0]),
    ("T_w and T_p: same invalid count in every capture", True),
    ("posed restart decisions per arm-G capture (range)", [2124, 2160]),
    ("Table 3 uncertain executions",
     {"T_p": 178, "L_p": 178, "T_w": 181, "T_p+lag": 173, "T_p@R": 36, "R": 242, "L-kappa": 238}),
    ("uncertain executions that could be invalid", {"T_p": 158, "R": 92, "L-kappa": 222}),
    ("restart executions labelled V-floor, every view", 0),
    ("invalid two-clock restarts: terminating, gone; fault's Pod; rollout-deleted old Pods; last (s)",
     [[26, 84], 0, 110, 9.9]),
    ("mitigation opportunities: G1 captures with an established effect; opportunities per capture",
     [["G1-002", "G1-005"], {"G1-002": 68, "G1-005": 56}]),
    ("recheck: difference [95%], 98.33%", [110, [100, 121], [97, 123]]),
    ("recheck: captures more / equal / fewer", [13, 3, 0]),
    ("recheck per scenario: difference [95%]",
     {"G1": [9, [3, 17]], "G2": [10, [3, 17]], "G3": [85, [84, 87]], "G4": [6, [3, 9]]}),
    ("recheck leave-one-out: range, intervals excluding 0", [[81, 110], [16, 16]]),
    ("recheck without G3: invalid, captures, difference [95%], more/equal/fewer",
     [[25, 0], 13, [25, [14, 36]], [10, 3, 0]]),
    ("recheck missed: difference [95%]", [30, [0, 68]]),
    ("T_p vs T_p@R: invalid, missed, difference [95%], captures", [[110, 0], [115, 115], [110, [100, 121]], [13, 3, 0]]),
    ("T_p@R vs R: invalid, missed, difference [95%], missed difference [95%], captures",
     [[0, 0], [115, 85], [0, [0, 0]], [30, [0, 64]], [0, 16, 0]]),
    ("T_p+lag vs T_p: invalid, missed, difference [95%], captures (T_p+lag more/equal/fewer)",
     [[119, 110], [118, 115], [9, [5, 14]], [7, 9, 0]]),
    ("approval reuse vs T_p (delays > 0): invalid, posed, difference [95%], 98.33% excludes 0, captures, missed",
     [[1462, 110], 25794, [1352, [1300, 1396]], True, 16, [93, 92]]),
    ("T_w vs T_p, restart, arm G: invalid, posed, difference [95%], captures, missed",
     [[110, 110], 34392, [0, [0, 0]], [0, 16, 0], [113, 115]]),
    ("T_w vs T_p, rollback, arm D: invalid, posed, difference [95%], captures, missed",
     [[0, 50], 5158, [-50, [-56, -44]], [0, 2, 6], [628, 662]]),
    ("T_w vs T_p, rollback, arm G: invalid, posed, difference [95%], captures, missed",
     [[2, 2], 31352, [0, [0, 0]], [0, 16, 0], [585, 586]]),
    ("watch rollback arm D: missed difference [95%]", [-34, [-36, -30]]),
    ("rollout end of G2-003 (s after the rollout started)", 35),
    ("watch rollback arm D: captures holding the difference (D1)",
     ["D1-001", "D1-002", "D1-003", "D1-004", "D1-005", "D1-006"]),
    ("watch rollback arm G: difference in G2", 0),
    ("98.33% intervals: recheck, approval reuse, watch rollback arm D", [[97, 123], [1287, 1403], [-58, -42]]),
    ("rollbacks, arm G: invalid by view; posed", [{"T_p": 2, "T_w": 2, "R": 0, "L-kappa": 2, "c-hind": 0}, 31352]),
    ("rollbacks, arm G: allowed as rollout complete, all allowed", {"T_p": [13220, 13224], "R": [24906, 24906]}),
    ("arm-D rollbacks by receipt stream: invalid (T_p, T_w), no view invalid, allowed unseen (T_p, T_w)",
     {"S0": [[0, 0], True, [3, 3]], "S30": [[25, 0], False, [28, 3]], "Snever": [[25, 0], False, [28, 3]]}),
    ("recommendation rollouts: old revision's last workload request after all new Pods were Ready (s)", [-3.6, 2.0]),
    ("rollbacks, arm G: invalid by capture and view",
     {"G2-006": {"L-kappa": 1, "T_p": 1, "T_w": 1}, "G4-001": {"L-kappa": 1, "T_p": 1, "T_w": 1}}),
    ("T_p vs T_p@R: first verdicts that differ", 19002),
    ("recheck lag: per-capture medians, maximum (s)", [[0.5, 0.7], 2.19]),
    ("T_p@R vs R: missed by delay (0, 10, 30, 80 s)", [[25, 28, 31, 31], [3, 20, 31, 31]]),
    ("posed per delay", 8598),
    ("invalid by delay (0, 10, 30, 80 s)",
     {"T_p": [0, 110, 0, 0], "T@F600": [0, 110, 677, 785], "L-kappa": [0, 110, 622, 730], "R": [0, 0, 0, 0],
      "T_p@R": [0, 0, 0, 0]}),
    ("executions by delay (0, 10, 30, 80 s)",
     {"T_p": [4901, 5577, 0, 0], "T@F600": [4901, 5577, 6383, 6383], "L-kappa": [4901, 4901, 4901, 4901],
      "R": [5781, 5641, 5840, 2965], "T_p@R": [4907, 5000, 5738, 2965]}),
    ("T_p invalid by cutoff (0, 5, 30 s)", [57, 53, 0]),
    ("delays 30 and 80 s: decisions expired, censored at the end of the records",
     {"T_p": {"30 s": [2065, 6533], "80 s": [2065, 6533]}, "R": {"30 s": [0, 1778], "80 s": [0, 5633]}}),
    ("T@F600: invalid", 1572),
    ("poller thinned x2, x4: invalid, missed, executions", [[110, 120, 10296], [110, 120, 10064]]),
    ("poller thinned: invalid unchanged in every capture", True),
    ("poller thinned: captures whose missed opportunities changed", ["G1-005"]),
    ("Pod-list median intervals (s): captured, x2, x4", [[2.4, 2.5], [4.9, 5.1], [9.8, 10.2]]),
    ("added latency 5 s, 30 s: invalid, missed, executions", [[110, 115, 10428], [0, 124, 0]]),
    ("Table 7: executions, EndpointSlice not ready, with service traffic, target served a request",
     {"T_p": {"unsafe (V-target)": [110, 110, 110, 1], "neutral": [10181, 0, 7279, 5667], "GT-2-B": [9, 0, 9, 6]},
      "L-kappa": {"unsafe (V-target)": [1462, 1462, 1410, 1], "neutral": [17896, 0, 7140, 5437], "GT-2-B": [8, 0, 8, 5]},
      "R": {"neutral": [19933, 0, 10311, 8005], "GT-2-B": [52, 0, 52, 23]}}),
    ("invalid executions near a call to the target's own address", [0, 0]),
    ("service-addressed probe calls: failing, all", [1, 788]),
    ("server spans with an error status", 0),
    ("failing Pod-address probes by scenario; R executions near one (neutral, U); T_p executions near one",
     [{"G1": 0, "G2": 35, "G3": 3, "G4": 0}, [10, 17], 0]),
    ("switch to onset (s): follow-up range; development capture with the original failure", [[6.3, 90.0], 0.5]),
    ("every API record delayed, cutoff +5 s: captures first at d = 10 s and 20 s (three policies)",
     [[8, 2], [8, 2], [8, 2]]),
    ("every failing cell of the three policies has a delay beyond the switch-to-cutoff gap", True),
    ("switch records delayed or corrected late: follow-up failures (three policies)", 0),
    ("span identity ranks the faulty Pod first in every cell after the onset", True),
    ("follow-up, unperturbed: every policy first after the onset, none at it", [True, True]),
    ("spans at their measured receipt: cells with an unchanged outcome, cells", [320, 320]),
    ("follow-up arm D: Pod-list median intervals (s)", [2.4, 2.5]),
    ("follow-up arm D: interval from the switch poll to the next poll (s)", [2.4, 2.9]),
    ("stress test: failing cells of the three policies by mode (faulty Pod absent, ranked last)",
     {"development | every API record | bitemporal_abstain_F600": {"absent": 37},
      "development | every API record | latest_state": {"absent": 61},
      "development | every API record | temporal_join": {"absent": 37},
      "development | switch records | bitemporal_abstain_F600": {"last": 74},
      "development | switch records | latest_state": {"absent": 14},
      "development | switch records | temporal_join": {"last": 74},
      "follow-up | every API record | bitemporal_abstain_F600": {"absent": 98},
      "follow-up | every API record | latest_state": {"absent": 98},
      "follow-up | every API record | temporal_join": {"absent": 98}}),
    ("I2-002 unperturbed after the onset: (rank, candidates) of temporal join and two-clock; latest state first",
     [[[3, 3]], True]),
    ("development Pod-list intervals: medians, longest; the one ending with I2-002's switch (s)",
     [[3.4, 4.6], 11.1, 7.4]),
    ("records valid before the cutoff, available after: decisions, kubelet, API; longest kubelet wait (s)",
     [3040, 3020, 48, 4.3]),
    ("valid-time replay, captured latency: first verdicts, dispositions, executions; its invalid count",
     [174, 726, 26, 112]),
    ("valid-time replay with 5 s, 30 s latency: first verdicts, executions", [[1508, 84], [14630, 10504]]),
    ("end-of-capture replay: first verdicts; decisions whose context changed", [23451, 8544]),
    ("two-clock first verdicts: abstain, allow, deny, needs approval", [19726, 10473, 2106, 2087]),
    ("end-of-capture replay: target verdicts (allow, deny); abstain/approval misreports; inversions",
     [[45, 44], 21813, 1638]),
    ("audit figure percentages (valid times 0, 5, 30 s; end of capture)", [0.5, 4.4, 42.5, 68.2]),
    ("Table 4: invalid, valid, uncertain, approval, denied, expired, censored (per view)",
     {"T_p": [110, 10190, 178, 2288, 4430, 4130, 13066], "T_w": [110, 10363, 181, 2522, 4020, 4130, 13066],
      "L-kappa": [1462, 17904, 238, 5928, 8860, 0, 0], "R": [0, 19985, 242, 1100, 4615, 48, 8402],
      "T@F600": [1572, 21430, 242, 2288, 8860, 0, 0]}),
    ("invalid per execution (%), per view", {"T_p": 1.05, "T_w": 1.03, "L-kappa": 7.46, "R": 0.0, "T@F600": 6.76}),
    ("invalid restart targets: gone, terminating, other states (per view)",
     {"T_p": [84, 26, 0], "T_w": [84, 26, 0], "L-kappa": [960, 502, 0], "R": [0, 0, 0], "T@F600": [1070, 502, 0]}),
    ("T_p vs R on decisions neither left censored: decisions; T_p invalid, executions; R invalid, executions",
     [17676, 47, 10415, 0, 11926]),
    ("recheck executions inside a mitigation window: posed as an opportunity, posed before it", [39, 13]),
    ("sweep: invalid, executions, missed, opportunities per setting",
     {"arm G | A | S0": {"F=30,N=30": [2, 13224, 586, 928], "F=30,N=0": [2, 15676, 579, 928],
                         "F=30,N=10": [2, 15558, 579, 928], "F=30,N=60": [2, 6348, 928, 928],
                         "F=30,N=600": [0, 0, 928, 928]},
      "arm D | A | S0": {"F=10,N=30": [0, 1696, 314, 670], "F=30,N=30": [0, 1696, 314, 670],
                         "F=60,N=30": [0, 1696, 314, 670], "F=120,N=30": [0, 1696, 314, 670],
                         "F=600,N=30": [0, 1696, 314, 670], "F=30,N=0": [0, 2562, 0, 670],
                         "F=30,N=10": [0, 2369, 0, 670], "F=30,N=60": [0, 885, 670, 670],
                         "F=30,N=600": [0, 0, 670, 670]},
      "arm D | A | S30": {"F=10,N=30": [25, 1721, 314, 670], "F=30,N=30": [25, 1721, 314, 670],
                          "F=60,N=30": [25, 1721, 314, 670], "F=120,N=30": [25, 1721, 314, 670],
                          "F=600,N=30": [25, 1721, 314, 670], "F=30,N=0": [25, 2562, 0, 670],
                          "F=30,N=10": [25, 2371, 0, 670], "F=30,N=60": [25, 910, 670, 670],
                          "F=30,N=600": [0, 0, 670, 670]},
      "arm D | A | Snever": {"F=10,N=30": [25, 1687, 348, 670], "F=30,N=30": [25, 1687, 348, 670],
                             "F=60,N=30": [25, 1687, 348, 670], "F=120,N=30": [25, 1687, 348, 670],
                             "F=600,N=30": [25, 1687, 348, 670], "F=30,N=0": [25, 2562, 0, 670],
                             "F=30,N=10": [25, 2371, 0, 670], "F=30,N=60": [25, 889, 670, 670],
                             "F=30,N=600": [0, 0, 670, 670]},
      "arm G | B | S0": {"F=10,N=30": [0, 4901, 116, 124], "F=30,N=30": [110, 10478, 115, 124],
                         "F=60,N=30": [787, 16861, 115, 124], "F=120,N=30": [1572, 23244, 115, 124],
                         "F=600,N=30": [1572, 23244, 115, 124], "F=30,N=0": [254, 12766, 82, 124],
                         "F=30,N=10": [225, 12486, 82, 124], "F=30,N=60": [110, 5308, 124, 124],
                         "F=30,N=600": [0, 0, 124, 124]}}),
    ("receipt-time audit: first verdicts, dispositions, executions misreported; invalid reported (0, 5, 30 s)",
     {"0 s": [152, 72, 15, 110], "5 s": [1404, 1550, 720, 110], "30 s": [11482, 17196, 5726, 528]}),
    ("receipt-time audit percentages (0, 5, 30 s)", [0.4, 4.1, 33.4]),
    ("audit from a receipt log with the records' own timestamps: first verdicts, dispositions, executions "
     "misreported; executions and invalid ones reported (0, 5, 30 s)",
     {"0 s": [0, 0, 0, 10478, 110], "5 s": [1292, 1494, 1494, 10490, 322], "30 s": [11608, 17196, 9071, 9071, 2122]}),
    ("audit from a receipt log with the records' own timestamps: percentages (0, 5, 30 s)", [0.0, 3.8, 33.8]),
    ("gate's executions with the poller's records 0, 5, 30 s later", [10478, 10428, 0]),
    ("audit replays' approval requests by the recent-change rule (receipt time, own timestamps; 5 and 30 s)",
     [[3556, 2726], [8604, 5117]]),
    ("poller store per arm-G capture: versions, keys (median); versions per key (range)",
     [5014.5, 49.0, [102.2, 106.5]]),
    ("decision log: input records per decision (median of capture medians; range); references; distinct records; "
     "store records, versions", [543.0, [471, 552], 15531080, 12083, 30222, 79876]),
    ("decision log: distinct records per store records (%, range over captures)", [33.4, 43.1]),
    ("Table 8: decisions changed; re-evaluable from their own entry, from all entries (per re-evaluation)",
     OrderedDict([("F=10,N=30", [8598, 0, 8598]), ("F=60,N=30", [8598, 0, 8598]), ("F=120,N=30", [17196, 0, 14534]),
                  ("F=600,N=30", [17196, 0, 13038]), ("F=30,N=0", [2288, 2288, 2288]),
                  ("F=30,N=10", [2008, 2008, 2008]), ("F=30,N=60", [5170, 5170, 5170]),
                  ("F=30,N=600", [10478, 10478, 10478]), ("at the recheck's instants", [15662, 17, 11876])])),
    ("mutually evaluable decisions: decisions; T_p invalid, uncertain, possibly invalid; R invalid, uncertain, "
     "possibly invalid, possibly invalid with a target request in the next 2 s",
     [17676, [47, 178, 158], [0, 242, 92, 74]]),
    ("mutually evaluable decisions: gate minus recheck, scored / every possibly invalid uncertain recheck execution "
     "invalid / only those without a target request after (point, 95%, 98.33%)",
     OrderedDict([("scored", [47, [36, 58], [34, 61]]),
                  ("recheck_possibly_invalid_counted", [-45, [-113, 15], [-130, 24]]),
                  ("recheck_possibly_invalid_without_target_request_after_counted", [29, [14, 45], [11, 48]])])),
    ("check to act: recheck executions invalid, uncertain, valid per lag (0, 0.1, 0.5, 1 s)",
     OrderedDict([("0 s", [0, 242, 19985]), ("0.1 s", [0, 209, 20018]), ("0.5 s", [0, 181, 20046]),
                  ("1 s", [0, 187, 20040])])),
    ("robustness: captures first with the onset 10 s early (temporal join, two-clock, span identity; +5, +30 s)",
     [[5, 5, 5], [6, 6, 6]]),
    ("robustness: every policy first in every capture for onset shifts of -5..+10 s", True),
    ("robustness: sampled traces, draws with the faulty Pod first (snapshot policies, span identity; 0.5, 0.25, "
     "0.1; +5 and +30 s)",
     {"0.5": [[67, 69, 67], [79, 80, 79]], "0.25": [[50, 56, 51], [73, 77, 73]], "0.1": [[13, 21, 14], [40, 56, 41]]}),
    ("robustness: spans without Pod identity, span identity draws first (0.5, 0.75, 0.9; +5 and +30 s); "
     "snapshot policies unaffected", [[[68, 79], [45, 77], [21, 49]], True]),
    ("sweep, restarts: invalid targets below floor, not Ready, terminating, gone (per setting)",
     {"F=10,N=30": [0, 0, 0, 0], "F=30,N=30": [0, 0, 26, 84], "F=60,N=30": [0, 0, 502, 285],
      "F=120,N=30": [0, 0, 502, 1070], "F=600,N=30": [0, 0, 502, 1070], "F=30,N=0": [49, 11, 100, 94],
      "F=30,N=10": [49, 11, 74, 91], "F=30,N=60": [0, 0, 26, 84], "F=30,N=600": [0, 0, 0, 0]}),
    ("sweep, restarts: invalid by dispatch delay 0 and 10 s (N = 0, 10, 30 s)", [[40, 214], [11, 214], [0, 110]]),
    ("sweep, restarts: executions added without the window; approvals of the window at 30 s", [2288, 2288]),
    ("restart decisions of the two-clock gate declined, by rule",
     {"DENY[R1]": 2882, "DENY[R3]": 1548, "NEEDS_APPROVAL[R2]": 2288}),
    ("rules that declined a decision (every view, stream and action)", ["R1", "R2", "R3"]),
    ("diagnosis: candidates per capture, policy and cutoff after the onset (range)", [2, 3]),
    ("robustness: onset 10 s early, latest state first (+5, +30 s); onset 5 s early, +5 s: captures with every "
     "policy first", [[8, 8], 8]),
    ("robustness, development: temporal join and two-clock first (complete, onset 2 s early; +5 s); span identity "
     "first (complete, onset 10 s late; +5 s); span identity draws first, half the traces (+5 s)",
     [[[4, 3], [4, 3]], [5, 4], [44, 50]]),
    ("arm-D rollbacks posed per receipt stream (S0, S30, Snever)", [2579, 2579, 2579]),
    ("two-clock gate with the recheck's lag: invalid, executions; targets gone, terminating, other states",
     [119, 10478, [90, 29, 0]]),
    ("robustness, development: draws first with half the traces (+5 s): temporal join, two-clock, span identity",
     [28, 28, 44]),
    ("latest snapshot at the recheck's instants: invalid executions, captures", [0, 16]),
    ("capture-level effect: gate minus recheck, approval reuse minus gate (median; range)",
     [[2.5, [0, 29]], [85.5, [62, 94]]]),
    ("failing service-address probe: capture; executions within 2 s by view and label",
     {"G3-002": {"T_p": {"U": 16, "unsafe (V-target)": 4}, "L-kappa": {"U": 16, "unsafe (V-target)": 4},
                 "R": {"U": 7}}}),
    ("deleted Pods: deletion request to first evidence of removal (s), recommendation, catalog (range)",
     [[21.2, 29.0], [1.0, 2.1]]),
    ("diagnosis: captures whose faulty Pod is the recommendation service's serving Pod / captures",
     [13, 13]),
    ("attribution, follow-up, captured records, 5 s cutoff: faulty Pod's [attributed and served, served, attributed] before and after the onset (span identity, latest state, temporal join, two-clock 600 s, 30 s)",
     [[[203, 203, 203], [72, 72, 72]], [[203, 203, 306], [72, 72, 72]], [[195, 203, 196], [72, 72, 72]], [[195, 203, 196], [72, 72, 72]], [[195, 203, 196], [72, 72, 72]]]),
    ("attribution, follow-up, captured records, 30 s cutoff: faulty Pod's [attributed and served, served, attributed] before and after the onset (span identity, latest state, temporal join, two-clock 600 s, 30 s)",
     [[[203, 203, 203], [290, 290, 290]], [[203, 203, 306], [290, 290, 290]], [[195, 203, 196], [290, 290, 290]], [[195, 203, 196], [290, 290, 290]], [[195, 203, 196], [290, 290, 290]]]),
    ("attribution, development, captured records, 5 s cutoff: faulty Pod's [attributed and served, served, attributed] before and after the onset (span identity, latest state, temporal join, two-clock 600 s, 30 s)",
     [[[117, 117, 117], [43, 43, 43]], [[117, 117, 183], [43, 43, 43]], [[87, 117, 87], [42, 43, 42]], [[87, 117, 87], [42, 43, 42]], [[87, 117, 87], [42, 43, 42]]]),
    ("attribution, development, captured records, 30 s cutoff: faulty Pod's [attributed and served, served, attributed] before and after the onset (span identity, latest state, temporal join, two-clock 600 s, 30 s)",
     [[[117, 117, 117], [173, 173, 173]], [[117, 117, 183], [173, 173, 173]], [[87, 117, 87], [172, 173, 172]], [[87, 117, 87], [172, 173, 172]], [[87, 117, 87], [172, 173, 172]]]),
    ("attribution, follow-up, every API record delayed (5 and 30 s cutoffs; latest state, temporal join, two-clock 600 s): cells delayed at least the switch-to-cutoff time, of these with no fault-window request attributed to the faulty Pod and the Pod not a candidate; other cells, of these with every fault-window request attributed to it, none wrongly, and the Pod ranked first",
     [144, 144, 240, 240]),
    ("attribution, development capture I2-002, 5 s cutoff, before the onset (span identity, latest state, temporal join); ranked first",
     [[[12, 12, 12], [12, 12, 38], [0, 12, 0]], [True, True, False]]),
    ("snapshots: realised list intervals (s; median over captures)", [2.45, 15.0, 30.0, 60.1]),
    ("snapshots: Pods; episodes starting, ready, not ready, terminating; short episodes", [90, [44, 53, 8, 45], 97]),
    ("snapshots: short episodes recorded, one clock and objects' timestamps (per interval); watch",
     [[89.0, 61.3, 40.7, 20.3], [94.0, 90.8, 78.9, 62.0], 97]),
    ("snapshots: start-ups, restarts, terminations recorded (one clock; objects' timestamps; per interval)",
     OrderedDict([("S", OrderedDict([("1", [42.0, 5.0, 42.0]), ("6", [19.7, 2.2, 39.5]), ("12", [9.8, 1.1, 29.8]),
                                     ("24", [4.9, 0.5, 14.9])])),
                  ("T", OrderedDict([("1", [44.0, 8.0, 42.0]), ("6", [43.3, 8.0, 39.5]), ("12", [41.2, 8.0, 29.8]),
                                     ("24", [39.1, 8.0, 14.9])]))])),
    ("snapshots: short episodes expected by min(1, d / interval) at the realised 15, 30, 60 s and at 300 s",
     [62.1, 42.3, 21.1, 4.2]),
    ("snapshots: replacement from the first new Pod's creation to the last old Pod's removal (s; min, median, max)",
     [3.0, 44.4, 62.1]),
    ("snapshots: recorded starts, one clock: median delay (s) per interval; objects' timestamps: placed within 1 s "
     "(%) per interval", [[1.7, 6.7, 11.8, 19.8], [100.0, 99.2, 98.9, 99.4]]),
    ("snapshots: wrong Pod status, % of answered Pod-seconds (one clock; objects' timestamps; per interval); "
     "Pod-seconds; watch wrong", [[0.35, 4.25, 8.6, 15.52], [0.0, 0.04, 1.55, 3.82], 14377, 0]),
    ("snapshots: object states the watch delivered; shown by the kept lists (%, per interval)",
     [1151, [47.6, 36.3, 31.3, 28.0]]),
    ("snapshots: gate F = 30 s per interval: executions (mean over phases), invalid (mean; range), missed (mean)",
     OrderedDict([("1", [10478.0, 110.0, [110, 110], 115.0]), ("6", [9447.3, 110.0, [110, 110], 122.7]),
                  ("12", [9055.0, 108.0, [92, 129], 118.3]), ("24", [4749.3, 39.3, [0, 103], 124.0])])),
    ("snapshots: gate F = 600 s invalid per interval (mean over phases)", [1572.0, 1472.0, 1485.3, 1485.3]),
    ("snapshots: gate F = 30 s minus captured, invalid and executions (point, 95%; 15, 30, 60 s)",
     OrderedDict([("6", [[0, [0, 0]], [-1030.7, [-1138.0, -928.3]]]),
                  ("12", [[-2, [-22, 19]], [-1423, [-1729.3, -1146.3]]]),
                  ("24", [[-70.7, [-86.0, -55.7]], [-5728.7, [-6011.7, -5402]]])])),
    ("snapshots: audit, first verdicts misreported (%; point, 95%) from one clock (2.45, 15, 30, 60 s) and from the "
     "objects' timestamps (15, 30, 60 s)",
     OrderedDict([("S", [[0.44, [0.28, 0.62]], [9.22, [8.76, 9.76]], [22.65, [21.83, 23.52]],
                         [37.16, [36.47, 37.78]]]),
                  ("T", [[7.26, [6.86, 7.64]], [19.63, [18.81, 20.64]], [36.51, [35.71, 37.19]]])])),
    ("snapshots: short episodes recorded, objects' timestamps minus one clock (point, 95%; 15, 30, 60 s)",
     [[29.5, [27.5, 31.3]], [38.2, [37.3, 39.2]], [41.6, [41.2, 42.1]]]),
    ("snapshots: wrong Pod-seconds, one clock minus objects' timestamps (point, 95%; 15, 30, 60 s)",
     [[592.5, [561.0, 620.0]], [960.8, [939.4, 981.4]], [1485.1, [1453.7, 1522.4]]]),
    ("snapshots: records per hour, lists (per interval); after merging duplicates (15, 60 s); watch events per "
     "hour; hours", [[18597, 3099, 1550, 775], [309, 241], 751, 1.34]),
    ("snapshots: gate F = 30 s, decisions declined for target identity (R1), recent change (R2), replica floor (R3) "
     "(mean over phases; per interval)",
     OrderedDict([("1", [2882.0, 2288.0, 1548.0]), ("6", [2586.7, 2752.7, 2409.3]), ("12", [2635.3, 3823.3, 1682.3]),
                  ("24", [3447.0, 7528.0, 1423.3])])),
    ("snapshots: executions at dispatch delays of 0 and 10 s, F = 30 s and 600 s (mean over phases; per interval)",
     OrderedDict([("1", [10478.0, 10478.0]), ("6", [9447.3, 9447.3]), ("12", [9055.0, 9035.7]),
                  ("24", [4749.3, 5260.7])])),
    ("snapshots: lists every 60 s, invalid executions at the 10 s delay per phase, F = 30 s and 600 s",
     [[15, 103, 0], [110, 120, 110]]),
    ("snapshots: lists every 30 s, invalid executions at the 10 s delay per phase, F = 30 s and 600 s",
     [[129, 92, 103], [110, 110, 120]]),
    ("snapshots: missed opportunities, F = 30 s and 600 s (mean over phases; per interval)",
     [[115.0, 122.7, 118.3, 124.0], [115.0, 122.7, 118.3, 124.0]]),
    ("snapshots: episode durations, median s (start-ups, not ready after a container restart, terminations)",
     [7, 7, 22]),
    ("snapshots: expected by min(1, d / interval), start-ups, restarts, terminations (realised 15, 30, 60 s)",
     [[19.7, 2.8, 39.7], [9.8, 1.4, 31.1], [4.9, 0.7, 15.5]]),
])


def check(got, want) -> list:
    bad = []
    for k, v in want.items():
        g = got.get(k, "<missing>")
        if json.loads(json.dumps(g)) != json.loads(json.dumps(v)):
            bad.append("%s: %s, published %s" % (k, json.dumps(g), json.dumps(v)))
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    results = Path(a.results)
    got = numbers(results)
    if not a.check:
        print(json.dumps(got, indent=1, ensure_ascii=False))
        return 0
    bad = ["tables: " + line for line in tables.check(tables.compute(results), tables.EXPECTED)]
    bad += check(got, EXPECTED)
    for line in bad:
        print("MISMATCH " + line)
    print("check: %s" % ("every number of the paper reproduced (%d table entries, %d replay entries)"
                         % (len(tables.EXPECTED), len(EXPECTED)) if not bad else "%d mismatches" % len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
