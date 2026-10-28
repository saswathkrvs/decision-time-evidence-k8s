"""Every table and reported number of the paper, recomputed from the per-capture outputs in ``results/``.

    python -m analysis.tables              # print the tables and the numbers quoted in the text
    python -m analysis.tables --check      # also compare each value with the published one (exit 1 on a mismatch)
    python -m analysis.tables --json out.json

Inputs: ``results/stage2/`` (the capture register, per-capture capture summaries, the governance adapter's
per-capture outputs and the diagnosis control's outputs) and ``results/development/`` (the diagnosis of the five
development fault captures, the development gate analysis and the matched rollback pilot). Standard library only.
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

from analysis import stats as ST  # noqa: E402

# The follow-up comparisons. X and Y are the gate views (T_p: two-clock store fed by the poller; T_w: fed by the watch
# collector; R: fresh-state recheck; L-kappa: approval reuse, the latest-snapshot verdict at the cutoff reused after the
# dispatch delay). "adapter" names the comparison's primary-cell sums in each capture's adapter output.
COMPARISONS = (
    {"id": "recheck", "title": "Two-clock poller vs fresh recheck; restart in arm G", "population": "G",
     "adapter": "H-G3", "X": "T_p", "Y": "R", "primary": True},
    {"id": "approval_reuse", "title": "Two-clock poller vs approval reuse; restart in arm G", "population": "G",
     "adapter": "H-G2", "X": "T_p", "Y": "L-kappa", "primary": True},
    {"id": "watch_G", "title": "Two-clock watch vs two-clock poller; restart in arm G", "population": "G",
     "adapter": "H-G4", "X": "T_w", "Y": "T_p", "primary": True},
    {"id": "watch_D", "title": "Two-clock watch vs two-clock poller; rollback in arm D", "population": "D",
     "adapter": "H-G4", "X": "T_w", "Y": "T_p", "primary": True},
    {"id": "watch_vs_recheck", "title": "Two-clock watch vs fresh recheck; restart in arm G (secondary)",
     "population": "G", "adapter": "H-G3 (T_w, R) secondary", "X": "T_w", "Y": "R", "primary": False},
    {"id": "watch_G_rollback", "title": "Two-clock watch vs two-clock poller; rollback in arm G (secondary)",
     "population": "G", "adapter": "action A secondary (H-G4)", "X": "T_w", "Y": "T_p", "primary": False},
)


def load(results) -> dict:
    results = Path(results)
    st = results / "stage2"
    reg = json.loads((st / "captures.json").read_text(encoding="utf-8"))
    adapter = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((st / "adapter").glob("*.json"))}
    return {"register": reg, "adapter": adapter,
            "summaries": json.loads((st / "capture_summaries.json").read_text(encoding="utf-8")),
            "diagnosis": json.loads((st / "diagnosis/summary.json").read_text(encoding="utf-8")),
            "dev_diagnosis_cells": {p.stem: json.loads(p.read_text(encoding="utf-8"))
                                    for p in sorted((results / "development/diagnosis").glob("*.json"))},
            "gate_audit": json.loads((results / "development/gate_audit.json").read_text(encoding="utf-8")),
            "pilot": json.loads((results / "development/rollback_pilot.json").read_text(encoding="utf-8"))}


def _delta_seconds(cell) -> int:
    return int(str(cell.get("delta")).split()[0])


def development_counts(per_capture: dict) -> dict:
    """Per (stream, Delta, policy): in how many of the development fault captures the faulty Pod is ranked first
    (``top1``) and how many hold the cell at all (``n - no_cell``; a stream that does not apply to a capture has no
    cell). Hindsight (the span-verified serving Pods) is listed with stream "-"."""
    captures = sorted(per_capture)
    rows = {}
    for name in captures:
        res = per_capture[name]
        for label, h in (res.get("hindsight") or {}).items():
            rows.setdefault(("-", _delta_seconds(h), "hindsight"), []).append((name, h))
        for c in res.get("cells") or []:
            rows.setdefault((c.get("stream"), _delta_seconds(c), c.get("policy")), []).append((name, c))
    out = []
    for (stream, delta, policy), present in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
        top1 = [n for n, c in present if (c.get("truth") or {}).get("outcome") == "top1"]
        out.append({"stream": stream, "delta_seconds": delta, "policy": policy, "n": len(captures),
                    "top1": len(top1), "no_cell": len(captures) - len(present), "top1_captures": top1})
    return {"n": len(captures), "captures": captures, "rows": out}


def population(reg: dict, name: str):
    """[(scenario, [captures in plan order]), ...] in plan order."""
    return [(s["scenario"], list(s["captures"])) for s in reg["populations"][name]]


def flatten(strata) -> list:
    return [c for _, caps in strata for c in caps]


def strata_positions(strata) -> list:
    out, pos = [], 0
    for _, caps in strata:
        out.append(list(range(pos, pos + len(caps))))
        pos += len(caps)
    return out


def comparison(c: dict, D: dict, resamples: dict) -> OrderedDict:
    strata = population(D["register"], c["population"])
    captures = flatten(strata)
    scenario_of = {cap: s for s, caps in strata for cap in caps}
    rows = []
    for cap in captures:
        a = D["adapter"][cap]
        sums = a["primary_sums"][c["adapter"]]
        x, y = sums["conditions"][c["X"]], sums["conditions"][c["Y"]]
        design = a["design_check"]["per_comparison"][c["adapter"]]
        rows.append({"capture": cap, "scenario": scenario_of[cap], "U_X": x["U"], "U_Y": y["U"], "M_X": x["M"],
                     "M_Y": y["M"], "posed": x["posed"], "GT2": min(x["GT2"], y["GT2"]),
                     "identical": sums.get("identical_first_verdicts_and_dispositions"),
                     "contested": design["contested"], "design_posed": design["posed"],
                     "d_U": y["U"] - x["U"], "d_M": x["M"] - y["M"]})
    totals = {k: sum(r[k] for r in rows) for k in ("U_X", "U_Y", "M_X", "M_Y", "posed", "GT2")}
    design = ST.design_check([r["contested"] for r in rows])
    design["posed"] = sum(r["design_posed"] for r in rows)
    du = ST.bootstrap(resamples[c["population"]], [r["d_U"] for r in rows])
    dm = ST.bootstrap(resamples[c["population"]], [r["d_M"] for r in rows])
    identical = all(r["U_X"] == r["U_Y"] and r["M_X"] == r["M_Y"] and r["identical"] in (True, None) for r in rows)
    paired = ST.paired_table([(r["U_X"], r["U_Y"]) for r in rows])
    return OrderedDict([("title", c["title"]), ("X", c["X"]), ("Y", c["Y"]), ("captures", len(rows)),
                        ("totals", totals), ("paired", paired), ("D_U", du), ("D_M", dm),
                        ("eligible_requests_by_capture", {r["capture"]: r["GT2"] for r in rows if r["GT2"]}),
                        ("design_check", design), ("label", ST.label(design, du, dm, ST.b_m(totals["GT2"]), identical)),
                        ("per_capture", rows)])


def compute(results) -> OrderedDict:
    D = load(results)
    reg = D["register"]
    out = OrderedDict()
    # Table 2: the follow-up captures
    study = [a for a in reg["attempts"] if a["kind"] == "study"]
    included = [a for a in study if a["included"]]
    out["table2"] = OrderedDict([
        ("captures_by_scenario", {s: sum(1 for a in included if a["scenario"] == s) for s in
                                  ("D1", "D2", "G1", "G2", "G3", "G4")}),
        ("captures_by_arm", {arm: sum(1 for a in included if a["arm"] == arm) for arm in ("D", "G")}),
        ("slots", len({a["slot"] for a in included})), ("attempts", len(study)),
        ("excluded", [{"capture": a["capture"], "reasons": a["reasons"]} for a in study if not a["included"]])])
    # observer validity over the study's attempts
    S = D["summaries"]
    checks = [S[a["capture"]]["observer_checks"] for a in study]
    poll = [c["poller_max_pod_list_gap_in_window_seconds"] for c in checks if c["poller_max_pod_list_gap_in_window_seconds"] is not None]
    watch = [c["watch_max_gap_overlap_in_window_seconds"] for c in checks if c["watch_max_gap_overlap_in_window_seconds"] is not None]
    recheck = [c["recheck_answered_fraction_in_window"] for c in checks if c["recheck_answered_fraction_in_window"] is not None]
    out["observers"] = {"poller_max_gap_seconds": [round(min(poll), 1), round(max(poll), 1)],
                        "watch_max_gap_seconds": max(watch), "recheck_min_answered_percent": round(100 * min(recheck), 1)}
    bands = [S[a["capture"]]["clock_band_ns"] / 1e9 for a in included]
    out["clock_band_seconds"] = [round(min(bands), 2), round(max(bands), 2)]
    lat = [S[a["capture"]]["recheck_read_latency_ms"] for a in included if S[a["capture"]].get("recheck_read_latency_ms")]
    out["recheck_read_ms"] = {"median_range": [round(min(x["median"] for x in lat)), round(max(x["median"] for x in lat))],
                              "max_seconds": round(max(x["max"] for x in lat) / 1000, 2), "captures": len(lat)}
    # Table 3 and the comparisons
    resamples = {p: ST.draw_resamples(strata_positions(population(reg, p))) for p in ("G", "D")}
    comps = OrderedDict((c["id"], comparison(c, D, resamples)) for c in COMPARISONS)
    out["comparisons"] = comps
    t3 = OrderedDict()
    for cid in ("recheck", "approval_reuse", "watch_G", "watch_D"):
        t = comps[cid]["totals"]
        t3[cid] = {"unsafe": [t["U_X"], t["U_Y"]], "posed": t["posed"], "missed": [t["M_X"], t["M_Y"]], "eligible": t["GT2"]}
    out["table3"] = t3
    rc = comps["recheck"]
    out["recheck_text"] = {
        "paired": [rc["paired"]["more"], rc["paired"]["equal"], rc["paired"]["fewer"]],
        "difference": [-rc["D_U"]["point"], [-rc["D_U"]["interval_95"][1], -rc["D_U"]["interval_95"][0]]],
        "contested": [rc["design_check"]["contested"], rc["design_check"]["posed"], rc["design_check"]["captures_with_one"],
                      rc["design_check"]["captures"]],
        "eligible_captures": len(rc["eligible_requests_by_capture"])}
    by_scenario = OrderedDict()
    for s in ("G1", "G2", "G3", "G4"):
        rows = [r for r in rc["per_capture"] if r["scenario"] == s]
        by_scenario[s] = [sum(r["U_X"] for r in rows), sum(r["U_Y"] for r in rows)]
    rest = [r for r in rc["per_capture"] if r["scenario"] != "G3"]
    out["recheck_by_scenario"] = by_scenario
    out["recheck_without_catalog_termination"] = {
        "unsafe": [sum(r["U_X"] for r in rest), sum(r["U_Y"] for r in rest)], "posed": sum(r["posed"] for r in rest),
        "captures": len(rest), "more": sum(1 for r in rest if r["U_X"] > r["U_Y"]),
        "equal": sum(1 for r in rest if r["U_X"] == r["U_Y"])}
    ar = comps["approval_reuse"]
    out["approval_reuse_text"] = {"fewer_in_every_capture": ar["paired"]["fewer"] == ar["captures"],
                                  "difference": [ar["D_U"]["point"], ar["D_U"]["interval_95"]],
                                  "excludes_0_98_33": ar["D_U"]["excludes_0_98_33"]}
    wd = comps["watch_D"]
    out["watch_D_text"] = {"difference": [wd["D_U"]["point"], wd["D_U"]["interval_95"]]}
    wg = comps["watch_G_rollback"]["totals"]
    out["watch_G_rollback"] = {"unsafe": [wg["U_X"], wg["U_Y"]], "posed": wg["posed"]}
    out["primary_design_checks_pass"] = all(comps[c["id"]]["design_check"]["passes"] for c in COMPARISONS if c["primary"])
    out["labels"] = {cid: comps[cid]["label"] for cid in comps}
    # matched latest-snapshot views and the reconstruction checks
    agree = {"first_verdict": 0, "disposition": 0, "compared": 0}
    q1 = {"append_only": [0, 0], "earlier_cutoff": [0, 0], "provenance": [0, 0], "graph_sqlite": [0, 0]}
    for cap in flatten(population(reg, "G")) + flatten(population(reg, "D")):
        a = D["adapter"][cap]
        for row in a["T2_comparisons"]:
            if list(row.get("pair") or []) in (["T_p", "L_p"], ["T_w", "L_w"]):
                agree["compared"] += int(row.get("posed_in_both") or 0)
                agree["first_verdict"] += int((row.get("first_verdict") or {}).get("differing_requests") or 0)
                agree["disposition"] += int((row.get("disposition") or {}).get("differing_requests") or 0)
        t = (a["T3_q1_checks"].get("totals") or {})
        c1 = t.get("check_1_append_only_corrections") or {}
        c2 = t.get("check_2_earlier_cutoff_invariance") or {}
        q1["append_only"][0] += int(c1.get("x") or 0); q1["append_only"][1] += int(c1.get("n") or 0)
        q1["earlier_cutoff"][0] += int(c2.get("x") or 0); q1["earlier_cutoff"][1] += int(c2.get("n") or 0)
        for unit in a["decision_phase"]["units"]:
            for key, field in (("provenance", "provenance"), ("graph_sqlite", "engines")):
                q1[key][0] += int((unit.get(field) or {}).get("x") or 0)
                q1[key][1] += int((unit.get(field) or {}).get("n") or 0)
    out["matched_views"] = agree
    out["reconstruction_checks_pass"] = {k: v[0] == v[1] and v[1] > 0 for k, v in q1.items()}
    # the follow-up diagnosis (arm D)
    hd = D["diagnosis"]["h_d"]
    rows = [r for obs in ("poller", "watch") for r in ((D["diagnosis"]["primary_d1"].get(obs) or {}).get("rows") or [])
            if r.get("family") in ("complete", "missing_switch") and r.get("delta") in ("30 s", "60 s")]
    out["followup_diagnosis"] = {"captures": hd["n_included_d1"],
                                 "every_policy_top1": all(r.get("top1") == r.get("n") for r in rows) and bool(rows),
                                 "effect_under_poller": len(hd["E_P"])}
    # development: diagnosis captures
    dev = development_counts(D["dev_diagnosis_cells"])

    def row(stream, policy, delta=30):
        return next(r for r in dev["rows"] if r["stream"] == stream and r["policy"] == policy and r["delta_seconds"] == delta)
    out["development_diagnosis"] = OrderedDict([
        ("captures", dev["n"]),
        ("join_and_two_clock_top1_complete", [row("complete", p)["top1"] for p in ("temporal_join", "bitemporal_abstain_F600")]),
        ("join_and_two_clock_top1_missing_switch", [row("missing_switch_poll", p)["top1"] for p in ("temporal_join", "bitemporal_abstain_F600")]),
        ("missing_switch_applicable", row("missing_switch_poll", "temporal_join")["n"] - row("missing_switch_poll", "temporal_join")["no_cell"]),
        ("span_identity_top1", row("-", "hindsight")["top1"])])
    missed = [c for c in dev["captures"] if c not in row("complete", "temporal_join")["top1_captures"]]
    if missed:
        cells = D["dev_diagnosis_cells"][missed[0]]
        truth = cells["evaluator_only"]["truth_entity"]
        hind = cells["hindsight"]["30 s"]["entities"][truth]["normal"]
        join = next(c for c in cells["cells"] if c["stream"] == "complete" and c["delta"] == "30 s"
                    and c["policy"] == "temporal_join")["entities"][truth]["normal"]
        two = next(c for c in cells["cells"] if c["stream"] == "complete" and c["delta"] == "30 s"
                   and c["policy"] == "bitemporal_abstain_F600")["entities"][truth]["normal"]
        out["development_diagnosis"]["missed_capture"] = {
            "capture": missed[0], "replacement_pod_pre_fault_requests": hind["n"],
            "join_assigned_elsewhere": join.get("lost_to_other"), "two_clock_abstained": two.get("lost_to_abstain")}
    # development: gate analysis and matched rollback pilot
    flips = D["gate_audit"]["flips"]
    out["development_gate"] = {"changed": len(flips), "of": D["gate_audit"]["design_size"]["as_known_decisions"],
                               "all_deny_to_abstain": all(f["flip_type"] == "DENY->ABSTAIN" for f in flips),
                               "blocked_allowed_changes": sum(1 for f in flips if f["flip_kind"] != "severity_only")}
    t_vs_l = D["pilot"]["T2_comparisons"]["T vs L"]
    out["rollback_pilot"] = {"posed": sum(r["posed"] for r in t_vs_l),
                             "differing_first_verdicts": sum(r["first_verdict"]["differing_requests"] for r in t_vs_l),
                             "differing_dispositions": sum(r["disposition"]["differing_requests"] for r in t_vs_l),
                             "change_bearing_captures": len({r["capture"] for r in t_vs_l})}
    return out


EXPECTED = OrderedDict([
    ("table2", {"captures_by_scenario": {"D1": 6, "D2": 2, "G1": 5, "G2": 5, "G3": 3, "G4": 3},
                "captures_by_arm": {"D": 8, "G": 16}, "slots": 24, "attempts": 26}),
    ("observers", {"poller_max_gap_seconds": [2.7, 6.4], "watch_max_gap_seconds": 0.0, "recheck_min_answered_percent": 97.9}),
    ("clock_band_seconds", [1.13, 2.29]),
    ("recheck_read_ms", {"median_range": [27, 36], "max_seconds": 1.06}),
    ("table3", {"recheck": {"unsafe": [110, 0], "posed": 34392, "missed": [115, 85], "eligible": 124},
                "approval_reuse": {"unsafe": [110, 1462], "posed": 25794, "missed": [92, 93], "eligible": 93},
                "watch_G": {"unsafe": [110, 110], "posed": 34392, "missed": [113, 115], "eligible": 124},
                "watch_D": {"unsafe": [0, 50], "posed": 5158, "missed": [268, 296], "eligible": 948}}),
    ("recheck_text", {"paired": [13, 3, 0], "difference": [110, [100, 121]], "contested": [14778, 34392, 16, 16],
                      "eligible_captures": 2}),
    ("recheck_by_scenario", {"G1": [9, 0], "G2": [10, 0], "G3": [85, 0], "G4": [6, 0]}),
    ("recheck_without_catalog_termination", {"unsafe": [25, 0], "posed": 28008, "captures": 13, "more": 10, "equal": 3}),
    ("approval_reuse_text", {"fewer_in_every_capture": True, "difference": [1352, [1300, 1396]], "excludes_0_98_33": True}),
    ("watch_D_text", {"difference": [50, [44, 56]]}),
    ("watch_G_rollback", {"unsafe": [2663, 2585], "posed": 31352}),
    ("primary_design_checks_pass", True),
    ("matched_views", {"first_verdict": 0, "disposition": 0}),
    ("reconstruction_checks_pass", {"append_only": True, "earlier_cutoff": True, "provenance": True, "graph_sqlite": True}),
    ("followup_diagnosis", {"captures": 6, "every_policy_top1": True, "effect_under_poller": 0}),
    ("development_diagnosis", {"captures": 5, "join_and_two_clock_top1_complete": [4, 4],
                               "join_and_two_clock_top1_missing_switch": [1, 1], "missing_switch_applicable": 4,
                               "span_identity_top1": 5,
                               "missed_capture": {"replacement_pod_pre_fault_requests": 12, "join_assigned_elsewhere": 12,
                                                  "two_clock_abstained": 12}}),
    ("development_gate", {"changed": 249, "of": 6480, "all_deny_to_abstain": True, "blocked_allowed_changes": 0}),
    ("rollback_pilot", {"posed": 17486, "differing_first_verdicts": 0, "differing_dispositions": 0,
                        "change_bearing_captures": 8}),
])


def check(got, want, path="") -> list:
    bad = []
    if isinstance(want, dict):
        for k, v in want.items():
            if not isinstance(got, dict) or k not in got:
                bad.append("%s.%s: missing" % (path, k))
            else:
                bad += check(got[k], v, "%s.%s" % (path, k))
    elif got != want:
        bad.append("%s: %r, published %r" % (path, got, want))
    return bad


def render(o: dict) -> str:
    L = []
    t2 = o["table2"]
    L += ["Table 2  Follow-up captures: %s; arm D %d, arm G %d; %d slots in %d attempts" % (
        t2["captures_by_scenario"], t2["captures_by_arm"]["D"], t2["captures_by_arm"]["G"], t2["slots"], t2["attempts"])]
    for e in t2["excluded"]:
        L.append("  excluded %s: %s" % (e["capture"], "; ".join(e["reasons"])))
    ob = o["observers"]
    L += ["  Observers: maximum polling gap %.1f-%.1f s; watch continuity gap %s s; recheck answered at least %.1f %% of ticks"
          % (ob["poller_max_gap_seconds"][0], ob["poller_max_gap_seconds"][1], ob["watch_max_gap_seconds"],
             ob["recheck_min_answered_percent"]),
          "  Clock band %.2f-%.2f s; recheck read median %d-%d ms per capture (maximum %.2f s)" % (
              o["clock_band_seconds"][0], o["clock_band_seconds"][1], o["recheck_read_ms"]["median_range"][0],
              o["recheck_read_ms"]["median_range"][1], o["recheck_read_ms"]["max_seconds"]), ""]
    L += ["Table 3  Principal remediation results (X vs Y)",
          "%-58s %-30s %s" % ("Comparison", "Unsafe simulated executions", "Missed opportunities")]
    for cid, t in o["table3"].items():
        title = o["comparisons"][cid]["title"]
        L.append("%-58s %-30s %s" % (title, "%d vs %d; %d posed" % (t["unsafe"][0], t["unsafe"][1], t["posed"]),
                                    "%d vs %d; %d eligible" % (t["missed"][0], t["missed"][1], t["eligible"])))
    L.append("")
    for cid, c in o["comparisons"].items():
        du = c["D_U"]
        L.append("  %-40s Y-X unsafe %+d, 95 %% [%s, %s], 98.33 %% [%s, %s]; captures X more/equal/fewer %d/%d/%d; "
                 "design check %d contested of %d in %d of %d captures; %s" % (
                     c["title"][:40], du["point"], du["interval_95"][0], du["interval_95"][1], du["interval_98_33"][0],
                     du["interval_98_33"][1], c["paired"]["more"], c["paired"]["equal"], c["paired"]["fewer"],
                     c["design_check"]["contested"], c["design_check"]["posed"], c["design_check"]["captures_with_one"],
                     c["design_check"]["captures"], c["label"]))
    L += ["  Recheck comparison by scenario (poller vs recheck): %s; without catalog terminations %s"
          % (o["recheck_by_scenario"], o["recheck_without_catalog_termination"]),
          "  Matched latest-snapshot views: %s; reconstruction checks pass: %s" % (o["matched_views"],
                                                                                o["reconstruction_checks_pass"]),
          "  Follow-up diagnosis: %s" % o["followup_diagnosis"], "",
          "Development: diagnosis %s" % dict(o["development_diagnosis"]),
          "Development: gate analysis %s" % o["development_gate"],
          "Development: matched rollback pilot %s" % o["rollback_pilot"]]
    return "\n".join(L)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", default=str(ROOT / "results"))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", default=None)
    a = parser.parse_args(argv)
    o = compute(a.results)
    print(render(o))
    if a.json:
        Path(a.json).write_text(json.dumps(o, indent=1, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    if a.check:
        bad = check(o, EXPECTED)
        print("\ncheck: %s" % ("every published value reproduced" if not bad else "%d mismatches" % len(bad)))
        for line in bad:
            print("  " + line)
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
