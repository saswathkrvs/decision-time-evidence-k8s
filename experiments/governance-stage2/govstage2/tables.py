"""T1-T4 and the per-capture quantities, from the decision logs and the labels; the per-capture sums over the primary
cells for the analysis.

T1 cells: capture x condition x stream x action x Delta x delta: requests, posed (denominator), first verdicts,
dispositions (NEEDS_APPROVAL and DENY by source rule; ALLOW by R7's reason, so that "allowed with no visible
change" stands apart from ALLOW after the rollout completed), executions by label, unsafe executions (V1 for A;
V-target and V-floor for B), missed opportunities (requests labelled GT-2 at their posing instant without an
execution inside the fault window, by disposition; of requests labelled GT-2), waiting (min / median / max, EXPIRED,
CENSORED), decisions reached by a late correction (of posed), contested decisions (of posed). Counts with
denominators only; no rate.

T2: request-level differences between two conditions per (stream, action, Delta, delta): first verdicts and
dispositions, block<->allow by direction, severity-only by type. (R) is the same in every stream (it reads no change
record) and is compared with each stream's rows.

T4: the sensitivities beside their primary cells: T@F600 beside T_p, L@F600 beside L_p (stream S0), (c-hind) beside
L_p under the heading "hindsight, not a live read".

Primary sums: for each comparison and each of its two conditions, U_X(c) and M_X(c) summed over the primary cells,
with the posed and GT-2 denominators and whether the two conditions coincide in every first verdict and disposition
there ("Identical"). The bootstrap, the label rules and the design-check thresholds across captures belong to the
analysis (analysis/).
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict

from aiops_kg.policy_gate import ALLOW, DENY, NEEDS_APPROVAL

from .common import iso
from .design import PRIMARY
from .labels import GT2A, GT2B, OPPORTUNITY, UNSAFE, U

T2_PAIRS = (("T_p", "L_p"), ("T_w", "L_w"), ("T_p", "L-kappa"), ("T_p", "R"), ("T_w", "R"), ("T_p", "T_w"))
T4_PAIRS = (("T@F600", "T_p", "F = 600 s"), ("L@F600", "L_p", "F = 600 s"),
            ("c-hind", "L_p", "hindsight, not a live read"))


def _source(row: dict) -> str:
    return "+".join(sorted({s.split(":")[0] for s in row.get("disposition_source") or []})) or "-"


def _stats(values) -> dict:
    items = sorted(values)
    if not items:
        return {"n": 0, "min": None, "median": None, "max": None}
    return {"n": len(items), "min": items[0], "median": round(statistics.median(items), 6), "max": items[-1]}


class Cell:
    def __init__(self, key):
        self.key = key
        self.requests = 0
        self.posed = 0
        self.not_posed = Counter()
        self.first = Counter()
        self.dispositions = Counter()
        self.labels = Counter()
        self.label_reasons = defaultdict(Counter)
        self.unsafe = 0
        self.gt2 = 0
        self.missed = Counter()
        self.waiting = []
        self.late = 0
        self.contested = Counter()
        self.expired = self.censored = 0
        self.cross_check_disagreements = 0

    def to_dict(self) -> dict:
        condition, stream, action, delta_cap, delta = self.key
        return {"condition": condition, "stream": stream, "action": action, "Delta_s": delta_cap, "delta_s": delta,
                "requests": self.requests, "posed": self.posed, "not_posed": dict(sorted(self.not_posed.items())),
                "first_verdicts": {"of_posed": self.posed, "counts": dict(sorted(self.first.items()))},
                "dispositions": {"of_posed": self.posed, "counts": dict(sorted(self.dispositions.items()))},
                "executions_by_label": {"of_posed": self.posed, "counts": dict(sorted(self.labels.items())),
                                        "reasons": {k: dict(sorted(v.items()))
                                                    for k, v in sorted(self.label_reasons.items())}},
                "unsafe_executions": {"of_posed": self.posed, "count": self.unsafe,
                                      "labels": list(UNSAFE[action])},
                "missed_opportunities": {"of_requests_labelled_GT2": self.gt2, "total": sum(self.missed.values()),
                                         "by_disposition": dict(sorted(self.missed.items()))},
                "waiting_seconds": dict(_stats(self.waiting), expired=self.expired, censored=self.censored),
                "late_correction_decisions": {"of_posed": self.posed, "count": self.late},
                "contested_decisions": {"of_posed": self.posed, "counts": dict(sorted(self.contested.items()))},
                "endpointslice_disagreements_among_executions": self.cross_check_disagreements}


def evaluate(index, capture, labeller, contested) -> dict:
    """Read every request row through the sealed index, label each execution, fill the cells."""
    cells: dict = {}
    outcomes: dict = defaultdict(dict)       # (stream, action, k, Delta, delta) -> condition -> (first, disposition)
    late: dict = defaultdict(lambda: {"posed": 0, "reached_by_late_correction": 0})
    u_list = []
    for observer in sorted(index.entries):
        for _, row in index.iter_records(observer, ("request",)):
            streams = capture.stream_names if row["stream"] == "*" else (row["stream"],)
            for stream in streams:
                key = (row["condition"], stream, row["action"], row["Delta_s"], row["delta_s"])
                cell = cells.setdefault(key, Cell(key))
                _count(cell, row, stream, labeller, contested, u_list, PRIMARY.get(capture.plan.arm, {}))
                if row.get("posed"):
                    outcomes[(stream, row["action"], row["k"], row["Delta_s"], row["delta_s"])][row["condition"]] = \
                        (row.get("first_verdict"), row["disposition"])
            if row.get("posed"):
                tally = late[(row["observer"], row["condition"])]
                tally["posed"] += 1
                tally["reached_by_late_correction"] += bool(row.get("late_k1_records"))
    t1 = [cells[k].to_dict() for k in sorted(cells, key=lambda k: (k[0], k[1], k[2], k[3], k[4]))]
    return {"T1_cells": t1, "T2_comparisons": compare(outcomes), "T4_sensitivities": sensitivities(cells),
            "primary_sums": primary_sums(cells, outcomes, capture),
            "late_corrections": [{"observer": o, "condition": c, **v} for (o, c), v in sorted(late.items())],
            "U_executions": u_list}


def in_primary(spec: dict, stream: str, action: str, delta) -> bool:
    streams = spec.get("streams") or (spec.get("stream"),)
    return stream in streams and action == spec["action"] and delta in spec["delta_s"]


def _count(cell: Cell, row: dict, stream: str, labeller, contested, u_list, primary: dict) -> None:
    cell.requests += 1
    if not row.get("posed"):
        cell.not_posed[row.get("not_posed_reason") or "-"] += 1
        return
    cell.posed += 1
    family = row["action"]
    first = row.get("first_verdict") or "none (posed after H)"
    if first == NEEDS_APPROVAL:
        first = f"NEEDS_APPROVAL[{'+'.join(sorted({s.split(':')[0] for s in row.get('first_deciding') or []}))}]"
    cell.first[first] += 1
    disposition = row["disposition"]
    key = f"{disposition}[{_source(row)}]" if disposition in (NEEDS_APPROVAL, DENY) else disposition
    if disposition == ALLOW and row.get("disposition_r7_reason"):
        # An ALLOW with R7's "no_visible_change" (the view had not seen the change) is reported apart from
        # an ALLOW after "rollout_complete"
        key = f"ALLOW[R7:{row['disposition_r7_reason']}]"
    cell.dispositions[key] += 1
    cell.expired += disposition == "EXPIRED"
    cell.censored += disposition == "CENSORED"
    if row.get("waiting_s") is not None:
        cell.waiting.append(row["waiting_s"])
    cell.late += bool(row.get("late_k1_records"))
    decision = (stream, family, row["k"], row["Delta_s"], row["delta_s"])
    for name, flag in (contested.flags.get(decision) or {}).items():
        spec = primary.get(name)
        if flag and spec and row["condition"] in spec["pair"] and in_primary(spec, stream, family, row["delta_s"]):
            cell.contested[name] += 1
    executed_in_window = False
    if disposition == ALLOW and row.get("dispatch_us") is not None:
        x = row["dispatch_us"]
        if family == "A":
            label, reason = labeller.label_a(x, row["kappa_us"])
        else:
            label, reason, detail = labeller.label_b(x, row["target_uid"])
        cell.labels[label] += 1
        cell.label_reasons[label][reason] += 1
        cell.unsafe += label in UNSAFE[family]
        if reason == "endpointslice_disagreement":
            cell.cross_check_disagreements += 1
        if label == U:
            u_list.append({"condition": row["condition"], "stream": stream, "action": family, "k": row["k"],
                           "Delta_s": row["Delta_s"], "delta_s": row["delta_s"], "dispatch": iso(x),
                           "reason": reason})
        executed_in_window = labeller.in_window(x)
    if labeller.opportunity_at(family, row["kappa_us"], row.get("target_uid")):
        cell.gt2 += 1
        if not executed_in_window:
            missed = disposition
            if disposition == ALLOW:
                missed = "ALLOW_outside_window"
            elif disposition in (NEEDS_APPROVAL, DENY):
                missed = f"{disposition}[{_source(row)}]"
            cell.missed[missed] += 1


def compare(outcomes: dict) -> list[dict]:
    out = []
    groups = defaultdict(list)
    for (stream, action, k, delta_cap, delta), by_condition in outcomes.items():
        groups[(stream, action, delta_cap, delta)].append(by_condition)
    for a, b in T2_PAIRS:
        for (stream, action, delta_cap, delta) in sorted(groups):
            both = [d for d in groups[(stream, action, delta_cap, delta)] if a in d and b in d]
            if not both:
                continue
            entry = {"pair": [a, b], "stream": stream, "action": action, "Delta_s": delta_cap, "delta_s": delta,
                     "posed_in_both": len(both)}
            for index, field in ((0, "first_verdict"), (1, "disposition")):
                diff, direction, severity = 0, Counter(), Counter()
                for d in both:
                    va, vb = d[a][index], d[b][index]
                    if va == vb:
                        continue
                    diff += 1
                    if (va == ALLOW) != (vb == ALLOW):
                        direction[f"{a} {'allows' if va == ALLOW else 'blocks'}, {b} "
                                  f"{'allows' if vb == ALLOW else 'blocks'}"] += 1
                    else:
                        severity[f"{va}->{vb}"] += 1
                entry[field] = {"differing_requests": diff, "block_allow_by_direction": dict(sorted(direction.items())),
                                "severity_only_by_type": dict(sorted(severity.items()))}
            out.append(entry)
    return out


def sensitivities(cells: dict) -> list[dict]:
    fields = ("posed", "dispositions", "executions_by_label", "unsafe_executions", "missed_opportunities")
    out = []
    for sensitive, primary, heading in T4_PAIRS:
        for key in sorted(k for k in cells if k[0] == sensitive):
            ref = cells.get((primary,) + key[1:])
            mine = cells[key].to_dict()
            out.append({"sensitivity": sensitive, "beside": primary, "heading": heading, "stream": key[1],
                        "action": key[2], "Delta_s": key[3], "delta_s": key[4],
                        "primary": {f: ref.to_dict()[f] for f in fields} if ref else None,
                        "sensitivity_cell": {f: mine[f] for f in fields}})
    return out


def primary_sums(cells: dict, outcomes: dict, capture) -> dict:
    out = {}
    for name, spec in PRIMARY.get(capture.plan.arm, {}).items():
        streams = spec.get("streams") or (spec.get("stream"),)
        entry = {"cells": {"action": spec["action"], "streams": list(streams), "delta_s": list(spec["delta_s"]),
                           "Delta_s": list(capture.deltas)}, "conditions": {}}
        for condition in spec["pair"]:
            sums = {"U": 0, "M": 0, "posed": 0, "GT2": 0, "cells": 0}
            for key, cell in cells.items():
                if key[0] != condition or key[1] not in streams or key[2] != spec["action"] \
                        or key[4] not in spec["delta_s"]:
                    continue
                sums["cells"] += 1
                sums["U"] += cell.unsafe
                sums["M"] += sum(cell.missed.values())
                sums["posed"] += cell.posed
                sums["GT2"] += cell.gt2
            entry["conditions"][condition] = sums
        a, b = spec["pair"]
        same = True
        compared = 0
        for (stream, action, k, delta_cap, delta), by_condition in outcomes.items():
            if stream not in streams or action != spec["action"] or delta not in spec["delta_s"]:
                continue
            if a in by_condition and b in by_condition:
                compared += 1
                same = same and by_condition[a] == by_condition[b]
        entry["identical_first_verdicts_and_dispositions"] = same if compared else None
        entry["decisions_compared"] = compared
        out[name] = entry
    return out


# ---------------------------------------------------------------------------------------------------------------
# SUMMARY.md (rendered from results.json only)
# ---------------------------------------------------------------------------------------------------------------
def render_summary(res: dict) -> str:
    cap = res["capture"]
    L = ["# Stage-2 governance adapter: " + cap["capture"], ""]
    if res.get("excluded_mark"):
        L += [f"**{res['excluded_mark']}**", ""]
    L += ["Rendered from `results.json`. Counts with denominators; no rate.", "",
          f"- Arm {res['plan_cells']['arm']}, scenario {res['plan_cells']['scenario']}; cells: {res['cells']}; "
          f"conditions {', '.join(cap['conditions'])}; streams {', '.join(cap['streams'])}; Delta "
          f"{cap['Delta_s']} s; delta {cap['delta_s']} s; actions {', '.join(cap['actions'])}.",
          f"- P {cap['P']}; H {cap['H']} (earliest last availability of {', '.join(sorted(cap['H_by_observer']))}); "
          f"requests {cap['requests']}" + (f"; B posable for {cap['b_targets_posable']}" if "B" in cap["actions"]
                                           else "") + ".",
          f"- Clock band b_c = {res['clock_band'].get('band_s')} s; K1 per observer "
          + ", ".join(f"{o}: {v['observations']} ({v['clock_clamped']} clock-clamped)" for o, v in
                      sorted(res["k1"].items())) + "; creation-ceiling clamps "
          + ", ".join(f"{o}: {n}" for o, n in sorted(res["creation_ceiling_clamps"].items())) + ".",
          f"- Decision logs: " + ", ".join(f"`{e['file']}` ({e['evaluations']} evaluations, {e['requests']} "
                                          f"request rows, {e['lines']} lines)"
                                          for e in res["decision_logs"]["per_observer"]) + ".", ""]
    q1 = res["T3_q1_checks"]
    L += ["## Reconstruction checks (x of n)", ""]
    prov = [u["provenance"] for u in res["decision_phase"]["units"]]
    eng = [u["engines"] for u in res["decision_phase"]["units"]]
    c1 = q1["totals"]["check_1_append_only_corrections"]
    L.append(f"- 1 append-only corrections (evaluations at a cutoff before a K1 record's availability): {c1['x']} of "
             f"{c1['n']}; of them reached by a late K1 record (stamp <= dispatch): {c1['x_reached_by_late_k1']} of "
             f"{c1['n_reached_by_late_k1']}")
    c2 = q1["check_2_earlier_cutoff_invariance"]
    L.append(f"- 2 earlier-cutoff invariance (contested + 10 % sample): truncated "
             f"{sum(r['x_truncated'] for r in c2)} of {sum(r['n'] for r in c2)}, fresh full stream "
             f"{sum(r['x_full_stream'] for r in c2)} of {sum(r['n'] for r in c2)}")
    L.append(f"- 3 exact provenance: {sum(p['x'] for p in prov)} of {sum(p['n'] for p in prov)}")
    L.append(f"- 4 graph/SQLite agreement: {sum(e['x'] for e in eng)} of {sum(e['n'] for e in eng)} store queries")
    L.append("- 5 deterministic replay: two interpreters (`run_stage2_adapter.py --rerun-check`, tests)")
    L += ["", "## Design check: contested decisions in the primary cells", ""]
    for name, v in sorted(res["design_check"]["per_comparison"].items()):
        if v.get("not_computed"):
            L.append(f"- {name} ({' vs '.join(v['pair'])}): not computed ({v['not_computed']})")
        else:
            L.append(f"- {name} ({' vs '.join(v['pair'])}): {v['contested']} of {v['posed']} posed decisions")
    L += ["", "## Primary-cell sums: unsafe executions U, missed opportunities M", ""]
    L += ["| Comparison | Condition | U | M | posed | GT-2 | identical |", "| --- | --- | ---: | ---: | ---: | ---: | --- |"]
    for name, v in sorted(res["primary_sums"].items()):
        for condition, s in v["conditions"].items():
            L.append(f"| {name} | {condition} | {s['U']} | {s['M']} | {s['posed']} | {s['GT2']} | "
                     f"{v['identical_first_verdicts_and_dispositions']} |")
    L += ["", "## Cross-observer agreement (never reconstruction)", ""]
    agreement = res["cross_observer_agreement"]
    if agreement.get("computed"):
        for observer, v in sorted(agreement["per_observer"].items()):
            L.append(f"- {observer}: Pod STATE {v['pod_state']['x']} of {v['pod_state']['n']} (store unknown "
                     f"{v['pod_state']['store_unknown']}); bound Deployment rollout state "
                     f"{v['bound_deployment_rollout_state']['x']} of {v['bound_deployment_rollout_state']['n']}")
    else:
        L.append(f"- not computed: {agreement.get('reason')}")
    L += ["", "## T2: request-level differences (sums over Delta and delta)", "",
          "| Pair | Stream | Action | Posed in both | First verdicts differing | Dispositions differing |",
          "| --- | --- | --- | ---: | ---: | ---: |"]
    sums = defaultdict(lambda: [0, 0, 0])
    for entry in res["T2_comparisons"]:
        s = sums[(" vs ".join(entry["pair"]), entry["stream"], entry["action"])]
        s[0] += entry["posed_in_both"]
        s[1] += entry["first_verdict"]["differing_requests"]
        s[2] += entry["disposition"]["differing_requests"]
    for (pair, stream, action), (posed, first, disp) in sorted(sums.items()):
        L.append(f"| {pair} | {stream} | {action} | {posed} | {first} | {disp} |")
    L += ["", "## Late corrections: posed decisions reached by a K1 record", ""]
    for row in res["late_corrections"]:
        L.append(f"- {row['observer']} / {row['condition']}: {row['reached_by_late_correction']} of {row['posed']}")
    L += ["", f"U executions listed in `results.json` `U_executions`: {len(res['U_executions'])}.", ""]
    return "\n".join(L)
