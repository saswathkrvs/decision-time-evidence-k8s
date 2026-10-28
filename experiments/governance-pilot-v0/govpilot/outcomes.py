"""Outcome evaluator of the development rollback pilot. A separate module from the decision reader.

It reads ground truth only after every verdict is logged: ``load_ground_truth`` refuses an open decision-log index,
and the reader's guard refuses ground_truth/ while the reader runs. Labels come from the evaluation-only fields plus
the full record stream (final versions); nothing here feeds back into a verdict.

Rollout labels. The evaluator applies R7's state function to every bound Deployment sighting (each with its own
generation) and treats R (patch response receipt) as an in-progress observation:
t_comp = min(W, first sighting showing revision r_C + 1 COMPLETE), where W counts only if the rollout wait exited 0;
t_inc = the last observation showing the change in progress before t_comp (R itself if none); FAILED sightings count
as in progress.

=================  ===========================================================================
instant x          label
=================  ===========================================================================
x < P              GT-0 (not posed; counted)
[P, R)             U (U_pre)
[R, t_inc]         GT-1s (execution = violation V1s)
(t_inc, t_comp)    U (U_c, the unresolved completion interval)
re-entries         U: instants between the COMPLETE observations bracketing a later in-progress sighting
from t_comp        complete: GT-2, late ALLOW, GT-3 or U (below)
=================  ===========================================================================

Complete instants: GT-2 when inside [active_start, active_end), the fault on the changed service's replacement Pod
(fault_target.service == changed service, selected_by == replacement_uid) and latency_effect_established; the same
conditions without an established effect are U; an execution at or after active_end for a request posed before
active_end in a GT-2 capture is a late ALLOW (neither violation nor success); every other complete instant is GT-3
(execution = violation V2). Evaluation-only extra U windows (I4-002/I4-003's catalog-rollout disruption) are U.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from aiops_kg.policy_gate import ALLOW, DENY, NEEDS_APPROVAL

from .common import R, s_to_us, seconds, ts_us
from .engine import CENSORED, ESCALATED, EXPIRED, DecisionLog
from .inputs import API, CHANGE_WAIT
from .rollout import COMPLETE, FAILED, IN_PROGRESS, Binding, sighting_state, status_value

GT0, GT1S, U, GT2, LATE, GT3, X1 = "GT-0", "GT-1s", "U", "GT-2", "LATE_ALLOW", "GT-3", "X1"
NEVER_COLLAPSED_FOR_DISPOSITIONS = ("S150", "S180")
EXECUTION_LABELS = (GT1S, U, GT2, LATE, GT3, X1)
VIOLATION_NAME = {GT1S: "V1s", GT3: "V2", X1: "V3"}


class UnsealedLog(PermissionError):
    """The evaluator was asked to read ground truth before all verdicts existed."""


@dataclass(frozen=True)
class GroundTruth:
    capture_id: str
    P: int | None
    R: int | None
    W: int | None
    wait_exit_code: int | None
    active_start: int | None
    active_end: int | None
    fault_present: bool
    fault_service: str | None
    fault_selected_by: str | None
    effect: bool | None
    changed_service: str | None
    extra_u: tuple = ()

    def to_dict(self) -> dict:
        return {"capture_id": self.capture_id, "P": R.iso(self.P), "R": R.iso(self.R), "W": R.iso(self.W),
                "wait_exit_code": self.wait_exit_code, "active_start": R.iso(self.active_start),
                "active_end": R.iso(self.active_end), "fault_present": self.fault_present,
                "fault_service": self.fault_service, "fault_selected_by": self.fault_selected_by,
                "latency_effect_established": self.effect, "changed_service": self.changed_service,
                "extra_u": [[R.iso(a), R.iso(b), why] for a, b, why in self.extra_u]}


def ground_truth_from_doc(doc: dict, *, extra_u=()) -> GroundTruth:
    """The evaluation-only fields of a ground_truth.json document."""
    observed = doc.get("observed") or {}
    change = observed.get("change") or {}
    fault = observed.get("fault_target") or {}
    timeline = doc.get("timeline_host") or {}
    def opt(text):
        return ts_us(text) if text else None

    def window(key):
        return opt((timeline.get(key) or {}).get("host_utc"))
    extra = tuple((ts_us(a), ts_us(b), why) for a, b, why in doc.get("fixture_extra_u_windows", ())) + tuple(extra_u)
    return GroundTruth(doc.get("capture_id"), opt(change.get("patch_request_started_at")),
                       opt(change.get("patch_response_received_at")), opt(change.get("rollout_reported_complete_at")),
                       change.get("wait_exit_code"), window("active_start"), window("active_end"),
                       bool(((doc.get("planned") or {}).get("labels") or {}).get("fault_present")),
                       fault.get("service"), fault.get("selected_by"),
                       (doc.get("evaluation_summary") or {}).get("latency_effect_established"), change.get("service"),
                       extra)


def load_ground_truth(capture_dir: Path, log: DecisionLog, *, catalog_disruption: bool = False) -> GroundTruth:
    """Open ground_truth/ only for a sealed log (all verdicts exist)."""
    if not log.sealed:
        raise UnsealedLog("ground truth may be read only after every verdict exists (seal the log first)")
    doc = json.loads((Path(capture_dir) / "ground_truth/ground_truth.json").read_text(encoding="utf-8"))
    extra = ()
    if catalog_disruption:
        W = (doc.get("observed") or {}).get("change", {}).get("rollout_reported_complete_at")
        if W:
            window = catalog_disruption_window(Path(capture_dir), ts_us(W))
            if window is not None:
                extra = (window,)
    return ground_truth_from_doc(doc, extra_u=extra)


def catalog_disruption_window(capture_dir: Path, W: int):
    """I4-002 / I4-003: from W to the first OK
    recommendation probe after the catalog rollout's own failures.

    Operationalised here: a probe is a probe row with recommendationservice calls,
    timed by its ``host_received_at``; it fails when any of those calls is not ``functional_ok``. The catalog
    rollout's own failures are the first run of consecutive failing probes received at or after W, and the window
    ends at the first OK probe after that run. Failing probes after the window are counted in the window's note but
    do not extend it (a later failure, for example during the fault window, is not the catalog rollout's). Returns
    None when no failing probe follows W or no OK probe follows the run."""
    rows = []
    with open(Path(capture_dir) / "ground_truth/probe_rows.jsonl", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    probes = []
    for row in rows:
        calls = [c for c in (row.get("batch") or {}).get("calls", []) if c.get("service") == "recommendationservice"]
        if not calls or not row.get("host_received_at"):
            continue
        probes.append((ts_us(row["host_received_at"]), all(c.get("functional_ok") is True for c in calls)))
    after = sorted(p for p in probes if p[0] >= W)
    first = next((i for i, (_, ok) in enumerate(after) if not ok), None)
    if first is None:
        return None
    stop = first
    while stop < len(after) and not after[stop][1]:
        stop += 1
    if stop == len(after):
        return None
    end = after[stop][0]
    later = sum(1 for _, ok in after[stop:] if not ok)
    note = (f"catalog rollout disruption: {stop - first} failing probe(s) "
            f"received W+{seconds(after[first][0] - W)} s to W+{seconds(after[stop - 1][0] - W)} s; first OK probe "
            f"W+{seconds(end - W)} s; {later} failing probe(s) later")
    return (W, end, note)


# ---------------------------------------------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------------------------------------------
class Labeller:
    """Physical and fault-window labels for one capture (from the full stream's final versions)."""

    def __init__(self, gt: GroundTruth, binding: Binding | None, final_records, freezes=(), *,
                 posing_P: int | None = None):
        self.gt = gt
        self.binding = binding
        self.input_errors: list[str] = []
        if posing_P is not None and gt.P is not None and posing_P != gt.P:
            self.input_errors.append(f"posing used P = {R.iso(posing_P)} (accepted patch row) but ground truth has "
                                     f"P = {R.iso(gt.P)}")
        self.sightings: list[tuple[int, str, str]] = []      # (observed_at, state, record id)
        self.t_inc = self.t_comp = None
        self.reentries: list[tuple[int, int | None]] = []
        self.freezes = tuple(freezes)
        if binding is None or gt.P is None:
            return
        withdrawn = {r.corrects for r in final_records if r.corrects is not None}
        for rec in final_records:
            if rec.kind != API or rec.id in withdrawn:
                continue
            resource = rec.payload_view()["resource_data"]
            if resource["kind"] != "Deployment" or resource["metadata"]["name"] != binding.deployment_name:
                continue
            result = sighting_state(status_value(resource), binding)
            state = result.state
            if state == COMPLETE:
                state = f"COMPLETE@{result.revision}"
            self.sightings.append((rec.observed_at, state, rec.id))
        self.sightings.sort()
        after = [(t, s) for t, s, _ in self.sightings if gt.R is not None and t > gt.R]
        first_after = next((rid for t, s, rid in self.sightings if gt.R is not None and t > gt.R), None)
        if first_after is not None:
            meta = next(r for r in final_records if r.id == first_after).payload_view()["resource_data"]["metadata"]
            if meta.get("generation") != binding.generation + 1:
                self.input_errors.append(f"first sighting after R ({first_after}) shows generation "
                                         f"{meta.get('generation')}, not g_C + 1 = {binding.generation + 1}")
        complete_times = [t for t, s in after if s == f"COMPLETE@{binding.changed_revision}"]
        # W bounds completion only when the rollout wait reported completion (exit 0)
        W = gt.W if gt.wait_exit_code in (0, None) else None
        candidates = [x for x in (W, min(complete_times) if complete_times else None) if x is not None]
        self.t_comp = min(candidates) if candidates else None
        progressing = [t for t, s in after if s in (IN_PROGRESS, FAILED)
                       and (self.t_comp is None or t < self.t_comp)]
        self.t_inc = max(progressing) if progressing else gt.R
        if self.t_comp is not None:
            completes = sorted({self.t_comp} | set(complete_times))
            reentries = set()
            for t, s in after:
                if s in (IN_PROGRESS, FAILED) and t > self.t_comp:
                    before = max(c for c in completes if c < t)
                    later = [c for c in completes if c > t]
                    reentries.add((before, later[0] if later else None))
            self.reentries = sorted(reentries, key=lambda x: (x[0], x[1] if x[1] is not None else 2 ** 62))

    # -- section 5.1 / 5.2 ----------------------------------------------------------------------------------------
    def physical(self, x: int) -> tuple[str, str]:
        gt = self.gt
        if gt.P is None:
            return "complete", "no_change"
        if x < gt.P:
            return GT0, "before_patch_request"
        if gt.R is None or x < gt.R:
            return U, "U_pre"
        if x <= self.t_inc:
            return GT1S, "in_progress"
        if self.t_comp is None or x < self.t_comp:
            return U, "U_c"
        for start, end in self.reentries:
            if start < x and (end is None or x < end):
                return U, "re_entry"
        return "complete", "complete"

    def freeze_existed(self, x: int) -> str | None:
        for f in self.freezes:
            payload = f.payload_view()
            if f.observed_at <= x and ts_us(payload["start"]) <= x < ts_us(payload["end"]):
                return f.id
        return None

    def gt2_conditions(self) -> bool:
        gt = self.gt
        return (gt.fault_present and gt.changed_service is not None and gt.fault_service == gt.changed_service
                and gt.fault_selected_by == "replacement_uid")

    def label(self, x: int, d: int | None = None) -> tuple[str, str]:
        """(label, detail) of instant x; d (the request's posing time) only matters for a late ALLOW."""
        phys, detail = self.physical(x)
        if phys != "complete":
            return phys, detail
        gt = self.gt
        for start, end, why in gt.extra_u:
            if start <= x < end:
                return U, why
        frozen = self.freeze_existed(x)
        if frozen:
            return X1, frozen
        inside = gt.active_start is not None and gt.active_start <= x < gt.active_end
        if self.gt2_conditions():
            if gt.effect:
                if inside:
                    return GT2, "constructed mitigation opportunity"
                if gt.active_end is not None and x >= gt.active_end and d is not None and d < gt.active_end:
                    return LATE, "executed at or after active_end; posed before it"
                return GT3, "outside the fault window"
            if inside:
                return U, "GT-2 conditions without an established effect"
            return GT3, "outside the fault window"
        if not gt.fault_present:
            return GT3, "no fault (sham window)" if inside else "no fault"
        return GT3, "fault on another service" if gt.fault_service != gt.changed_service else "not attributable"

    def to_dict(self) -> dict:
        return {"t_inc": R.iso(self.t_inc), "t_comp": R.iso(self.t_comp),
                "reentries": [[R.iso(a), R.iso(b)] for a, b in self.reentries],
                "bound_deployment_sightings": len(self.sightings), "input_errors": self.input_errors}


def gt1p(x: int, gt: GroundTruth, stream_records) -> bool:
    """GT-1p: P <= x and the completion receipt's final version is not usable at x in the stream under test."""
    if gt.P is None or x < gt.P:
        return False
    withdrawn = {r.corrects for r in stream_records if r.corrects is not None}
    finals = [r for r in stream_records if r.kind == CHANGE_WAIT and r.id not in withdrawn]
    return not any(r.available_at <= x for r in finals)


# ---------------------------------------------------------------------------------------------------------------
# Cells
# ---------------------------------------------------------------------------------------------------------------
def _stats(values) -> dict:
    items = sorted(values)
    if not items:
        return {"n": 0, "min": None, "median": None, "max": None}
    return {"n": len(items), "min": items[0], "median": round(statistics.median(items), 6), "max": items[-1]}


def _source(row: dict) -> str:
    return "+".join(sorted({s.split(":")[0] for s in row.get("disposition_source") or []})) or "-"


NO_VISIBLE_CHANGE = "no_visible_change"
ROLLOUT_COMPLETE = "rollout_complete"


def allow_split(posed: list[dict], has_r7: bool) -> dict:
    """ALLOW dispositions by R7's state-clause reason at the disposition instant.

    "allowed_with_no_visible_change" counts R7 ``no_visible_change``; "allowed_after_rollout_complete" counts every
    other ALLOW (``rollout_complete``, and any other reason, which ``by_r7_reason`` would list). The two sum to the
    ALLOW count. Views without R7 (view (a)) are not split."""
    allows = [r for r in posed if r["disposition"] == ALLOW]
    if not has_r7:
        return {"of_allow": len(allows), "not_split": "view without R7 (view (a))"}
    reasons = Counter((r.get("disposition_r7_reason") or "R7 reason not logged").split("+procedural:")[0]
                      for r in allows)
    unseen = reasons.get(NO_VISIBLE_CHANGE, 0)
    return {"of_allow": len(allows), "allowed_with_no_visible_change": unseen,
            "allowed_after_rollout_complete": len(allows) - unseen, "by_r7_reason": dict(sorted(reasons.items()))}


def evaluate_cell(rows: list[dict], labeller: Labeller, stream_records, *, has_r7: bool = True) -> dict:
    gt = labeller.gt
    posed = [r for r in rows if r["posed"]]
    n = len(posed)
    first = Counter()
    for r in posed:
        verdict = r.get("first_verdict")
        if verdict == NEEDS_APPROVAL:
            verdict = f"NEEDS_APPROVAL[{'+'.join(sorted({s.split(':')[0] for s in r['first_deciding']}))}]"
        first[verdict or "none (posed after H)"] += 1
    escalations = sum(r["disposition"] == ESCALATED for r in posed)
    dispositions = Counter()
    for r in posed:
        key = r["disposition"]
        if key in (NEEDS_APPROVAL, DENY):
            key = f"{key}[{_source(r)}]"
        elif key == ESCALATED:
            key = "NEEDS_APPROVAL[escalation]"
        dispositions[key] += 1
    executions = Counter()
    gt1p_count = 0
    executed = {}
    for r in posed:
        if r["disposition"] != ALLOW:
            continue
        x = ts_us(r["disposition_at"])
        label, detail = labeller.label(x, r["d_us"])
        executions[label] += 1
        executed[(r["k"], r["d_us"])] = (x, label)
        if gt1p(x, gt, stream_records):
            gt1p_count += 1
    gt2_at_d = [r for r in posed if labeller.label(r["d_us"], r["d_us"])[0] == GT2]
    missed = Counter()
    costs = []
    for r in gt2_at_d:
        hit = executed.get((r["k"], r["d_us"]))
        inside = hit is not None and gt.active_start <= hit[0] < gt.active_end
        if not inside:
            key = r["disposition"]
            if key == ALLOW:
                key = "ALLOW_after_window"
            elif key in (NEEDS_APPROVAL, DENY):
                key = f"{key}[{_source(r)}]"
            elif key == ESCALATED:
                key = "NEEDS_APPROVAL[escalation]"
            missed[key] += 1
        end = min(hit[0], gt.active_end) if hit is not None else gt.active_end
        costs.append(round((end - r["d_us"]) / 1e6, 6))
    waiting = [r["waiting_s"] for r in posed if r.get("waiting_s") is not None]
    return {
        "requests": len(rows), "posed": n, "not_posed_GT0": len(rows) - n,
        "first_verdicts": {"of_posed": n, "counts": dict(sorted(first.items()))},
        "escalations": {"of_posed": n, "count": escalations},
        "dispositions": {"of_posed": n, "counts": dict(sorted(dispositions.items())),
                         "allow_split": allow_split(posed, has_r7)},
        "executions_by_label": {"of_posed": n, "counts": {
            "V1s (GT-1s)": executions[GT1S], "U": executions[U], "GT-2": executions[GT2],
            "late ALLOW": executions[LATE], "V2 (GT-3)": executions[GT3], "V3 (X1, fixtures only)": executions[X1]}},
        "gt1p_executions": {"of_posed": n, "count": gt1p_count, "note": "procedural count, reported apart"},
        "missed_opportunities": {"of_requests_labelled_GT2_at_d": len(gt2_at_d), "by_disposition":
                                 dict(sorted(missed.items())), "total": sum(missed.values())},
        "waiting_seconds": dict(_stats(waiting), expired=sum(r["disposition"] == EXPIRED for r in posed),
                                censored=sum(r["disposition"] == CENSORED for r in posed)),
        "cost_of_waiting_seconds": dict(_stats(costs), of_requests_labelled_GT2_at_d=len(gt2_at_d)),
    }


def cells(log: DecisionLog, labellers: dict, stream_records: dict) -> list[dict]:
    """Section 5.3 quantities per capture x view x stream x Delta (needs a sealed log)."""
    from .views import CAUSAL_VIEWS, HINDSIGHT_VIEWS

    if not log.sealed:
        raise UnsealedLog("outcomes need a sealed decision log")
    groups: dict[tuple, list] = {}
    for r in log.requests:
        groups.setdefault((r["capture"], r["view"], r["stream"], r["delta_s"]), []).append(r)
    out = []
    for key in sorted(groups):
        capture, view, stream, delta = key
        base = view.split("@", 1)[0]
        spec = CAUSAL_VIEWS[base] if base in CAUSAL_VIEWS else HINDSIGHT_VIEWS[base]
        rows = sorted(groups[key], key=lambda r: r["k"])
        out.append({"capture": capture, "view": view, "stream": stream, "delta_s": delta,
                    **evaluate_cell(rows, labellers[capture], stream_records[(capture, stream)],
                                    has_r7=spec.r7 is not None)})
    return out


def compare(log: DecisionLog, view_a: str, view_b: str) -> list[dict]:
    """T2: request-level differences between two views, per capture x stream x Delta, for first verdicts and for
    eventual dispositions; block<->allow by direction, severity-only by type. Only cells in which both views ran are
    compared (a fixture plan may run a view on fewer captures); posing does not depend on the view, so both views
    pose the same requests in such a cell, which is checked."""
    index = {}
    for r in log.requests:
        if r["posed"]:
            index[(r["capture"], r["view"], r["stream"], r["delta_s"], r["k"])] = r
    ran_a = {k[:1] + k[2:4] for k in index if k[1] == view_a}
    ran_b = {k[:1] + k[2:4] for k in index if k[1] == view_b}
    out = []
    for capture, stream, delta in sorted(ran_a & ran_b):
        ks = sorted(k[4] for k in index if k[:4] == (capture, view_a, stream, delta))
        if ks != sorted(k[4] for k in index if k[:4] == (capture, view_b, stream, delta)):
            raise ValueError(f"{view_a} and {view_b} posed different requests in {capture} {stream} {delta}")
        cell = {"capture": capture, "stream": stream, "delta_s": delta, "views": [view_a, view_b], "posed": len(ks)}
        for field in ("first_verdict", "disposition"):
            diff, block_allow, severity = 0, Counter(), Counter()
            for k in ks:
                a = index[(capture, view_a, stream, delta, k)].get(field)
                b = index[(capture, view_b, stream, delta, k)].get(field)
                if a == b:
                    continue
                diff += 1
                if (a == ALLOW) != (b == ALLOW):
                    block_allow[f"{view_a} {'allows' if a == ALLOW else 'blocks'}, {view_b} "
                                f"{'allows' if b == ALLOW else 'blocks'}"] += 1
                else:
                    severity[f"{a}->{b}"] += 1
            cell[field] = {"differing_requests": diff, "block_allow_by_direction": dict(sorted(block_allow.items())),
                           "severity_only_by_type": dict(sorted(severity.items()))}
        out.append(cell)
    return out


def collapsed_cells(log: DecisionLog, stream_records: dict, horizons: dict) -> list[dict]:
    """Section 6.3 reporting rule: per capture x view x Delta, the streams whose cell inputs are identical by
    construction. First verdicts: the change records usable at each request's d are the same (record, availability)
    pairs; eventual dispositions: the same within each request's window [d, min(d + E, H)]. Each group with two or
    more streams is printed once; ``outcomes_identical`` checks that the logged outcomes indeed coincide."""
    from .inputs import CHANGE_KINDS
    from .views import CAUSAL_VIEWS, HINDSIGHT_VIEWS, causal_view

    groups: dict[tuple, dict] = {}
    for r in log.requests:
        if r["posed"]:
            groups.setdefault((r["capture"], r["view"], r["delta_s"]), {}).setdefault(r["stream"], []).append(r)
    out = []
    for (capture, view, delta) in sorted(groups):
        base = view.split("@", 1)[0]
        spec = causal_view(view) if base in CAUSAL_VIEWS else HINDSIGHT_VIEWS[base]
        H = horizons[capture]
        first_fp, disp_fp, first_out, disp_out = {}, {}, {}, {}
        for stream, rows in sorted(groups[(capture, view, delta)].items()):
            rows = sorted(rows, key=lambda r: r["k"])
            change = [c for c in stream_records[(capture, stream)] if c.kind in CHANGE_KINDS]
            first_fp[stream] = tuple(tuple(sorted((c.id, c.available_at, c.corrects) for c in change
                                                  if c.available_at <= r["d_us"])) for r in rows)
            ends = [H if spec.E is None else min(H, r["d_us"] + s_to_us(spec.E)) for r in rows]
            disp_fp[stream] = tuple(tuple(sorted((c.id, c.available_at, c.corrects) for c in change
                                                 if c.available_at <= end)) for r, end in zip(rows, ends, strict=True))
            first_out[stream] = [r.get("first_verdict") for r in rows]
            disp_out[stream] = [(r["disposition"], r.get("disposition_at")) for r in rows]
        entry = {"capture": capture, "view": view, "delta_s": delta, "first_verdicts": [], "dispositions": []}
        for field, fps, outs in (("first_verdicts", first_fp, first_out), ("dispositions", disp_fp, disp_out)):
            by_fp: dict = {}
            for stream, fp in fps.items():
                if field == "dispositions" and stream in NEVER_COLLAPSED_FOR_DISPOSITIONS:
                    continue        # section 6.3: S150 and S180 are never collapsed for eventual dispositions
                by_fp.setdefault(fp, []).append(stream)
            for streams in by_fp.values():
                if len(streams) > 1:
                    entry[field].append({"streams": sorted(streams), "outcomes_identical":
                                         all(outs[s] == outs[streams[0]] for s in streams)})
        if entry["first_verdicts"] or entry["dispositions"]:
            out.append(entry)
    return out
