"""Reconstruction checks and cross-observer agreement on the decision logs of one capture.

1. Append-only corrections, on real records: every logged causal evaluation of the poller and watch stores at a
   cutoff before some K1 record's availability is re-evaluated on the same stream with every K1 record available
   after its cutoff removed; verdict, rule trace and record IDs must be identical. The subset a late K1 record
   reaches (its kubelet stamp at or before the dispatch instant) is counted apart.
2. Earlier-cutoff invariance on all evaluations of contested decisions plus a 10 % sample of the rest, drawn with
   ``random.Random(0).sample(sorted(rest), ceil(0.1 x len(rest)))`` per capture. Each is re-run (a) on the model
   inputs truncated at its cutoff (stores rebuilt; govpilot.checks.truncate_model) and (b) on a freshly built full
   stream; (R)'s evaluations are re-run on a freshly built tick store.
3. Exact provenance: on every causal evaluation as it is computed (engine2.ObserverContext._provenance).
4. Graph/SQLite agreement on every store query (the dual engine raises on a disagreement; counts per unit).
5. Deterministic replay: two interpreters (tests/test_stage2_adapter.py, and run_stage2_adapter.py --rerun-check).

Cross-observer agreement: at every answered recheck response instant x_R up to H, the poller's and the watch's
two-clock stores (stream S0, F = 30 s) answer, as of x_R, each Pod's STATE in the response and the bound Deployment's
rollout state (R7's state function), against the response; x of n per observer. This is never a reconstruction check:
the observers are different streams and a disagreement is not a replay failure.
"""
from __future__ import annotations

import bisect
import math
import random
from collections import defaultdict

from aiops_kg import fault_control_kill as K

from .common import R, canonical, dt
from .conditions import CONDITIONS, LATEST, TWO_CLOCK, action_a, action_b, records_behind, trace
from .design import decision_key
from .engine2 import ObserverContext, RecheckContext
from .forward import ForwardTracedView
from .mapping2 import ClampLog, build_model_inputs_clamped, gate_records, k1_for_store, merge_k1, snapshot_pod_rows
from govpilot import rollout  # noqa: E402  (read-only)
from govpilot.checks import truncate_model  # noqa: E402
from govpilot.inputs import STREAM_BY_NAME  # noqa: E402

SAMPLE_FRACTION = 0.10
COMPARISON_CONDITIONS = {"H-G2": ("T_p", "L-kappa"), "H-G3": ("T_p", "R"), "H-G4": ("T_p", "T_w"),
                         "H-G3 (T_w, R) secondary": ("T_w", "R"), "action A secondary (H-G4)": ("T_p", "T_w")}


def _act(capture, key: str):
    if key == "A":
        return action_a(capture.capture_id, capture.binding)
    return action_b(capture.capture_id, capture.changed_service, key.split(":", 1)[1])


def _row_eval_ids(row: dict, schedules: dict) -> list[str]:
    """The evaluation IDs of one request row (its first instant and every schedule instant up to its last)."""
    ev = row.get("evaluations") or {}
    if not ev.get("count"):
        return []
    cond = CONDITIONS[row["condition"]]
    cap = row["capture"]
    if row["observer"] == "recheck":
        return [f"{cap}|recheck|*|recheck_response|{row['action_key']}|{tick}" for tick in ev.get("ticks", [])]
    instants = [ev["first_cutoff_us"]] + [t for t in schedules[ev["schedule"]]
                                          if ev["first_cutoff_us"] < t <= ev["last_cutoff_us"]]
    delta = round(row["delta_s"] * 1_000_000)
    out = []
    for tau in instants:
        observation = tau if cond.posing == "approve_then_execute" else tau + delta
        out.append(f"{cap}|{row['observer']}|{row['stream']}|{cond.eval_view}|{row['action_key']}|{tau}|"
                   f"{observation}")
    return out


def select_check2(index, capture, contested) -> tuple[set, dict]:
    population, hindsight = set(), set()
    for observer in capture.observers:
        for kind, entry in index.iter_unverified(observer, ("evaluation",)):
            if "hindsight" in entry:
                hindsight.add(entry["eval_id"])
            else:
                population.add(entry["eval_id"])
    chosen = set()
    for observer in capture.observers:
        schedules = {}
        for kind, obj in index.iter_unverified(observer, ("schedule", "request")):
            if kind == "schedule":
                schedules[obj["key"]] = obj["instants_us"]
                continue
            if not obj.get("posed"):
                continue
            key = (capture.stream_names[0] if obj["stream"] == "*" else obj["stream"],) + decision_key(obj)[1:]
            hit = any(obj["condition"] in pair and contested.is_contested(name, key)
                      for name, pair in COMPARISON_CONDITIONS.items())
            if obj["stream"] == "*":
                hit = hit or any(obj["condition"] in pair and contested.is_contested(name, (s,) + key[1:])
                                 for name, pair in COMPARISON_CONDITIONS.items() for s in capture.stream_names)
            if hit:
                chosen.update(i for i in _row_eval_ids(obj, schedules) if i in population)
    rest = sorted(population - chosen)
    k = math.ceil(SAMPLE_FRACTION * len(rest)) if rest else 0
    sampled = set(random.Random(0).sample(rest, k)) if k else set()
    return chosen | sampled, {"population": len(population), "contested_evaluations": len(chosen),
                              "rest": len(rest), "sampled_from_rest": k, "hindsight_not_checked": len(hindsight),
                              "rule": "all evaluations of contested decisions + Random(0).sample(sorted(rest), "
                                      "ceil(0.1 x len(rest))), per capture"}


def _store_k1(inputs, observer):
    api, _ = gate_records(inputs.observer_api(observer))
    records = tuple(inputs.base_records) + tuple(api)
    k1_obs, _ = k1_for_store(inputs.k1_rows[observer], snapshot_pod_rows(api, observer), band_us=inputs.band_us)
    return records, k1_obs


def _view_of(entry: dict) -> tuple[str, float]:
    knowledge, _, f = entry["view"].partition("@F")
    return knowledge, float(f)


def q1_checks(index, capture, inputs, contested, *, progress=None) -> dict:
    sample, sample_info = select_check2(index, capture, contested)
    out = {"check_1_append_only_corrections": [], "check_2_earlier_cutoff_invariance": [],
           "check_2_sample": sample_info, "agreement": None}
    for observer in capture.observers:
        if observer == "recheck":
            out["check_2_earlier_cutoff_invariance"].append(_recheck_check2(index, capture, inputs, sample))
            continue
        records, k1_obs = _store_k1(inputs, observer)
        # (record ID, availability, valid time in the store): a late record is one available after the cutoff
        # whose valid time is at or before the dispatch instant
        k1_rows = sorted(((o.record_id, _us(o.available_at), _stamp_of(o)) for o in k1_obs),
                         key=lambda t: (t[1], t[0]))
        for stream in capture.stream_names:
            spec = STREAM_BY_NAME[stream]
            cache = BoundedFactCache()
            fresh = ObserverContext(capture, observer, spec, records, k1_obs, ClampLog(), None, fact_cache=cache)
            prepared = (fresh.records, fresh.manifest)
            base = build_model_inputs_clamped(fresh.records, capture.binding, ClampLog())
            arrivals = _truncation_points(fresh.model)
            last_k1 = k1_rows[-1][1] if k1_rows else None
            entries = []
            for kind, entry in index.iter_unverified(observer, ("evaluation",)):
                if entry["stream"] != stream or "hindsight" in entry:
                    continue
                pending = last_k1 is not None and last_k1 > entry["cutoff_us"]
                if pending or entry["eval_id"] in sample:
                    reached = pending and any(available > entry["cutoff_us"] and stamp <= entry["observation_us"]
                                              for _, available, stamp in k1_rows)
                    entries.append((entry, pending, reached))
            c1 = {"observer": observer, "stream": stream, "n": 0, "x": 0, "n_reached_by_late_k1": 0,
                  "x_reached_by_late_k1": 0, "failures": [], "stores_rebuilt": 0}
            c2 = {"observer": observer, "stream": stream, "n": 0, "x_truncated": 0, "x_full_stream": 0,
                  "failures": [], "stores_rebuilt": 0}
            # one slot per check: the evaluations are taken in cutoff order, so each check's key (the K1 prefix,
            # the truncation point) only grows and every context is built once
            slots = {"k1": [None, None], "trunc": [None, None]}
            try:
                for entry, pending, reached in sorted(entries, key=lambda item: (item[0]["cutoff_us"],
                                                                                  item[0]["eval_id"])):
                    tau, x = entry["cutoff_us"], entry["observation_us"]
                    knowledge, F = _view_of(entry)
                    act = _act(capture, entry["action"])
                    logged = trace(entry, fresh.store(knowledge))
                    if pending:
                        prefix = tuple(rid for rid, available, _ in k1_rows if available <= tau)

                        def k1_context(prefix=prefix):
                            keep = set(prefix)
                            subset = [o for o in k1_obs if o.record_id in keep]
                            return ObserverContext(capture, observer, spec, records, subset, ClampLog(), None,
                                                   model=merge_k1(base, subset), fact_cache=cache, prepared=prepared)
                        ctx = _slot(slots, "k1", prefix, k1_context, c1)
                        again, store, _ = ctx.compute(knowledge, F, act, tau, x)
                        ok = trace(again, store) == logged
                        c1["n"] += 1
                        c1["x"] += ok
                        c1["n_reached_by_late_k1"] += reached
                        c1["x_reached_by_late_k1"] += reached and ok
                        if not ok and len(c1["failures"]) < 20:
                            c1["failures"].append(entry["eval_id"])
                    if entry["eval_id"] in sample:
                        position = bisect.bisect_right(arrivals, tau)
                        point = arrivals[position - 1] if position else None

                        def truncated_context(tau=tau):
                            return ObserverContext(capture, observer, spec, records, k1_obs, ClampLog(), None,
                                                   model=truncate_model(fresh.model, tau), fact_cache=cache,
                                                   prepared=prepared)
                        ctx = _slot(slots, "trunc", point, truncated_context, c2)
                        truncated, store, _ = ctx.compute(knowledge, F, act, tau, x)
                        again, fresh_store, _ = fresh.compute(knowledge, F, act, tau, x)
                        c2["n"] += 1
                        ok_t = trace(truncated, store) == logged
                        ok_f = trace(again, fresh_store) == logged
                        c2["x_truncated"] += ok_t
                        c2["x_full_stream"] += ok_f
                        if not (ok_t and ok_f) and len(c2["failures"]) < 20:
                            c2["failures"].append(entry["eval_id"])
            finally:
                for holder in slots.values():
                    if holder[1] is not None:
                        holder[1].close()
                fresh.close()
            out["check_1_append_only_corrections"].append(c1)
            out["check_2_earlier_cutoff_invariance"].append(c2)
            if progress:
                progress(f"{capture.capture_id} checks {observer} {stream}: check 1 {c1['x']}/{c1['n']}, "
                         f"check 2 {c2['x_truncated']}/{c2['n']}")
    out["check_1_note"] = ("n counts every logged causal evaluation of the poller and watch stores at a cutoff "
                           "before some K1 record's availability ('Every evaluation at a "
                           "cutoff before that availability keeps its answer'); each is re-evaluated with every K1 "
                           "record available after its cutoff removed. n_reached_by_late_k1: those a late K1 record "
                           "reaches (stamp <= dispatch)")
    totals = {}
    for name in ("check_1_append_only_corrections", "check_2_earlier_cutoff_invariance"):
        rows = out[name]
        totals[name] = {"n": sum(r["n"] for r in rows),
                        "x": sum(r.get("x", r.get("x_truncated", 0)) for r in rows)}
    rows = out["check_1_append_only_corrections"]
    totals["check_1_append_only_corrections"].update(
        n_reached_by_late_k1=sum(r["n_reached_by_late_k1"] for r in rows),
        x_reached_by_late_k1=sum(r["x_reached_by_late_k1"] for r in rows))
    out["totals"] = totals
    return out


def _us(value) -> int:
    from .common import to_us
    return to_us(value)


def _stamp_of(observation) -> int:
    from .common import to_us
    return to_us(observation.observed_at)


class BoundedFactCache(dict):
    """govpilot's per-group fact cache (``a1_facts`` / ``latest_facts`` ``cache=``) holding at most ``per_group``
    versions of each (rule, subject, predicate) group, least recently used out first. Its keys carry every record ID
    of the group, so an unbounded cache grows with the square of a group's size over the many truncated stores of
    check 2 (each truncation point is a new version of every group it extends); the checks visit cutoffs in
    increasing order, so an evicted version is not asked for again, while the full stream's versions stay in use."""

    def __init__(self, per_group: int = 3):
        super().__init__()
        self.per_group = per_group
        self._order: dict = {}

    def _touch(self, key) -> None:
        order = self._order.setdefault(key[:2], [])
        if key in order:
            order.remove(key)
        order.append(key)
        while len(order) > self.per_group:
            dict.pop(self, order.pop(0), None)

    def __getitem__(self, key):
        value = dict.__getitem__(self, key)
        self._touch(key)
        return value

    def __setitem__(self, key, value) -> None:
        dict.__setitem__(self, key, value)
        self._touch(key)


def _truncation_points(model) -> list[int]:
    """Every instant at which govpilot.checks.truncate_model's result changes (each of its filters' instants), so
    that two cutoffs with the same latest point below them share one truncated model."""
    points = {R.to_us(o.available_at) for o in model.observations}
    points |= {R.to_us(f.available_at) for f in model.identity_facts}
    points |= set(model.withdrawals.values()) | set(model.completion_withdrawals.values())
    points |= set(model.freeze_withdrawals.values()) | set(model.availability.values())
    points |= {c.available_at for c in model.completion_receipts} | {f.available_at for f in model.freezes}
    return sorted(points)


def _slot(slots: dict, name: str, key, factory, counts: dict):
    """The context of one check for ``key``, replacing (and closing) the slot's previous context on a new key."""
    holder = slots[name]
    if holder[1] is None or holder[0] != key:
        if holder[1] is not None:
            holder[1].close()
        holder[0], holder[1] = key, factory()
        counts["stores_rebuilt"] += 1
    return holder[1]


def _recheck_check2(index, capture, inputs, sample) -> dict:
    """(R)'s sampled evaluations re-run on a freshly built tick store (the truncation of a one-response store at
    its own receipt is the store itself)."""
    out = {"observer": "recheck", "stream": "*", "n": 0, "x_truncated": 0, "x_full_stream": 0, "failures": []}
    fresh = RecheckContext(capture, inputs.recheck_ticks, ClampLog(), None)
    by_tick = {t["tick"]: i for i, t in enumerate(fresh.ticks)}
    try:
        for kind, entry in index.iter_unverified("recheck", ("evaluation",)):
            if entry["eval_id"] not in sample:
                continue
            act = _act(capture, entry["action"])
            store, model = fresh._store(by_tick[entry["tick"]])
            from .conditions import decide
            again, _ = decide(view_name="recheck_response", knowledge="recheck_response", F=entry["F_s"], store=store,
                              act=act, binding=capture.binding, service_deployments=capture.service_deployments,
                              floors=capture.floors, cutoff_us=entry["x_r_us"], observation_us=entry["x_r_us"],
                              view_config={"view": "recheck_response", "knowledge": "recheck_response",
                                           "F_seconds": entry["F_s"], "N_seconds": 30.0, "S_seconds": 300.0,
                                           "r7": "state", "observer": "recheck",
                                           "r2_start": "current ReplicaSet creationTimestamp + 1 s, clamped to x_R"})
            out["n"] += 1
            ok = trace(again, store) == trace(entry, store)
            out["x_truncated"] += ok
            out["x_full_stream"] += ok
            if not ok and len(out["failures"]) < 20:
                out["failures"].append(entry["eval_id"])
    finally:
        fresh.close()
    return out


# ---------------------------------------------------------------------------------------------------------------
# Cross-observer agreement
# ---------------------------------------------------------------------------------------------------------------
def cross_observer_agreement(capture, inputs) -> dict:
    if not inputs.recheck_ticks or capture.binding is None:
        return {"computed": False, "reason": "no answered recheck tick or no planned change",
                "semantics": "never reconstruction"}
    from .common import ts_us
    services = set(capture.service_deployments)
    out = {"computed": True, "semantics": "never reconstruction: different observation streams; "
                                          "a disagreement is not a replay failure",
           "store": "two-clock (A1), stream S0, F = 30 s, as of each response receipt x_R <= H", "per_observer": {}}
    ticks = [(ts_us(p["response_received_at"]), p) for _, p in inputs.recheck_ticks]
    ticks = [(x, p) for x, p in ticks if x <= capture.H]
    for observer in ("poller", "watch"):
        if observer not in capture.observers and not inputs.observer_api(observer):
            continue
        if not inputs.observer_api(observer):
            continue
        records, k1_obs = _store_k1(inputs, observer)
        ctx = ObserverContext(capture, observer, STREAM_BY_NAME["S0"], records, k1_obs, ClampLog(), None)
        pods = {"n": 0, "x": 0, "store_unknown": 0, "by_response_state": defaultdict(lambda: [0, 0])}
        rollout_state = {"n": 0, "x": 0, "store_unknown": 0}
        try:
            store = ctx.store(TWO_CLOCK)
            for x_r, payload in ticks:
                view = ForwardTracedView(store, dt(x_r), dt(x_r), carry_forward_seconds=30.0, engine="dual")
                for obj in payload.get("objects") or []:
                    if obj["kind"] == "Pod" and (obj["metadata"].get("labels") or {}).get("app") in services:
                        response = K.pod_state(obj)
                        res = view.resolve(f"Pod/{obj['metadata']['uid']}", "STATE")
                        pods["n"] += 1
                        tally = pods["by_response_state"][response]
                        tally[1] += 1
                        if res.status != "resolved":
                            pods["store_unknown"] += 1
                        elif res.value == response:
                            pods["x"] += 1
                            tally[0] += 1
                    elif obj["kind"] == "Deployment" and obj["metadata"].get("uid") == capture.binding.deployment_uid:
                        response = rollout.sighting_state(rollout.status_value(obj), capture.binding).state
                        state, _ = rollout.resolve_state(view, capture.binding)
                        rollout_state["n"] += 1
                        if state.state == rollout.UNKNOWN:
                            rollout_state["store_unknown"] += 1
                        if state.state == response:
                            rollout_state["x"] += 1
        finally:
            ctx.close()
        pods["by_response_state"] = {k: {"x": v[0], "n": v[1]} for k, v in sorted(pods["by_response_state"].items())}
        out["per_observer"][observer] = {"pod_state": pods, "bound_deployment_rollout_state": rollout_state}
    out["responses"] = len(ticks)
    return out


def canonical_trace(entry, store) -> str:
    return canonical({"verdict": entry["verdict"], "records": records_behind(store, [x for r in entry["rules"]
                                                                                    for x in r["ids"]])})
