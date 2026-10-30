"""Further replays of the arm-G restart decisions: decision instant, record timing and poll interval.

Each analysis reuses the adapter's own posing (``engine2.pose``, ``run_request``), gate evaluation
(``ObserverContext.evaluate``, ``RecheckContext``) and outcome labels (``labels.Labeller``); only the knowledge a
decision reads, or the instant at which it is made, changes. All of them pose action B (restart of the changed
service's serving Pod) in stream S0 over the primary cells: cutoffs Delta = 0, 5, 30 s after the request start and
dispatch delays delta = 0, 10, 30, 80 s. Decisions are computed first; the labels are built afterwards.

Conditions (``CONDITIONS``):

``T_p``, ``L_p``, ``R``
    the adapter's conditions, recomputed (their counts must equal the published per-capture sums).
``T_p@R``, ``L_p@R``  (latency-matched)
    the poller-fed two-clock (latest-snapshot) gate evaluated at the recheck's own instants: for each posed request,
    at every answered recheck tick that (R) itself would read (request started in [x, x + E), received by H), the
    poller store is queried with cutoff = observation = that tick's receipt x_R; the first non-ABSTAIN verdict
    decides and an ALLOW executes at that x_R. Same instants as (R), the poller's knowledge instead of a fresh read.
``T_p+lag``  (delay only)
    the two-clock poller gate's own decisions, each ALLOW executed at the receipt of the first answered recheck
    tick whose request started at or after the gate's dispatch instant (no execution when there is none before H).
    Same knowledge as T_p, the recheck's actuation delay added.
``T_p[event-time]``  (audit reconstruction)
    the two-clock gate on an event-time-only record of the same poller stream: every record treated as available
    at its own valid time (observations at observed_at, identity facts at valid_from), as an audit that keeps valid
    times but not availability times would replay the decision.
``T_p[thin k]``, ``L_p[thin k]``  (poll interval)
    the poller stream thinned to every k-th poll (Pod, ReplicaSet and Deployment lists of one poll kept or dropped
    together; the poller's K1 rows thinned with them).
``L-kappa``
    approval reuse, recomputed for the surrogate check below.

Audit (``audit`` in the output), for every posed decision of T_p:

* records of the changed service's Pods and of the bound Deployment whose valid time is at or before the cutoff but
  which became available only after it (what an event-time-only record would add to the decision's evidence);
* the gate's verdict recomputed on the event-time-only record (``T_p[event-time]``);
* the end-of-capture state: the target Pod's status and the number of other Ready Pods at the cutoff and at the end
  of the label evidence, and the gate's verdict on the final store (cutoff = observation = H), as an audit that only
  kept the latest state would see the decision.

Surrogate check (``surrogate_pass``, a separate pass): every execution of T_p, L-kappa and R with its label, and at
the execution instant x the EndpointSlice readiness of the target and of the service (the endpoints controller, a
second readiness source that the labels already cross-check), the server spans of the changed service starting
within 2 s of x (count, non-OK status, duration, and whether the target Pod itself served a request in the 2 s after
x), and the probe calls overlapping [x - 2 s, x + 2 s], counted separately for calls to the service address and calls
to the target Pod's own address (count, failures, distinct failing calls). Unsafe and neutral executions are reported
side by side. The executions are counterfactual: nothing was restarted during the capture, so this evidence
describes the state of the service at x, not an effect of the restart. The same pass records how long the fault's
target Pod stayed not ready after the first kill, from the labeller's kubelet (K1) history (``fault_not_ready``).

Uncertain labels on the mutually evaluable decisions (``uncertain_pass``, a separate pass): on the posed decisions
that neither T_p nor R left censored (as ``sweeps.mutually_evaluable``), the invalid executions of both views and
every execution with an uncertain label, by the label's reason, with whether the target Pod itself served a request
(a server span starting) in the 2 s before and in the 2 s after the execution instant.
"""
from __future__ import annotations

import bisect
import dataclasses
import json
import statistics
import time
from collections import OrderedDict, defaultdict
from pathlib import Path

from aiops_kg.policy_gate import ABSTAIN, ALLOW

from .capture import manifest_grace_seconds, read_decision_inputs, read_label_inputs
from .common import R, iso, s_to_us
from .conditions import CONDITIONS as ADAPTER_CONDITIONS
from .engine2 import ObserverContext, RecheckContext, pose, run_request
from .labels import GT2B, U, UNSAFE, Labeller
from .mapping2 import ClampLog, gate_records, k1_for_store, snapshot_pod_rows
from .pipeline import build_capture, service_pod_uids
from govpilot.inputs import STREAM_BY_NAME  # noqa: E402

ACTION, STREAM = "B", "S0"
DELTAS_CAP, DISPATCH = (0, 5, 30), (0, 10, 30, 80)
BASE = ("T_p", "L_p", "R")
CONDITIONS = BASE + ("T_p@R", "L_p@R", "T_p+lag", "T_p[event-time]", "T_p[thin 2]", "L_p[thin 2]", "T_p[thin 4]",
                     "L_p[thin 4]", "L-kappa")
WINDOW_US = 2_000_000


# ---------------------------------------------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------------------------------------------
def poll_number(record) -> int | None:
    snap = record.payload_view().get("snapshot_id") or ""
    head = snap.split("-", 1)[0]
    return int(head) if head.isdigit() else None


def thinned(inputs, k: int):
    """(poller API records, poller K1 rows) keeping every k-th poll (polls 1, 1 + k, 1 + 2k, ...)."""
    api = [r for r in inputs.poller_api if poll_number(r) is None or (poll_number(r) - 1) % k == 0]
    kept = {r.id for r in api}
    k1 = [row for row in inputs.k1_rows["poller"] if row["record_id"] in kept]
    return tuple(api), k1


def pod_list_intervals(api) -> dict:
    """Median and maximum interval (s) between consecutive Pod lists of a poller stream (observation instants)."""
    firsts = {}
    for r in api:
        snap = r.payload_view().get("snapshot_id") or ""
        if snap.endswith("-pods"):
            firsts[snap] = min(firsts.get(snap, r.observed_at), r.observed_at)
    times = sorted(firsts.values())
    gaps = [(b - a) / 1e6 for a, b in zip(times, times[1:])]
    return {"lists": len(times), "median_s": round(statistics.median(gaps), 3) if gaps else None,
            "max_s": round(max(gaps), 3) if gaps else None}


def poller_context(capture, inputs, *, api=None, k1_rows=None, stream=STREAM):
    """(the poller store's context in ``stream`` (default S0), the K1 index of the changed service's Pods:
    (stamp, available))."""
    gated, _ = gate_records(inputs.poller_api if api is None else api)
    records = tuple(inputs.base_records) + tuple(gated)
    rows = inputs.k1_rows["poller"] if k1_rows is None else k1_rows
    k1_obs, extraction = k1_for_store(rows, snapshot_pod_rows(gated, "poller"), band_us=inputs.band_us)
    uids = service_pod_uids(inputs, capture.changed_service)
    k1_index = sorted((o["stamp_us"], o["available_at_us"]) for o in extraction["observations"] if o["pod_uid"] in uids)
    ctx = ObserverContext(capture, "poller", STREAM_BY_NAME[stream], records, k1_obs, ClampLog(), None)
    return ctx, k1_index


def event_time_model(model):
    """The same records with every availability moved to the record's valid time (see the module docstring)."""
    observations, availability = [], dict(model.availability)
    for o in model.observations:
        observed = R.to_us(o.observed_at)
        observations.append(dataclasses.replace(o, available_at=o.observed_at) if o.available_at > o.observed_at
                            else o)
        availability[o.record_id] = min(availability.get(o.record_id, observed), observed)
        for rid in model.provenance.get(o.record_id, ()):
            if rid in availability:
                availability[rid] = min(availability[rid], observed)
    facts = []
    for f in model.identity_facts:
        if f.valid_from is not None and f.available_at > f.valid_from:
            facts.append(dataclasses.replace(f, available_at=f.valid_from))
            if f.source_id in availability:
                availability[f.source_id] = min(availability[f.source_id], R.to_us(f.valid_from))
        else:
            facts.append(f)
    return dataclasses.replace(model, observations=tuple(observations), identity_facts=tuple(facts),
                               availability=availability)


def to_event_time(ctx: ObserverContext) -> ObserverContext:
    ctx.close()
    ctx.model = event_time_model(ctx.model)
    ctx._stores, ctx.memo, ctx._schedules, ctx._hind_index = {}, {}, {}, None
    return ctx


# ---------------------------------------------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------------------------------------------
def requests_of(capture):
    for delta_cap in DELTAS_CAP:
        for delta in DISPATCH:
            for k, t_us in capture.requests:
                yield delta_cap, delta, k, t_us


def at_recheck_instants(cond, ctx: ObserverContext, rctx: RecheckContext, capture, act, row: dict) -> dict:
    """A poller-store condition evaluated at the recheck ticks (R) would read for this request."""
    x, H = row["x_us"], capture.H
    out = dict(row, condition=cond.name + "@R")
    if x > H:
        out.update(disposition="CENSORED", dispatch_us=None, first_verdict=None, evaluations={"count": 0})
        return out
    first, decided = None, None
    used = 0
    for index in rctx.window(x, x + s_to_us(cond.E), H):
        x_r = rctx.ticks[index]["x_r_us"]
        result = ctx.evaluate(cond, act, x_r, x_r)
        used += 1
        if first is None:
            first = (result, x_r)
        if result["verdict"] != ABSTAIN:
            decided = (result, x_r)
            break
    out.update(first_verdict=first[0]["verdict"] if first else None,
               first_instant_us=first[1] if first else None, evaluations={"count": used})
    if decided is not None:
        result, x_r = decided
        out.update(disposition=result["verdict"], disposition_cutoff_us=x_r,
                   dispatch_us=x_r if result["verdict"] == ALLOW else None)
    else:
        out.update(disposition="EXPIRED" if x + s_to_us(cond.E) <= H else "CENSORED", dispatch_us=None)
    return out


def first_tick_receipt(rctx: RecheckContext, at: int, H: int):
    """Receipt of the first answered tick whose request started at or after ``at`` and that was received by H."""
    for index in rctx.window(at, H + 1, H):
        return rctx.ticks[index]["x_r_us"]
    return None


def decisions(converted, plan_path, *, raw=None, which=CONDITIONS, audit=True, progress=None) -> tuple:
    """All rows of the requested conditions for one capture (decisions only; no label is read). T_p and R are always
    computed; ``audit=False`` skips the decision-side audit facts."""
    inputs = read_decision_inputs(converted, raw=raw)
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    capture = build_capture(inputs, plan_doc, conditions=list(BASE))
    if capture.plan.arm != "G":
        raise ValueError("arm-G captures only")
    Tp, Lp, Rc = ADAPTER_CONDITIONS["T_p"], ADAPTER_CONDITIONS["L_p"], ADAPTER_CONDITIONS["R"]
    Lk = ADAPTER_CONDITIONS["L-kappa"]
    rows = defaultdict(list)
    timing = OrderedDict()
    meta = {"capture": capture.capture_id, "H": iso(capture.H), "requests": len(capture.requests)}

    def note(name, started):
        timing[name] = round(time.perf_counter() - started, 1)
        if progress:
            progress("%s %s %.1f s" % (capture.capture_id, name, timing[name]))

    started = time.perf_counter()
    rctx = RecheckContext(capture, inputs.recheck_ticks, ClampLog(), None)
    ctx, k1_index = poller_context(capture, inputs)
    lags = []
    for delta_cap, delta, k, t_us in requests_of(capture):
        rr = run_request(Rc, rctx, capture, ACTION, k, t_us, delta_cap, delta, None)
        rows["R"].append(rr)
        tp = run_request(Tp, ctx, capture, ACTION, k, t_us, delta_cap, delta, None, k1_index=k1_index)
        rows["T_p"].append(tp)
        if "L_p" in which:
            rows["L_p"].append(run_request(Lp, ctx, capture, ACTION, k, t_us, delta_cap, delta, None,
                                           k1_index=k1_index))
        if "L-kappa" in which:
            rows["L-kappa"].append(run_request(Lk, ctx, capture, ACTION, k, t_us, delta_cap, delta, None))
        if not tp.get("posed"):
            for name in ("T_p@R", "L_p@R", "T_p+lag"):
                if name in which:
                    rows[name].append(dict(tp, condition=name))
            continue
        posed, kappa, act, _ = pose(capture, ACTION, k, t_us, delta_cap)
        if "T_p@R" in which:
            rows["T_p@R"].append(at_recheck_instants(Tp, ctx, rctx, capture, act, tp))
        if "L_p@R" in which:
            rows["L_p@R"].append(at_recheck_instants(Lp, ctx, rctx, capture, act, tp))
        if "T_p+lag" in which:
            moved = dict(tp, condition="T_p+lag")
            if tp.get("disposition") == ALLOW and tp.get("dispatch_us") is not None:
                x_r = first_tick_receipt(rctx, tp["dispatch_us"], capture.H)
                moved["dispatch_us"] = x_r
                moved["moved_from_us"] = tp["dispatch_us"]
                if x_r is None:
                    moved["disposition"] = "CENSORED"
                else:
                    lags.append((x_r - tp["dispatch_us"]) / 1e6)
            rows["T_p+lag"].append(moved)
    if audit:
        meta["audit_inputs"] = audit_inputs(ctx, capture, rows["T_p"], Tp)
    ctx.close()
    rctx.close()
    note(", ".join(n for n in ("T_p", "L_p", "R", "T_p@R", "L_p@R", "T_p+lag", "L-kappa")
                   if n in which or n in ("T_p", "R")), started)
    if "T_p[event-time]" in which:
        started = time.perf_counter()
        ectx = to_event_time(poller_context(capture, inputs)[0])
        for delta_cap, delta, k, t_us in requests_of(capture):
            row = run_request(Tp, ectx, capture, ACTION, k, t_us, delta_cap, delta, None)
            rows["T_p[event-time]"].append(dict(row, condition="T_p[event-time]"))
        ectx.close()
        note("T_p[event-time]", started)
    intervals = {"published": pod_list_intervals(inputs.poller_api)}
    for k in (2, 4):
        names = [n for n in ("T_p[thin %d]" % k, "L_p[thin %d]" % k) if n in which]
        if not names:
            continue
        started = time.perf_counter()
        api, k1_rows = thinned(inputs, k)
        intervals["thin %d" % k] = pod_list_intervals(api)
        tctx = poller_context(capture, inputs, api=api, k1_rows=k1_rows)[0]
        for delta_cap, delta, k_, t_us in requests_of(capture):
            for name, cond in (("T_p[thin %d]" % k, Tp), ("L_p[thin %d]" % k, Lp)):
                if name in names:
                    row = run_request(cond, tctx, capture, ACTION, k_, t_us, delta_cap, delta, None)
                    rows[name].append(dict(row, condition=name))
        tctx.close()
        note("thin %d" % k, started)
    meta["poll_intervals"] = intervals
    meta["recheck_lag_s"] = {"n": len(lags), "median": round(statistics.median(lags), 3) if lags else None,
                             "max": round(max(lags), 3) if lags else None}
    meta["seconds"] = timing
    return inputs, capture, rows, meta


def audit_inputs(ctx: ObserverContext, capture, rows_tp, Tp) -> dict:
    """Decision-side audit facts (no label): for every posed T_p decision, the records of the changed service's
    Pods and the bound Deployment with valid time <= cutoff and availability > cutoff (K1 points and API sightings
    separately); and the gate's verdict on the final store (cutoff = observation = H) per target Pod."""
    import bisect
    relevant = ctx.relevant
    k1_ids = ctx.k1_ids
    late = {"k1": [], "api": []}
    for o in ctx.model.observations:
        if relevant is not None and o.subject not in relevant:
            continue
        observed, available = R.to_us(o.observed_at), R.to_us(o.available_at)
        if available > observed:
            late["k1" if o.record_id in k1_ids else "api"].append((observed, available))
    with_late = {"k1": 0, "api": 0, "either": 0}
    lag_s = {"k1": [], "api": []}
    for row in rows_tp:
        if not row.get("posed"):
            continue
        kappa = row["kappa_us"]
        hit = False
        for kind in ("k1", "api"):
            gaps = [available - kappa for observed, available in late[kind] if observed <= kappa < available]
            if gaps:
                with_late[kind] += 1
                lag_s[kind].append(max(gaps) / 1e6)
                hit = True
        with_late["either"] += hit
    final = {}
    for row in rows_tp:
        if row.get("posed") and row["target_uid"] not in final:
            act = capture.action_b(row["target_uid"])
            final[row["target_uid"]] = ctx.evaluate(Tp, act, capture.H, capture.H)["verdict"]
    differs_first = differs_disposition = n = 0
    for row in rows_tp:
        if not row.get("posed"):
            continue
        n += 1
        differs_first += final[row["target_uid"]] != row.get("first_verdict")
        differs_disposition += final[row["target_uid"]] != row.get("disposition")
    return {"posed": n,
            "decisions_with_records_valid_before_cutoff_available_after": with_late,
            "largest_wait_for_such_a_record_s": {k: {"median": round(statistics.median(v), 3) if v else None,
                                                      "max": round(max(v), 3) if v else None}
                                                  for k, v in lag_s.items()},
            "final_store_verdict": {"targets": len(final), "verdicts": dict(sorted(
                {v: sum(1 for x in final.values() if x == v) for v in set(final.values())}.items())),
                                    "first_verdict_differs": differs_first,
                                    "disposition_differs": differs_disposition}}


def span_rows(converted: Path, service: str) -> list:
    """Server spans of ``service``: (start us, end us, Pod UID, rpc status) from the span_claim rows."""
    out = []
    with open(Path(converted) / "accepted_evidence.jsonl", encoding="utf-8") as handle:
        for line in handle:
            if '"span_claim"' not in line:
                continue
            rec = json.loads(line).get("record") or {}
            if rec.get("kind") != "span_claim":
                continue
            p = rec["payload"]
            span = p.get("span") or {}
            res = p.get("resource_attributes") or {}
            if span.get("kind") != 2 or res.get("service.name") != service or "Health/Check" in span.get("name", ""):
                continue
            attrs = p.get("span_attributes") or {}
            status = attrs.get("rpc.response.status_code") or (span.get("status") or {}).get("code") or "UNSET"
            out.append((int(span["startTimeUnixNano"]) // 1000, int(span["endTimeUnixNano"]) // 1000,
                        res.get("k8s.pod.uid"), str(status).strip('"')))
    return sorted(out)


def probe_calls(raw: Path, service: str) -> list:
    """Probe calls to ``service``: (issued us, received us, Pod UID or None, ok, call id). A call sent to one Pod's
    own address (row ``addressing`` "pod_ip" and the call's address equal to the row's ``target_address``) carries
    that Pod's UID; a call to the service address carries None."""
    path = Path(raw) / "ground_truth" / "probe_rows.jsonl"
    out = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            issued = row.get("host_issued_wall_ns")
            received = row.get("host_received_wall_ns")
            if issued is None or received is None:
                continue
            for call in (row.get("batch") or {}).get("calls") or []:
                if call.get("service") != service:
                    continue
                to_pod = row.get("addressing") == "pod_ip" and call.get("address") == row.get("target_address")
                out.append((int(issued) // 1000, int(received) // 1000, row.get("target_pod_uid") if to_pod else None,
                            call.get("outcome") == "ok", call.get("probe_id") or row.get("probe_id")))
    return out


OK_STATUS = ("OK", "0", "UNSET")
PROBE_KINDS = ("service", "target_pod")


def _group() -> dict:
    g = {"executions": 0, "es_target_not_ready": 0, "es_target_unknown": 0, "es_ready_endpoints": [],
         "with_spans": 0, "spans": 0, "span_errors": 0, "with_span_error": 0, "span_ms": [], "target_spans": 0,
         "with_target_span_after": 0}
    for kind in PROBE_KINDS:
        g.update({"with_probes_" + kind: 0, "probe_calls_" + kind: 0, "probe_failures_" + kind: 0,
                  "with_probe_failure_" + kind: 0, "failing_probe_calls_" + kind: set()})
    return g


def surrogate(rows_by_condition: dict, labeller, spans, probes) -> dict:
    """Evidence at the execution instants, by label (module docstring). Probe calls are counted separately for the
    service address and for the target Pod's own address; ``distinct_failing_probe_calls_*`` counts each failing
    call once however many executions lie within the window around it."""
    service = labeller.service
    pods = [p for p in labeller.pods.values() if p.service == service]
    durations = [e - s for s, e, _, status in spans if status in OK_STATUS]
    nominal_ms = statistics.median(durations) / 1000 if durations else None
    starts = [sp[0] for sp in spans]
    statuses = defaultdict(int)
    for sp in spans:
        statuses[sp[3]] += 1
    out = OrderedDict([("service", service), ("window_s", WINDOW_US / 1e6), ("nominal_span_median_ms", nominal_ms),
                       ("server_spans_in_capture_by_status", dict(sorted(statuses.items()))),
                       ("probe_calls_in_capture", OrderedDict([
                           ("service", sum(1 for c in probes if c[2] is None)),
                           ("service_failing", sum(1 for c in probes if c[2] is None and not c[3])),
                           ("pod_address", sum(1 for c in probes if c[2] is not None)),
                           ("pod_address_failing", sum(1 for c in probes if c[2] is not None and not c[3]))]))])
    for name, rows in rows_by_condition.items():
        groups = defaultdict(_group)
        for row in rows:
            if not row.get("posed") or row.get("disposition") != ALLOW or row.get("dispatch_us") is None:
                continue
            x, target = row["dispatch_us"], row["target_uid"]
            label, reason, _ = labeller.label_b(x, target)
            key = "unsafe (%s)" % label if label in UNSAFE[ACTION] else label
            g = groups[key]
            g["executions"] += 1
            es = labeller.slice_ready(target, service, x)
            if es is None:
                g["es_target_unknown"] += 1
            elif es is False:
                g["es_target_not_ready"] += 1
            g["es_ready_endpoints"].append(sum(1 for p in pods if labeller.slice_ready(p.uid, service, x)))
            near = spans[bisect.bisect_left(starts, x - WINDOW_US):bisect.bisect_right(starts, x + WINDOW_US)]
            g["target_spans"] += sum(1 for sp in near if sp[2] == target)
            g["with_target_span_after"] += any(sp[2] == target and sp[0] >= x for sp in near)
            if near:
                g["with_spans"] += 1
                g["spans"] += len(near)
                errors = sum(1 for sp in near if sp[3] not in OK_STATUS)
                g["span_errors"] += errors
                g["with_span_error"] += errors > 0
                g["span_ms"].extend((sp[1] - sp[0]) / 1000 for sp in near)
            calls = [c for c in probes if c[0] <= x + WINDOW_US and c[1] >= x - WINDOW_US]
            for kind, chosen in (("service", [c for c in calls if c[2] is None]),
                                 ("target_pod", [c for c in calls if c[2] == target])):
                if not chosen:
                    continue
                failed = [c for c in chosen if not c[3]]
                g["with_probes_" + kind] += 1
                g["probe_calls_" + kind] += len(chosen)
                g["probe_failures_" + kind] += len(failed)
                g["with_probe_failure_" + kind] += bool(failed)
                g["failing_probe_calls_" + kind].update(c[4] for c in failed)
        summary = OrderedDict()
        for key in sorted(groups):
            g = groups[key]
            ms = sorted(g.pop("span_ms"))
            ready = g.pop("es_ready_endpoints")
            for kind in PROBE_KINDS:
                g["distinct_failing_probe_calls_" + kind] = len(g.pop("failing_probe_calls_" + kind))
            g["es_ready_endpoints_median"] = statistics.median(ready) if ready else None
            g["span_ms_median"] = round(statistics.median(ms), 3) if ms else None
            g["span_ms_p90"] = round(ms[int(0.9 * (len(ms) - 1))], 3) if ms else None
            summary[key] = g
        out[name] = summary
    return out


SURROGATE_CONDITIONS = ("T_p", "L-kappa", "R")


def fault_not_ready(labeller) -> OrderedDict:
    """The fault target's not-ready interval after the first kill, from the labeller's kubelet (K1) history: from the
    first not-ready stamp at or after the kill's request start (floored to the whole second, as kubelet stamps are)
    to the next ready stamp. ``seconds`` is None without a kill, or when the target is not ready again within the
    label evidence."""
    out = OrderedDict([("fault_pod", labeller.fault_pod), ("kill_started", None), ("not_ready_stamp", None),
                       ("ready_stamp", None), ("seconds", None)])
    if not labeller.kills or labeller.fault_pod not in labeller.pods:
        return out
    kill = min(k["start"] for k in labeller.kills)
    out["kill_started"] = iso(kill)
    floor = kill - kill % 1_000_000
    transitions = labeller.pods[labeller.fault_pod].transitions
    start = next((stamp for stamp, state in transitions if stamp >= floor and state == "not_ready"), None)
    if start is None:
        return out
    out["not_ready_stamp"] = iso(start)
    end = next((stamp for stamp, state in transitions if stamp > start and state == "ready"), None)
    if end is not None:
        out["ready_stamp"] = iso(end)
        out["seconds"] = round((end - start) / 1e6, 3)
    return out


def executions_not_neutral(rows_by_condition: dict, labeller) -> dict:
    """Every execution whose label is not neutral: cell, request, instant, target and label."""
    out = OrderedDict()
    for name, rows in rows_by_condition.items():
        listed = []
        for row in rows:
            if not row.get("posed") or row.get("disposition") != ALLOW or row.get("dispatch_us") is None:
                continue
            label, reason, _ = labeller.label_b(row["dispatch_us"], row["target_uid"])
            if label == "neutral":
                continue
            listed.append(OrderedDict([("Delta_s", row["Delta_s"]), ("delta_s", row["delta_s"]), ("k", row["k"]),
                                       ("x", iso(row["dispatch_us"])), ("target_uid", row["target_uid"]),
                                       ("label", label), ("reason", reason if isinstance(reason, str) else None)]))
        out[name] = listed
    return out


def surrogate_pass(converted, plan_path, out_path, *, raw=None, progress=None) -> dict:
    """The surrogate check (module docstring) for T_p, L-kappa and R, with their counts (which must equal the
    published per-capture sums) and the list of their non-neutral executions."""
    inputs, capture, rows, meta = decisions(converted, plan_path, raw=raw, which=SURROGATE_CONDITIONS, audit=False,
                                            progress=progress)
    from .capture import raw_capture_of
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(Path(converted).resolve())
    started = time.perf_counter()
    labeller = Labeller.build(capture, inputs, read_label_inputs(Path(converted).resolve(), raw_dir),
                              manifest_grace_seconds(inputs.configuration))
    chosen = OrderedDict((n, rows[n]) for n in SURROGATE_CONDITIONS)
    doc = OrderedDict([("capture", capture.capture_id), ("scenario", capture.plan.scenario),
                       ("cells", {"action": ACTION, "stream": STREAM, "Delta_s": list(DELTAS_CAP),
                                  "delta_s": list(DISPATCH)}),
                       ("conditions", OrderedDict((n, count(r, labeller)) for n, r in chosen.items())),
                       ("surrogate", surrogate(chosen, labeller, span_rows(Path(converted).resolve(), labeller.service),
                                               probe_calls(raw_dir, labeller.service))),
                       ("executions_not_neutral", executions_not_neutral(chosen, labeller)),
                       ("fault_not_ready", fault_not_ready(labeller))])
    meta["seconds"]["labels and evidence"] = round(time.perf_counter() - started, 1)
    doc["seconds"] = meta["seconds"]
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc


UNCERTAIN_VIEWS = ("T_p", "R")


def target_traffic(spans, starts, x: int, target: str) -> tuple:
    """Whether ``target`` served a request starting in [x - 2 s, x) and in [x, x + 2 s]."""
    lo, mid = bisect.bisect_left(starts, x - WINDOW_US), bisect.bisect_left(starts, x)
    hi = bisect.bisect_right(starts, x + WINDOW_US)
    return (any(spans[i][2] == target for i in range(lo, mid)),
            any(spans[i][2] == target for i in range(mid, hi)))


def uncertain_on_mutual(rows_tp, rows_r, labeller, spans) -> OrderedDict:
    """Invalid executions and executions with an uncertain label, per view, on the posed decisions that neither T_p
    nor R left censored; the uncertain ones by reason, with the target's own traffic around the execution."""
    starts = [sp[0] for sp in spans]
    views = OrderedDict((v, OrderedDict([("invalid", 0), ("uncertain", OrderedDict())])) for v in UNCERTAIN_VIEWS)
    decided = 0
    for a, b in zip(rows_tp, rows_r):
        assert (a["k"], a["Delta_s"], a["delta_s"]) == (b["k"], b["Delta_s"], b["delta_s"])
        if not a.get("posed") or "CENSORED" in (a.get("disposition"), b.get("disposition")):
            continue
        decided += 1
        for name, row in (("T_p", a), ("R", b)):
            if row.get("disposition") != ALLOW or row.get("dispatch_us") is None:
                continue
            x, target = row["dispatch_us"], row["target_uid"]
            label, reason, _ = labeller.label_b(x, target)
            if label in UNSAFE[ACTION]:
                views[name]["invalid"] += 1
            elif label == U:
                before, after = target_traffic(spans, starts, x, target)
                c = views[name]["uncertain"].setdefault(reason, OrderedDict([
                    ("executions", 0), ("target_served_before", 0), ("target_served_after", 0),
                    ("target_served_before_and_after", 0)]))
                c["executions"] += 1
                c["target_served_before"] += before
                c["target_served_after"] += after
                c["target_served_before_and_after"] += before and after
    for v in views.values():
        v["uncertain"] = OrderedDict(sorted(v["uncertain"].items()))
    return OrderedDict([("decisions", decided), ("window_s", WINDOW_US / 1e6), ("views", views)])


def uncertain_pass(converted, plan_path, out_path, *, raw=None, progress=None) -> dict:
    """See the module docstring (uncertain labels on the mutually evaluable decisions)."""
    inputs, capture, rows, meta = decisions(converted, plan_path, raw=raw, which=UNCERTAIN_VIEWS, audit=False,
                                            progress=progress)
    from .capture import raw_capture_of
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(Path(converted).resolve())
    started = time.perf_counter()
    labeller = Labeller.build(capture, inputs, read_label_inputs(Path(converted).resolve(), raw_dir),
                              manifest_grace_seconds(inputs.configuration))
    spans = span_rows(Path(converted).resolve(), labeller.service)
    doc = OrderedDict([("capture", capture.capture_id), ("scenario", capture.plan.scenario),
                       ("mutually_evaluable", uncertain_on_mutual(rows["T_p"], rows["R"], labeller, spans))])
    meta["seconds"]["labels and evidence"] = round(time.perf_counter() - started, 1)
    doc["seconds"] = meta["seconds"]
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc


# ---------------------------------------------------------------------------------------------------------------
# Labels and counts
# ---------------------------------------------------------------------------------------------------------------
def count(rows, labeller) -> OrderedDict:
    """Unsafe executions (V-target, V-floor) and missed opportunities (GT-2-B at posing without an execution inside
    the fault window), as ``tables._count``; plus the label of every execution and the counts of every cell
    (``by_cell``, keyed "cutoff +Delta s | delta d s": posed, executions, U, M, GT2)."""
    out = OrderedDict([("posed", 0), ("U", 0), ("M", 0), ("GT2", 0), ("executions", 0)])
    by_label, by_delay = defaultdict(int), defaultdict(lambda: [0, 0, 0])
    by_cell = {}
    for row in rows:
        if not row.get("posed"):
            continue
        key = (row["Delta_s"], row["delta_s"])
        cell = by_cell.setdefault(key, OrderedDict([("posed", 0), ("executions", 0), ("U", 0), ("M", 0), ("GT2", 0)]))
        out["posed"] += 1
        cell["posed"] += 1
        executed_in_window = False
        if row.get("disposition") == ALLOW and row.get("dispatch_us") is not None:
            x = row["dispatch_us"]
            label, reason, _ = labeller.label_b(x, row["target_uid"])
            by_label[label] += 1
            out["executions"] += 1
            cell["executions"] += 1
            unsafe = label in UNSAFE[ACTION]
            out["U"] += unsafe
            cell["U"] += unsafe
            by_delay[row["delta_s"]][0] += unsafe
            executed_in_window = labeller.in_window(x)
        if labeller.opportunity_at(ACTION, row["kappa_us"], row.get("target_uid")):
            out["GT2"] += 1
            cell["GT2"] += 1
            by_delay[row["delta_s"]][2] += 1
            if not executed_in_window:
                out["M"] += 1
                cell["M"] += 1
                by_delay[row["delta_s"]][1] += 1
    out["executions_by_label"] = dict(sorted(by_label.items()))
    out["by_dispatch_delay"] = {"%d s" % d: {"U": v[0], "M": v[1], "GT2": v[2]} for d, v in sorted(by_delay.items())}
    out["by_cell"] = OrderedDict(("cutoff +%g s | delta %g s" % k, dict(v)) for k, v in sorted(by_cell.items()))
    return out


def verdict_agreement(rows_a, rows_b) -> dict:
    """Request-level agreement of two conditions on the same posed requests."""
    first = disp = execs = 0
    n = 0
    for a, b in zip(rows_a, rows_b):
        if not a.get("posed"):
            continue
        assert (a["k"], a["Delta_s"], a["delta_s"]) == (b["k"], b["Delta_s"], b["delta_s"])
        n += 1
        first += a.get("first_verdict") != b.get("first_verdict")
        disp += a.get("disposition") != b.get("disposition")
        execs += (a.get("dispatch_us") is not None) != (b.get("dispatch_us") is not None)
    return {"posed": n, "first_verdict_differs": first, "disposition_differs": disp, "execution_differs": execs}


def evidence_shift(rows_tp, labeller) -> dict:
    """Decision context at the cutoff against the end-of-capture state (what a last-state record would show): the
    target Pod's kubelet status and the number of other Ready Pods of the service, at kappa and at the label horizon."""
    end = labeller.label_horizon
    n = target_changed = others_changed = either = 0
    for row in rows_tp:
        if not row.get("posed") or end is None:
            continue
        n += 1
        kappa, uid = row["kappa_us"], row["target_uid"]
        s0, s1 = labeller.pod_status(uid, kappa)[0], labeller.pod_status(uid, end)[0]
        service = labeller.service
        others0 = sum(1 for p in labeller.pods.values() if p.service == service and p.uid != uid
                      and labeller.pod_status(p.uid, kappa)[0] == "ready")
        others1 = sum(1 for p in labeller.pods.values() if p.service == service and p.uid != uid
                      and labeller.pod_status(p.uid, end)[0] == "ready")
        target_changed += s0 != s1
        others_changed += others0 != others1
        either += (s0 != s1) or (others0 != others1)
    return {"posed": n, "target_status_differs": target_changed, "other_ready_pods_differ": others_changed,
            "either_differs": either, "end": iso(end) if end else None}


def run(converted, plan_path, out_path, *, raw=None, which=CONDITIONS, progress=None) -> dict:
    inputs, capture, rows, meta = decisions(converted, plan_path, raw=raw, which=which, progress=progress)
    from .capture import raw_capture_of
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(Path(converted).resolve())
    label_inputs = read_label_inputs(Path(converted).resolve(), raw_dir)
    labeller = Labeller.build(capture, inputs, label_inputs, manifest_grace_seconds(inputs.configuration))
    doc = OrderedDict([("capture", capture.capture_id), ("scenario", capture.plan.scenario), ("meta", meta),
                       ("cells", {"action": ACTION, "stream": STREAM, "Delta_s": list(DELTAS_CAP),
                                  "delta_s": list(DISPATCH)}),
                       ("conditions", OrderedDict((name, count(rows[name], labeller))
                                                  for name in CONDITIONS if name in rows))])
    agree = OrderedDict()
    for a, b in (("T_p", "T_p@R"), ("T_p", "T_p[event-time]"), ("T_p", "L_p"), ("T_p@R", "L_p@R"),
                 ("T_p", "T_p[thin 2]"), ("T_p", "T_p[thin 4]")):
        if a in rows and b in rows:
            agree["%s vs %s" % (a, b)] = verdict_agreement(rows[a], rows[b])
    doc["agreement"] = agree
    doc["audit"] = OrderedDict([
        ("posed", meta["audit_inputs"]["posed"]),
        ("records_valid_before_cutoff_available_after", meta["audit_inputs"][
            "decisions_with_records_valid_before_cutoff_available_after"]),
        ("largest_wait_for_such_a_record_s", meta["audit_inputs"]["largest_wait_for_such_a_record_s"]),
        ("event_time_reconstruction", agree.get("T_p vs T_p[event-time]")),
        ("event_time_reconstruction_counts", doc["conditions"].get("T_p[event-time]")),
        ("decisions_with_late_k1_records_by_dispatch", sum(1 for r in rows["T_p"] if r.get("posed")
                                                           and r.get("late_k1_records"))),
        ("end_of_capture_state", evidence_shift(rows["T_p"], labeller)),
        ("final_store_verdict", meta["audit_inputs"]["final_store_verdict"])])
    meta.pop("audit_inputs", None)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc


# ---------------------------------------------------------------------------------------------------------------
# Pipeline latency: every poller record (API sightings and K1 rows) available d s later
# ---------------------------------------------------------------------------------------------------------------
LATENCIES = (5, 30)


def delayed_poller(inputs, seconds: float):
    """(poller API records, poller K1 rows) with every availability moved ``seconds`` later (valid times unchanged)."""
    from aiops_kg import fault_control_kill as K
    shift = s_to_us(seconds)
    api = tuple(dataclasses.replace(r, available_at=r.available_at + shift) for r in inputs.poller_api)
    rows = []
    for row in inputs.k1_rows["poller"]:
        moved = dict(row)
        moved["available_at_us"] = K._time_field(row, "available_at") + shift
        rows.append(moved)
    return api, rows


def latency_pass(converted, plan_path, out_path, *, raw=None, latencies=LATENCIES, progress=None) -> dict:
    """T_p on the poller stream as captured, on an event-time-only record (valid times), and with the poller's
    records arriving d s later; unsafe and missed counts, and how many verdicts the event-time-only record would
    report differently from the gate's actual one at each latency."""
    inputs = read_decision_inputs(converted, raw=raw)
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    capture = build_capture(inputs, plan_doc, conditions=list(BASE))
    Tp = ADAPTER_CONDITIONS["T_p"]
    rows, timing = OrderedDict(), OrderedDict()
    variants = [("T_p", None), ("T_p[event-time]", "event")] + [("T_p[late %d]" % d, d) for d in latencies]
    for name, spec in variants:
        started = time.perf_counter()
        if spec is None:
            ctx = poller_context(capture, inputs)[0]
        elif spec == "event":
            ctx = to_event_time(poller_context(capture, inputs)[0])
        else:
            api, k1 = delayed_poller(inputs, spec)
            ctx = poller_context(capture, inputs, api=api, k1_rows=k1)[0]
        rows[name] = [dict(run_request(Tp, ctx, capture, ACTION, k, t_us, dc, d, None), condition=name)
                      for dc, d, k, t_us in requests_of(capture)]
        ctx.close()
        timing[name] = round(time.perf_counter() - started, 1)
        if progress:
            progress("%s %s %.1f s" % (capture.capture_id, name, timing[name]))
    from .capture import raw_capture_of
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(Path(converted).resolve())
    labeller = Labeller.build(capture, inputs, read_label_inputs(Path(converted).resolve(), raw_dir),
                              manifest_grace_seconds(inputs.configuration))
    doc = OrderedDict([("capture", capture.capture_id), ("scenario", capture.plan.scenario),
                       ("latencies_s", list(latencies)), ("seconds", timing),
                       ("conditions", OrderedDict((n, count(r, labeller)) for n, r in rows.items())),
                       ("event_time_vs", OrderedDict((n, verdict_agreement(rows[n], rows["T_p[event-time]"]))
                                                     for n in rows if n != "T_p[event-time]"))])
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc

