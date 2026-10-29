"""Tests of the further replays of the arm-G restart decisions (experiments/governance-stage2/govstage2/replays.py).

The worlds are those of tests/test_stage2_adapter.py, written by ``govstage2.fixtures`` (no real capture is read):

- FAST: a 3-replica rollout that completes at 5.2 s; poller lists every 2 s from 0 to 60 s (polls 000 to 030, Pods
  at t, each Pod row available 0.5 ms after the previous one); recheck ticks every second from 0 to 60 s, received
  60 ms after their start; four requests (k1 3.0 s on rec-a, k2 20.0 s, k3 26.0 s, k4 40.0 s on rec-d).
- KILL: FAST's rollout, then rec-e killed (Ready False since 30.0 s, Ready again 45.0 s) with the EndpointSlice
  stale after 30.45 s, and a worker fault on rec-f active over [70, 90) s.

Expectations are derived from these timelines. The replay must reproduce the adapter's own decisions wherever their
cells overlap (cutoff +0 s; dispatch delays 0, 10 and 30 s).
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_DIR = ROOT / "experiments/governance-stage2"
if str(ADAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(ADAPTER_DIR))

from govstage2 import fixtures as FX, pipeline as P, replays as RV  # noqa: E402
from govstage2.capture import manifest_grace_seconds, read_decision_inputs, read_label_inputs  # noqa: E402
from govstage2.common import iter_gzip_records  # noqa: E402
from govstage2.engine2 import LogIndex  # noqa: E402
from govstage2.labels import Labeller  # noqa: E402

from aiops_kg.policy_gate import ALLOW  # noqa: E402

from test_stage2_adapter import fast_plan, fast_world, kill_world  # noqa: E402

T = FX.T
REC, CAT = "recommendationservice", "productcatalogservice"
TICK_LAG_US = 60_000


def s(us):
    return None if us is None else round((us - FX.BASE_US) / 1e6, 6)


@pytest.fixture(scope="module")
def fast(tmp_path_factory):
    """FAST decided twice: by the adapter's decision phase (cutoff +0 s; delays 0, 10, 30 s) and by the replay
    (cutoffs 0, 5, 30 s; delays 0, 10, 30, 80 s)."""
    tmp = tmp_path_factory.mktemp("fast_replay")
    world, obs, plan = fast_world()
    converted = FX.write_capture(tmp / "FX-FAST", world, obs, plan, capture_id="FX-FAST")
    plan_path = tmp / "plan.json"
    plan_path.write_text(json.dumps(fast_plan()), encoding="utf-8")
    inputs = read_decision_inputs(converted)
    capture = P.build_capture(inputs, fast_plan(), conditions=["T_p", "L_p", "L-kappa", "R"])
    logs = tmp / "out" / "decision_logs"
    logs.mkdir(parents=True)
    index = LogIndex(logs, meta={"capture": capture.capture_id})
    P.decision_phase(capture, inputs, logs, index, {"capture": capture.capture_id})
    adapter = {}
    for observer in index.entries:
        for _, row in iter_gzip_records(index.path_of(observer), ("request",)):
            if row["action"] == "B" and row["stream"] in ("S0", "*"):
                adapter[(row["condition"], row["k"], row["Delta_s"], row["delta_s"])] = row
    _, rcapture, rows, meta = RV.decisions(converted, plan_path)
    return {"converted": converted, "inputs": inputs, "capture": rcapture, "adapter": adapter, "rows": rows,
            "meta": meta}


@pytest.fixture(scope="module")
def kill(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("kill_replay")
    world, obs, plan = kill_world()
    converted = FX.write_capture(tmp / "FX-KILL", world, obs, plan, capture_id="FX-KILL")
    plan_doc = FX.fixture_plan({"arms/G/observers/recheck": None}, knowledge_cutoff_offsets_seconds=[0],
                               dispatch_delays_seconds={"D": [0], "G": [0]})
    inputs = read_decision_inputs(converted)
    capture = P.build_capture(inputs, plan_doc, conditions=["T_p", "T_w"])
    labeller = Labeller.build(capture, inputs, read_label_inputs(converted, converted.parent),
                              manifest_grace_seconds(inputs.configuration))
    return {"labeller": labeller, "uid": lambda key: world.params[key][1]["uid"]}


def by_cell(rows):
    return {(r["k"], r["Delta_s"], r["delta_s"]): r for r in rows}


# ---------------------------------------------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------------------------------------------
def test_replay_reproduces_the_adapter_decisions(fast):
    """T_p, L_p, R and L-kappa as the adapter decided them, in every overlapping cell; 4 requests x 12 cells."""
    rows, adapter = fast["rows"], fast["adapter"]
    for cond in ("T_p", "L_p", "R", "L-kappa"):
        assert len(rows[cond]) == 4 * len(RV.DELTAS_CAP) * len(RV.DISPATCH)
        mine = by_cell(rows[cond])
        compared = 0
        for (c, k, cutoff, delay), ref in adapter.items():
            if c != cond:
                continue
            row = mine[(k, cutoff, delay)]
            assert (row["posed"], row["disposition"], row.get("dispatch_us"), row.get("first_verdict")) == \
                (ref["posed"], ref["disposition"], ref.get("dispatch_us"), ref.get("first_verdict")), (cond, k, delay)
            compared += 1
        assert compared == 4 * 3, cond


def test_recheck_lag_moves_each_execution_to_the_next_tick_receipt(fast):
    """T_p+lag keeps T_p's decisions; an ALLOW dispatched at y executes at the receipt of the first tick starting at
    or after y (ticks start on whole seconds, received 60 ms later; none after 60 s)."""
    tp, lag = by_cell(fast["rows"]["T_p"]), by_cell(fast["rows"]["T_p+lag"])
    moved = 0
    for key, row in tp.items():
        other = lag[key]
        assert other["first_verdict"] == row.get("first_verdict")
        if row.get("disposition") != ALLOW or row.get("dispatch_us") is None:
            assert other.get("dispatch_us") == row.get("dispatch_us")
            continue
        start = math.ceil(s(row["dispatch_us"]) - 1e-9)
        if start > 60:
            assert (other["disposition"], other["dispatch_us"]) == ("CENSORED", None)
        else:
            assert other["dispatch_us"] == T(start) + TICK_LAG_US
            assert other["moved_from_us"] == row["dispatch_us"]
            moved += 1
    assert moved > 0
    lags = fast["meta"]["recheck_lag_s"]
    assert lags["n"] == moved and 0 < lags["median"] <= 1.06 and lags["max"] <= 1.06


def test_poller_gate_at_the_recheck_instants(fast):
    """T_p@R decides at R's own tick receipts: after the rollout settled (5.2 s) the poller's store shows what the
    recheck reads, so for k2 and k4 it reaches R's verdicts at R's instants. k2 (a = 21.0): delay 10 s gives x = 31.0
    and the 31.06 receipt, where the new ReplicaSet is 28.06 s old (< 30 s): NEEDS_APPROVAL; k4 (a = 41.0): the
    41.06 and 51.06 receipts, ages >= 30 s: ALLOW there. Every execution is at a tick receipt at or after x."""
    at_r, r = by_cell(fast["rows"]["T_p@R"]), by_cell(fast["rows"]["R"])
    for key in ((2, 0, 10), (4, 0, 0), (4, 0, 10)):
        assert (at_r[key]["disposition"], at_r[key].get("dispatch_us")) == (r[key]["disposition"],
                                                                           r[key].get("dispatch_us")), key
    assert (at_r[(4, 0, 0)]["disposition"], s(at_r[(4, 0, 0)]["dispatch_us"])) == ("ALLOW", 41.06)
    assert (at_r[(2, 0, 10)]["disposition"], s(at_r[(2, 0, 10)]["disposition_cutoff_us"])) == ("NEEDS_APPROVAL",
                                                                                             31.06)
    for row in fast["rows"]["T_p@R"]:
        if row.get("dispatch_us") is not None:
            receipt = s(row["dispatch_us"]) - 0.06
            assert abs(receipt - round(receipt)) < 1e-6 and row["dispatch_us"] >= row["x_us"]
    assert [r["disposition"] for r in fast["rows"]["L_p@R"]] == [r["disposition"] for r in fast["rows"]["T_p@R"]]


# ---------------------------------------------------------------------------------------------------------------
# Stores: polls, thinning, record timing
# ---------------------------------------------------------------------------------------------------------------
def test_poll_numbers_thinning_and_intervals(fast):
    """Polls 000 .. 030 every 2 s; every 2nd poll keeps 001, 003, .. 029 (15 lists, 4 s apart), every 4th keeps
    001, 005, .. 029 (8 lists, 8 s apart); the K1 rows follow their Pod rows."""
    inputs = fast["inputs"]
    numbers = {RV.poll_number(r) for r in inputs.poller_api}
    assert numbers == set(range(31))
    for k, kept_polls, gap in ((2, set(range(1, 31, 2)), 4.0), (4, set(range(1, 31, 4)), 8.0)):
        api, k1 = RV.thinned(inputs, k)
        assert {RV.poll_number(r) for r in api} == kept_polls
        ids = {r.id for r in api}
        assert k1 and all(row["record_id"] in ids for row in k1)
        assert len(k1) == sum(1 for r in api if (r.payload_view().get("snapshot_id") or "").endswith("-pods"))
        assert RV.pod_list_intervals(api) == {"lists": len(kept_polls), "median_s": gap, "max_s": gap}
    assert RV.pod_list_intervals(inputs.poller_api) == {"lists": 31, "median_s": 2.0, "max_s": 2.0}
    assert fast["meta"]["poll_intervals"] == {"published": {"lists": 31, "median_s": 2.0, "max_s": 2.0},
                                              "thin 2": {"lists": 15, "median_s": 4.0, "max_s": 4.0},
                                              "thin 4": {"lists": 8, "median_s": 8.0, "max_s": 8.0}}


def test_delayed_poller_moves_availability_only(fast):
    from aiops_kg import fault_control_kill as K
    inputs = fast["inputs"]
    api, k1 = RV.delayed_poller(inputs, 5)
    assert len(api) == len(inputs.poller_api) and len(k1) == len(inputs.k1_rows["poller"])
    for before, after in zip(inputs.poller_api, api):
        assert after.available_at - before.available_at == 5_000_000
        assert after.observed_at == before.observed_at and after.id == before.id
    for before, after in zip(inputs.k1_rows["poller"], k1):
        assert after["available_at_us"] == K._time_field(before, "available_at") + 5_000_000


def test_event_time_model_makes_every_record_available_at_its_valid_time(fast):
    ctx = RV.poller_context(fast["capture"], fast["inputs"])[0]
    late = sum(1 for o in ctx.model.observations if o.available_at > o.observed_at)
    assert late > 0                                        # every fixture row arrives 0.5 ms or more after its poll
    event = RV.to_event_time(ctx)
    assert all(o.available_at <= o.observed_at for o in event.model.observations)
    assert all(f.available_at <= f.valid_from for f in event.model.identity_facts if f.valid_from is not None)
    event.close()


def test_event_time_and_thinned_replays_cover_every_request(fast):
    rows = fast["rows"]
    keys = set(by_cell(rows["T_p"]))
    for name in ("T_p[event-time]", "T_p[thin 2]", "L_p[thin 2]", "T_p[thin 4]", "L_p[thin 4]"):
        assert set(by_cell(rows[name])) == keys and all(r["condition"] == name for r in rows[name])
        assert [r["posed"] for r in rows[name]] == [r["posed"] for r in rows["T_p"]]


# ---------------------------------------------------------------------------------------------------------------
# Counts and the evidence at the execution instants
# ---------------------------------------------------------------------------------------------------------------
def _row(target, kappa, x, cutoff, delay, disposition=ALLOW):
    return {"posed": True, "disposition": disposition, "dispatch_us": None if x is None else T(x), "kappa_us": T(kappa),
            "target_uid": target, "Delta_s": cutoff, "delta_s": delay, "k": 1}


def test_count_by_label_cell_and_delay(kill):
    """KILL's labels (tests/test_stage2_adapter.py): rec-e at 38.0 s V-target, rec-d at 20.0 s neutral, rec-f at
    80.0 s an opportunity (GT-2-B) inside the fault window."""
    uid = kill["uid"]
    rows = [_row(uid("rec-e"), 28.0, 38.0, 0, 10),                       # unsafe
            _row(uid("rec-d"), 20.0, 20.0, 0, 0),                        # neutral
            _row(uid("rec-f"), 80.0, None, 5, 0, disposition="DENY"),    # opportunity missed
            _row(uid("rec-f"), 80.0, 80.0, 5, 0),                        # opportunity taken
            {"posed": False, "disposition": "NOT_POSED", "Delta_s": 0, "delta_s": 0}]
    out = RV.count(rows, kill["labeller"])
    assert {k: out[k] for k in ("posed", "U", "M", "GT2", "executions")} == {"posed": 4, "U": 1, "M": 1, "GT2": 2,
                                                                             "executions": 3}
    assert out["executions_by_label"] == {"GT-2-B": 1, "V-target": 1, "neutral": 1}
    assert out["by_cell"] == {
        "cutoff +0 s | delta 0 s": {"posed": 1, "executions": 1, "U": 0, "M": 0, "GT2": 0},
        "cutoff +0 s | delta 10 s": {"posed": 1, "executions": 1, "U": 1, "M": 0, "GT2": 0},
        "cutoff +5 s | delta 0 s": {"posed": 2, "executions": 1, "U": 0, "M": 1, "GT2": 2}}
    assert out["by_dispatch_delay"] == {"0 s": {"U": 0, "M": 1, "GT2": 2}, "10 s": {"U": 1, "M": 0, "GT2": 0}}


def test_span_rows_keep_server_spans_of_the_service(tmp_path):
    def claim(kind, service, name, start, end, status=None, code=None):
        attrs = {} if status is None else {"rpc.response.status_code": status}
        span = {"kind": kind, "name": name, "startTimeUnixNano": str(start * 1000), "endTimeUnixNano": str(end * 1000)}
        if code is not None:
            span["status"] = {"code": code}
        return {"record": {"kind": "span_claim", "payload": {
            "span": span, "span_attributes": attrs,
            "resource_attributes": {"service.name": service, "k8s.pod.uid": "pod-" + service[:3]}}}}
    lines = [claim(2, REC, "hipstershop.RecommendationService/ListRecommendations", 20, 25, status="OK"),
             claim(2, REC, "hipstershop.RecommendationService/ListRecommendations", 10, 12, code="ERROR"),
             claim(3, REC, "hipstershop.ProductCatalogService/ListProducts", 11, 12, status="OK"),     # client span
             claim(2, REC, "grpc.health.v1.Health/Check", 13, 14, status="OK"),                        # health check
             claim(2, CAT, "hipstershop.ProductCatalogService/ListProducts", 15, 16, status="OK"),     # other service
             {"record": {"kind": "api_observation", "payload": {}}}]
    (tmp_path / "accepted_evidence.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines), encoding="utf-8")
    assert RV.span_rows(tmp_path, REC) == [(10, 12, "pod-rec", "ERROR"), (20, 25, "pod-rec", "OK")]


def test_probe_calls_tell_service_and_pod_addressing_apart(tmp_path):
    """A probe row sends one call per service; a Pod-addressed row sends only the call whose address is the row's
    target_address to that Pod, the other call still goes to its service address."""
    rows = [{"addressing": "service", "host_issued_wall_ns": 1_000_000, "host_received_wall_ns": 2_000_000,
             "target_pod_uid": None, "target_address": None, "probe_id": "p1",
             "batch": {"calls": [{"address": REC + ":8080", "service": REC, "outcome": "ok", "probe_id": "p1/rec"},
                                 {"address": CAT + ":3550", "service": CAT, "outcome": "rpc_error",
                                  "probe_id": "p1/cat"}]}},
            {"addressing": "pod_ip", "host_issued_wall_ns": 3_000_000, "host_received_wall_ns": 4_000_000,
             "target_pod_uid": "uid-cat-1", "target_address": "10.0.0.5:3550", "probe_id": "p2",
             "batch": {"calls": [{"address": REC + ":8080", "service": REC, "outcome": "ok", "probe_id": "p2/rec"},
                                 {"address": "10.0.0.5:3550", "service": CAT, "outcome": "rpc_error",
                                  "probe_id": "p2/cat"}]}},
            {"addressing": "service", "host_issued_wall_ns": 5_000_000, "host_received_wall_ns": None,
             "batch": {"calls": [{"address": CAT + ":3550", "service": CAT, "outcome": "ok"}]}}]
    (tmp_path / "ground_truth").mkdir()
    (tmp_path / "ground_truth" / "probe_rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows),
                                                                encoding="utf-8")
    assert RV.probe_calls(tmp_path, CAT) == [(1000, 2000, None, False, "p1/cat"),
                                             (3000, 4000, "uid-cat-1", False, "p2/cat")]
    assert RV.probe_calls(tmp_path, REC) == [(1000, 2000, None, True, "p1/rec"), (3000, 4000, None, True, "p2/rec")]
    assert RV.probe_calls(tmp_path / "missing", CAT) == []


def test_surrogate_evidence_by_label(kill):
    """Two unsafe executions on rec-e (38.0 s, 38.5 s; its EndpointSlice entry is not ready since 30.45 s) and one
    neutral execution on rec-d (20.0 s). rec-e served a request at 37.0 s, within 2 s before both (counted once per
    execution, never as served after); rec-d serves at 21.0 s. One
    failing service-addressed call (37.6 s) and one failing call to rec-e's own address (38.4 s) lie within 2 s of
    both unsafe executions and count once each as distinct calls; a failing call to rec-f's address does not count
    for rec-e; one span with an error status (38.3 s, rec-f) lies near both."""
    uid, lab = kill["uid"], kill["labeller"]
    e, d, f = uid("rec-e"), uid("rec-d"), uid("rec-f")
    rows = [_row(e, 28.0, 38.0, 0, 10), _row(e, 28.5, 38.5, 5, 10), _row(d, 20.0, 20.0, 0, 0)]
    spans = sorted([(T(37.0), T(37.01), e, "OK"), (T(21.0), T(21.01), d, "OK"), (T(38.2), T(38.21), f, "OK"),
                    (T(38.3), T(38.31), f, "UNAVAILABLE")])
    probes = [(T(37.6), T(37.7), None, False, "svc-1"), (T(38.4), T(38.45), e, False, "pod-e"),
              (T(38.1), T(38.15), f, False, "pod-f"), (T(20.2), T(20.3), None, True, "svc-2")]
    out = RV.surrogate({"T_p": rows}, lab, spans, probes)
    assert out["service"] == REC and out["window_s"] == 2.0
    assert out["server_spans_in_capture_by_status"] == {"OK": 3, "UNAVAILABLE": 1}
    assert out["probe_calls_in_capture"] == {"service": 2, "service_failing": 1, "pod_address": 2,
                                             "pod_address_failing": 2}
    unsafe, neutral = out["T_p"]["unsafe (V-target)"], out["T_p"]["neutral"]
    assert {k: unsafe[k] for k in ("executions", "es_target_not_ready", "with_spans", "spans", "span_errors",
                                   "with_span_error", "target_spans", "with_target_span_after")} == {
        "executions": 2, "es_target_not_ready": 2, "with_spans": 2, "spans": 6, "span_errors": 2,
        "with_span_error": 2, "target_spans": 2, "with_target_span_after": 0}
    assert {k: unsafe[k] for k in ("with_probes_service", "probe_failures_service", "with_probe_failure_service",
                                   "distinct_failing_probe_calls_service", "with_probes_target_pod",
                                   "probe_failures_target_pod", "with_probe_failure_target_pod",
                                   "distinct_failing_probe_calls_target_pod")} == {
        "with_probes_service": 2, "probe_failures_service": 2, "with_probe_failure_service": 2,
        "distinct_failing_probe_calls_service": 1, "with_probes_target_pod": 2, "probe_failures_target_pod": 2,
        "with_probe_failure_target_pod": 2, "distinct_failing_probe_calls_target_pod": 1}
    assert {k: neutral[k] for k in ("executions", "es_target_not_ready", "with_target_span_after",
                                    "with_probes_service", "with_probe_failure_service",
                                    "with_probes_target_pod")} == {
        "executions": 1, "es_target_not_ready": 0, "with_target_span_after": 1, "with_probes_service": 1,
        "with_probe_failure_service": 0, "with_probes_target_pod": 0}
    listed = RV.executions_not_neutral({"T_p": rows}, lab)["T_p"]
    assert [(x["x"][11:23], x["target_uid"], x["label"], x["reason"]) for x in listed] == [
        ("12:00:38.000", e, "V-target", "not_ready"), ("12:00:38.500", e, "V-target", "not_ready")]


def test_fault_not_ready_interval_from_the_kubelet_history():
    """KILL's rec-e history (not_ready 2.0, ready 4.0, not_ready 30.0, not_ready 31.0, ready 45.0) with a kill whose
    request started at 30.4 s: the 30.0 s stamp is the first not-ready stamp at or after the kill floored to the
    whole second, the next ready stamp is 45.0 s: 15 s. No kill, or no ready stamp after the kill: no interval."""
    from types import SimpleNamespace
    history = [(T(2.0), "not_ready"), (T(4.0), "ready"), (T(30.0), "not_ready"), (T(31.0), "not_ready"),
               (T(45.0), "ready")]
    pod = SimpleNamespace(transitions=history)
    lab = SimpleNamespace(fault_pod="uid-e", pods={"uid-e": pod}, kills=[{"start": T(30.4), "end": T(30.6)}])
    out = RV.fault_not_ready(lab)
    assert (s(FX.ts_us(out["not_ready_stamp"])), s(FX.ts_us(out["ready_stamp"])), out["seconds"]) == (30.0, 45.0, 15.0)
    assert RV.fault_not_ready(SimpleNamespace(fault_pod="uid-e", pods={"uid-e": pod}, kills=[]))["seconds"] is None
    cut = SimpleNamespace(transitions=history[:4])
    lab = SimpleNamespace(fault_pod="uid-e", pods={"uid-e": cut}, kills=[{"start": T(30.4), "end": T(30.6)}])
    assert RV.fault_not_ready(lab)["seconds"] is None and RV.fault_not_ready(lab)["not_ready_stamp"] is not None
