"""Tests of the governance adapter of the follow-up study (experiments/governance-stage2/govstage2).

Every expectation below is a literal derived by hand from the fixture's timeline; none is copied from a run. Three
worlds, all written by ``govstage2.fixtures`` in converter v4's layout (no real capture is read):

- FAST (``fast_world``): a 3-replica rollout that completes early. P = 2.0 s, R = 2.2 s; the new ReplicaSet rs-rec-2
  is created at 2.5 s (creationTimestamp 2 s, so gate v1's creation ceiling is 3.0 s); rec-d/e/f created 2.6, Ready
  4.0; the old Pods rec-a/b/c are deleted at 4.1 and gone at 5.0; the Deployment reports complete at 5.2. Poller
  lists every 2 s from 0 to 60 s (Pods at t, ReplicaSets at t + 0.4, Deployments at t + 0.8, each row 0.5 ms after
  the previous one); recheck ticks every second from 0 to 60 s (x_R = start + 60 ms); no watch. Requests (t_k, Pod,
  span acquisition): k1 (3.0, rec-a, 4.0), k2 (20.0, rec-d, 21.0), k3 (26.0, rec-d, 27.5), k4 (40.0, rec-d, 41.0).
  Grid: Delta = 0, delta in {0, 10, 30} s; conditions T_p, L_p, L-kappa, R; stream S0. H = 60.060001 s (the last
  recheck receipt; the poller's last row is at 60.801 s).
- KILL (``kill_world``): FAST's rollout, then rec-e killed (Ready False since 30.0, reported 30.4; restarted 31.0;
  Ready again 45.0, reported 45.3), the EndpointSlice not refreshed after 30.45 until 60.0; an F1 worker fault on
  rec-f active [70, 90) with its effect established. Poller to 100 s; watch from 0.1 s (snapshots at n + 0.3).
- TINY (``govstage2.fixtures.tiny_g2``): the end-to-end world of ``--check`` (rollout from P = 10 s with a container
  kill mid-rollout, five requests, all three observers).
"""
from __future__ import annotations

import dataclasses
import gzip
import json
import math
import os
import random
import shutil
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_DIR = ROOT / "experiments/governance-stage2"
CLI = ADAPTER_DIR / "run_stage2_adapter.py"
if str(ADAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(ADAPTER_DIR))

from govstage2 import checks2, design, engine2, mapping2, pipeline as P  # noqa: E402
from govstage2 import conditions as C, fixtures as FX  # noqa: E402
from govstage2.capture import (SeparationError, decision_guard, manifest_grace_seconds, read_decision_inputs,  # noqa
                               read_label_inputs)
from govstage2.common import EXPECTATION_FILE, Refused, dt, iter_gzip_records  # noqa: E402
from govstage2.engine2 import LogIndex, SealedLogError, UnsealedLogError  # noqa: E402
from govstage2.forward import ForwardGraphStore, ForwardOperationalView, ForwardSqliteStore, build_forward_store  # noqa
from govstage2.labels import Labeller  # noqa: E402

from aiops_kg import policy_gate as PG, temporal as TM  # noqa: E402
from govpilot import mapping as GM, rollout  # noqa: E402
from govpilot.inputs import STREAM_BY_NAME  # noqa: E402

REC, CAT = "recommendationservice", "productcatalogservice"
T = FX.T


def s(us):
    """Fixture seconds of an instant (None stays None)."""
    return None if us is None else round((us - FX.BASE_US) / 1e6, 6)


def us_of(value) -> int:
    from govstage2.common import to_us
    return to_us(value)


# ---------------------------------------------------------------------------------------------------------------
# Worlds
# ---------------------------------------------------------------------------------------------------------------
def rollout_world() -> FX.World:
    w = FX.base_world()
    dep = "dep-" + REC
    w.put(2.1, dep, generation=2)
    w.put(2.5, dep, observed=2, revision="2", status_replicas=6, updated=3, unavailable=3,
          progressing="ReplicaSetUpdated", progressing_since=2.5)
    w.put(2.5, "rs-rec-2", "ReplicaSet", name=f"{REC}-rech2", app=REC, hash="rech2",
          dep_uid=w.params[dep][1]["uid"], revision="2", created=2.5, replicas=3, ready=0, generation=1)
    for key, ip in (("rec-d", "10.0.0.21"), ("rec-e", "10.0.0.22"), ("rec-f", "10.0.0.23")):
        FX.pod(w, 2.6, key, REC, "rs-rec-2", created=2.6, ready=False, ready_since=2.6, phase="Pending", restarts=0)
        FX.pod(w, 3.0, key, REC, "rs-rec-2", phase="Running", started=3.0, ip=ip)
        FX.pod(w, 4.0, key, REC, "rs-rec-2", ready=True, ready_since=4.0)
    w.refresh_slice(4.05, REC)
    w.put(4.06, "rs-rec-2", ready=3)
    w.put(4.08, "rs-rec-1", replicas=0, ready=0, generation=2)
    for old in ("rec-a", "rec-b", "rec-c"):
        FX.pod(w, 4.1, old, REC, "rs-rec-1", deleting=4.1, ready=False, ready_since=4.1)
    w.refresh_slice(4.15, REC)
    for old in ("rec-a", "rec-b", "rec-c"):
        w.delete(5.0, old)
    w.refresh_slice(5.05, REC)
    w.put(5.2, dep, status_replicas=3, updated=3, ready=3, available=3, unavailable=0,
          progressing="NewReplicaSetAvailable", progressing_since=5.2)
    return w


def fast_world():
    obs = FX.Observers(poller_lists=tuple(2.0 * n for n in range(31)),
                       recheck_ticks=tuple(float(t) for t in range(61)))
    plan = FX.Plan(scenario="G2", P=2.0, R=2.2, W=5.5,
                   requests=((1, 3.0, {REC: "rec-a", CAT: "cat-a"}, 1.0),
                             (2, 20.0, {REC: "rec-d", CAT: "cat-b"}, 1.0),
                             (3, 26.0, {REC: "rec-d", CAT: "cat-a"}, 1.5),
                             (4, 40.0, {REC: "rec-d", CAT: "cat-b"}, 1.0)))
    return rollout_world(), obs, plan


def fast_plan() -> dict:
    return FX.fixture_plan({"arms/G/observers/watch": None, "arms/G/change_record_streams": ["S0"]},
                           knowledge_cutoff_offsets_seconds=[0], dispatch_delays_seconds={"D": [0], "G": [0, 10, 30]})


def kill_world():
    w = rollout_world()
    FX.pod(w, 30.4, "rec-e", REC, "rs-rec-2", ready=False, ready_since=30.0)
    w.refresh_slice(30.45, REC)
    FX.pod(w, 31.0, "rec-e", REC, "rs-rec-2", restarts=1, last_finished=30.0, last_started=3.0, started=31.0)
    FX.pod(w, 45.3, "rec-e", REC, "rs-rec-2", ready=True, ready_since=45.0)
    w.refresh_slice(60.0, REC)
    obs = FX.Observers(poller_lists=tuple(2.0 * n for n in range(51)), watch_start=0.1,
                       watch_snapshots=tuple(n + 0.3 for n in range(1, 101)), watch_stop=101.0)
    plan = FX.Plan(scenario="G2", P=2.0, R=2.2, W=5.5,
                   requests=((1, 3.0, {REC: "rec-a", CAT: "cat-a"}, 1.0),
                             (2, 20.0, {REC: "rec-d", CAT: "cat-b"}, 1.0),
                             (3, 38.0, {REC: "rec-d", CAT: "cat-a"}, 1.0),
                             (4, 80.0, {REC: "rec-f", CAT: "cat-b"}, 1.0)),
                   fault={"service": REC, "pod_key": "rec-f", "selected_by": "random_ready_replica",
                          "active": (70.0, 90.0), "effect": True})
    return w, obs, plan


# ---------------------------------------------------------------------------------------------------------------
# Module fixtures
# ---------------------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def fast(tmp_path_factory):
    """FAST through the decision phase and the record-timing phase (no labels)."""
    tmp = tmp_path_factory.mktemp("fast")
    world, obs, plan = fast_world()
    converted = FX.write_capture(tmp / "FX-FAST", world, obs, plan, capture_id="FX-FAST")
    inputs = read_decision_inputs(converted)
    capture = P.build_capture(inputs, fast_plan(), conditions=["T_p", "L_p", "L-kappa", "R"])
    logs = tmp / "out" / "decision_logs"
    logs.mkdir(parents=True)
    index = LogIndex(logs, meta={"capture": capture.capture_id})
    decision = P.decision_phase(capture, inputs, logs, index, {"capture": capture.capture_id})
    rows = {}
    for observer in index.entries:
        for _, row in iter_gzip_records(index.path_of(observer), ("request",)):
            rows[(row["condition"], row["action"], row["k"], row["delta_s"])] = row
    timing = design.transitions(inputs, capture)
    contested = design.contested(index, capture, timing)
    return {"tmp": tmp, "world": world, "converted": converted, "inputs": inputs, "capture": capture,
            "index": index, "decision": decision, "rows": rows, "timing": timing, "contested": contested}


@pytest.fixture(scope="module")
def kill(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("kill")
    world, obs, plan = kill_world()
    converted = FX.write_capture(tmp / "FX-KILL", world, obs, plan, capture_id="FX-KILL")
    plan_doc = FX.fixture_plan({"arms/G/observers/recheck": None}, knowledge_cutoff_offsets_seconds=[0],
                               dispatch_delays_seconds={"D": [0], "G": [0]})
    inputs = read_decision_inputs(converted)
    capture = P.build_capture(inputs, plan_doc, conditions=["T_p", "T_w"])
    labeller = Labeller.build(capture, inputs, read_label_inputs(converted, converted.parent),
                              manifest_grace_seconds(inputs.configuration))
    return {"world": world, "labeller": labeller, "uid": lambda key: world.params[key][1]["uid"]}


@pytest.fixture(scope="module")
def e2e(tmp_path_factory):
    """TINY end to end under the --check plan (every condition, Delta = 0, delta in {0, 10}, S0 and Snever)."""
    tmp = tmp_path_factory.mktemp("e2e")
    results = P.run_check_fixture(tmp)
    return {"tmp": tmp, "results": results, "out": tmp / "out", "converted": tmp / "FX-G2-001" / "evidence",
            "plan": tmp / "fixture_plan.json"}


def _store_inputs(ctx_capture, inputs):
    """The poller's S0 model inputs exactly as the decision phase builds them."""
    api, _ = mapping2.gate_records(inputs.observer_api("poller"))
    records = tuple(inputs.base_records) + tuple(api)
    k1_obs, _ = mapping2.k1_for_store(inputs.k1_rows["poller"], mapping2.snapshot_pod_rows(api, "poller"),
                                      band_us=inputs.band_us)
    return engine2.ObserverContext(ctx_capture, "poller", STREAM_BY_NAME["S0"], records, k1_obs, mapping2.ClampLog(),
                                   None)


# ---------------------------------------------------------------------------------------------------------------
# Posing with delta (implementation note)
# ---------------------------------------------------------------------------------------------------------------
def test_forward_classes_lift_only_the_guard(fast):
    """The view and resolvers refuse observation > cutoff; the forward subclasses accept it, and for observation <=
    cutoff every forward resolver answers exactly as the one (both engines, every subject and predicate of FAST's
    poller store, at two cutoffs)."""
    ctx = _store_inputs(fast["capture"], fast["inputs"])
    facts, support = GM.a1_facts(ctx.model.observations, ctx.model.withdrawals)
    facts = tuple(facts) + tuple(ctx.model.identity_facts)
    frozen = PG.BitemporalStore(facts, engines=("graph", "sqlite"))
    with pytest.raises(ValueError, match="observed_at cannot be later than knowledge_cutoff"):
        PG.OperationalView(frozen, dt(T(31.0)), dt(T(21.0)), carry_forward_seconds=30.0)
    with pytest.raises(ValueError, match="observed_at cannot be later than decision_at"):
        frozen.engine("graph").resolve("Pod/x", PG.STATE, dt(T(31.0)), dt(T(21.0)), 30.0)
    view = ForwardOperationalView(frozen, dt(T(31.0)), dt(T(21.0)), carry_forward_seconds=30.0)
    assert view.observed_at > view.knowledge_cutoff
    graph, sqlite = ForwardGraphStore(facts), ForwardSqliteStore(facts)
    keys = sorted({(f.subject, f.predicate) for f in facts})
    compared = 0
    for cutoff in (4.0, 21.0):
        for observed in (cutoff - 5.0, cutoff):
            args = (dt(T(observed)), dt(T(cutoff)), 30.0)
            for subject, predicate in keys:
                assert graph.resolve(subject, predicate, *args) == frozen.engine("graph").resolve(subject, predicate,
                                                                                                 *args)
                assert sqlite.resolve(subject, predicate, *args) == frozen.engine("sqlite").resolve(subject, predicate,
                                                                                                   *args)
                compared += 1
    assert compared == 4 * len(keys) and len(keys) > 30


def _frozen_decide(store, act, capture, kappa_us, F, N, S):
    view = GM.TracedView(store, dt(kappa_us), dt(kappa_us), carry_forward_seconds=F, engine="dual")
    config = dataclasses.replace(C.gate_config(capture.service_deployments, capture.floors, F),
                                 change_window_seconds=N, stale_view_seconds=S)
    rules = list(PG.evaluate(act.action, view, config).rules)
    state, ids = rollout.resolve_state(view, capture.binding)
    rules.append(rollout.r7_rule(state, ids, capture.binding, None))
    return PG.combine(r.verdict for r in rules), [(r.rule, r.verdict, r.reason, tuple(r.record_ids)) for r in rules]


def _forward_decide(store, act, capture, knowledge, kappa_us, delta_s):
    entry, _ = C.decide(view_name=f"{knowledge}@F30", knowledge=knowledge, F=30.0, store=store, act=act,
                        binding=capture.binding, service_deployments=capture.service_deployments,
                        floors=capture.floors, cutoff_us=kappa_us, observation_us=kappa_us + round(delta_s * 1e6),
                        view_config={"test": True})
    return entry["verdict"], [(r["rule"], r["verdict"], r["reason"], tuple(r["ids"])) for r in entry["rules"]]


def test_delta_equivalence_shortened_F_N_S(fast):
    """On a fixture without future-dated facts, evaluating at (kappa, kappa + delta) with F, N and S equals evaluating
    at kappa with F - delta, N - delta and S - delta (verdict, rule, reason and record IDs of R1-R7), for both
    knowledge rules. Hand-computed cases on FAST (F = N = 30 s, S = 300 s): B(rec-d) at kappa = 27.5 with delta = 10
    is ALLOW (R2: the newest generation start is rs-rec-2's ceiling 3.0, so x - 3.0 = 34.5 >= 30, and kappa - 3.0 =
    24.5 >= 20); at kappa = 21 with delta = 10 it is NEEDS_APPROVAL by R2 (28 < 30; 18 < 20); at kappa = 21 with
    delta = 30 it is ABSTAIN because rec-d's STATE, confirmed by the 20.0 s list, is stale at 51 (and with F - delta
    = 0 at 21); A at kappa = 26 with delta = 10 is ALLOW (36 - 2.2 = 33.8 >= 30; 26 - 2.2 = 23.8 >= 20)."""
    capture, ctx = fast["capture"], _store_inputs(fast["capture"], fast["inputs"])
    uid = lambda key: fast["world"].params[key][1]["uid"]
    actions = {"A": capture.action_a(), "B(rec-a)": capture.action_b(uid("rec-a")),
               "B(rec-d)": capture.action_b(uid("rec-d"))}
    stores = {}
    for knowledge, derive in ((C.TWO_CLOCK, GM.a1_facts), (C.LATEST, GM.latest_facts)):
        facts, support = derive(ctx.model.observations, ctx.model.withdrawals)
        everything = tuple(facts) + tuple(ctx.model.identity_facts)
        assert all(f.valid_from is None or f.valid_from <= f.available_at for f in everything)  # no future-dated fact
        stores[knowledge] = (build_forward_store((facts, support), ctx.model.identity_facts, label=knowledge),
                             GM.PilotStore(everything, support, label="pilot-" + knowledge))
    literal = {("B(rec-d)", 27.5, 10): ("ALLOW", []), ("B(rec-d)", 21.0, 10): ("NEEDS_APPROVAL", ["R2"]),
               ("B(rec-d)", 21.0, 30): ("ABSTAIN", ["R1", "R2", "R3", "R7"]), ("A", 26.0, 10): ("ALLOW", [])}
    compared = 0
    for knowledge, (forward_store, frozen_store) in stores.items():
        for name, act in actions.items():
            for kappa in (3.0, 4.0, 6.5, 21.0, 27.5, 41.0):
                for delta in (0, 10, 25, 30):
                    forward = _forward_decide(forward_store, act, capture, knowledge, T(kappa), delta)
                    frozen = _frozen_decide(frozen_store, act, capture, T(kappa), 30.0 - delta, 30.0 - delta,
                                            300.0 - delta)
                    assert forward == frozen, (knowledge, name, kappa, delta)
                    compared += 1
                    if (name, kappa, delta) in literal:
                        verdict, deciding = literal[(name, kappa, delta)]
                        assert forward[0] == verdict
                        assert [r for r, v, _, _ in forward[1] if v == verdict and v != "ALLOW"] == deciding
    assert compared == 2 * 3 * 6 * 4
    assert _forward_decide(stores[C.TWO_CLOCK][0], actions["B(rec-d)"], capture, C.TWO_CLOCK, T(21.0), 30)[1][0][2] \
        == "state_stale_confirmation"


# ---------------------------------------------------------------------------------------------------------------
# The conditions on FAST
# ---------------------------------------------------------------------------------------------------------------
B_EXPECTED = {
    # (k, delta): T_p (= L_p) disposition, T_p dispatch, L-kappa disposition, L-kappa dispatch
    (1, 0): ("DENY", None, "DENY", None), (1, 10): ("DENY", None, "DENY", None),
    (1, 30): ("CENSORED", None, "DENY", None),
    (2, 0): ("NEEDS_APPROVAL", None, "NEEDS_APPROVAL", None), (2, 10): ("NEEDS_APPROVAL", None, "NEEDS_APPROVAL", None),
    (2, 30): ("CENSORED", None, "NEEDS_APPROVAL", None),
    (3, 0): ("NEEDS_APPROVAL", None, "NEEDS_APPROVAL", None), (3, 10): ("ALLOW", 37.5, "NEEDS_APPROVAL", None),
    (3, 30): ("CENSORED", None, "NEEDS_APPROVAL", None),
    (4, 0): ("ALLOW", 41.0, "ALLOW", 41.0), (4, 10): ("ALLOW", 51.0, "ALLOW", 51.0),
    (4, 30): ("CENSORED", None, "ALLOW", 71.0),
}


def _outcome(row):
    return (row.get("first_verdict"), row["disposition"])


def test_two_clock_equals_latest_h_g1(fast):
    """H-G1: (T_p) and (L_p) read the same records with the same F, schedule and expiry; on FAST (no recorded
    validity end of a newest record, no conflict, no K1 clock-band case) every first verdict, deciding rule,
    disposition and dispatch instant is identical, in all 24 request rows."""
    rows = fast["rows"]
    keys = [(a, k, d) for a in ("A", "B") for k in (1, 2, 3, 4) for d in (0, 10, 30)]
    for a, k, d in keys:
        t, l = rows[("T_p", a, k, d)], rows[("L_p", a, k, d)]
        for field in ("first_verdict", "first_deciding", "disposition", "disposition_source", "dispatch_us",
                      "disposition_cutoff_us", "waiting_s"):
            assert t.get(field) == l.get(field), (a, k, d, field)
    assert len(keys) == 24


def test_two_clock_vs_l_kappa_differ_exactly_where_a_bound_ends_in_kappa_x(fast):
    """H-G2: (T) evaluates freshness and R2's window at x = kappa + delta, (L-kappa) at kappa. Hand-computed B rows on
    FAST (B_EXPECTED; timeline in the module docstring): R2's window for rec-d ends at 3.0 + 30 = 33.0 (rs-rec-2's
    creation ceiling), every fact (T) relies on was confirmed by the latest list before kappa (c + 30 < kappa + 30 =
    x for delta = 30, so (T) abstains until H and is CENSORED), rec-a is absent from the 6.0 s list (available 6.0025
    s) and the rollout is reported complete by the 6.8 s Deployment row. The two conditions differ in exactly the
    rows where a relied-on record's freshness or R2's window ends in (kappa, x]."""
    rows, H = fast["rows"], fast["capture"].H
    assert s(H) == 60.060001
    for (k, d), (t_disp, t_at, l_disp, l_at) in B_EXPECTED.items():
        t, lk = rows[("T_p", "B", k, d)], rows[("L-kappa", "B", k, d)]
        assert (t["disposition"], s(t.get("dispatch_us")), lk["disposition"], s(lk.get("dispatch_us"))) == \
            (t_disp, t_at, l_disp, l_at), (k, d)
    k1 = rows[("T_p", "B", 1, 0)]
    assert k1["first_deciding"] == ["R7:rollout_in_progress:old_replicas_pending_termination"]
    assert k1["disposition_source"] == ["R1:target_gone"] and s(k1["disposition_cutoff_us"]) == 6.0025
    assert rows[("T_p", "B", 2, 30)]["waiting_s"] == 39.060001 and rows[("T_p", "B", 4, 30)]["waiting_s"] == 19.060001
    assert rows[("T_p", "B", 3, 10)]["first_r2_window_end_us"] == T(33.0)
    assert rows[("T_p", "A", 3, 10)]["first_r2_window_end_us"] == T(32.2)    # the patch response R + N
    differing = []
    for a in ("A", "B"):
        for k in (1, 2, 3, 4):
            for d in (0, 10, 30):
                t, lk = rows[("T_p", a, k, d)], rows[("L-kappa", a, k, d)]
                kappa, x = t["kappa_us"], t["x_us"]
                ends = [e for r in (t, lk) for e in (r.get("first_freshness_ends_us") or [])] + \
                    [r["first_r2_window_end_us"] for r in (t, lk) if r.get("first_r2_window_end_us") is not None]
                differs = _outcome(t) != _outcome(lk)
                assert differs == any(kappa < e <= x for e in ends), (a, k, d)
                if differs:
                    differing.append((a, k, d))
    assert differing == [("A", 1, 30), ("A", 2, 30), ("A", 3, 10), ("A", 3, 30), ("A", 4, 30),
                         ("B", 1, 30), ("B", 2, 30), ("B", 3, 10), ("B", 3, 30), ("B", 4, 30)]


def test_recheck_uses_first_response_at_or_after_x_and_executes_at_x_r(fast):
    """(R): the first answered response whose request started at or after x; an ALLOW executes at its receipt x_R =
    start + 60 ms; R2 starts at the current ReplicaSet's creationTimestamp + 1 s = 3.0 s. k3 has kappa_B = 27.5
    (a_3 = 27.5): delta = 10 gives x = 37.5, the 38 s tick, age 38.06 - 3.0 = 35.06 >= 30, ALLOW at 38.06; delta =
    0 the 28 s tick, NEEDS_APPROVAL (25.06 < 30). k2 delta = 30: x = 51.0 equals a tick start, so that tick (x_R
    51.06) is used. k4 delta = 30: x = 71 > H, CENSORED without a response. k1 (rec-a, deleted at 5.0): the 4 s
    tick shows the rollout in progress (R7 ABSTAIN); every later response lacks rec-a, so R1-R3 abstain (target not
    found; one response carries no absence) until H: CENSORED, never DENY."""
    rows = fast["rows"]
    r = rows[("R", "B", 3, 10)]
    assert (r["stream"], s(r["x_us"]), r["evaluations"]["ticks"], r["first_response_request_started_us"]) == \
        ("*", 37.5, [38], T(38.0))
    assert (r["disposition"], s(r["dispatch_us"]), r["waiting_s"]) == ("ALLOW", 38.06, 0.56)
    assert (rows[("R", "B", 3, 0)]["disposition"], s(rows[("R", "B", 3, 0)]["disposition_cutoff_us"])) == \
        ("NEEDS_APPROVAL", 28.06)
    r = rows[("R", "B", 2, 30)]
    assert (r["evaluations"]["ticks"], s(r["dispatch_us"])) == ([51], 51.06)
    r = rows[("R", "B", 4, 30)]
    assert (r["disposition"], r["posed_after_horizon"], r["evaluations"]["count"]) == ("CENSORED", True, 0)
    r = rows[("R", "B", 1, 0)]
    assert r["first_deciding"] == ["R7:rollout_in_progress:old_replicas_pending_termination"]
    assert (r["disposition"], r["waiting_s"], r["evaluations"]["count"]) == ("CENSORED", 56.060001, 57)
    assert rows[("R", "B", 1, 10)]["first_deciding"] == ["R1:target_not_found", "R2:target_not_found",
                                                         "R3:target_not_found"]
    assert [(k, d, rows[("R", "B", k, d)]["disposition"], s(rows[("R", "B", k, d)].get("dispatch_us")))
            for k in (2, 4) for d in (0, 10)] == [(2, 0, "NEEDS_APPROVAL", None), (2, 10, "NEEDS_APPROVAL", None),
                                                 (4, 0, "ALLOW", 41.06), (4, 10, "ALLOW", 51.06)]
    starts = [row for _, row in iter_gzip_records(fast["index"].path_of("recheck"), ("r2_start",))]
    deployment = fast["capture"].binding.deployment_uid
    at_38 = [row for row in starts if row["tick"] == 38 and row["subject"] == f"Deployment/{deployment}"]
    assert [(row["start"], row["clamped_to_x_R"]) for row in at_38] == [("2026-10-19T12:00:03.000000Z", False)]


def test_recheck_r2_start_is_clamped_to_x_r_and_recorded():
    """(R)'s R2 start = the current ReplicaSet's creationTimestamp + 1 s, clamped to x_R: a ReplicaSet created at
    100 s (stamp 12:01:40) read in a response received at 100.56 s starts at 100.56, not 101.0; recorded."""
    dep_uid, rs_uid = "dep-uid-0001", "rs-uid-0001"
    deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {
        "name": REC, "uid": dep_uid, "generation": 2, "creationTimestamp": "2026-10-19T11:50:00Z",
        "annotations": {"deployment.kubernetes.io/revision": "2"}}, "status": {"observedGeneration": 2}}
    rs = {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {
        "name": REC + "-new", "uid": rs_uid, "generation": 1, "creationTimestamp": "2026-10-19T12:01:40Z",
        "annotations": {"deployment.kubernetes.io/revision": "2"},
        "ownerReferences": [{"kind": "Deployment", "uid": dep_uid, "controller": True}]}}
    payload = {"response_received_at": FX.iso9(T(100.56)), "objects": [deployment, rs], "tick": 7,
               "collection_id": "c"}
    clamps = mapping2.ClampLog()
    model, starts = mapping2.recheck_model(mapping2.tick_records(payload, "recheck:c/7"), clamps)
    by_subject = {row["subject"]: row for row in starts}
    for subject in (f"Deployment/{dep_uid}", f"ReplicaSet/{rs_uid}"):
        assert (by_subject[subject]["ceiling"], by_subject[subject]["start"], by_subject[subject]["clamped_to_x_R"]) \
            == ("2026-10-19T12:01:41.000000Z", "2026-10-19T12:01:40.560000Z", True)
    generation = [o for o in model.observations if o.predicate == PG.GENERATION]
    assert sorted(s(us_of(o.starts_at)) for o in generation) == [100.56, 100.56]
    # gate v1's own creation ceiling of the new ReplicaSet (STATE and GENERATION) is clamped and recorded as well
    assert [(r["subject"], r["predicate"], r["observed_at"], r["shift_us"]) for r in clamps.rows()] == [
        (f"ReplicaSet/{rs_uid}", "GENERATION", "2026-10-19T12:01:40.560000Z", 440_000),
        (f"ReplicaSet/{rs_uid}", "STATE", "2026-10-19T12:01:40.560000Z", 440_000)]


def test_kappa_b_rule(fast):
    """A is posed at kappa = t_k + Delta when kappa >= P; B at kappa_B = max(t_k + Delta, a_k) with a_k the
    acquisition of request k's server span of the changed service. k3: t = 26.0, a = 27.5."""
    capture = fast["capture"]
    t3 = T(26.0)
    assert [(posed, s(kappa)) for posed, kappa, _, _ in
            (engine2.pose(capture, "B", 3, t3, delta) for delta in (0, 5, 30))] == [(True, 27.5), (True, 31.0),
                                                                                  (True, 56.0)]
    assert engine2.pose(capture, "A", 3, t3, 0)[:2] == (True, T(26.0))
    posed, kappa, _, reason = engine2.pose(capture, "A", 3, T(1.0), 0)
    assert (posed, s(kappa), reason) == (False, 1.0, "before the patch request P")
    assert fast["rows"][("T_p", "B", 3, 0)]["kappa_us"] == T(27.5)
    assert fast["rows"][("T_p", "A", 3, 0)]["kappa_us"] == T(26.0)
    no_span = dataclasses.replace(capture, b_targets={3: {"why": "no server span of recommendationservice"}})
    assert engine2.pose(no_span, "B", 3, t3, 0)[0] is False


# ---------------------------------------------------------------------------------------------------------------
# Labels, after the seal and never from R1-R7
# ---------------------------------------------------------------------------------------------------------------
def test_labels_action_a_rollout_interval(kill):
    """Section 7.1 on KILL: P = 2.0, R = 2.2; the physical rollout ends at max(old-revision request end 3.015, the
    first instant with 3 new Pods Ready = 4.0) = 4.0; b_c = 1.25 s; the F1 worker fault on rec-f (a new-revision
    Pod) is active [70, 90) with its effect established."""
    lab = kill["labeller"]
    assert (s(lab.rollout["end_us"]), lab.rollout["end_basis"], lab.band_us) == (4.0, "last new Pod Ready stamp",
                                                                                  1_250_000)
    cases = [((1.0, None), ("GT-0", "before_patch_request")), ((2.1, None), ("U", "U_pre")),
             ((2.5, None), ("V1", "inside_physical_rollout_interval")),
             ((3.5, None), ("U", "rollout_end_within_band")),
             ((20.0, None), ("V2 (GT-3)", "outside the fault window")),
             ((80.0, None), ("GT-2-A", "constructed mitigation opportunity")),
             ((95.0, 85.0), ("LATE_ALLOW", "executed at or after active_end; posed before it")),
             ((95.0, 92.0), ("V2 (GT-3)", "outside the fault window"))]
    for (x, kappa), expected in cases:
        assert lab.label_a(T(x), None if kappa is None else T(kappa)) == expected, x


def test_labels_action_b_kill_floor_neutral_band_and_endpointslices(kill):
    """Section 7.2 on KILL (floor 2 for recommendationservice): rec-e's kubelet history is not_ready 2.0, ready 4.0,
    not_ready 30.0 (kill), not_ready 31.0 (restart), ready 45.0; the EndpointSlice is stale from 45.0 to 60.0."""
    lab, uid = kill["labeller"], kill["uid"]
    transitions = [(s(stamp), state) for stamp, state in lab.pods[uid("rec-e")].transitions]
    assert transitions == [(2.0, "not_ready"), (4.0, "ready"), (30.0, "not_ready"), (31.0, "not_ready"),
                           (45.0, "ready")]
    cases = [
        (("rec-d", 20.0), ("neutral", "healthy replica restarted with the floor kept")),
        (("rec-e", 38.0), ("V-target", "not_ready")),                      # the killed target, 7 s from both stamps
        (("rec-d", 38.0), ("V-floor", "below_floor")),                     # others Ready: rec-f only, 1 < 2
        (("rec-e", 30.5), ("U", "target_ready_transition_within_band")),   # 0.5 s after the 30.0 stamp
        (("rec-d", 44.5), ("U", "floor_count_within_band")),               # rec-e's 45.0 stamp within the band
        (("rec-d", 50.0), ("U", "endpointslice_disagreement")),            # kubelet: rec-e Ready; slice: not
        (("rec-f", 80.0), ("GT-2-B", "worker Pod restarted while the worker was active")),
        (("rec-f", 95.0), ("neutral", "healthy replica restarted with the floor kept")),
        (("rec-a", 4.5), ("U", "target_deletion_request_within_band")),   # deletionTimestamp 24 - grace 20 = 4.0
        (("rec-a", 6.0), ("V-target", "gone")),                            # DELETED event at 5.02
        (("rec-d", 200.0), ("U", "beyond_label_evidence")),
    ]
    for (key, x), expected in cases:
        assert lab.label_b(T(x), uid(key))[:2] == expected, (key, x)
    floor = lab.label_b(T(38.0), uid("rec-d"))[2]["floor"]
    assert floor == {"floor": 2, "ready_others_certain": 1, "ready_others_possible": 1}
    assert lab.label_b(T(50.0), uid("rec-d"))[2]["cross_check"][uid("rec-e")] == "disagree_beyond_band"
    assert lab.opportunity_at("B", T(80.0), uid("rec-f")) and not lab.opportunity_at("B", T(80.0), uid("rec-d"))
    assert lab.opportunity_at("A", T(80.0), None) and lab.in_window(T(80.0)) and not lab.in_window(T(90.0))


# ---------------------------------------------------------------------------------------------------------------
# Record timing: contested decisions and check 2's sample
# ---------------------------------------------------------------------------------------------------------------
def test_contested_decision_counts(fast):
    """FAST's primary B cells (S0; H-G2: delta in {10, 30}, 8 posed; H-G3: delta in {0, 10, 30}, 12 posed).
    H-G2: contested when a transition stamp, a relied-on freshness end or R2's window end lies in (kappa, x]: k1 at
    delta 10 (the Deployment's Progressing update stamped 5.0 in (4, 14]), every delta = 30 row (freshness ends c +
    30 in (kappa, kappa + 30]) and k3 at delta 10 (R2 ends 33.0 in (27.5, 37.5]); not k2 or k4 at delta 10: 6 of 8.
    H-G3: some transition stamped by x first reflected in the poller store after kappa: only k1 (kappa 4.0; rec-d's
    creation, stamp 2.0, first listed by the 4.0 s list, row available 4.003): 3 of 12. The comparisons with (T_w)
    are not computed (no watch in FAST)."""
    counts = fast["contested"].counts
    assert {k: (v["contested"], v["posed"]) for k, v in counts.items() if not v.get("not_computed")} == \
        {"H-G2": (6, 8), "H-G3": (3, 12)}
    assert sorted(k for k, v in counts.items() if v.get("not_computed")) == \
        ["H-G3 (T_w, R) secondary", "H-G4", "action A secondary (H-G4)"]
    flags = fast["contested"].flags
    assert [flags[("S0", "B", k, 0, 10)]["H-G2"] for k in (1, 2, 3, 4)] == [True, False, True, False]
    created = [t for t in fast["timing"].items if t["kind"] == "pod_created" and s(t["stamp_us"]) == 2.0]
    assert sorted(s(t["avail"]["poller"]) for t in created) == [4.003, 4.0035, 4.004]
    unseen = [t for t in fast["timing"].items if t["kind"] == "pod_lastTransitionTime" and s(t["stamp_us"]) == 2.0]
    assert [t["recorded_by"] for t in unseen] == [["recheck"]] * 3                 # only a recheck saw them not Ready
    assert sorted(s(t["avail"]["poller"]) for t in unseen) == [4.003, 4.0035, 4.004]   # reflected by the next list


def test_check2_sample_is_contested_plus_ten_percent_with_random_0(fast):
    """Section 9.5: all evaluations of contested decisions plus Random(0).sample(sorted(rest), ceil(0.1 n)); with no
    contested decision the sample is exactly Random(0).sample(sorted(all), ceil(0.1 n))."""
    index, capture = fast["index"], fast["capture"]
    population = sorted({e["eval_id"] for o in capture.observers
                         for _, e in iter_gzip_records(index.path_of(o), ("evaluation",))})
    none_contested, info = checks2.select_check2(index, capture, design.Contested(capture.plan.arm))
    k = math.ceil(0.1 * len(population))
    assert (info["contested_evaluations"], info["rest"], info["sampled_from_rest"]) == (0, len(population), k)
    assert none_contested == set(random.Random(0).sample(population, k))
    chosen, info = checks2.select_check2(index, capture, fast["contested"])
    assert chosen == checks2.select_check2(index, capture, fast["contested"])[0]
    assert info["contested_evaluations"] > 0 and info["sampled_from_rest"] == math.ceil(0.1 * info["rest"])
    assert len(chosen) == info["contested_evaluations"] + info["sampled_from_rest"]
    row = fast["rows"][("T_p", "B", 3, 10)]                        # contested for H-G2 (and its only evaluation)
    assert row["first_eval"] in chosen


# ---------------------------------------------------------------------------------------------------------------
# The creation-ceiling clamp, the guard, the decision-log index
# ---------------------------------------------------------------------------------------------------------------
def _sighting(observed: float) -> dict:
    created = T(100.0)
    meta = {"uid": "rs-uid-1", "name": "rs-new", "generation": 1, "creationTimestamp": "2026-10-19T12:01:40Z",
            "ownerReferences": [{"kind": "Deployment", "uid": "dep-uid-1", "controller": True}]}
    return {"record_id": "fx/rs/1", "collection_id": "c", "snapshot_id": "s1", "resource": "replicasets",
            "kind": "ReplicaSet", "uid": "rs-uid-1", "name": "rs-new", "subject": "ReplicaSet/rs-uid-1",
            "created_at": dt(created), "observed_at": dt(T(observed)), "available_at": dt(T(observed + 0.01)),
            "index_available_at": dt(T(observed + 0.01)), "clock_adjusted": False, "source_sha256": None,
            "resource_data": {"kind": "ReplicaSet", "metadata": meta}}


def test_creation_ceiling_clamp_is_recorded():
    """Gate v1 gives a ReplicaSet created at 100 s (stamp 12:01:40) the ceiling 101.0 s; a sighting at 100.4 s makes
    the mapping raise. The clamped mapping (the same code object, one global rebound) starts STATE and GENERATION
    at 100.4 s and records both clamps (shift 0.6 s); a sighting at 101.2 s is not clamped."""
    with pytest.raises(ValueError, match="starts_at cannot be later than observed_at"):
        GM.pga().build_observations([_sighting(100.4)], None, {}, include_receipts=False)
    clamps = mapping2.ClampLog()
    observations, _, _ = mapping2.clamped_build_observations([_sighting(100.4)], clamps)
    starts = {(o.predicate, s(us_of(o.starts_at))) for o in observations if o.starts_at is not None}
    assert starts == {("STATE", 100.4), ("GENERATION", 100.4)}
    assert [(r["predicate"], r["ceiling"], r["observed_at"], r["shift_us"]) for r in clamps.rows()] == [
        ("GENERATION", "2026-10-19T12:01:41.000000Z", "2026-10-19T12:01:40.400000Z", 600_000),
        ("STATE", "2026-10-19T12:01:41.000000Z", "2026-10-19T12:01:40.400000Z", 600_000)]
    later = mapping2.ClampLog()
    mapping2.clamped_build_observations([_sighting(101.2)], later)
    assert later.rows() == []
    assert GM.pga().build_observations.__globals__["Observation"] is PG.Observation      # the module is untouched


def test_creation_ceiling_clamps_in_the_tiny_capture(e2e):
    """TINY: rs-rec-2 is created at 10.15 s (stamp 10, ceiling 11.0). The poller's 10.4 s ReplicaSet list sees it
    (STATE + GENERATION: 2 clamps); the watch's snapshots at 10.170002 (after its creation event), 10.220002 (after
    rec-d's creation event) and 10.3 (periodic) do (6 clamps); every recheck response after its creation is received
    at 11.06 s or later (0)."""
    results = e2e["results"]
    assert results["creation_ceiling_clamps"] == {"poller": 2, "recheck": 0, "watch": 6}
    index = LogIndex.load(e2e["out"] / P.INDEX_FILE)
    rows = [row for _, row in index.iter_records("watch", ("clamp",))]
    assert sorted((r["observed_at"], r["shift_us"]) for r in rows if r["predicate"] == "GENERATION") == [
        ("2026-10-19T12:00:10.170002Z", 829_998), ("2026-10-19T12:00:10.220002Z", 779_998),
        ("2026-10-19T12:00:10.300000Z", 700_000)]
    assert {r["ceiling"] for r in rows} == {"2026-10-19T12:00:11.000000Z"}


def test_decision_guard_blocks_evaluation_files(fast):
    converted = fast["converted"]
    raw = converted.parent
    with decision_guard(converted, raw):
        with pytest.raises(SeparationError):
            open(raw / "ground_truth" / "ground_truth.json", "rb").close()
        with pytest.raises(SeparationError):
            open(converted / "evaluation_only" / "stage2" / "host_command.jsonl", "rb").close()
        with pytest.raises(SeparationError):
            open(converted / "stage2" / "api_watch_event.jsonl", "rb").close()
        open(converted / "accepted_evidence.jsonl", "rb").close()
    open(raw / "ground_truth" / "ground_truth.json", "rb").close()


def test_sealed_index_refuses_a_modified_log(e2e, tmp_path):
    """Section 7: labels are computed only after the decision logs are written; the evaluator reads rows only through
    the sealed index, which re-checks every log's SHA-256 first."""
    copy = tmp_path / "out"
    shutil.copytree(e2e["out"], copy)
    index = LogIndex.load(copy / P.INDEX_FILE)
    assert sum(1 for _ in index.iter_records("poller")) == index.entries["poller"]["requests"]
    path = index.path_of("poller")
    lines = gzip.decompress(path.read_bytes()).split(b"\n")
    target = next(i for i, line in enumerate(lines) if line.startswith(b'{"request":') and b'"ALLOW"' in line)
    lines[target] = lines[target].replace(b'"ALLOW"', b'"DENY"', 1)
    path.write_bytes(gzip.compress(b"\n".join(lines), mtime=0))
    with pytest.raises(SealedLogError):
        list(index.iter_records("poller"))
    unsealed = LogIndex(copy / P.LOGS_DIR, meta={}, entries=dict(index.entries))
    with pytest.raises(UnsealedLogError):
        list(unsealed.iter_records("watch"))
    with pytest.raises(UnsealedLogError):
        unsealed.write(tmp_path / "index.json")


# ---------------------------------------------------------------------------------------------------------------
# End to end: reconstruction checks, marks, the committed expectation
# ---------------------------------------------------------------------------------------------------------------
def test_q1_checks_on_the_k1_fixture(e2e):
    """Section 9.5: check 1 (append-only corrections) has n > 0 on a capture with K1 records (Stage 1 had n = 0)
    and every check holds: 1, 2 (truncated and fresh full stream), 3 (exact provenance), 4 (graph = SQLite)."""
    results = e2e["results"]
    q1 = results["T3_q1_checks"]
    c1 = q1["totals"]["check_1_append_only_corrections"]
    assert c1["n"] > 0 and c1["x"] == c1["n"]
    c2 = q1["check_2_earlier_cutoff_invariance"]
    assert sum(r["n"] for r in c2) > 0
    assert all(r["x_truncated"] == r["n"] == r["x_full_stream"] and not r["failures"] for r in c2)
    for unit in results["decision_phase"]["units"]:
        assert unit["provenance"]["x"] == unit["provenance"]["n"] > 0
        assert unit["engines"]["disagreements"] == 0 and unit["engines"]["n"] > 0
    sample = q1["check_2_sample"]
    assert sample["sampled_from_rest"] == math.ceil(0.1 * sample["rest"])
    assert results["k1"]["poller"]["observations"] > 0 and results["k1"]["watch"]["observations"] > 0


def test_outputs_match_the_committed_expectation(e2e):
    results = e2e["results"]
    assert (e2e["out"] / P.SUMMARY_FILE).is_file()
    for name in ("FX-G2-001.poller.jsonl.gz", "FX-G2-001.watch.jsonl.gz", "FX-G2-001.recheck.jsonl.gz"):
        assert (e2e["out"] / P.LOGS_DIR / name).is_file()
    expected = json.loads(EXPECTATION_FILE.read_text(encoding="utf-8"))
    assert P.diff_docs(expected, P.expectation_view(results)) == []


def _cli(*args, env_extra=None):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", **(env_extra or {}))
    return subprocess.run([sys.executable, str(CLI), *map(str, args)], capture_output=True, text=True, env=env,
                          cwd=str(ROOT))


def test_two_interpreter_determinism_via_rerun_check(e2e, tmp_path):
    """The rerun check: the same capture and arguments in two interpreters (different PYTHONHASHSEED) give
    byte-identical outputs (results.json, SUMMARY.md, the decision-log index and every gzipped decision log)."""
    out = tmp_path / "run"
    done = _cli("--capture", e2e["converted"], "--plan", e2e["plan"], "--out", out,
                "--conditions", "T_p,L-kappa,R,T_w", "--rerun-check", "--quiet", env_extra={"PYTHONHASHSEED": "0"})
    assert done.returncode == 0, done.stdout + done.stderr
    report = json.loads(done.stdout[done.stdout.index("{"):])["rerun_check_deterministic_replay"]
    assert report["identical"] is True and report["files"] == 6
    results = json.loads((out / P.RESULTS_FILE).read_text(encoding="utf-8"))
    assert results["capture"]["conditions"] == ["T_p", "R", "T_w", "L-kappa"]


def test_cli_refusals(e2e, fast, tmp_path):
    done = _cli("--capture", e2e["converted"], "--plan", e2e["plan"], "--out", e2e["out"])
    assert done.returncode == 2 and "exists" in done.stderr
    # an excluded capture (validity fields) is refused, and analysed only with --allow-excluded, marked
    world, obs, plan = fast_world()
    plan = dataclasses.replace(plan, valid=False)
    converted = FX.write_capture(tmp_path / "FX-BAD", world, obs, plan, capture_id="FX-BAD")
    plan_path = tmp_path / "plan.json"
    doc = fast_plan()
    doc["posing"]["dispatch_delays_seconds"]["G"] = [0]
    plan_path.write_text(json.dumps(doc), encoding="utf-8")
    done = _cli("--capture", converted, "--plan", plan_path, "--out", tmp_path / "c", "--conditions", "T_p")
    assert done.returncode == 2 and "excluded by its validity fields" in done.stderr
    assert not (tmp_path / "c").exists()
    done = _cli("--capture", converted, "--plan", plan_path, "--out", tmp_path / "e", "--conditions", "T_p",
                "--allow-excluded", "--quiet")
    assert done.returncode == 0, done.stderr
    results = json.loads((tmp_path / "e" / P.RESULTS_FILE).read_text(encoding="utf-8"))
    assert results["excluded_mark"].startswith("EXCLUDED") and "EXCLUDED" in \
        (tmp_path / "e" / P.SUMMARY_FILE).read_text(encoding="utf-8")


def test_arm_d_primary_cells(tmp_path):
    """Arm D (no recheck, action A, delta = 0) through the same adapter: --cells primary keeps (T_p, T_w), streams
    S30 and Snever, action A; H is the earlier of the poller's and the watch's last availabilities."""
    world, obs, plan = FX.tiny_g2()
    plan = dataclasses.replace(plan, scenario="D1")
    obs = dataclasses.replace(obs, recheck_ticks=())
    converted = FX.write_capture(tmp_path / "FX-D1", world, obs, plan, capture_id="FX-D1")
    out = tmp_path / "out"
    done = _cli("--capture", converted, "--plan", ROOT / "phase3/stage2_plan.json", "--out", out,
                "--cells", "primary", "--quiet")
    assert done.returncode == 0, done.stdout + done.stderr
    results = json.loads((out / P.RESULTS_FILE).read_text(encoding="utf-8"))
    cap = results["capture"]
    assert (cap["conditions"], cap["streams"], cap["actions"], cap["delta_s"]) == (["T_p", "T_w"], ["S30", "Snever"],
                                                                                    ["A"], [0])
    assert sorted(cap["H_by_observer"]) == ["poller", "watch"] and cap["H"] == min(cap["H_by_observer"].values())
    assert list(results["design_check"]["per_comparison"]) == ["H-G4"]
    assert sorted(p.name for p in (out / P.LOGS_DIR).iterdir()) == ["FX-D1.poller.jsonl.gz", "FX-D1.watch.jsonl.gz"]


def test_cli_check_reproduces_the_expectation():
    done = _cli("--check", "--quiet")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "reproduces" in done.stdout
