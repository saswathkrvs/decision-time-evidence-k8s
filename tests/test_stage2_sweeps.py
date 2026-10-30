"""Tests of the coverage, parameter-sweep and receipt-time-audit replays (experiments/governance-stage2/govstage2/
sweeps.py) on the FAST world of tests/test_stage2_adapter.py (written by ``govstage2.fixtures``; no real capture is
read): a 3-replica rollout that completes at 5.2 s, poller lists every 2 s, recheck ticks every second, four
requests."""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_DIR = ROOT / "experiments/governance-stage2"
if str(ADAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(ADAPTER_DIR))

from govstage2 import conditions as C, fixtures as FX, pipeline as P, replays as RV, sweeps as SW  # noqa: E402
from govstage2.capture import read_decision_inputs  # noqa: E402

from test_stage2_adapter import fast_plan, fast_world  # noqa: E402

KINDS = ("executions", "expired", "censored")


@pytest.fixture(scope="module")
def fast(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fast_sweeps")
    world, obs, plan = fast_world()
    converted = FX.write_capture(tmp / "FX-FAST", world, obs, plan, capture_id="FX-FAST")
    plan_path = tmp / "plan.json"
    plan_path.write_text(json.dumps(fast_plan()), encoding="utf-8")
    doc = SW.sweep_pass(converted, plan_path, tmp / "out" / "FX-FAST.json")
    return {"converted": converted, "plan": plan_path, "doc": doc}


def test_default_window_keeps_the_published_evaluation_identity():
    tp = C.CONDITIONS["T_p"]
    assert tp.N == C.N_SECONDS and tp.eval_view == "two_clock@F30"
    assert dataclasses.replace(tp, N=0.0).eval_view == "two_clock@F30@N0"
    assert dataclasses.replace(tp, F=600.0).eval_view == "two_clock@F600"


def test_settings_vary_one_parameter_at_a_time():
    names = [name for name, _, _ in SW.settings()]
    assert len(names) == len(set(names)) == len(SW.SWEEP_F) + len(SW.SWEEP_N) - 1
    assert all(F == 30.0 or N == 30.0 for _, F, N in SW.settings())


def test_every_posed_decision_has_one_outcome(fast):
    for view, t in fast["doc"]["coverage"].items():
        declined = sum(t["declined"].values())
        assert t["executions"] + declined + t["expired"] + t["censored"] == t["posed"], view
        assert t["invalid"] + t["valid"] + t["uncertain"] == t["executions"], view
        assert sum(t["invalid_by_target_state"].values()) == t["invalid"], view


def test_sweep_reuses_the_gate_at_its_own_parameters(fast):
    doc = fast["doc"]
    base = doc["sweep"]["B | S0"]["F=30,N=30"]
    tp = doc["coverage"]["T_p"]
    for k in ("posed", "executions", "invalid", "uncertain", "valid", "expired", "censored"):
        assert base[k] == tp[k], k


def test_every_setting_poses_the_same_decisions_and_a_zero_window_never_asks(fast):
    cells = fast["doc"]["sweep"]["B | S0"]
    assert len({c["posed"] for c in cells.values()}) == 1
    assert not any("R2" in key for key in cells["F=30,N=0"]["declined"])
    for c in cells.values():
        assert c["executions"] + sum(c["declined"].values()) + c["expired"] + c["censored"] == c["posed"]


def test_mutually_evaluable_decisions_exclude_censoring(fast):
    m = fast["doc"]["mutually_evaluable"]["T_p vs R"]
    assert m["decisions"] == m["posed"] - m["excluded_censored"]
    for side in ("a", "b"):
        assert sum(m["outcomes"][side].values()) == m["decisions"]
        assert "censored" not in m["outcomes"][side]


def test_receipt_time_model_moves_valid_times_to_availability(fast):
    inputs = read_decision_inputs(fast["converted"])
    capture = P.build_capture(inputs, fast_plan(), conditions=list(RV.BASE))
    ctx, _ = RV.poller_context(capture, inputs)
    model = SW.receipt_time_model(ctx.model)
    assert all(o.observed_at == o.available_at and o.starts_at is None for o in model.observations)
    assert all(f.valid_from is None or f.valid_from == f.available_at for f in model.identity_facts)
    assert len(model.observations) == len(ctx.model.observations)
    ctx.close()


def test_receipt_time_audit_compares_like_with_like(fast):
    audit = fast["doc"]["audit"]
    assert list(audit) == ["0 s", "5 s", "30 s"]
    for latency, a in audit.items():
        assert a["receipt_time_vs_gate"]["posed"] == a["gate"]["posed"] == a["receipt_time_replay"]["posed"]


def test_lagged_view_executes_the_gates_allows_later(fast):
    cov = fast["doc"]["coverage"]
    lag, tp = cov["T_p+lag"], cov["T_p"]
    assert lag["posed"] == tp["posed"] and lag["declined"] == tp["declined"] and lag["expired"] == tp["expired"]
    assert lag["executions"] + (lag["censored"] - tp["censored"]) == tp["executions"]


def test_input_log_does_not_change_a_decision(fast):
    """The decision-log hook (``ObserverContext.input_log``/``trace``) only records; every row is unchanged."""
    inputs = read_decision_inputs(fast["converted"])
    plan_doc = json.loads(Path(fast["plan"]).read_text(encoding="utf-8"))
    capture = P.build_capture(inputs, plan_doc, conditions=list(RV.BASE))
    tp = C.CONDITIONS["T_p"]
    plain, k1 = RV.poller_context(capture, inputs)
    logged, k1b = RV.poller_context(capture, inputs)
    logged.input_log, logged.trace = {}, []
    a = SW._rows(tp, plain, capture, "B", k1_index=k1)
    b = SW._rows(tp, logged, capture, "B", k1_index=k1b)
    assert a == b
    assert logged.input_log and len(logged.trace) >= len(logged.input_log)
    plain.close()
    logged.close()


def test_decision_log_counts_are_consistent(fast, tmp_path):
    doc = SW.decision_log_pass(fast["converted"], fast["plan"], tmp_path / "FX-FAST.json")
    assert doc["posed"] == fast["doc"]["coverage"]["T_p"]["posed"]
    assert set(doc["questions"]) == {name for name, F, N in SW.settings() if (F, N) != (30.0, 30.0)} | {
        "at the recheck's instants"}
    for name, q in doc["questions"].items():
        assert q["posed"] == doc["posed"], name
        assert q["own_log"] <= q["all_logs"] <= q["posed"], name
        assert q["changed_own_log"] <= q["changed_all_logs"] <= q["outcome_changed"] <= q["posed"], name
    assert 0 < doc["log"]["distinct_records"] <= doc["store"]["records"]


def test_check_to_act_at_zero_lag_is_the_recheck_itself(fast, tmp_path):
    doc = SW.check_to_act_pass(fast["converted"], fast["plan"], tmp_path / "FX-FAST.json")
    r = fast["doc"]["coverage"]["R"]
    zero = doc["executions_by_lag"]["0 s"]
    assert (zero["invalid"], zero["uncertain"], zero["valid"]) == (r["invalid"], r["uncertain"], r["valid"])
    for lag, v in doc["executions_by_lag"].items():
        assert sum(v.values()) == r["executions"], lag
