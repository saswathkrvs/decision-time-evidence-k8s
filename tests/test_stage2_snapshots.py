"""Tests of the snapshot-history analysis (experiments/governance-stage2/govstage2/snapshots.py) on the FAST and KILL
worlds of tests/test_stage2_adapter.py (written by ``govstage2.fixtures``; no real capture is read)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_DIR = ROOT / "experiments/governance-stage2"
if str(ADAPTER_DIR) not in sys.path:
    sys.path.insert(0, str(ADAPTER_DIR))

from govstage2 import fixtures as FX, pipeline as P, replays as RV, snapshots as SN, sweeps as SW  # noqa: E402
from govstage2.capture import manifest_grace_seconds, read_decision_inputs, read_label_inputs  # noqa: E402
from govstage2.conditions import CONDITIONS  # noqa: E402
from govstage2.engine2 import run_request  # noqa: E402
from govstage2.labels import Labeller, PodHistory  # noqa: E402

from test_stage2_adapter import fast_plan, fast_world, kill_world  # noqa: E402

S_US = 1_000_000


@pytest.fixture(scope="module")
def fast(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fast_snapshots")
    world, obs, plan = fast_world()
    converted = FX.write_capture(tmp / "FX-FAST", world, obs, plan, capture_id="FX-FAST")
    plan_path = tmp / "plan.json"
    plan_path.write_text(json.dumps(fast_plan()), encoding="utf-8")
    doc = SN.snapshot_pass(converted, plan_path, tmp / "out" / "FX-FAST.json")
    return {"converted": converted, "plan": plan_path, "doc": doc}


@pytest.fixture(scope="module")
def kill(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("kill_snapshots")
    world, obs, plan = kill_world()
    converted = FX.write_capture(tmp / "FX-KILL", world, obs, plan, capture_id="FX-KILL")
    plan_doc = FX.fixture_plan({"arms/G/observers/recheck": None}, knowledge_cutoff_offsets_seconds=[0],
                               dispatch_delays_seconds={"D": [0], "G": [0]})
    inputs = read_decision_inputs(converted)
    capture = P.build_capture(inputs, plan_doc, conditions=["T_p", "T_w"])
    labeller = Labeller.build(capture, inputs, read_label_inputs(converted, converted.parent),
                              manifest_grace_seconds(inputs.configuration))
    doc = SN.state_measures(inputs, capture, labeller, converted)
    return {"world": world, "inputs": inputs, "labeller": labeller, "doc": doc,
            "uid": lambda key: world.params[key][1]["uid"]}


def test_phase_zero_is_the_published_thinning(fast):
    inputs = read_decision_inputs(fast["converted"])
    for k in (2, 4):
        api, rows = SN.thinned_phase(inputs, k, 0)
        api_ref, rows_ref = RV.thinned(inputs, k)
        assert [r.id for r in api] == [r.id for r in api_ref]
        assert [r["record_id"] for r in rows] == [r["record_id"] for r in rows_ref]


def test_the_phases_of_an_interval_partition_the_polls(fast):
    inputs = read_decision_inputs(fast["converted"])
    polls = [n for n, _ in SN.poll_lists(inputs)]
    for k in (2, 3, 6):
        kept = [[n for n in polls if SN.kept(n, k, j)] for j in range(k)]
        assert sorted(n for phase in kept for n in phase) == polls
        assert sum(len(phase) for phase in kept) == len(polls)


def test_pod_content_reads_deletion_before_readiness():
    ready = {"metadata": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    assert SN.pod_content(ready) == "ready"
    assert SN.pod_content({"metadata": {}, "status": {"conditions": [{"type": "Ready", "status": "False"}]}}) \
        == "not_ready"
    assert SN.pod_content({"metadata": {}, "status": {}}) == "not_ready"
    assert SN.pod_content(dict(ready, metadata={"deletionTimestamp": "2026-01-01T00:00:00Z"})) == "terminating"


def test_episodes_split_a_pod_timeline_and_keep_those_beginning_in_the_window():
    lab = Labeller()
    p = PodHistory("u1", "pod-1", "svc", "h", created_us=10 * S_US)
    p.transitions = [(10 * S_US, "not_ready"), (15 * S_US, "ready"), (40 * S_US, "not_ready"),
                     (47 * S_US, "ready"), (80 * S_US, "not_ready")]
    p.deletion_request_us = 70 * S_US
    p.gone_after_us = 95 * S_US
    lab.pods["u1"] = p
    got = SN.episodes(lab, ["u1"], 0, 200 * S_US)
    assert got == [("u1", "starting", 10 * S_US, 15 * S_US), ("u1", "ready", 15 * S_US, 40 * S_US),
                   ("u1", "not_ready", 40 * S_US, 47 * S_US), ("u1", "ready", 47 * S_US, 70 * S_US),
                   ("u1", "terminating", 70 * S_US, 95 * S_US)]
    assert [e[1] for e in SN.episodes(lab, ["u1"], 20 * S_US, 60 * S_US)] == ["not_ready", "ready"]


def test_the_captured_interval_reproduces_the_gate(fast):
    """At k = 1 the two-clock history is the gate's own store and the one-clock history its receipt-time replay."""
    doc = fast["doc"]
    inputs = read_decision_inputs(fast["converted"])
    capture = P.build_capture(inputs, json.loads(Path(fast["plan"]).read_text()), conditions=list(RV.BASE))
    Tp = CONDITIONS["T_p"]
    ctx, index = RV.poller_context(capture, inputs)
    gate = [run_request(Tp, ctx, capture, RV.ACTION, k, t, dc, d, None, k1_index=index)
            for dc, d, k, t in RV.requests_of(capture)]
    ctx.close()
    sctx = SW.to_receipt_time(RV.poller_context(capture, inputs)[0])
    one_clock = [run_request(Tp, sctx, capture, RV.ACTION, k, t, dc, d, None) for dc, d, k, t in RV.requests_of(capture)]
    sctx.close()
    assert doc["audit"]["1/0"]["T"]["first_verdict_differs"] == 0
    assert doc["audit"]["1/0"]["T"]["disposition_differs"] == 0
    assert doc["audit"]["1/0"]["S"] == RV.verdict_agreement(gate, one_clock)
    assert doc["decisions"]["1/0"]["T F30"]["posed"] == sum(1 for r in gate if r.get("posed"))
    assert doc["decisions"]["1/0"]["T F30"]["executions"] == sum(1 for r in gate if r.get("posed")
                                                                  and r.get("dispatch_us") is not None
                                                                  and r.get("disposition") == "ALLOW")


def test_counts_are_consistent(fast):
    doc = fast["doc"]
    for history in ("S", "T"):
        for k, by_type in doc["episodes"]["recorded"][history].items():
            for kind, n in by_type.items():
                assert 0 <= n <= doc["episodes"]["by_type"][kind] + 1e-9, (history, k, kind)
    for k in doc["episodes"]["recorded"]["S"]:
        for kind in SN.TYPES:
            assert doc["episodes"]["recorded"]["S"][k][kind] <= doc["episodes"]["recorded"]["T"][k][kind] + 1e-9
    for k, by_kind in doc["object_states"]["recorded"].items():
        for kind, n in by_kind.items():
            assert n <= doc["object_states"]["watch"][kind] + 1e-9
    volume = doc["volume"]["poller"]
    assert volume["intervals"]["1"]["records"] == volume["records"]
    for k, v in volume["intervals"].items():
        assert v["merged_records"] <= v["records"]


def test_a_short_state_between_kept_lists_is_recovered_from_the_records_own_stamps(kill):
    """KILL: rec-e is not ready from 30.0 s (reported 30.4) to 45.0 s; lists every 2 s. Kept every 12th list (24 s
    apart), most phases miss the episode, but the restart count and termination stamp of the next kept list place
    it in every phase; the watch records it."""
    doc = kill["doc"]
    uid = kill["uid"]("rec-e")
    ref = [e for e in doc["episodes"]["reference"] if e["pod"] == uid and e["type"] == "not_ready"]
    assert len(ref) == 1 and ref[0]["seconds"] == 15.0
    n = doc["episodes"]["by_type"]["not_ready"]
    assert doc["episodes"]["recorded"]["S"]["1"]["not_ready"] == n
    assert doc["episodes"]["recorded"]["S"]["12"]["not_ready"] < n
    assert doc["episodes"]["recorded"]["T"]["12"]["not_ready"] == n
    assert doc["episodes"]["recorded"]["W"]["events"]["not_ready"] == n
