"""Tests of the record-delay sweep of the diagnosis control (experiments/diagnosis-control-v1/run_diagnosis_stress.py)
and of its summary (analysis/stress_summary.py).

The capture is fixture D1-F02 of run_diagnosis_control_v1.FIXTURES (built in code, no real capture is read): poller
lists at odd seconds 81 .. 199 s (Pods at t, ReplicaSets at t + 0.1, Deployments at t + 0.2, every row available
0.25 s after it was observed); the new recommendation Pod NEW is created at 100.4 s and Ready at 112.0 s, the old
Pod OLD terminating from 112.1 s and gone at 114.0 s; the fault on NEW starts at 120.0 s. The 113 s Pod list is the
first to show a Pod of the service leave Ready (OLD terminating) and NEW Ready: the switch poll, 7.0 s before the
onset, with two revealing records.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "experiments" / "diagnosis-control-v1"
sys.dont_write_bytecode = True
for _path in (ROOT / "src", HERE, ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import run_diagnosis_control_v1 as D  # noqa: E402
import run_diagnosis_stress as S  # noqa: E402
from aiops_kg import replay as R  # noqa: E402

from analysis import stress_summary as RS  # noqa: E402

NEW, OLD = "Pod/" + D.FIX_UID["NEW"], "Pod/" + D.FIX_UID["OLD"]
SNAPSHOT_POLICIES = (D.LS, D.TJ, D.BA)


@pytest.fixture(scope="module")
def f02(tmp_path_factory):
    capture = D.build_fixture_capture(tmp_path_factory.mktemp("stress") / "D1-F02", "D1-F02")
    bridge, _ = D.load_bridge_input(capture, D.POLLER)
    grid = D.DELTAS
    result = S.analyse(capture)
    return {"capture": capture, "bridge": bridge, "result": result, "grid_before": grid}


def rows(result, stream, delta, policy):
    out = [r for r in result["rows"] if (r["stream"], r["delta_s"], r["policy"]) == (stream, delta, policy)]
    assert len(out) == 1, (stream, delta, policy)
    return out[0]


def test_switch_poll_and_its_records(f02):
    at, targets = S.switch_targets(f02["bridge"])
    assert at == D.fix_us(113.0)
    revealed = sorted((r.subject, r.value) for r in f02["bridge"].records if r.record_id in targets)
    assert revealed == sorted([(OLD, "terminating"), (NEW, "ready")])


def test_stress_streams_perturb_only_what_they_name(f02):
    base = {r.record_id: r for r in f02["bridge"].records}
    streams, at, targets = S.stress_streams(f02["bridge"])
    names = [s["name"] for s in streams]
    assert names == ["complete"] + [f"{family}_{d}s" for d in S.DELAYS
                                    for family in ("delayed_switch", "corrected_late", "delayed_api")]
    by_name = {s["name"]: s["records"] for s in streams}
    delayed = {r.record_id: r for r in by_name["delayed_switch_20s"]}
    assert delayed.keys() == base.keys()
    for rid, r in base.items():
        shift = delayed[rid].available_at - r.available_at
        assert shift == (20 * R.US if rid in targets else 0), rid
        assert delayed[rid].observed_at == r.observed_at
    api = {r.record_id: r for r in by_name["delayed_api_20s"]}
    for rid, r in base.items():
        assert api[rid].available_at - r.available_at == (20 * R.US if r.kind in D.API_KINDS else 0), rid
    late = {r.record_id: r for r in by_name["corrected_late_20s"]}
    for rid in targets:
        assert rid not in late
        stale, corrected = late[rid + "#stale"], late[rid + "#corrected"]
        assert stale.available_at == base[rid].available_at and stale.value != base[rid].value
        assert corrected.available_at == base[rid].available_at + 20 * R.US and corrected.value == base[rid].value
        assert corrected.corrects == stale.record_id


def test_cutoff_gaps_and_the_restored_grid(f02):
    result = f02["result"]
    assert (result["switch_records"], result["onset_minus_switch_s"]) == (2, 7.0)
    assert {(r["delta_s"], r["cutoff_minus_switch_s"]) for r in result["rows"]} == \
        {(d, 7.0 + d) for d in (0, 5, 10, 20, 30, 60)}
    assert D.DELTAS == f02["grid_before"]


def test_pod_list_intervals(f02):
    """Pod lists at the odd seconds 81 .. 199 s: 60 lists 2 s apart; the switch poll (113 s) follows the 111 s list.
    The ReplicaSet and Deployment rows (0.1 s and 0.2 s later) are not Pod observations and add no list."""
    assert f02["result"]["pod_list_intervals"] == {"lists": 60, "median_s": 2.0, "max_s": 2.0,
                                                   "ending_with_switch_s": 2.0, "following_switch_s": 2.0}
    summary = RS.compute_from_doc({"delays_s": list(S.DELAYS), "deltas_s": [d for _, d in S.DELTAS],
                                   "per_capture": [f02["result"]]})
    assert summary["follow_up"]["per_capture"]["D1-F02"]["pod_list_intervals"] == f02["result"]["pod_list_intervals"]


def test_delayed_api_records_fail_only_beyond_the_switch_gap(f02):
    """Every API record d s later: at cutoff +5 s (125 s) the newest usable Pod list is the one observed by
    124.75 - d s. Up to d = 10 s that includes the switch poll (113 s): NEW is Ready and ranked first. From d = 20 s
    the newest usable list is at most 103 s, where NEW is not Ready: it serves no attributed request and is absent.
    At cutoff +30 s (150 s) the switch poll is usable up to d = 30 s and not from d = 45 s."""
    result = f02["result"]
    for policy in SNAPSHOT_POLICIES:
        assert rows(result, "complete", 5, policy)["top1"], policy
        for delta, last_ok, first_fail in ((5, 10, 20), (30, 30, 45)):
            assert rows(result, f"delayed_api_{last_ok}s", delta, policy)["top1"], (policy, delta)
            failed = rows(result, f"delayed_api_{first_fail}s", delta, policy)
            assert (failed["top1"], failed["outcome"]) == (False, "absent"), (policy, delta)
    for delta in (5, 30, 60):
        assert rows(result, "-", delta, "hindsight")["top1"]


def test_summary_first_failing_delay_and_gap(f02):
    """analysis/stress_summary.py on the same capture: the first failing delay of the snapshot policies is 20 s at
    cutoff +5 s (gap 12 s) and 45 s at cutoff +30 s (gap 37 s); every failure lies beyond the gap."""
    found = {(t["family"], t["delta_s"], t["policy"]): t for t in RS.thresholds(f02["result"], list(S.DELAYS))}
    for policy in SNAPSHOT_POLICIES:
        for delta, first, gap in ((5, 20, 12.0), (30, 45, 37.0)):
            t = found[("delayed_api", delta, policy)]
            assert (t["first_failing_delay_s"], t["cutoff_minus_switch_s"]) == (first, gap), (policy, delta)
    for t in found.values():
        if t["first_failing_delay_s"] is not None and t["policy"] in SNAPSHOT_POLICIES:
            assert t["first_failing_delay_s"] > t["cutoff_minus_switch_s"], t


def test_summarise_counts_captures(f02):
    table = S.summarise([f02["result"], dict(f02["result"], capture="copy")])
    entry = table["delayed_api_20s | 5 s | temporal_join"]
    assert entry == {"top1": 0, "n": 2, "failing": ["D1-F02", "copy"]}


def test_robustness_variants_on_the_fixture(f02):
    """The robustness test on D1-F02: the complete variant equals the stress test's complete stream at the same
    cutoffs; spans without Pod identity change only span identity (the snapshot policies never read it)."""
    res = S.robustness(f02["capture"])
    complete = {(r["delta_s"], r["policy"]): r["top1"] for r in res["variants"]["complete"]}
    stress = {(r["delta_s"], r["policy"]): int(r["top1"]) for r in f02["result"]["rows"]
              if r["stream"] in ("complete", "-") and r["delta_s"] in (5, 30)}
    assert complete == stress
    assert set(res["variants"]) == {"complete"} | {"onset_shift_%+ds" % e for e in S.ONSET_SHIFTS} | {
        "sampled_%g" % p for p in S.SAMPLED} | {"identity_missing_%g" % p for p in S.IDENTITY_MISSING}
    for p in S.IDENTITY_MISSING:
        for r in res["variants"]["identity_missing_%g" % p]:
            assert r["draws"] == len(S.SEEDS)
            if r["policy"] != "hindsight":
                assert r["top1"] == r["draws"] * complete[(r["delta_s"], r["policy"])], r


def test_attribution_on_the_fixture(f02):
    """The attribution analysis on D1-F02: span identity attributes exactly; with every API record 20 s late at the
    +5 s cutoff (beyond the 12 s from the switch poll to the cutoff) no fault-window request reaches NEW, which is not
    a candidate, while 10 s late every one does; the faulty Pod is the recommendation service's serving Pod."""
    res = S.attribution(f02["capture"])
    assert res["faulty_pod_is_the_recommendation_service_s_serving_pod"] is True

    def one(stream, delta, policy):
        out = [r for r in res["rows"] if (r["stream"], r["delta_s"], r["policy"]) == (stream, delta, policy)]
        assert len(out) == 1
        return out[0]
    for delta in (5, 30):
        exact = one("complete", delta, "hindsight")["faulty_pod"]
        for window, (correct, served, attributed) in exact.items():
            assert correct == served == attributed, window
    for policy in SNAPSHOT_POLICIES:
        late = one("delayed_api_20s", 5, policy)
        assert late["faulty_pod"]["anomalous"][0] == 0 and not late["candidate"] and not late["top1"], policy
        timely = one("delayed_api_10s", 5, policy)
        correct, served, attributed = timely["faulty_pod"]["anomalous"]
        assert served > 0 and correct == served == attributed and timely["top1"], policy
