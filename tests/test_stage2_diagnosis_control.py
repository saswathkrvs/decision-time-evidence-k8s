"""Tests of the diagnosis control of the follow-up study (arm D): experiments/diagnosis-control-v1/{load_stage2_task,
run_diagnosis_control_v1}.py.

What is tested, and against what:
  - the loader reproduces replay.load_capture_task byte for byte on poller rows (task_fingerprint: every Record field,
    the candidates, the requests and the whole task context): on a poller-only fixture, on every converted
    development capture present in phase3/captures and on the converter's synthetic follow-up capture; its copied
    constants equal the attribution-lag script's; its bridge input equals context_bridge.load_capture_input; its
    streams equal the development runner's; its grid equals the development captures' recorded cells;
  - hand-computed expectations on the three fixtures of run_diagnosis_control_v1.FIXTURES (3 Pods, one switch, one
    fault window), derived in the comments below from the fixture timeline alone;
  - the watch store ranks the truth Pod where the poller gap made it absent; the event-level switch variants;
  - E_P / E_W / verdict on hand-built situations (success, untested, refuted, and refuted with E_P empty);
  - the creation-ceiling clamp is recorded and changes no Pod Record;
  - inclusion (rules 1-3) and determinism in two separate processes, whose outputs equal the fixture expectation;
  - --validity-only decides rule 3 and writes nothing else.

Tests that need the development captures (phase3/captures) or the 22 Sep rollout (results/evidence-index-pilot-002,
data/raw/rollout-telemetry/pilot-001) are skipped when those are absent.
"""
import json
import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "experiments" / "diagnosis-control-v1"
sys.dont_write_bytecode = True
for _path in (ROOT / "src", HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import load_stage2_task as L  # noqa: E402
import run_diagnosis_control_v1 as D  # noqa: E402
from aiops_kg import context_bridge as B  # noqa: E402
from aiops_kg import replay as R  # noqa: E402

REC, CAT = D.REC, D.CAT
NEW, OLD = "Pod/" + D.FIX_UID["NEW"], "Pod/" + D.FIX_UID["OLD"]
PHASE3 = ROOT / "phase3" / "captures"
REAL = sorted(p for p in PHASE3.iterdir() if (p / "evidence" / "accepted_evidence.jsonl").exists()) \
    if PHASE3.exists() else []


@contextmanager
def frozen_script(relative: str, name: str):
    """Import a experiment script by path for a comparison, then undo its import-time side effects on sys.path and
    the bytecode flag (the scripts insert src/ and set sys.dont_write_bytecode)."""
    path, flag = list(sys.path), sys.dont_write_bytecode
    try:
        yield R.import_script(ROOT / relative, name)
    finally:
        sys.path[:] = path
        sys.dont_write_bytecode = flag


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    """The three fixture captures, analysed once (fixture mode, other attempt kinds allowed)."""
    folder = tmp_path_factory.mktemp("fixtures")
    captures = {name: D.build_fixture_capture(folder / name, name) for name in D.FIXTURES}
    results = {name: D.jsonable(D.analyse_capture(path, mode="FIXTURE", allow_other_kinds=True))
               for name, path in captures.items()}
    return {"captures": captures, "results": results, "folder": folder}


def rows_of(res, observer, **where):
    block = res["observers"][observer] if observer in res["observers"] else res["secondary_observers"][observer]
    return [r for r in block["rows"] if all(r[k] == v for k, v in where.items())]


def one(rows):
    assert len(rows) == 1, rows
    return rows[0]


def cell_of(res, observer, stream, delta, policy):
    return next(c for c in res["observers"][observer]["cells"] if (c["stream"], c["delta"], c["policy"]) ==
                (stream, delta, policy))


# ---------------------------------------------------------------------------------------------------------------
# 1. The loader reproduces replay.load_capture_task byte for byte on poller rows
# ---------------------------------------------------------------------------------------------------------------
def test_loader_identity_on_a_poller_only_fixture(tmp_path):
    capture = D.build_fixture_capture(tmp_path / "D1-F02", "D1-F02", poller_only=True)
    for service in (REC, CAT):
        frozen = R.load_capture_task(capture, service, root=ROOT)
        mine = L.load_stage2_task(capture, service, observer=L.POLLER, root=ROOT)
        assert L.task_fingerprint(mine) == L.task_fingerprint(frozen)
        assert [L.record_row(r) for r in mine.records] == [L.record_row(r) for r in frozen.records]
        assert mine.module is None and frozen.module is not None   # the one field left out, documented
    store = L.load_observer(capture, L.POLLER)
    assert store.clamps == [] and store.report["sightings"] == len(store.sightings) > 0
    with pytest.raises(FileNotFoundError):                         # a poller-only capture has no watch rows
        L.load_observer(capture, L.WATCH)
    with pytest.raises(ValueError):
        L.load_observer(capture, "recheck")


@pytest.mark.skipif(not REAL, reason="no converted Phase-3 capture in phase3/captures")
@pytest.mark.parametrize("capture", REAL, ids=[p.name for p in REAL])
def test_loader_identity_on_the_real_phase3_captures(capture):
    for service in (REC, CAT):
        frozen = R.load_capture_task(capture, service, root=ROOT)
        mine = L.load_stage2_task(capture, service, observer=L.POLLER, root=ROOT)
        assert L.task_fingerprint(mine) == L.task_fingerprint(frozen), (capture.name, service)


@pytest.mark.skipif(not (ROOT / "results/evidence-index-pilot-002/accepted_evidence.jsonl").exists(),
                    reason="the 22 Sep rollout evidence is not in this working copy")
def test_loader_identity_on_the_22sep_rollout_rebuilt_as_a_phase3_capture(tmp_path):
    """The real 22 Sep 2026 rollout (396 API sightings), rebuilt as a Phase-3 capture by replay-policy-v1's
    check_capture_mode.build_fixture and converted by the phase3/convert_capture.py."""
    fixture = tmp_path / "R22SEP-001"
    with frozen_script("experiments/replay-policy-v1/check_capture_mode.py", "ccm_for_diagnosis_tests") as ccm:
        ccm.build_fixture(fixture)
    with frozen_script("phase3/convert_capture.py", "convert_capture_for_diagnosis_tests") as converter:
        converter.convert(fixture, fixture / "evidence")
    store = L.load_observer(fixture, L.POLLER)
    assert len(store.sightings) == 396 and store.clamps == []
    for service in (REC, CAT):
        assert L.task_fingerprint(L.task_for_service(store, service)) == \
            L.task_fingerprint(R.load_capture_task(fixture, service, root=ROOT)), service


@pytest.fixture(scope="module")
def synthetic_stage2(tmp_path_factory):
    """The converter's own synthetic Stage-2 capture (phase3/convert_stage2.py, a 3-replica G2 scenario written by the
    real collectors' code with fake clocks), converted once."""
    import importlib
    folder = tmp_path_factory.mktemp("synthetic")
    path, flag = list(sys.path), sys.dont_write_bytecode
    try:                                   # by name, as tests/test_stage2_converter.py imports it (its dataclasses
        sys.path.insert(0, str(ROOT / "phase3"))       # need the module registered); sys.path restored after
        converter = importlib.import_module("convert_stage2")
        info = converter.build_synthetic_capture(folder / converter.SYNTHETIC_CAPTURE_ID)
        converter.convert(info["capture"], info["capture"] / "evidence")
    finally:
        sys.path[:] = path
        sys.dont_write_bytecode = flag
    return info["capture"]


def test_loader_identity_on_the_converter_synthetic_capture_and_its_watch_rows(synthetic_stage2):
    capture = synthetic_stage2
    for service in (REC, CAT):
        assert L.task_fingerprint(L.load_stage2_task(capture, service)) == \
            L.task_fingerprint(R.load_capture_task(capture, service, root=ROOT))
    watch = L.load_observer(capture, L.WATCH)
    # the converter notes: three snapshot rows of the new ReplicaSet fall in its creation second
    assert [(c["kind"], c["name"], c["predicates"]) for c in watch.clamps] == \
        [("ReplicaSet", "recommendationservice-7d9f6c4b8d", ["STATE", "GENERATION"])] * 3
    task = L.task_for_service(watch, REC)
    assert [c.key for c in task.candidates] == [c.key for c in L.load_stage2_task(capture, REC).candidates]
    assert {r.kind for r in task.records} == {"api", "absence"} and len(task.records) > 3 * len(
        L.load_stage2_task(capture, REC).records)
    assert all(r.group and r.group.startswith(watch.report["collection_id"]) for r in task.records)


def test_loader_constants_equal_the_attribution_lag_script():
    with frozen_script("experiments/attribution-lag-v1/run_attribution_lag.py", "ala_for_diagnosis_tests") as ala:
        assert L.RETIRED == frozenset(ala.RETIRED)
        assert L.DELTAS == tuple(ala.DELTAS)
        assert L.CARRY_FORWARD_US == ala.CARRY_FORWARD_US
        assert L.pod_state.__doc__ and all(L.pod_state(obj) == ala.pga.pod_state(obj) for obj in (
            {"metadata": {}, "status": {"phase": "Running", "containerStatuses": [{"ready": True}]}},
            {"metadata": {"deletionTimestamp": "x"}, "status": {"phase": "Running"}},
            {"metadata": {}, "status": {"phase": "Failed"}}, {"metadata": {}, "status": {"phase": "Succeeded"}},
            {"metadata": {}, "status": {"phase": "Pending", "containerStatuses": [{"ready": False}]}}))


def test_poller_rows_refuse_a_watch_basis_like_the_frozen_load_sightings(tmp_path, fixtures):
    """Gate v1 refuses any observation_basis but snapshot_receipt; so does the poller observer here."""
    capture = shutil.copytree(fixtures["captures"]["D1-F02"], tmp_path / "copy")
    evidence = capture / "evidence" / "accepted_evidence.jsonl"
    watch_rows = (capture / "evidence" / L.SNAPSHOT_FILE).read_text(encoding="utf-8").splitlines()[:1]
    evidence.write_text(evidence.read_text(encoding="utf-8") + watch_rows[0] + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="unexpected observation basis"):
        L.load_stage2_task(capture, REC)
    with pytest.raises(SystemExit, match="unexpected observation basis"):
        R.load_capture_task(capture, REC, root=ROOT)


def test_bridge_input_streams_and_policies_equal_the_frozen_runner(fixtures):
    capture = fixtures["captures"]["D1-F01"]
    mine, _ = D.load_bridge_input(capture, D.POLLER)
    frozen = B.load_capture_input(capture, root=ROOT)
    assert [L.record_row(r) for r in mine.records] == [L.record_row(r) for r in frozen.records]
    assert [(s.service, s.candidates) for s in mine.services] == [(s.service, s.candidates) for s in frozen.services]
    assert (mine.spans, mine.changed_service, mine.notes) == (frozen.spans, frozen.changed_service, frozen.notes)
    with frozen_script("experiments/context-bridge-v1/run_context_bridge_v1.py", "cb_for_diagnosis_tests") as cb:
        with frozen_script("experiments/replay-policy-v1/run_replay_policy_v1.py", "rpv1_for_diagnosis_tests") as rp:
            theirs, their_skipped = cb.capture_streams(rp, frozen)
            assert [p.name for p in rp.make_policies()] == [p.name for p in D.make_policies()]
    ours, our_skipped = D.bridge_streams(mine)
    assert [s["name"] for s in ours] == [s["name"] for s in theirs] == list(B.PROTOCOL["streams"])
    for a, b in zip(ours, theirs):
        assert [L.record_row(r) for r in a["records"]] == [L.record_row(r) for r in b["records"]], a["name"]
        assert (a["family"], a["description"], a["manifest"]) == (b["family"], b["description"], b["manifest"])
    assert our_skipped == their_skipped == []


@pytest.mark.skipif(not (PHASE3 / "I2-002" / "context_bridge" / "results.json").exists(),
                    reason="the committed Phase-3 capture I2-002 is not present")
def test_the_poller_arm_reproduces_the_committed_phase3_cells():
    """I2-002 (the L-4 capture): the reproduced grid and shaping give the committed context_bridge/results.json."""
    capture = PHASE3 / "I2-002"
    committed = json.loads((capture / "context_bridge" / "results.json").read_text(encoding="utf-8"))
    bridge, _ = D.load_bridge_input(capture, D.POLLER)
    truth = B.load_capture_truth(capture)
    streams, skipped = D.bridge_streams(bridge)
    policies = D.make_policies()
    hindsight, cells = D.run_grid(bridge, streams, policies, truth["onset"], truth["truth_entity"])
    mine = D.jsonable(D.base_results(bridge, streams, skipped, policies, truth["onset"], truth["onset_source"],
                                     hindsight, cells, {}))
    for key in ("setup", "entity_names", "unsighted_entities", "policies", "streams", "hindsight", "cells"):
        assert mine[key] == committed[key], key


# ---------------------------------------------------------------------------------------------------------------
# 2. Hand-computed expectations on the fixtures
# ---------------------------------------------------------------------------------------------------------------
def test_fixture_windows_and_hindsight(fixtures):
    res = fixtures["results"]["D1-F01"]
    setup = res["observers"][D.POLLER]["setup"]
    counts = setup["window_request_counts_by_true_pod"]
    # F01: OLD serves i 40..64 (25) of the normal window, NEW i 65..79 (15) and all 40 anomalous requests
    assert counts == {"anomalous": {f"catalog p1 {D.FIX_UID['CAT'][:8]}": 40, f"recommendation new {D.FIX_UID['NEW'][:8]}": 40},
                      "normal": {f"catalog p1 {D.FIX_UID['CAT'][:8]}": 40, f"recommendation new {D.FIX_UID['NEW'][:8]}": 15,
                                 f"recommendation old {D.FIX_UID['OLD'][:8]}": 25}}
    for observer in D.PRIMARY_OBSERVERS:
        hind = {r["delta"]: r for r in rows_of(res, observer, stream="-")}
        assert (hind["0 s"]["outcome"], hind["0 s"]["rank"], hind["0 s"]["candidates"]) == ("not_top1", 3, 3)
        assert all((hind[d]["outcome"], hind[d]["rank"]) == ("top1", 1) for d in ("5 s", "30 s", "60 s"))
    # at Delta = 5 s the anomalous requests ended by c = 125 s are t = 120.0 .. 124.5 (80 ms each): 10
    assert res["observers"][D.POLLER]["hindsight"]["5 s"]["requests"]["anomalous"] == {"observed": 10,
                                                                                       "not_yet_observed": 30}


def test_hand_computed_attribution_counts(fixtures):
    r1, r2, r3 = (fixtures["results"][n] for n in ("D1-F01", "D1-F02", "D1-F03"))
    tj, ba = D.TJ, D.BA
    # F01 poller, Delta = 30 s: temporal_join reads OLD ready@111 and NEW not_ready@111 over [111, 126): NEW's requests
    # i 65..91 (t 112.5..125.5) go to OLD: 27 mis-attributed, request/66-92; bitemporal_abstain finds a transition
    # between 111 and 126 for both Pods (two_pods_possible) on i 62..91 (30) and also abstains on t = 100.0 and 100.5
    # (i 40, 41): NEW's creation floor is 100 s but its first record 101 s, so it cannot be ruled out there: 32.
    front = cell_of(r1, D.POLLER, "complete", "30 s", tj)["services"][REC]
    assert (front["mis_attributed"], front["wrong_request_ids"], front["abstained"]) == (27, "66-92", 0)
    front = cell_of(r1, D.POLLER, "complete", "30 s", ba)["services"][REC]
    assert (front["abstained"], front["abstained_request_ids"], front["mis_attributed"]) == (32, "41-42, 63-92", 0)
    assert front["abstain_reasons"] == {"two_pods_possible": 32}
    # F01 watch: the switch is seen at 112.02 (NEW ready) and 112.12 (OLD terminating); temporal_join makes no error;
    # bitemporal_abstain abstains on t = 100.0 (as above, NEW first seen 100.42) and on t = 111.5, 112.0 (NEW not_ready
    # @111.3 and ready@112.02 bracket them while OLD is still ready): 3, request/41, 64-65
    assert cell_of(r1, D.WATCH, "complete", "30 s", tj)["services"][REC]["mis_attributed"] == 0
    assert cell_of(r1, D.WATCH, "complete", "30 s", ba)["services"][REC]["abstained_request_ids"] == "41, 64-65"
    # F02 poller (lists at 111 and 113): temporal_join errs on i 65 only (t 112.5); bitemporal abstains on i 40, 41
    # and 62..65 (t in [111, 113)): 6
    assert cell_of(r2, D.POLLER, "complete", "30 s", tj)["services"][REC]["wrong_request_ids"] == "66"
    assert cell_of(r2, D.POLLER, "complete", "30 s", ba)["services"][REC]["abstained_request_ids"] == "41-42, 63-66"
    # F03 watch: the last pods snapshot before the gap (115.3) shows OLD ready, NEW not_ready; the relist (120.4001)
    # shows NEW ready and OLD absent: temporal_join gives NEW's i 73..80 (t 116.5..120.0) to OLD: 8, request/74-81;
    # bitemporal_abstain abstains on t = 100.0 and on t in [115.3, 120.4001): i 71..80, 11 in all
    front = cell_of(r3, D.WATCH, "complete", "30 s", tj)["services"][REC]
    assert (front["mis_attributed"], front["wrong_request_ids"]) == (8, "74-81")
    assert cell_of(r3, D.WATCH, "complete", "30 s", ba)["services"][REC]["abstained_request_ids"] == "41, 72-81"
    # latest_state merges both Pods into NEW everywhere: OLD's normal-window requests are mis-attributed (25; F03: 33)
    assert cell_of(r1, D.WATCH, "complete", "30 s", D.LS)["services"][REC]["mis_attributed"] == 25
    assert cell_of(r3, D.POLLER, "complete", "30 s", D.LS)["services"][REC]["mis_attributed"] == 33


def test_the_watch_store_ranks_the_truth_pod_where_the_poller_gap_made_it_absent(fixtures):
    res = fixtures["results"]["D1-F01"]
    for policy in (D.LS, D.TJ, D.BA, D.B30):
        # Delta = 5 s, c = 125 s: the poller's next Pod list after 111 s is at 126 s, so NEW is still not_ready in every
        # usable record; no request is attributed to it: not a candidate, absent; its fault requests feed OLD (Top-1)
        polled = one(rows_of(res, D.POLLER, stream="complete", delta="5 s", policy=policy))
        assert (polled["outcome"], polled["reason"], polled["rank"], polled["vs_hindsight"]) == \
            ("absent", "not_a_candidate", None, "worse")
        assert polled["top1_entity"] == OLD and polled["wrong_decision"] is True
    for policy in (D.TJ, D.BA, D.B30):
        watched = one(rows_of(res, D.WATCH, stream="complete", delta="5 s", policy=policy))
        assert (watched["outcome"], watched["rank"], watched["top1_entity"], watched["vs_hindsight"]) == \
            ("top1", 1, NEW, "equal")
    # Delta = 30 s: the poller's NEW is a candidate (its requests from 126 s) without a baseline: rank 3 of 3 (0, tied
    # with the catalog Pod), worse than hindsight; the watch ranks it first
    for policy in (D.TJ, D.BA):
        assert one(rows_of(res, D.POLLER, stream="complete", delta="30 s", policy=policy))["rank"] == 3
        assert one(rows_of(res, D.WATCH, stream="complete", delta="30 s", policy=policy))["rank"] == 1
    paired = {(p["family"], p["delta"], p["policy"]): p["comparison"] for p in res["paired_poller_watch"]}
    assert paired[("complete", "5 s", D.TJ)] == paired[("complete", "30 s", D.BA)] == "better"
    assert paired[("complete", "30 s", D.LS)] == "equal"


def test_watch_switch_variants_are_defined_on_the_event(fixtures):
    res = fixtures["results"]["D1-F01"]
    facts = res["observers"][D.WATCH]["watch_switch"]
    # the first record showing OLD leave ready is the snapshot after the MODIFIED event received 112.12 s
    # (deletionTimestamp set): two snapshot rows are materialised from that event (112.1201 and the periodic 112.3)
    # before OLD's next event (113.12); the event's own snapshot holds three Pod records (OLD, NEW, CAT)
    assert (facts["constructed"], facts["carrier_type"], facts["carrier_event_type"]) == \
        (True, "api_watch_event", "MODIFIED")
    assert (facts["preceding_value"], facts["revealed_value"], facts["snapshot_rows_from_carrier"]) == \
        ("ready", "terminating", 2)
    entries = {s["name"]: s for s in res["observers"][D.WATCH]["streams"]}
    missing = entries["missing_switch_event"]["watch_variant"]
    assert (missing["records_dropped"], missing["records_withheld"]) == (3, 1)
    corrected = entries["corrected_late_event_3s"]["watch_variant"]
    assert corrected["corrected_pairs"] == 2 and corrected["corrected_available_at"] == D.R.iso(D.fix_us(115.120001))
    # withholding it leaves OLD ready@112.3: bitemporal also abstains on t = 112.5 and 113.0 (OLD ready@112.3 vs
    # terminating@113.12; NEW ready): 5; temporal_join tie-breaks to the newest Pod (NEW), still correct
    assert cell_of(res, D.WATCH, "missing_switch_event", "30 s", D.BA)["services"][REC]["abstained_request_ids"] == \
        "41, 64-67"
    assert cell_of(res, D.WATCH, "missing_switch_event", "30 s", D.TJ)["services"][REC]["mis_attributed"] == 0
    # the poller's own rule drops the 126 s poll (OLD absent, NEW ready): the join errs on i 65..95 (31)
    assert cell_of(res, D.POLLER, "missing_switch_poll", "30 s", D.TJ)["services"][REC]["mis_attributed"] == 31
    # F03: the switch is first revealed by an absence (the relist after the gap): the watch variants are not built
    f3 = fixtures["results"]["D1-F03"]["observers"][D.WATCH]
    assert f3["watch_switch"]["constructed"] is False and "first revealed by an absence" in f3["watch_switch"]["reason"]
    assert {s["name"] for s in f3["streams"] if "not_applicable" in s} == set(D.WATCH_SWITCH)


def test_receipt_availability_row(fixtures):
    res = fixtures["results"]["D1-F01"]
    block = res["receipt_availability"][D.POLLER]
    # every request becomes observable at its catalog span's receipt (end + 3 s, t + 3.00125 s), after the root's
    # (end + 2 s): at c = 125 s only t = 120.0 .. 121.5 of the anomalous window (4 requests)
    assert block["availability"]["feeding_spans_by_acquisition_basis"] == {"live_tail_line": 400}
    assert block["hindsight"]["5 s"]["requests"]["anomalous"] == {"observed": 4, "not_yet_observed": 36}
    assert block["hindsight"]["0 s"]["requests"]["normal"] == {"observed": 34, "not_yet_observed": 6}
    assert [s["name"] for s in block["streams"]] == ["complete"]


# ---------------------------------------------------------------------------------------------------------------
# 3. The H-D rule on hand-built situations
# ---------------------------------------------------------------------------------------------------------------
def test_hd_facts_per_fixture(fixtures):
    hd = {name: res["h_d"] for name, res in fixtures["results"].items()}
    assert [hd[n][D.POLLER]["in_E"] for n in D.FIXTURES] == [True, False, False]
    assert [hd[n][D.WATCH]["in_E"] for n in D.FIXTURES] == [False, False, True]
    worse = {(w["policy"], w["delta"], w["outcome"], w["rank"]) for w in hd["D1-F01"][D.POLLER]["worse"]}
    assert worse == {(D.TJ, "30 s", "not_top1", 3), (D.TJ, "60 s", "not_top1", 3), (D.BA, "30 s", "not_top1", 3),
                     (D.BA, "60 s", "not_top1", 3)}
    assert all(c["rank"] == 1 for n in ("D1-F02",) for o in D.PRIMARY_OBSERVERS for c in hd[n][o]["cells"])


def test_hd_rule_success_untested_refuted(fixtures):
    hd = {name: res["h_d"] for name, res in fixtures["results"].items()}
    success = D.hd_rule([hd["D1-F01"], hd["D1-F02"]])
    assert (success["E_P"], success["E_W"], success["verdict"]) == (["D1-F01"], [], "confirmed as a poller artefact")
    untested = D.hd_rule([hd["D1-F02"]])
    assert (untested["E_P"], untested["E_W"], untested["verdict"]) == ([], [], "untested")
    assert "never as support" in untested["reading"]
    assert D.hd_rule([])["verdict"] == "untested" and D.hd_rule([])["n_included_d1"] == 0
    refuted = D.hd_rule([hd[n] for n in D.FIXTURES])
    assert (refuted["E_P"], refuted["E_W"], refuted["verdict"]) == (["D1-F01"], ["D1-F03"], "refuted")
    assert "Top-1 in" not in refuted["reading"] and refuted["n_included_d1"] == 3
    # the refuting capture's mechanism: NEW's 7 normal-window requests (t 116.5..119.5) went to OLD under the join,
    # were abstained on under the two-clock rule; the watch's last pods record before NEW's first served request
    # (116.5 s) is not_ready at 115.3 s, the next one ready at the relist (120.4001 s), 5.1001 s later; the 4.9 s
    # pods continuity gap overlaps
    mechanisms = refuted["mechanisms_E_W"]["D1-F03"]
    assert {(m["policy"], m["delta"]) for m in mechanisms} == {(D.TJ, "30 s"), (D.TJ, "60 s"), (D.BA, "30 s"),
                                                               (D.BA, "60 s")}
    join = next(m for m in mechanisms if (m["policy"], m["delta"]) == (D.TJ, "30 s"))
    assert join["classification"].startswith("truth Pod has no baseline: its 7 normal-window requests went to "
                                              "another Pod (7)")
    assert (join["normal_n"], join["hindsight_normal_n"], join["rank"], join["hindsight_rank"]) == (0, 7, 3, 1)
    gap = join["record_gap_at_first_served_request"]
    assert (gap["last_before"]["value"], gap["first_after"]["value"], gap["interval_seconds"]) == \
        ("not_ready", "ready", 5.1001)
    assert [g["duration_seconds"] for g in join["watch_continuity_gaps_overlapping"]] == [4.9]
    # the fixture's clock probes bound the node-host offset to +-0.05 s: b_c = 1.05 s; NEW's first ready record (the
    # relist, 120.4001 s) is 3.9001 s after its first served window request (116.5 s): more than b_c, so a clock offset
    # alone cannot explain it (in F01 the poller's is 126 - 112.5 = 13.5 s)
    assert (join["clock_band_seconds"], join["first_ready_record_minus_first_served_request_seconds"]) == (1.05, 3.9001)
    assert {m["first_ready_record_minus_first_served_request_seconds"]
            for m in refuted["mechanisms_E_P"]["D1-F01"]} == {13.5}
    two_clock = next(m for m in mechanisms if (m["policy"], m["delta"]) == (D.BA, "30 s"))
    assert (two_clock["normal_lost_to_abstain"], two_clock["top1_entity"]) == (7, None)
    # refuted with E_P empty: the watch shows an effect the poller did not
    alone = D.hd_rule([hd["D1-F03"]])
    assert (alone["E_P"], alone["E_W"], alone["verdict"]) == ([], ["D1-F03"], "refuted")
    assert "E_P is empty as well" in alone["reading"]


def test_cross_capture_counts_in_the_l4_convention(fixtures):
    results = [fixtures["results"][n] for n in D.FIXTURES]
    summary = D.jsonable(D.summarise(results, mode="FIXTURE"))
    rows = {(r["family"], r["delta"], r["policy"]): r for r in summary["primary_d1"][D.POLLER]["rows"]}
    tj30 = rows[("complete", "30 s", D.TJ)]
    assert (tj30["top1"], tj30["not_top1"], tj30["absent"], tj30["no_cell"], tj30["n"]) == (2, 1, 0, 0, 3)
    assert tj30["text"] == "Top-1 in 2 of 3" and tj30["top1_in"] == ["D1-F02", "D1-F03"]
    assert tj30["rank_worse_than_hindsight_in"] == ["D1-F01"] and tj30["wrong_decision_in"] == ["D1-F01"]
    assert rows[("complete", "5 s", D.LS)]["absent"] == 1
    watch = {(r["family"], r["delta"], r["policy"]): r for r in summary["primary_d1"][D.WATCH]["rows"]}
    assert watch[("complete", "30 s", D.TJ)]["rank_worse_than_hindsight_in"] == ["D1-F03"]
    assert watch[("missing_switch", "30 s", D.TJ)]["streams"] == ["missing_switch_event"]
    assert watch[("missing_switch", "30 s", D.TJ)]["no_cell"] == 1          # F03: not constructed (absence switch)
    paired = {(p["family"], p["delta"], p["policy"]): p for p in summary["primary_d1_paired_poller_watch"]}
    assert (paired[("complete", "30 s", D.TJ)]["better_in"], paired[("complete", "30 s", D.TJ)]["worse_in"]) == \
        (["D1-F01"], ["D1-F03"])
    assert summary["h_d"]["verdict"] == "refuted" and summary["primary_d2"][D.POLLER]["n"] == 0
    # the descriptive sets on secondary rows (never the verdict): F = 30 s changes nothing (every record gap is under
    # 30 s, so no sighting goes stale); the receipt row shifts every request by 3.00125 s without moving a switch;
    # the event log has no gap in F01 / F02 and the same relist in F03; the poller's missing-switch rows leave NEW
    # without a baseline only in F01 (F02 keeps 10 of its 15 normal-window requests, F03 2 of 7: t 119.0 and 119.5);
    # the watch's event-level variant exists for F01 and F02 only and is harmless there
    sets = summary["h_d_secondary_rows"]
    assert sets["bitemporal_F30_in_place_of_F600"] == {"E_P": ["D1-F01"], "E_W": ["D1-F03"]}
    assert sets["telemetry_at_receipt"] == {"E_P": ["D1-F01"], "E_W": ["D1-F03"]}
    assert sets["watch_event_log"] == {"E_E": ["D1-F03"]}
    assert sets["missing_switch"] == {"E_P": ["D1-F01"], "E_W": [], "watch_rows_in": ["D1-F01", "D1-F02"]}


def test_an_analysis_error_is_recorded_and_the_run_goes_on(tmp_path, fixtures):
    broken = D.build_fixture_capture(tmp_path / "caps" / "D1-X02", "D1-F02", poller_only=True)   # no watch rows
    outcome = D.run([broken], tmp_path / "out", mode="FIXTURE", allow_other_kinds=True)
    assert outcome["errors"] == 1
    record = json.loads((tmp_path / "out" / "D1-X02" / "results.json").read_text(encoding="utf-8"))
    assert record["category"] == "analysis_error" and record["capture"]["scenario"] == "D1"
    assert record["error"].startswith("FileNotFoundError: <capture>/evidence/stage2/") and str(tmp_path) not in \
        json.dumps(record)
    assert outcome["summary"]["h_d"]["verdict"] == "untested" and outcome["summary"]["h_d"]["n_included_d1"] == 0


# ---------------------------------------------------------------------------------------------------------------
# 4. The creation-ceiling clamp
# ---------------------------------------------------------------------------------------------------------------
def test_the_clamp_is_recorded(fixtures):
    capture = fixtures["captures"]["D1-F01"]
    watch = L.load_observer(capture, L.WATCH)
    # RS2 is created at 100.3 s (creationTimestamp 100 s, ceiling 101 s); the watch's snapshots at its ADDED event
    # (100.3201 s) and at NEW's ADDED event (100.4201 s) show it before 101 s; the periodic one at 100.3 s precedes it
    assert [(c["kind"], c["subject"], c["predicates"], c["observed_at"], c["creation_ceiling"]) for c in watch.clamps] \
        == [("ReplicaSet", "ReplicaSet/" + D.FIX_UID["RS2"], ["STATE", "GENERATION"], D.R.iso(D.fix_us(t)),
             D.R.iso(D.fix_us(101.0))) for t in (100.3201, 100.4201)]
    assert L.load_observer(capture, L.WATCH_EVENT).report["clamps"][0]["observed_at"] == D.R.iso(D.fix_us(100.32))
    assert L.load_observer(capture, L.POLLER).clamps == []
    assert fixtures["results"]["D1-F01"]["loaders"][D.WATCH]["clamps"] == D.jsonable(watch.clamps)
    # the mapping refuses such a sighting (and so the Phase-3 loader on a watch capture, had it read the rows)
    sighting = next(s for s in watch.sightings if s["record_id"] == watch.clamps[0]["record_id"])
    with frozen_script("experiments/policy-gate-v1/run_policy_gate_audit.py", "pga_for_diagnosis_tests") as pga:
        with pytest.raises(ValueError, match="starts_at cannot be later than observed_at"):
            pga.build_observations([sighting], None, {}, include_receipts=False)


def test_a_poller_clamp_changes_no_pod_record(tmp_path):
    """A poller sample inside RS2's creation second (Pods at 100.5 s, ReplicaSets at 100.6 s): the Phase-3 loader
    raises; this loader clamps and records it, and its Pod Records equal the Phase-3 loader's on the same capture
    with RS2 created a second earlier (no clamp needed there)."""
    clamped = D.build_fixture_capture(tmp_path / "late", "D1-F02", poller_only=True, extra_poll=100.5)
    earlier = D.build_fixture_capture(tmp_path / "early", "D1-F02", poller_only=True, extra_poll=100.5,
                                      rs2_created=99.3)
    with pytest.raises(ValueError, match="starts_at cannot be later than observed_at"):
        R.load_capture_task(clamped, REC, root=ROOT)
    store = L.load_observer(clamped, L.POLLER)
    assert [(c["kind"], c["observed_at"]) for c in store.clamps] == [("ReplicaSet", D.R.iso(D.fix_us(100.6)))]
    assert L.load_observer(earlier, L.POLLER).clamps == []
    for service in (REC, CAT):
        mine, frozen = L.task_for_service(store, service), R.load_capture_task(earlier, service, root=ROOT)
        assert [L.record_row(r) for r in mine.records] == [L.record_row(r) for r in frozen.records]
        assert mine.candidates == frozen.candidates and mine.truth == frozen.truth


# ---------------------------------------------------------------------------------------------------------------
# 5. Inclusion, attempt kinds, determinism
# ---------------------------------------------------------------------------------------------------------------
def _edit_capture_json(capture: Path, change):
    path = capture / "capture.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_inclusion_section10(tmp_path, fixtures):
    source = fixtures["captures"]["D1-F02"]
    cases = {"rule2": lambda d: d["section10"]["rule_2"].update(passed=False, checks={"watch": False}),
             "missing": lambda d: d.pop("section10"),
             "pilot": lambda d: d["stage2"].update(kind="pilot", pilot=True),
             "armG": lambda d: d["stage2"].update(arm="G")}
    out = {}
    for name, change in cases.items():
        capture = shutil.copytree(source, tmp_path / name)
        _edit_capture_json(capture, change)
        out[name] = D.analyse_capture(capture, mode="FIXTURE", allow_other_kinds=True)
    assert out["rule2"]["category"] == "excluded" and "observers" not in out["rule2"]
    assert out["rule2"]["reasons"] == ["inclusion rule 2 not passed: watch"]
    assert out["missing"]["category"] == "excluded" and "no section10 record" in out["missing"]["reasons"][0]
    assert out["pilot"]["category"] == "not_analysed" and "pilot" in out["pilot"]["reasons"][0]
    assert out["armG"]["category"] == "not_analysed" and "arm D only" in out["armG"]["reasons"][0]
    study_run = D.analyse_capture(source, mode="study", allow_other_kinds=False)
    assert study_run["category"] == "not_analysed"
    # a truth Pod the watch never sighted: rule 3 fails on the watch's input ('sighted by both observers')
    capture = shutil.copytree(source, tmp_path / "unsighted")
    snapshot = capture / "evidence" / L.SNAPSHOT_FILE
    lines = [line for line in snapshot.read_text(encoding="utf-8").splitlines() if D.FIX_UID["NEW"] not in line]
    snapshot.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = D.analyse_capture(capture, mode="FIXTURE", allow_other_kinds=True)
    assert result["category"] == "excluded"
    assert any(r.startswith("watch: fault target Pod is not a sighted Pod") for r in result["reasons"])
    assert result["inclusion"]["rule_3"][D.POLLER]["included"] is True


def test_determinism_in_two_processes_and_the_committed_expectation(tmp_path):
    script = HERE / "run_diagnosis_control_v1.py"
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT / "src"))
    runs = [subprocess.Popen([sys.executable, str(script), "--fixture-run", "--out", str(tmp_path / name)],
                             cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for name in ("one", "two")]
    for process in runs:
        stdout, stderr = process.communicate(timeout=600)
        assert process.returncode == 0, stderr.decode()[-2000:]
    files = sorted(p.relative_to(tmp_path / "one").as_posix() for p in (tmp_path / "one").rglob("*") if p.is_file())
    assert files == sorted(p.relative_to(tmp_path / "two").as_posix() for p in (tmp_path / "two").rglob("*")
                           if p.is_file())
    assert len(files) == 2 + 3 * len(D.FIXTURES)
    for name in files:
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes(), name
    for name in files:
        text = (tmp_path / "one" / name).read_text(encoding="utf-8")
        assert str(tmp_path) not in text and str(ROOT) not in text           # no absolute path in any output
    expected = json.loads(D.EXPECTATION.read_text(encoding="utf-8"))
    results = [json.loads((tmp_path / "one" / n / "results.json").read_text(encoding="utf-8")) for n in D.FIXTURES]
    summary = json.loads((tmp_path / "one" / "summary.json").read_text(encoding="utf-8"))
    assert D.semantic_table(summary, results) == expected["semantic"]
    assert expected["semantic"]["h_d"] == {"verdict": "refuted", "E_P": ["D1-F01"], "E_W": ["D1-F03"],
                                           "n_included_d1": 3}


# ---------------------------------------------------------------------------------------------------------------
# 6. --validity-only: inclusion rule 3 without any ranking (added 19 Oct 2026)
# ---------------------------------------------------------------------------------------------------------------
def test_validity_only_decides_rule_3_and_writes_nothing_else(tmp_path, fixtures, monkeypatch):
    """Every ranking, cell and H-D function is replaced by one that fails, so none of them was called."""
    source = fixtures["captures"]["D1-F02"]
    rule2 = shutil.copytree(source, tmp_path / "caps" / "D1-X12")
    _edit_capture_json(rule2, lambda d: d["section10"]["rule_2"].update(passed=False, checks={"watch": False}))
    unsighted = shutil.copytree(source, tmp_path / "caps" / "D1-X3W")
    snapshot = unsighted / "evidence" / L.SNAPSHOT_FILE
    snapshot.write_text("".join(line + "\n" for line in snapshot.read_text(encoding="utf-8").splitlines()
                                if D.FIX_UID["NEW"] not in line), encoding="utf-8")
    pilot = shutil.copytree(source, tmp_path / "caps" / "P9-D1-001")
    _edit_capture_json(pilot, lambda d: d["stage2"].update(kind="pilot", pilot=True))
    full = {name: res["inclusion"] for name, res in fixtures["results"].items()}
    for capture in (rule2, unsighted):
        full[capture.name] = D.jsonable(D.analyse_capture(capture, mode="FIXTURE",
                                                          allow_other_kinds=True))["inclusion"]
    full[pilot.name] = full["D1-F02"]
    assert D.analyse_capture(pilot, mode="FIXTURE", allow_other_kinds=True)["category"] == \
        "not_analysed"

    def forbidden(*args, **kwargs):
        raise AssertionError("--validity-only called a ranking, cell or H-D function")
    for module, name in ((D, "make_policies"), (D, "bridge_streams"), (D, "watch_switch_streams"), (D, "run_grid"),
                         (D, "observer_block"), (D, "l4_rows"), (D, "capture_hd"), (D, "hd_rule"), (D, "summarise"),
                         (B, "evaluate_cell"), (B, "rank_entities"), (B, "truth_rank")):
        monkeypatch.setattr(module, name, forbidden)
    out = tmp_path / "validity"
    captures = [str(p) for p in fixtures["captures"].values()] + [str(rule2), str(unsighted), str(pilot)]
    assert D.main(["--validity-only", "--any-kind", "--out", str(out), "--captures", *captures]) == 0
    # (a) the two files and nothing else
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*")) == list(D.VALIDITY_FILES) == \
        ["validity.json", "validity.md"]
    text, md = ((out / name).read_text(encoding="utf-8") for name in D.VALIDITY_FILES)
    doc = json.loads(text)
    label = ("VALIDITY ONLY: inclusion rule 3 (bridge inclusion items 2-3); no ranking, condition or "
             "label computed")
    assert doc["label"] == D.VALIDITY_LABEL == label and label in md
    # (b) the verdict is the full run's inclusion block, and nothing of the analysis is written
    assert sorted(doc["captures"]) == sorted(full)
    for name, entry in doc["captures"].items():
        assert entry["inclusion"] == full[name], name
        assert set(entry) == {"verdict", "reasons", "pilot", "capture_dir", "capture", "converter", "manifest",
                              "inclusion"}, name
    assert {n: e["verdict"] for n, e in doc["captures"].items()} == {
        "D1-F01": "primary_included", "D1-F02": "primary_included", "D1-F03": "primary_included",
        "D1-X12": "excluded", "D1-X3W": "excluded", "P9-D1-001": "primary_included"}
    lines = [line for line in md.splitlines() if line.split(":")[0] in full]
    assert len(lines) == 2 * len(full)
    assert lines[:2] == ["D1-F01: primary included", "D1-F01: secondary rule not applicable (primary included)"]
    assert "D1-X12: excluded — inclusion rule 2 not passed: watch" in lines
    assert "D1-X12: secondary rule not admitted — rules 1-2 not passed (nothing loaded)" in lines
    assert any(r.startswith("watch: fault target Pod is not a sighted Pod") for r in full["D1-X3W"]["reasons"])
    assert "D1-X3W: excluded — " + "; ".join(full["D1-X3W"]["reasons"]) in lines
    assert f"P9-D1-001: primary included [{D.PILOT_NOTE}]" in lines
    assert str(tmp_path) not in text + md and str(ROOT) not in text + md      # no absolute path
    with pytest.raises(SystemExit):
        D.main(["--validity-only", "--fixture-run", "--out", str(tmp_path / "fixture")])
    assert not (tmp_path / "fixture").exists()
