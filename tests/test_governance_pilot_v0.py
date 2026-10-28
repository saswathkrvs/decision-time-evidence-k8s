"""Tests of the governance pilot v0 adapter (experiments/governance-pilot-v0/govpilot).

Synthetic fixtures only (``govpilot.fixtures``): no real capture is read by any test. The fixture tests are the
classes ``Test01`` ... ``Test15``; the remaining classes cover the causal guarantee, the matched schedule, hindsight
isolation, the input mapping, the evaluator, the capture-run path, the decision logs and the input dry run.

Standard fixture timeline (seconds after the fixture origin): patch request P = 29.2, response R = 29.6 (row
available 29.6005); Deployment sightings at 0.8 + 3n (the changed Deployment's row available 0.5 ms later):
30.8 generation 2 / observedGeneration 1, 33.8 and 36.8 surge (total 2, updated 1), 39.8 COMPLETE at revision 2;
rollout-wait W = 39.5 (row available 39.5005); active window [60, 80); last list 250 s.
"""
import ast
import dataclasses
import gzip
import hashlib
import inspect
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "experiments/governance-pilot-v0"
for path in (ROOT / "src", PILOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from aiops_kg import replay as R  # noqa: E402
from aiops_kg.policy_gate import ABSTAIN, ALLOW, DENY, NEEDS_APPROVAL, materialize_facts  # noqa: E402

from govpilot import checks, common, engine, inputs, mapping, outcomes, rollout, views  # noqa: E402
from govpilot import fixtures as FX  # noqa: E402
from govpilot import run_dev  # noqa: E402
from govpilot.fixtures import DELETE, T  # noqa: E402
from govpilot.inputs import STREAM_BY_NAME, StreamSpec  # noqa: E402

US = 1_000_000


# ---------------------------------------------------------------------------------------------------------------
# Shared fixture builders (cached; every context memoises its evaluations)
# ---------------------------------------------------------------------------------------------------------------
SCENARIOS = {
    "fault": FX.STANDARD["fault"],
    "failed": FX.STANDARD["failed"],
    "failed-noconditions": dataclasses.replace(FX.STANDARD["failed"], name="failed-noconditions",
                                               conditions_recorded=False),
    "stale-deployment": dataclasses.replace(FX.STANDARD["fault"], name="stale-deployment",
                                            deployment_lists_until=50.0),
    "r6": dataclasses.replace(FX.STANDARD["fault"], name="r6", workload_lists_until=50.0, last_list=400.0),
    "other-uid": dataclasses.replace(FX.STANDARD["fault"], name="other-uid", deployment_overrides=(
        (45.8, {"metadata": {"uid": "dep-other-uid"}}),)),
    "revision-3": dataclasses.replace(FX.STANDARD["fault"], name="revision-3", deployment_overrides=(
        (45.8, {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "3"}}}),)),
    "no-annotation": dataclasses.replace(FX.STANDARD["fault"], name="no-annotation", deployment_overrides=(
        (45.8, {"metadata": {"annotations": {}}}),)),
    "no-spec-replicas": dataclasses.replace(FX.STANDARD["fault"], name="no-spec-replicas", deployment_overrides=(
        (45.8, {"spec": {"replicas": DELETE}}),)),
    "no-generation": dataclasses.replace(FX.STANDARD["fault"], name="no-generation", deployment_overrides=(
        (45.8, {"metadata": {"generation": DELETE}}),)),
}


def contradictory_row(sc):
    """A second sighting of the changed Deployment in the 39.8 s list, still showing the surge."""
    resource = FX.deployment_resource(sc, sc.changed_service, 36.8)
    return [FX.deployment_row(sc, 39.8, resource, seq_suffix="contradiction", snapshot=13, available_offset_us=700)]


@lru_cache(maxsize=None)
def model(name: str, extra: str = ""):
    sc = SCENARIOS[name]
    extra_rows = contradictory_row if extra == "contradiction" else None
    extra_records = FX.x1_records(extra, sc) if extra in ("intime", "X1a", "X1b") else ()
    ci = FX.scenario_inputs(sc, extra_rows=extra_rows, extra_records=extra_records)
    return views.capture_model(ci.capture_id, ci.records, ci.requests)


_CONTEXTS = {}


def context(name: str, stream="S0", extra: str = "", records=None):
    key = (name, stream if isinstance(stream, str) else stream.name, extra, id(records) if records else None)
    if key not in _CONTEXTS:
        m = model(name, extra)
        if records is not None:
            _CONTEXTS[key] = views.StreamContext(m, key[1], records)
        else:
            spec = STREAM_BY_NAME[stream] if isinstance(stream, str) else stream
            _CONTEXTS[key] = engine.stream_context(m, spec)
    return _CONTEXTS[key]


def ev(view: str, ctx, seconds: float = None, us: int = None):
    tau = us if us is not None else T(seconds)
    return views.evaluate_causal(views.causal_view(view), ctx, tau)


def rule(entry, rule_id):
    return next(r for r in entry["rules"] if r["rule"] == rule_id)


def binding():
    return model("fault").binding


def status(**overrides):
    base = {"uid": binding().deployment_uid, "name": "recommendationservice", "revision": "2", "generation": 2,
            "has_generation": True, "spec_replicas": 1,
            "status": {"observedGeneration": 2, "replicas": 1, "updatedReplicas": 1, "availableReplicas": 1},
            "conditions_recorded": False, "progressing_reason": None}
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------------------------------------------
# Fixture tests
# ---------------------------------------------------------------------------------------------------------------
class Test01IncompleteSurge(unittest.TestCase):
    def test_kubectl_order_spec1_updated1_available1_total2_is_in_progress(self):
        result = rollout.deployment_state(2, status(status={"observedGeneration": 2, "replicas": 2,
                                                            "updatedReplicas": 1, "availableReplicas": 1}),
                                          binding())
        self.assertEqual((result.state, result.reason), (rollout.IN_PROGRESS, "old_replicas_pending_termination"))

    def test_views_abstain_during_the_surge(self):
        for view in ("T", "L"):
            entry = ev(view, context("fault"), 34.0)
            self.assertEqual(entry["r7"]["state"], rollout.IN_PROGRESS)
            self.assertEqual(entry["r7"]["reason"], "old_replicas_pending_termination")
            self.assertEqual(rule(entry, "R7")["verdict"], ABSTAIN)
            self.assertEqual(entry["verdict"], ABSTAIN)


class Test02StaleGeneration(unittest.TestCase):
    def test_generation_above_observed_generation(self):
        result = rollout.deployment_state(2, status(revision="1", status={"observedGeneration": 1, "replicas": 1,
                                                                          "updatedReplicas": 1,
                                                                          "availableReplicas": 1}), binding())
        self.assertEqual((result.state, result.reason), (rollout.IN_PROGRESS, "spec_update_not_observed"))

    def test_sighting_with_unobserved_spec_update(self):
        entry = ev("T", context("fault"), 31.0)            # 30.8 sighting: generation 2, observedGeneration 1
        self.assertEqual(entry["r7"]["reason"], "spec_update_not_observed")

    def test_patch_receipt_newer_than_the_latest_sighting(self):
        entry = ev("T", context("fault"), 30.0)            # receipt usable, latest sighting 27.8 is revision 1
        self.assertEqual(entry["r7"]["reason"], "spec_update_not_observed")
        self.assertIn("change:FX-fault:recommendationservice:patch#response_received_at",
                      views.records_behind(context("fault").store("two_clock"), rule(entry, "R7")["ids"]))
        unseen = ev("T", context("fault", "Snever"), 30.0)  # same instant without the receipt
        self.assertEqual(unseen["r7"]["state"], rollout.COMPLETE)


class Test03FailedRollout(unittest.TestCase):
    def test_progress_deadline_exceeded_is_failed_and_needs_approval(self):
        result = rollout.deployment_state(2, status(status={"observedGeneration": 2, "replicas": 2,
                                                            "updatedReplicas": 1, "availableReplicas": 1},
                                                    conditions_recorded=True,
                                                    progressing_reason=rollout.TIMED_OUT_REASON), binding())
        self.assertEqual(result.state, rollout.FAILED)
        self.assertEqual(rollout.state_clause_verdict(result, binding()), (NEEDS_APPROVAL, "rollout_failed"))
        entry = ev("T", context("failed"), 70.0)
        self.assertEqual(entry["r7"]["state"], rollout.FAILED)
        self.assertEqual(entry["verdict"], NEEDS_APPROVAL)
        self.assertEqual(entry["deciding"], ["R7:rollout_failed"])

    def test_never_failed_without_conditions(self):
        entry = ev("T", context("failed-noconditions"), 70.0)
        self.assertEqual(entry["r7"]["state"], rollout.IN_PROGRESS)
        self.assertIn("progress_condition_not_recorded", entry["r7"]["notes"])
        self.assertEqual(entry["verdict"], ABSTAIN)
        timeout = rollout.deployment_state(2, status(progressing_reason=rollout.TIMED_OUT_REASON,
                                                     conditions_recorded=False), binding())
        self.assertNotEqual(timeout.state, rollout.FAILED)

    def test_failed_wait_receipt_needs_approval_in_the_procedural_views(self):
        ctx = context("failed")
        wait = next(c for c in ctx.model.completion_receipts)
        self.assertEqual(wait.exit_code, 1)
        entry = ev("T+p", ctx, us=wait.available_at)
        self.assertIn("procedural:rollout_wait_failed", rule(entry, "R7")["reason"])
        self.assertEqual(rule(entry, "R7")["verdict"], NEEDS_APPROVAL)


class Test04RevisionMismatch(unittest.TestCase):
    def test_unit_cases(self):
        b = binding()
        self.assertEqual(rollout.deployment_state(2, status(uid="other"), b).reason, "uid_not_bound")
        self.assertEqual(rollout.deployment_state(2, status(revision="3"), b).reason, "revision_not_bound")
        self.assertEqual(rollout.deployment_state(2, status(revision=None), b).reason, "revision_absent")
        self.assertEqual(rollout.deployment_state(2, status(revision="x2"), b).reason, "revision_invalid")
        for case in ("other", "3", None):
            self.assertEqual(rollout.deployment_state(2, status(uid=case) if case == "other"
                                                      else status(revision=case), b).state, rollout.UNKNOWN)

    def test_views_report_unknown(self):
        for name, reason in (("other-uid", "uid_not_bound"), ("revision-3", "revision_not_bound"),
                             ("no-annotation", "revision_absent")):
            for view in ("T", "L"):
                entry = ev(view, context(name), 46.0)
                self.assertEqual((entry["r7"]["state"], entry["r7"]["reason"]), (rollout.UNKNOWN, reason), name)
                self.assertEqual(rule(entry, "R7")["verdict"], ABSTAIN)


class Test05AbsentFields(unittest.TestCase):
    def test_absent_counters_read_as_zero(self):
        b = binding()
        partial = rollout.deployment_state(2, status(status={"observedGeneration": 2, "replicas": 1}), b)
        self.assertEqual(partial.reason, "updated_below_spec")      # absent updatedReplicas read as 0
        scaled = rollout.deployment_state(2, status(spec_replicas=0, status={"observedGeneration": 2}), b)
        self.assertEqual(scaled.state, rollout.COMPLETE)
        empty = rollout.deployment_state(2, status(status={}), b)
        self.assertEqual(empty.reason, "spec_update_not_observed")  # absent observedGeneration read as 0

    def test_absent_generation_or_spec_replicas_is_unknown(self):
        b = binding()
        self.assertEqual(rollout.deployment_state(2, status(has_generation=False, generation=None), b).reason,
                         "generation_absent")
        self.assertEqual(rollout.deployment_state(2, status(spec_replicas=None), b).reason, "spec_replicas_absent")
        self.assertEqual(rollout.deployment_state(2, status(status={"replicas": -1}), b).reason,
                         "status_counter_invalid")
        self.assertEqual(rollout.deployment_state("two", status(), b).reason, "generation_invalid")
        for name, reason in (("no-spec-replicas", "spec_replicas_absent"), ("no-generation", "generation_absent")):
            entry = ev("T", context(name), 46.0)
            self.assertEqual((entry["r7"]["state"], entry["r7"]["reason"]), (rollout.UNKNOWN, reason), name)


class Test06ContradictorySameInstantSightings(unittest.TestCase):
    def test_unknown_in_T_and_L(self):
        ctx = context("fault", extra="contradiction")
        for view in ("T", "L"):
            before = ev(view, ctx, 39.0)
            during = ev(view, ctx, 40.0)
            after = ev(view, ctx, 43.0)
            self.assertEqual(before["r7"]["state"], rollout.IN_PROGRESS)
            self.assertEqual(during["r7"]["state"], rollout.UNKNOWN, view)
            self.assertEqual(during["r7"]["reason"], "status_conflict", view)
            self.assertEqual(after["r7"]["state"], rollout.COMPLETE)

    def test_conflict_appears_only_once_both_records_are_usable(self):
        ctx = context("fault", extra="contradiction")
        first = T(39.8) + 500             # the original row; the contradicting row is available 0.2 ms later
        self.assertEqual(ev("T", ctx, us=first)["r7"]["state"], rollout.COMPLETE)
        self.assertEqual(ev("T", ctx, us=T(39.8) + 700)["r7"]["state"], rollout.UNKNOWN)


class Test07LateCorrection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = model("fault").records
        original = next(r for r in base if r.kind == "api_observation" and r.observed_at == T(39.8)
                        and r.subject == binding().deployment_key)
        cls.original = original
        cls.correction = FX.correction_of(original, available_at=T(41.0), resource_changes={
            "status": {"replicas": 2, "availableReplicas": 1, "readyReplicas": 1}})
        cls.records = base + (cls.correction,)
        cls.ctx = context("fault", "S0+correction", records=cls.records)

    def test_predecessor_withdrawn_at_the_correction_availability(self):
        at40, at415, at43 = (ev("T", self.ctx, s) for s in (40.0, 41.5, 43.0))
        self.assertEqual(at40["r7"]["state"], rollout.COMPLETE)
        self.assertEqual(at415["r7"]["state"], rollout.IN_PROGRESS)
        self.assertEqual(at43["r7"]["state"], rollout.COMPLETE)
        store = self.ctx.store("two_clock")
        self.assertIn(self.original.id, views.records_behind(store, rule(at40, "R7")["ids"]))
        cited = views.records_behind(store, rule(at415, "R7")["ids"])
        self.assertIn(self.correction.id, cited)
        self.assertNotIn(self.original.id, cited)

    def test_earlier_answers_unchanged_after_the_correction_is_appended(self):
        before = views.evaluate_causal(views.causal_view("T"), context("fault"), T(40.0))
        after = ev("T", self.ctx, 40.0)
        self.assertEqual((before["verdict"], before["rules"]), (after["verdict"], after["rules"]))
        log = engine.DecisionLog()
        for k, t in model("fault").requests[15:30]:
            engine.run_request(views.causal_view("T"), self.ctx, k, t, 0, log)
            engine.run_request(views.causal_view("L"), self.ctx, k, t, 0, log)
        result = checks.check_append_only(log, self.ctx)
        self.assertGreater(result["n"], 0)
        self.assertEqual(result["x"], result["n"], result["failures"])


class Test08UnseenChange(unittest.TestCase):
    def test_no_visible_change_and_the_evaluator_labels_the_instant(self):
        ctx = context("fault", "Snever")
        log = engine.DecisionLog()
        k, t = next((k, t) for k, t in model("fault").requests if t == T(30.0))
        row = engine.run_request(views.causal_view("T"), ctx, k, t, 0, log)
        self.assertEqual(row["disposition"], ALLOW)
        entry = ev("T", ctx, 30.0)
        self.assertEqual(rule(entry, "R7")["reason"], "no_visible_change")
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        labeller = outcomes.Labeller(gt, binding(), model("fault").records)
        self.assertEqual(labeller.label(T(30.0), T(30.0))[0], outcomes.GT1S)


class Test09ReceiptBoundary(unittest.TestCase):
    WAIT300 = StreamSpec("W300", 300.0, kinds=("change_wait",))
    WAITNEVER = StreamSpec("Wnever", drop=True, kinds=("change_wait",))
    WAIT30 = StreamSpec("W30", 30.0, kinds=("change_wait",))

    def test_non_procedural_views_never_wait_for_the_completion_receipt(self):
        base = context("fault")
        schedule = engine.candidate_schedule(base)
        sample = [t for t in schedule if T(38.0) <= t <= T(75.0)]
        for spec in (self.WAIT300, self.WAITNEVER):
            other = context("fault", spec)
            for view in ("T", "L", "d", "a"):
                for tau in sample:
                    a, b = ev(view, base, us=tau), ev(view, other, us=tau)
                    self.assertEqual((a["verdict"], a["rules"]), (b["verdict"], b["rules"]), (view, spec.name, tau))
            for tau in sample[::7]:
                a = views.evaluate_hindsight(views.hindsight_view("c-hind", hindsight=True), base, tau,
                                             hindsight=True)
                b = views.evaluate_hindsight(views.hindsight_view("c-hind", hindsight=True), other, tau,
                                             hindsight=True)
                self.assertEqual(a["verdict"], b["verdict"])

    def test_procedural_view_eligible_exactly_at_the_receipt_availability(self):
        ctx = context("fault", self.WAIT30)
        available = next(c.available_at for c in ctx.model.completion_receipts)
        self.assertEqual(available, T(39.5) + 500 + 30 * US)
        self.assertEqual(ev("T+p", ctx, us=available - 1)["verdict"], ABSTAIN)
        self.assertEqual(ev("T+p", ctx, us=available)["verdict"], ALLOW)
        log = engine.DecisionLog()
        k, t = next((k, t) for k, t in model("fault").requests if t == T(50.0))
        row = engine.run_request(views.causal_view("T+p"), ctx, k, t, 0, log)
        self.assertEqual((row["disposition"], row["disposition_at"]), (ALLOW, R.iso(available)))

    def test_a_late_older_patch_receipt_changes_nothing_in_R7(self):
        late = context("fault", StreamSpec("P20", 20.0, kinds=("change_patch",)))
        never = context("fault", StreamSpec("Pnever", drop=True, kinds=("change_patch",)))
        arrival = T(29.6) + 500 + 20 * US
        self.assertGreater(arrival, T(39.8) + 500)             # after the sighting showing revision 2 complete
        for tau in [t for t in engine.candidate_schedule(late) if arrival <= t <= T(120.0)]:
            for view in ("T", "L"):
                a, b = rule(ev(view, late, us=tau), "R7"), rule(ev(view, never, us=tau), "R7")
                self.assertEqual((a["verdict"], a["reason"], a["detail"]), (b["verdict"], b["reason"], b["detail"]))

    def test_but_R2_reads_the_same_generation_records(self):
        """Section 3A: GENERATION feeds R2 too. The late receipt moves R2's window start from the first sighting of
        generation 2 (30.8 s) to R (29.6 s), so between 59.6 s and 60.8 s the combined verdicts differ."""
        late = context("fault", StreamSpec("P20", 20.0, kinds=("change_patch",)))
        never = context("fault", StreamSpec("Pnever", drop=True, kinds=("change_patch",)))
        self.assertEqual(ev("T", late, 60.0)["verdict"], ALLOW)
        self.assertEqual(ev("T", never, 60.0)["deciding"], ["R2:changed_recently"])
        self.assertEqual(rule(ev("T", late, 60.0), "R7")["reason"], rule(ev("T", never, 60.0), "R7")["reason"])


class Test10TimerOnlyReEvaluation(unittest.TestCase):
    def assertNoArrival(self, ctx, tau):
        self.assertNotIn(tau, set(ctx.model.availability.values()))

    def test_freshness_boundary_t_p_plus_F(self):
        ctx = context("stale-deployment")
        boundary = T(48.8) + 30 * US                           # last Deployment sighting 48.8 s, F = 30 s
        self.assertNoArrival(ctx, boundary)
        self.assertIn(boundary, engine.candidate_schedule(ctx))
        for view in ("T", "L"):
            self.assertEqual(ev(view, ctx, us=boundary - 1)["verdict"], ALLOW)
            at = ev(view, ctx, us=boundary)
            self.assertEqual(at["verdict"], ABSTAIN)
            self.assertEqual(at["r7"]["state"], rollout.UNKNOWN)

    def test_R2_window_end(self):
        ctx = context("fault")
        end = T(29.6) + 30 * US                                # generation 2 began at R (receipt), N = 30 s
        self.assertNoArrival(ctx, end)
        self.assertIn(end, engine.candidate_schedule(ctx))
        self.assertEqual(ev("T", ctx, us=end - 1)["deciding"], ["R2:changed_recently"])
        self.assertEqual(ev("T", ctx, us=end)["verdict"], ALLOW)

    def test_R6_limit_is_one_microsecond_after_newest_plus_S(self):
        ctx = context("r6")
        spec = views.causal_view("T@F600")
        at = views.evaluate_causal(spec, ctx, T(200.0))
        newest = max(ctx.store("two_clock").fact(fid).available_at for r in at["rules"][:5] for fid in r["ids"]
                     if not fid.startswith("freeze:"))
        limit = R.to_us(newest) + 300 * US
        self.assertIn(limit + 1, engine.candidate_schedule(ctx))
        self.assertLessEqual(limit + 1, ctx.capture.H)
        self.assertEqual(views.evaluate_causal(spec, ctx, limit)["verdict"], ALLOW)
        later = views.evaluate_causal(spec, ctx, limit + 1)
        self.assertEqual(later["verdict"], NEEDS_APPROVAL)
        self.assertEqual(later["deciding"], ["R6:view_may_be_stale"])

    def test_open_request_is_re_evaluated_when_freshness_expires(self):
        ctx = context("stale-deployment", "Snever")
        log = engine.DecisionLog()
        k, t = next((k, t) for k, t in model("stale-deployment").requests if t == T(70.0))
        row = engine.run_request(views.causal_view("T+p"), ctx, k, t, 0, log)
        instants = log.evaluation_instants(row)
        boundary = T(48.8) + 30 * US
        self.assertIn(boundary, instants)
        index = instants.index(boundary)
        before = log.evaluations[f"FX-stale-deployment|T+p|Snever|{instants[index - 1]}"]
        at = log.evaluations[f"FX-stale-deployment|T+p|Snever|{boundary}"]
        self.assertEqual(rule(before, "R1")["verdict"], ALLOW)
        self.assertEqual(rule(at, "R1")["verdict"], ABSTAIN)          # no record arrived; time passed


class Test11SideChannel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="govpilot-test-")
        cls.dir = FX.write_capture(SCENARIOS["fault"], Path(cls.tmp.name) / "FX-fault")
        ci = inputs.read_capture(cls.dir)
        cls.model = views.capture_model(ci.capture_id, ci.records, ci.requests)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_four_checks(self):
        result = checks.side_channel(self.model, self.dir)
        self.assertTrue(all(v["ok"] for v in result["per_stream"].values()), result)
        self.assertEqual(result["per_stream"]["Snever"]["receipt_derived_records"], 0)
        self.assertTrue(result["snever_equals_receipt_rows_deleted"])
        self.assertTrue(result["capture_json_deletion_byte_identical"])
        self.assertTrue(result["binding_equal_S0_Snever"])
        self.assertTrue(result["ok"])

    def test_every_copy_follows_the_shifted_row(self):
        records, _ = inputs.perturb(self.model.records, STREAM_BY_NAME["S30"])
        m = mapping.build_model_inputs(inputs.bound_change_records(records, self.model.binding), self.model.binding)
        patch = next(r for r in self.model.records if r.kind == "change_patch")
        for rid in m.receipt_observations:
            self.assertEqual(m.availability[rid], patch.available_at + 30 * US)
        for receipt in m.completion_receipts:
            original = next(r for r in self.model.records if r.id == receipt.record_id)
            self.assertEqual(receipt.available_at, original.available_at + 30 * US)

    def test_reader_never_reads_the_side_copy(self):
        self.assertTrue((self.dir / "evidence/capture.json").exists())
        with self.assertRaises(inputs.ReaderSeparationError):
            inputs.read_capture(self.dir, reader=lambda d: (d / "evidence/capture.json").read_text())

    def test_gate_v1_store_equals_the_live_audit_store(self):
        result = checks.gate_v1_vs_live(self.dir, self.model)
        self.assertTrue(result["equal"], result["differences"])
        self.assertGreater(result["facts_adapter"], 0)


class Test12TiesTerminalOutcomesCensoring(unittest.TestCase):
    def test_expiry_at_exactly_d_plus_E_pre_empts_an_arrival(self):
        ctx = context("fault")
        d = T(30.0)
        arrival = T(39.8) + 500                              # the COMPLETE sighting's availability
        k = 999
        for E_us, expected in ((arrival - d, engine.EXPIRED), (arrival - d + 1, NEEDS_APPROVAL)):
            spec = dataclasses.replace(views.causal_view("T"), name=f"T-E{E_us}", E=E_us / US)
            log = engine.DecisionLog()
            row = engine.run_request(spec, ctx, k, d, 0, log)
            self.assertEqual(row["disposition"], expected)
            if expected == engine.EXPIRED:
                self.assertEqual(row["waiting_s"], E_us / US)
                self.assertNotIn(arrival, log.evaluation_instants(row))

    def test_terminal_verdict_at_H_and_censoring(self):
        H = model("fault").H
        wait = next(r for r in model("fault").records if r.kind == "change_wait")
        at_h = StreamSpec("WatH", (H - wait.available_at) / US, kinds=("change_wait",))
        ctx = context("fault", at_h)
        self.assertEqual(next(c.available_at for c in ctx.model.completion_receipts), H)
        log = engine.DecisionLog()
        row = engine.run_request(views.causal_view("T+p"), ctx, 999, T(200.0), 0, log)
        self.assertEqual((row["disposition"], row["disposition_at"], row["censored"]), (ALLOW, R.iso(H), False))
        never = context("fault", "Snever")
        row = engine.run_request(views.causal_view("T+p"), never, 999, T(200.0), 0, log)
        self.assertEqual((row["disposition"], row["censored"]), (engine.CENSORED, True))
        self.assertEqual(row["waiting_s"], round((H - T(200.0)) / US, 6))
        self.assertEqual(log.evaluation_instants(row)[-1], H)
        late = engine.run_request(views.causal_view("T"), never, 998, H + US, 0, log)
        self.assertEqual((late["disposition"], late["posed_after_horizon"], late["evaluations"]["count"]),
                         (engine.CENSORED, True, 0))

    def test_escalation_and_not_posed(self):
        log = engine.DecisionLog()
        row = engine.run_request(views.causal_view("d"), context("fault"), 1, T(34.0), 0, log)
        self.assertEqual((row["first_verdict"], row["disposition"], row["waiting_s"]),
                         (ABSTAIN, engine.ESCALATED, 0.0))
        before = engine.run_request(views.causal_view("T"), context("fault"), 2, T(29.0), 0, log)
        self.assertEqual(before["disposition"], engine.NOT_POSED)


class Test13X1(unittest.TestCase):
    def test_freeze_declared_in_time_denies(self):
        entry = ev("T", context("fault", extra="intime"), 70.0)
        self.assertEqual(entry["verdict"], DENY)
        self.assertEqual(entry["deciding"], ["R4:freeze_window_active"])
        self.assertEqual(rule(entry, "R4")["ids"], ["freeze:freeze:X1-intime"])

    def test_X1a_allowed_as_known_denied_corrected_and_a_violation(self):
        ctx = context("fault", extra="X1a")
        tau = T(70.0)
        self.assertEqual(ev("T", ctx, us=tau)["verdict"], ALLOW)
        corrected = views.evaluate_hindsight(views.hindsight_view("CV", hindsight=True), ctx, tau, hindsight=True)
        self.assertEqual(corrected["verdict"], DENY)
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        freezes = [r for r in model("fault", "X1a").records if r.kind == "freeze_declaration"]
        labeller = outcomes.Labeller(gt, binding(), model("fault", "X1a").records, freezes)
        self.assertEqual(labeller.label(tau, tau)[0], outcomes.X1)

    def test_X1b_never_a_violation(self):
        ctx = context("fault", extra="X1b")
        tau = T(70.0)
        self.assertEqual(ev("T", ctx, us=tau)["verdict"], ALLOW)
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        freezes = [r for r in model("fault", "X1b").records if r.kind == "freeze_declaration"]
        labeller = outcomes.Labeller(gt, binding(), model("fault", "X1b").records, freezes)
        for seconds in range(55, 90):
            self.assertNotEqual(labeller.label(T(seconds), T(seconds))[0], outcomes.X1)
        self.assertTrue(all(r.simulated for r in freezes))


class Test14Determinism(unittest.TestCase):
    def test_two_interpreters_produce_byte_identical_outputs(self):
        ok, text = run_dev.rerun_check(quick=True)
        self.assertTrue(ok, text)
        self.assertIn("run_a == run_b: true", text)

    def test_graph_equals_sqlite_on_every_query(self):
        ctx = context("fault", "S30")
        for seconds in range(28, 90, 3):
            ev("T", ctx, seconds)
            ev("L", ctx, seconds)
        result = checks.check_engines([ctx])
        self.assertGreater(result["n"], 0)
        self.assertEqual((result["x"], result["disagreements"]), (result["n"], 0))

    def test_a_disagreement_is_refused(self):
        from aiops_kg.temporal import Resolution

        class Liar:
            def resolve(self, *args):
                return Resolution("unknown", None, (), "lie")
        store = context("fault").store("two_clock")
        dual = mapping.DualEngine(store.engine("graph"), Liar())
        with self.assertRaises(mapping.EngineDisagreement):
            dual.resolve(binding().deployment_key, "STATE", R.from_us(T(50.0)), R.from_us(T(50.0)), 30.0)

    def test_repeated_evaluation_is_identical(self):
        a = views.evaluate_causal(views.causal_view("L"), engine.stream_context(model("fault"), STREAM_BY_NAME["S0"]),
                                  T(45.0))
        b = views.evaluate_causal(views.causal_view("L"), engine.stream_context(model("fault"), STREAM_BY_NAME["S0"]),
                                  T(45.0))
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


class Test15ReaderEvaluatorSeparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="govpilot-test-")
        cls.dir = FX.write_capture(SCENARIOS["fault"], Path(cls.tmp.name) / "FX-fault")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_reader_opens_only_its_two_inputs(self):
        ci = inputs.read_capture(self.dir)
        self.assertEqual(len(ci.requests), len(SCENARIOS["fault"].requests))
        for forbidden in ("ground_truth/ground_truth.json", "evidence/evaluation_only/incident_entry.json",
                          "evidence/capture.json", "capture.json", "incident.json"):
            with self.assertRaises(inputs.ReaderSeparationError, msg=forbidden):
                inputs.read_capture(self.dir, reader=lambda d, f=forbidden: (d / f).read_bytes())

    def test_evaluator_needs_a_sealed_log(self):
        log = engine.DecisionLog()
        with self.assertRaises(outcomes.UnsealedLog):
            outcomes.load_ground_truth(self.dir, log)
        with self.assertRaises(outcomes.UnsealedLog):
            outcomes.cells(log, {}, {})
        log.seal()
        gt = outcomes.load_ground_truth(self.dir, log)
        self.assertEqual(gt.changed_service, "recommendationservice")
        with self.assertRaises(engine.SealedLogError):
            log.add_request({})

    def test_guard_is_inert_outside_the_reader(self):
        self.assertIn("EVALUATION_ONLY", (self.dir / "ground_truth/ground_truth.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------------------------
# The brief's further checks
# ---------------------------------------------------------------------------------------------------------------
class TestCausalGuarantee(unittest.TestCase):
    def test_an_injected_future_record_is_never_read_before_it_is_available(self):
        m = model("fault")
        sc = SCENARIOS["fault"]
        # a SIMULATED freeze over the whole run, declared at 10 s but available only at 100 s (R4 reads it), and a
        # Deployment sighting (its own one-row list) that becomes available after H
        late_freeze = inputs.freeze_record("late", T(0.0), T(400.0), T(10.0), T(100.0))
        beyond_row = FX.deployment_row(sc, 46.9, FX.deployment_resource(sc, sc.changed_service, 36.8),
                                       seq_suffix="beyond", snapshot=98, available_offset_us=1000 * US)
        beyond, _ = inputs.records_from_rows([(1, beyond_row)], "injected")
        ctx = views.StreamContext(m, "S0+future", m.records + (late_freeze,) + beyond)
        self.assertGreater(beyond[0].available_at, m.H)
        log = engine.DecisionLog()
        for view in ("T", "L", "T+p", "L+p", "d", "a"):
            for k, t in m.requests:
                for delta in (0, 30):
                    engine.run_request(views.causal_view(view), ctx, k, t, delta, log)
        stores = {label: ctx.store(label) for label in ("two_clock", "latest", "gate_v1")}
        used_after = 0
        for entry in log.evaluations.values():
            records = views.records_behind(stores[entry["store"]], [x for r in entry["rules"] for x in r["ids"]])
            for rid in records:
                self.assertLessEqual(ctx.model.availability[rid], entry["instant_us"], (entry["eval_id"], rid))
            self.assertNotIn(beyond[0].id, records)
            if late_freeze.id in records:
                self.assertGreaterEqual(entry["instant_us"], T(100.0))
                used_after += 1
            elif entry["instant_us"] >= T(100.0):
                self.fail(f"{entry['eval_id']} ignores a usable freeze")
        self.assertGreater(used_after, 0)
        early = [e for e in log.evaluations.values() if e["instant_us"] < T(100.0)]
        self.assertTrue(early and all(e["verdict"] != DENY for e in early))

    def test_the_guard_refuses_a_future_citation(self):
        ctx = context("fault")
        entry = {"view": "T"}
        with self.assertRaises(views.CausalityViolation):
            views.check_causal(entry, ["change:FX-fault:recommendationservice:rollout-wait"], ctx, T(30.0))


class TestMatchedSchedule(unittest.TestCase):
    def test_L_and_T_see_identical_instants(self):
        for stream in ("S0", "S30", "Snever"):
            ctx = context("fault", stream)
            log = engine.DecisionLog()
            rows = {}
            for view in ("T", "L", "T+p", "L+p"):
                for k, t in model("fault").requests:
                    for delta in (0, 30):
                        rows[(view, k, delta)] = engine.run_request(views.causal_view(view), ctx, k, t, delta, log)
            self.assertEqual({k[2] for k in log.schedules if k[:2] == ("FX-fault", stream)}, {"causal"})
            schedule = engine.candidate_schedule(ctx)
            for (view, k, delta), row in rows.items():
                if not row["posed"] or view not in ("T", "T+p"):
                    continue
                other = rows[("L" if view == "T" else "L+p", k, delta)]
                mine, theirs = log.evaluation_instants(row), log.evaluation_instants(other)
                common = min(len(mine), len(theirs))
                self.assertEqual(mine[:common], theirs[:common])
                expected = engine.request_instants(schedule, row["d_us"], ctx.capture.H, 120.0)
                self.assertEqual(mine, list(expected[:len(mine)]))
                self.assertEqual(theirs, list(expected[:len(theirs)]))


class TestHindsightIsolation(unittest.TestCase):
    def test_c_hind_cannot_be_reached_from_the_Q2_path(self):
        with self.assertRaises(views.HindsightRequired):
            views.causal_view("c-hind")
        with self.assertRaises(views.HindsightRequired):
            views.causal_view("CV")
        with self.assertRaises(views.HindsightRequired):
            engine.run_q2(model("fault"), engine.DecisionLog(), views=("T", "c-hind"), streams=("S0",))
        with self.assertRaises(views.HindsightRequired):
            views.evaluate_causal(views.HINDSIGHT_VIEWS["c-hind"], context("fault"), T(40.0))
        with self.assertRaises(views.HindsightRequired):
            views.hindsight_view("c-hind", hindsight=False)
        with self.assertRaises(TypeError):
            views.hindsight_view("c-hind")
        with self.assertRaises(views.HindsightRequired):
            views.evaluate_hindsight(views.HINDSIGHT_VIEWS["c-hind"], context("fault"), T(40.0), hindsight=False)
        with self.assertRaises(views.HindsightRequired):
            engine.run_hindsight(model("fault"), engine.DecisionLog(), hindsight=False)

    def test_c_hind_reads_the_future_and_says_so(self):
        entry = views.evaluate_hindsight(views.hindsight_view("c-hind", hindsight=True), context("fault"), T(37.0),
                                         hindsight=True)
        self.assertEqual(entry["r7"]["state"], rollout.COMPLETE)    # the 39.8 s sighting, used at 37 s
        self.assertGreater(entry["hindsight"]["max_distance_seconds"], 0)
        self.assertIn("hindsight", entry["hindsight"]["kind"])
        causal = ev("T", context("fault"), 37.0)
        self.assertEqual(causal["r7"]["state"], rollout.IN_PROGRESS)


class TestInputsAndMapping(unittest.TestCase):
    def test_records_are_immutable_and_perturbation_is_pure(self):
        m = model("fault")
        before = [r.to_dict() for r in m.records]
        shifted, manifest = inputs.perturb(m.records, STREAM_BY_NAME["S300"])
        self.assertEqual([r.to_dict() for r in m.records], before)
        self.assertEqual(manifest["perturbation"], "delay")
        self.assertEqual(manifest["changed"], 2)
        dropped, manifest = inputs.perturb(m.records, STREAM_BY_NAME["Snever"])
        self.assertFalse([r for r in dropped if r.kind in inputs.CHANGE_KINDS])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            m.records[0].available_at = 0

    def test_scorr_is_a_labelled_constructed_correction(self):
        records, manifest = inputs.perturb(model("fault").records, STREAM_BY_NAME["Scorr"])
        stale = next(r for r in records if r.id.endswith("#scorr-stale"))
        corrected = next(r for r in records if r.corrects == stale.id)
        patch = next(r for r in records if r.kind == "change_patch")
        self.assertTrue(stale.simulated)
        self.assertEqual(stale.available_at, patch.available_at)
        self.assertEqual(stale.observed_at, T(29.6))
        self.assertGreater(corrected.available_at, stale.available_at)
        self.assertTrue(manifest["applicable"])

    def test_binding_comes_from_sightings_and_refuses_a_changed_pre_patch_sighting(self):
        b = binding()
        self.assertEqual((b.revision, b.changed_revision, b.generation), (1, 2, 1))
        bad = dataclasses.replace(FX.STANDARD["fault"], name="bad-binding", deployment_overrides=(
            (24.8, {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "2"}}}),))
        ci = FX.scenario_inputs(bad)
        with self.assertRaises(inputs.InputError):
            views.capture_model(ci.capture_id, ci.records, ci.requests)

    def test_a1_facts_equal_materialize_facts_without_corrections_or_conflicts(self):
        obs = context("fault").model.gate_v1_observations()
        mine, mine_support = mapping.a1_facts(obs, {})
        theirs, theirs_support = materialize_facts(obs)
        self.assertEqual(sorted(mine, key=lambda f: f.fact_id), sorted(theirs, key=lambda f: f.fact_id))
        self.assertEqual(mine_support, theirs_support)

    def test_two_clock_resolver_matches_bitemporal_abstain_at_observation_time_equal_cutoff(self):
        ctx = context("fault", "S30")
        store = ctx.store("two_clock")
        b = binding()
        for subject, predicate in ((b.deployment_key, "GENERATION"), (b.status_subject, rollout.ROLLOUT_STATUS)):
            records = [R.Record(o.record_id, o.subject, o.predicate, o.value, R.to_us(o.observed_at),
                                R.to_us(o.available_at)) for o in ctx.model.observations
                       if (o.subject, o.predicate) == (subject, predicate)]
            stream = R.Stream(records)
            for tau in engine.candidate_schedule(ctx)[::5]:
                answer = R.bitemporal_abstain(stream, subject, predicate, tau, tau, freshness_seconds=30.0)
                res = store.engine("graph").resolve(subject, predicate, R.from_us(tau), R.from_us(tau), 30.0)
                self.assertEqual(answer.value, res.value if res.status == "resolved" else None, (predicate, tau))

    def test_latest_facts_answer_latest_with_freshness(self):
        store = context("fault").store("latest")
        b = binding()
        res = store.engine("graph").resolve(b.status_subject, rollout.ROLLOUT_STATUS, R.from_us(T(41.0)),
                                            R.from_us(T(41.0)), 30.0)
        self.assertEqual(json.loads(res.value)["status"]["replicas"], 1)
        stale = context("stale-deployment").store("latest")
        res = stale.engine("graph").resolve(b.status_subject, rollout.ROLLOUT_STATUS, R.from_us(T(79.0)),
                                            R.from_us(T(79.0)), 30.0)
        self.assertEqual((res.status, res.reason), ("unknown", "stale_confirmation"))

    def test_requests_ignore_the_reference_block_and_span_pod_claims(self):
        ci = FX.scenario_inputs(SCENARIOS["fault"])
        self.assertEqual([k for k, _ in ci.requests], list(range(1, len(SCENARIOS["fault"].requests) + 1)))
        self.assertEqual(ci.requests[0][1], T(20.0))


class TestOutcomes(unittest.TestCase):
    def labeller(self):
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        return outcomes.Labeller(gt, binding(), model("fault").records)

    def test_rollout_intervals(self):
        lab = self.labeller()
        self.assertEqual((lab.t_inc, lab.t_comp), (T(36.8), T(39.5)))
        expected = {29.0: outcomes.GT0, 29.3: outcomes.U, 29.6: outcomes.GT1S, 36.8: outcomes.GT1S,
                    37.0: outcomes.U, 39.5: outcomes.GT3, 60.0: outcomes.GT2, 79.9: outcomes.GT2, 85.0: outcomes.GT3}
        for seconds, label in expected.items():
            self.assertEqual(lab.label(T(seconds), T(seconds))[0], label, seconds)
        self.assertEqual(lab.label(T(85.0), T(70.0))[0], outcomes.LATE)
        self.assertEqual(lab.input_errors, [])

    def test_gt1p_follows_the_stream_under_test(self):
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        s0 = context("fault").records
        never = context("fault", "Snever").records
        self.assertTrue(outcomes.gt1p(T(39.0), gt, s0))
        self.assertFalse(outcomes.gt1p(T(40.0), gt, s0))
        self.assertTrue(outcomes.gt1p(T(200.0), gt, never))
        scorr = context("fault", "Scorr").records
        self.assertTrue(outcomes.gt1p(T(35.0), gt, scorr))     # the final version is the real receipt

    def test_cells_are_counts_with_denominators(self):
        m = model("fault")
        log = engine.DecisionLog()
        contexts = engine.run_q2(m, log, views=("T", "d"), streams=("S0",), deltas=(0,))
        log.seal()
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        cells = outcomes.cells(log, {m.capture_id: outcomes.Labeller(gt, m.binding, m.records)},
                               {(m.capture_id, "S0"): contexts["S0"].records})
        t_cell = next(c for c in cells if c["view"] == "T")
        self.assertEqual(t_cell["posed"] + t_cell["not_posed_GT0"], t_cell["requests"])
        self.assertEqual(sum(t_cell["dispositions"]["counts"].values()), t_cell["posed"])
        self.assertEqual(t_cell["dispositions"]["of_posed"], t_cell["posed"])
        d_cell = next(c for c in cells if c["view"] == "d")
        self.assertGreater(d_cell["escalations"]["count"], 0)
        self.assertNotIn("rate", json.dumps(cells))

    def test_allow_split_by_r7_reason_sums_to_the_allow_count(self):
        """Under Snever the change is never recorded, so the request at 30 s is allowed with no visible change
        (labelled GT-1s by its instant); the later ALLOWs follow rollout_complete. The two categories sum to
        the ALLOW count; view (a) has no R7 and is not split."""
        m = model("fault")
        log = engine.DecisionLog()
        contexts = engine.run_q2(m, log, views=("T", "T+p", "a"), streams=("Snever", "S0"), deltas=(0,))
        log.seal()
        gt = outcomes.ground_truth_from_doc(FX.scenario_ground_truth(SCENARIOS["fault"]))
        labeller = outcomes.Labeller(gt, m.binding, m.records)
        cells = {(c["view"], c["stream"]): c for c in outcomes.cells(
            log, {m.capture_id: labeller}, {(m.capture_id, s): ctx.records for s, ctx in contexts.items()})}
        for (view, stream), c in cells.items():
            split, allow = c["dispositions"]["allow_split"], c["dispositions"]["counts"].get("ALLOW", 0)
            self.assertEqual(split["of_allow"], allow, (view, stream))
            if view == "a":
                self.assertIn("not_split", split)
                continue
            self.assertEqual(split["allowed_with_no_visible_change"] + split["allowed_after_rollout_complete"],
                             allow, (view, stream))
            self.assertEqual(sum(split["by_r7_reason"].values()), allow)
        never = cells[("T", "Snever")]["dispositions"]["allow_split"]
        self.assertGreater(never["allowed_with_no_visible_change"], 0)
        self.assertGreater(never["allowed_after_rollout_complete"], 0)
        self.assertEqual(set(never["by_r7_reason"]), {outcomes.NO_VISIBLE_CHANGE, outcomes.ROLLOUT_COMPLETE})
        self.assertEqual(cells[("T", "S0")]["dispositions"]["allow_split"]["allowed_with_no_visible_change"], 0)
        unseen = [r for r in log.requests if r["view"] == "T" and r["stream"] == "Snever"
                  and r.get("disposition_r7_reason") == "no_visible_change"]
        self.assertTrue(unseen)
        for r in unseen:                                      # the evaluator's label is still the instant's label
            self.assertEqual(labeller.label(common.ts_us(r["disposition_at"]), r["d_us"])[0], outcomes.GT1S)

    def test_catalog_disruption_window_ends_after_the_first_failing_run(self):
        def probe(seconds, ok):
            return {"host_received_at": FX.iso(seconds), "batch": {"calls": [
                {"service": "recommendationservice", "functional_ok": ok},
                {"service": "productcatalogservice", "functional_ok": True}]}}
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "ground_truth").mkdir()
            path = Path(tmp) / "ground_truth/probe_rows.jsonl"

            def write(rows):
                path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            W = T(39.5)
            write([probe(38.0, False), probe(39.0, True), probe(40.1, False), probe(42.1, False), probe(44.0, True),
                   probe(46.0, True), probe(65.0, False), probe(67.0, True)])
            start, end, why = outcomes.catalog_disruption_window(Path(tmp), W)
            self.assertEqual((start, end), (W, T(44.0)))            # the failure at 65 s does not extend it
            self.assertIn("2 failing probe(s)", why)
            self.assertIn("1 failing probe(s) later", why)
            write([probe(38.0, False), probe(41.0, True)])           # no failure at or after W
            self.assertIsNone(outcomes.catalog_disruption_window(Path(tmp), W))
            write([probe(40.0, False), probe(42.0, False)])          # no OK probe after the failures
            self.assertIsNone(outcomes.catalog_disruption_window(Path(tmp), W))

    def test_t2_compares_only_cells_in_which_both_views_ran(self):
        m = model("fault")
        log = engine.DecisionLog()
        engine.run_q2(m, log, views=("T", "d"), streams=("S0",), deltas=(0,))
        engine.run_q2(m, log, views=("T",), streams=("S30",), deltas=(0,))      # (d) not run on S30
        log.seal()
        rows = outcomes.compare(log, "T", "d")
        self.assertEqual([(r["capture"], r["stream"], r["delta_s"]) for r in rows], [(m.capture_id, "S0", 0)])
        row = rows[0]
        self.assertEqual(row["posed"], sum(1 for r in log.requests if r["view"] == "T" and r["stream"] == "S0"
                                           and r["posed"]))
        self.assertEqual(row["first_verdict"]["differing_requests"], 0)          # (d) shares (T)'s knowledge rule
        disposition = row["disposition"]
        self.assertGreater(disposition["differing_requests"], 0)
        self.assertTrue(all(key.endswith("->ESCALATED") for key in disposition["severity_only_by_type"]))
        self.assertLessEqual(set(disposition["block_allow_by_direction"]), {"T allows, d blocks"})
        self.assertEqual(sum(disposition["severity_only_by_type"].values())
                         + sum(disposition["block_allow_by_direction"].values()), disposition["differing_requests"])


def redirect_default_paths(test: unittest.TestCase) -> dict:
    """For the rest of ``test``, point run_dev's default output folders (CAPTURES_OUT and FIXTURES_OUT) at a new,
    empty temporary folder (unittest.mock; the govpilot modules are not edited), so that nothing in the test
    writes capture_results/ or fixtures_results/ through a default. Returns run_dev's redirected paths by name."""
    tmp = tempfile.TemporaryDirectory(prefix="govpilot-defaults-")
    test.addCleanup(tmp.cleanup)
    folder = Path(tmp.name)
    paths = {"CAPTURES_OUT": folder / "capture_results", "FIXTURES_OUT": folder / "fixtures_results"}
    patchers = [mock.patch.multiple(run_dev, **paths)]
    for patcher in patchers:
        patcher.start()
        test.addCleanup(patcher.stop)
    return paths


class TestCaptureRunOnFixtures(unittest.TestCase):
    """The --captures path end to end (abort checks, decision and hindsight runs, seal, evaluator, reconstruction checks,
    T1-T4) on two fixture capture directories in a temporary folder, with a small grid. No real capture is read."""

    @staticmethod
    def fixture_captures(tmp: Path) -> tuple[Path, list[dict]]:
        root = tmp / "captures"
        specs = []
        for key in ("fault", "nochange"):
            sc = dataclasses.replace(FX.STANDARD[key], requests=tuple(range(20, 100, 8)))
            FX.write_capture(sc, root / sc.capture_id)
            specs.append({"id": sc.capture_id, "role": key})
        return root, specs

    def test_capture_run_path_on_fixture_captures(self):
        redirect_default_paths(self)
        with tempfile.TemporaryDirectory(prefix="govpilot-capture-run-") as tmp:
            root, specs = self.fixture_captures(Path(tmp))
            out = Path(tmp) / "out"
            paths = run_dev.run_captures(out, captures_root=root, captures=specs,
                                         views=("T", "L", "T+p", "L+p", "d", "a", "T@F600"),
                                         streams=("S0", "S150", "Snever"), deltas=(0,), hindsight_streams=("S0",),
                                         expected_requests=10)
            self.assertEqual([p.relative_to(out).as_posix() for p in paths],
                             ["results.json", "decision_log_index.json", "decision_logs/FX-fault.jsonl.gz",
                              "decision_logs/FX-nochange.jsonl.gz"])
            res = json.loads((out / "results.json").read_text(encoding="utf-8"))
            logs = res["decision_logs"]
            listed = {e["capture"]: e for e in json.loads((out / "decision_log_index.json").read_text(
                encoding="utf-8"))["logs"]}
            for entry in logs["per_capture"]:                  # one gzip per capture, as the index lists it
                text = gzip.decompress((out / "decision_logs" / entry["file"]).read_bytes())
                self.assertEqual(hashlib.sha256(text).hexdigest(), listed[entry["capture"]]["sha256_of_uncompressed_text"])
                self.assertEqual((len(text), (out / "decision_logs" / entry["file"]).stat().st_size),
                                 (entry["text_bytes"], entry["gzip_bytes"]))
                self.assertIn(f'"capture":"{entry["capture"]}"', text.decode("utf-8").splitlines()[0])

            self.assertEqual([(s["capture"], s["ok"], sorted(s["per_stream"])) for s in res["side_channel"]],
                             [(c, True, sorted(inputs.CAPTURE_STREAMS)) for c in ("FX-fault", "FX-nochange")])
            self.assertEqual([(s["capture"], s["equal"]) for s in res["gate_v1_store_vs_live_audit"]],
                             [("FX-fault", True)])
            q1 = res["T3_q1_checks"]
            for name in ("append_only_corrections", "provenance", "earlier_cutoff_invariance"):
                self.assertEqual([(c["capture"], c["stream"]) for c in q1[name]],
                                 [("FX-fault", "S0"), ("FX-fault", "S150"), ("FX-fault", "Snever")], name)
            self.assertTrue(all(c["n"] == 0 for c in q1["append_only_corrections"]))   # no capture correction
            self.assertIn("n = 0", q1["check_1_note"])
            self.assertTrue(all(c["x"] == c["n"] > 0 for c in q1["provenance"]))
            self.assertTrue(all(c["x_truncated"] == c["n"] == c["x_full_stream"] and c["n"] > 0
                                for c in q1["earlier_cutoff_invariance"]))
            self.assertGreater(q1["graph_sqlite_agreement"]["n"], 0)
            self.assertEqual(q1["graph_sqlite_agreement"]["x"], q1["graph_sqlite_agreement"]["n"])

            t1_views = {c["view"] for c in res["T1_cells"]}
            self.assertEqual(t1_views, {"T", "L", "T+p", "L+p", "d", "a"})
            for c in res["T1_cells"]:
                self.assertEqual(sum(c["dispositions"]["counts"].values()), c["posed"])
                split = c["dispositions"]["allow_split"]
                self.assertEqual(split["of_allow"], c["dispositions"]["counts"].get("ALLOW", 0))
                if c["view"] == "a":
                    self.assertIn("not_split", split)
                else:
                    self.assertEqual(split["allowed_with_no_visible_change"]
                                     + split["allowed_after_rollout_complete"], split["of_allow"])
                if c["capture"] == "FX-nochange":
                    self.assertEqual(c["posed"], 0)
            t4 = res["T4_sensitivities"]
            self.assertEqual(t4["c-hind"]["heading"], "hindsight, not a live read")
            self.assertTrue(t4["F600"] and all(r["primary_view"] == "T" and r["primary"] for r in t4["F600"]))
            self.assertTrue(t4["c-hind"]["rows"] and all(r["primary_view"] == "L" and r["primary"]
                                                         for r in t4["c-hind"]["rows"]))
            self.assertEqual(set(res["T2_comparisons"]), {"T vs L", "T+p vs L+p", "T vs d", "T vs a"})
            by_capture = {c["capture"]: c for c in res["captures"]}
            self.assertIsNone(by_capture["FX-nochange"]["binding"])
            self.assertEqual(by_capture["FX-fault"]["binding"]["deployment_uid"], binding().deployment_uid)


    def test_capture_run_is_byte_identical_in_two_interpreters(self):
        """Reconstruction check 5 on the capture-run path with per-capture logs: two interpreters
        (PYTHONHASHSEED 1 and 2) run ``run_captures`` on the same fixture captures and write
        byte-identical files: results.json, the decision-log index and every per-capture decision log."""
        program = ("import json, sys\nfrom pathlib import Path\nfrom unittest import mock\n"
                   f"sys.path[:0] = [{str(ROOT / 'src')!r}, {str(PILOT)!r}]\n"
                   "from govpilot import run_dev\n"
                   "a = json.loads(sys.argv[1])\n"
                   "with mock.patch.multiple(run_dev, **{k: Path(v) for k, v in a['defaults'].items()}):\n"
                   "    run_dev.run_captures(Path(a['out']), captures_root=Path(a['root']),\n"
                   "                         captures=a['specs'], views=('T', 'T+p', 'a'), streams=('S0', 'Snever'),\n"
                   "                         deltas=(0,), hindsight_streams=('S0',), expected_requests=10)\n")
        defaults = {name: str(path) for name, path in redirect_default_paths(self).items()}
        with tempfile.TemporaryDirectory(prefix="govpilot-capture-rerun-") as tmp:
            tmp = Path(tmp)
            root, specs = self.fixture_captures(tmp)
            published = {}
            for label, seed in (("run_a", "1"), ("run_b", "2")):
                out = tmp / label
                arguments = json.dumps({"out": str(out), "root": str(root),
                                        "specs": specs, "defaults": defaults})
                proc = subprocess.run([sys.executable, "-c", program, arguments], cwd=str(ROOT), capture_output=True,
                                      text=True, env=dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE="1"))
                self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
                published[label] = {n: common.sha256_file(out / n) for n in run_dev.output_files(out, summary=False)}
            self.assertEqual(sorted(published["run_a"]), ["decision_log_index.json", "decision_logs/FX-fault.jsonl.gz",
                                                          "decision_logs/FX-nochange.jsonl.gz", "results.json"])
            self.assertEqual(published["run_a"], published["run_b"])
        self.assertFalse(run_dev.CAPTURES_OUT.exists())

    def test_capture_streams_exclude_scorr(self):
        """Scorr is a labelled software fixture, never a capture stream."""
        self.assertEqual(inputs.CAPTURE_STREAMS, ("S0", "S30", "S150", "S180", "S300", "S1200", "Snever"))
        parameters = inspect.signature(run_dev.run_captures).parameters
        self.assertEqual(parameters["streams"].default, inputs.CAPTURE_STREAMS)
        self.assertEqual(parameters["hindsight_streams"].default, inputs.CAPTURE_STREAMS)
        self.assertIn("Scorr", run_dev.ALL_STREAMS)                 # still in the fixture plan
        self.assertIn("Scorr", run_dev.fixture_plan()[0]["streams"])


class TestDecisionLogs(unittest.TestCase):
    """Per-capture decision logs and the decision-log index."""

    def test_streamed_log_equals_its_text_and_the_index_guards_the_evaluator(self):
        m = model("fault")
        log = engine.DecisionLog(meta={"capture": m.capture_id})
        engine.run_q2(m, log, views=("T",), streams=("S0",), deltas=(0,))
        text, digest = log.text(), log.digest()
        self.assertEqual(digest, hashlib.sha256(text.encode("utf-8")).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            index = engine.LogIndex(Path(tmp), meta={"kind": "test"})
            entry = index.write(log, m.capture_id)
            self.assertEqual(gzip.decompress((Path(tmp) / entry["file"]).read_bytes()).decode("utf-8"), text)
            self.assertEqual((entry["sha256_of_uncompressed_text"], entry["requests"]), (digest, len(log.requests)))
            with self.assertRaises(engine.SealedLogError):
                log.add_request({})                             # a written log takes no more rows
            with self.assertRaises(engine.UnsealedLogError):
                index.read_requests(m.capture_id)               # no evaluator before the seal
            index.seal()
            with self.assertRaises(engine.SealedLogError):
                index.write(engine.DecisionLog(), "other")
            rows = index.read_requests(m.capture_id)
            self.assertEqual(len(rows.requests), len(log.requests))
            self.assertTrue(rows.sealed)
            (Path(tmp) / entry["file"]).write_bytes(gzip.compress(b'{"meta":{}}\n', mtime=0))
            with self.assertRaises(engine.SealedLogError):
                index.read_requests(m.capture_id)               # a changed file is refused


class TestDryRunOnFixtures(unittest.TestCase):
    """--dry-run-inputs on fixture captures (the real run reads the nine captures): the report lists, per capture, the
    client and server gitVersion that raw/kubectl-version.stdout records and whether both equal the pin. The file
    is read outside the decision reader, whose guard refuses it."""

    def test_dry_run_lists_the_recorded_kubectl_versions_per_capture(self):
        with tempfile.TemporaryDirectory(prefix="govpilot-dry-run-") as tmp:
            tmp = Path(tmp)
            specs = []
            for key, client in (("fault", rollout.KUBECTL_CLIENT_PIN), ("nochange", "v1.33.0")):
                sc = FX.STANDARD[key]
                FX.write_capture(sc, tmp / "captures" / sc.capture_id, kubectl_client=client)
                specs.append({"id": sc.capture_id, "role": key})
            paths = run_dev.dry_run_inputs(tmp / "out", captures_root=tmp / "captures", captures=specs)
            self.assertEqual([p.name for p in paths], ["input_coverage.json", "input_coverage.md"])
            report = json.loads((tmp / "out/input_coverage.json").read_text(encoding="utf-8"))
            self.assertEqual({c["capture"]: (c["kubectl_version"]["client_gitVersion"],
                                             c["kubectl_version"]["server_gitVersion"],
                                             c["kubectl_version"]["matches_pin"]) for c in report["captures"]},
                             {"FX-fault": ("v1.34.1", "v1.34.11", True), "FX-nochange": ("v1.33.0", "v1.34.11", False)})
            pin = report["kubectl_pin"]
            self.assertEqual((pin["captures_matching"], pin["of_captures"], pin["file"]),
                             (1, 2, "raw/kubectl-version.stdout"))
            self.assertEqual(pin["reference"]["pin"], rollout.KUBECTL_REFERENCE["pin"])
            self.assertTrue(rollout.KUBECTL_REFERENCE["pin"].startswith(
                "kubectl v1.34.1 (client) / Kubernetes v1.34.11 (server), recorded in "
                "phase3/captures/<C>/raw/kubectl-version.stdout for all nine captures"))
            self.assertIn("outside the decision reader", pin["read_by"])
            table = (tmp / "out/input_coverage.md").read_text(encoding="utf-8")
            self.assertIn("| v1.34.1 / v1.34.11 |", table)
            self.assertIn("| v1.33.0 / v1.34.11 |", table)
            self.assertIn("matches it in 1 of 2 captures", table)
            with self.assertRaises(inputs.ReaderSeparationError):              # not one of the reader's inputs
                inputs.read_capture(tmp / "captures/FX-fault",
                                    reader=lambda d: (d / "raw/kubectl-version.stdout").read_bytes())


if __name__ == "__main__":
    unittest.main()
