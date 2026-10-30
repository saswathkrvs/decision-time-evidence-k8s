"""Decision coverage, a parameter sweep of the gate and a receipt-time audit of the follow-up captures.

    sweep_pass(converted, plan_path, out_path)      # results/stage2/analyses/sweeps/<capture>.json

Every analysis reuses the adapter's posing (``engine2.pose``, ``run_request``), gate evaluation
(``ObserverContext.evaluate``, ``RecheckContext``) and outcome labels (``labels.Labeller``), as ``replays.py`` does;
only the gate's parameters, or the record a replay reads, change. Cells: the capture plan's cutoffs Delta and dispatch
delays delta.

``coverage`` (arm G, action B, stream S0)
    every posed decision of T_p, L-kappa, R and T_p+lag (T_p's decisions, each allow executed at the next answered
    recheck tick after its dispatch instant, as in ``replays.py``) by outcome: executed with a definite label
    (invalid: V-target or V-floor; valid: neutral or a mitigation opportunity), executed with an uncertain label, or
    not executed -- approval requested or denied (by deciding rule), expired, or censored at the common horizon (not
    evaluable); per dispatch delay. ``mutually_evaluable``: the decisions that neither T_p nor R left censored, with
    both views' outcomes on them. ``invalid_by_target_state``: the target's state at each invalid execution (gone,
    terminating, not ready, below the floor), i.e. what a restart request would have met.
    ``opportunity_executions``: executions inside a mitigation window, split by whether the decision was posed while
    the opportunity existed.

``sweep`` (arm G: actions B and A in stream S0; arm D: action A in streams S0, S30 and Snever)
    the two-clock poller gate (T_p) with the freshness limit F and R2's recent-change window N varied one at a time:
    F in ``SWEEP_F`` at N = 30 s, N in ``SWEEP_N`` at F = 30 s (arm-G rollbacks: N only). Per setting: posed,
    executions, invalid, uncertain, valid, mitigation opportunities and missed ones, and the decisions not executed
    by verdict and deciding rule.

``store`` (arm G): the poller's two-clock store in stream S0 -- versions (observations), identity facts and distinct
    (subject, predicate) keys, i.e. what a latest-snapshot store keeps one version of. ``evaluations`` in every count:
    the gate evaluations the decisions needed (with ``seconds``, the evaluation cost of this implementation).

``audit`` (arm G, action B, stream S0)
    T_p's decisions replayed from a receipt-time record -- every record taken to hold from the instant it became
    available (observations valid from their availability, recorded transition times dropped, identity facts valid
    from their availability), as an auditor holding an append-only log with receipt timestamps only would replay
    them -- at the captured latency and with every poller record 5 and 30 s later, against the gate's own decisions
    on the same records (first verdict, disposition, execution), with the invalid executions the replay reports.
"""
from __future__ import annotations

import dataclasses
import json
import time
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

from aiops_kg.policy_gate import ALLOW

from .capture import arm_plan, manifest_grace_seconds, raw_capture_of, read_decision_inputs, read_label_inputs
from .common import iso
from .conditions import CONDITIONS as ADAPTER_CONDITIONS
from .engine2 import RecheckContext, run_request
from .labels import GT2A, GT2B, U, UNSAFE, Labeller
from .mapping2 import ClampLog
from .pipeline import build_capture
from .replays import BASE, delayed_poller, first_tick_receipt, poller_context, verdict_agreement

SWEEP_F = (10.0, 30.0, 60.0, 120.0, 600.0)
SWEEP_N = (0.0, 10.0, 30.0, 60.0, 600.0)
LATENCIES = (5, 30)
D_STREAMS = ("S0", "S30", "Snever")
OPPORTUNITY = {"A": GT2A, "B": GT2B}


def settings():
    """(name, F, N) of every swept setting; the shared point F = N = 30 s once."""
    out = [("F=%g,N=30" % f, f, 30.0) for f in SWEEP_F]
    out += [("F=30,N=%g" % n, 30.0, n) for n in SWEEP_N if n != 30.0]
    return out


def requests(capture):
    for delta_cap in capture.plan.deltas:
        for delta in capture.plan.dispatch:
            for k, t_us in capture.requests:
                yield delta_cap, delta, k, t_us


def label_of(labeller, family: str, row: dict):
    x = row["dispatch_us"]
    if family == "A":
        label, reason = labeller.label_a(x, row["kappa_us"])
        return label, reason
    label, reason, _ = labeller.label_b(x, row["target_uid"])
    return label, reason


def outcome(row: dict, labeller, family: str) -> tuple:
    """(kind, detail) of one posed decision: ('invalid' | 'valid' | 'uncertain', label reason) for an execution,
    else ('not executed', disposition[deciding rules]) or ('censored', ...)."""
    disposition = row.get("disposition")
    if disposition == ALLOW and row.get("dispatch_us") is not None:
        label, reason = label_of(labeller, family, row)
        if label in UNSAFE[family]:
            return "invalid", reason, label
        if label == U:
            return "uncertain", reason, label
        return "valid", reason, label
    if disposition == "CENSORED":
        return "censored", "horizon", None
    if disposition == "EXPIRED":
        return "expired", "expiry", None
    rules = sorted({s.split(":")[0] for s in row.get("disposition_source") or []})
    return "declined", "%s[%s]" % (disposition, "+".join(rules)), None


def tally(rows, labeller, family: str) -> OrderedDict:
    out = OrderedDict([("posed", 0), ("executions", 0), ("invalid", 0), ("uncertain", 0), ("valid", 0),
                       ("opportunities", 0), ("missed", 0), ("expired", 0), ("censored", 0), ("evaluations", 0)])
    declined, invalid_reasons, uncertain_reasons = Counter(), Counter(), Counter()
    by_delay = defaultdict(lambda: Counter())
    in_window_exec = Counter()
    for row in rows:
        if not row.get("posed"):
            continue
        out["posed"] += 1
        out["evaluations"] += (row.get("evaluations") or {}).get("count", 0)
        d = row["delta_s"]
        by_delay[d]["posed"] += 1
        kind, detail, label = outcome(row, labeller, family)
        executed_in_window = False
        opportunity = labeller.opportunity_at(family, row["kappa_us"], row.get("target_uid"))
        if kind in ("invalid", "uncertain", "valid"):
            out["executions"] += 1
            out[kind] += 1
            by_delay[d]["executions"] += 1
            by_delay[d][kind] += 1
            if kind == "invalid":
                invalid_reasons[detail] += 1
            elif kind == "uncertain":
                uncertain_reasons[detail] += 1
            executed_in_window = labeller.in_window(row["dispatch_us"])
            if label == OPPORTUNITY[family]:
                in_window_exec["posed as an opportunity" if opportunity else "posed before the opportunity"] += 1
        elif kind == "declined":
            declined[detail] += 1
            by_delay[d]["declined"] += 1
        else:
            out[kind] += 1
            by_delay[d][kind] += 1
        if opportunity:
            out["opportunities"] += 1
            by_delay[d]["opportunities"] += 1
            if not executed_in_window:
                out["missed"] += 1
                by_delay[d]["missed"] += 1
    out["declined"] = dict(sorted(declined.items()))
    out["invalid_by_target_state"] = dict(sorted(invalid_reasons.items()))
    out["uncertain_by_reason"] = dict(sorted(uncertain_reasons.items()))
    out["opportunity_executions"] = dict(sorted(in_window_exec.items()))
    out["by_dispatch_delay"] = OrderedDict(("%g s" % d, dict(sorted(v.items()))) for d, v in sorted(by_delay.items()))
    return out


def mutually_evaluable(rows_a, rows_b, labeller, family: str) -> OrderedDict:
    """The posed decisions that neither view left censored at the common horizon, and both views' outcomes."""
    out = OrderedDict([("posed", 0), ("excluded_censored", 0)])
    kinds = {"a": Counter(), "b": Counter()}
    by_delay = defaultdict(lambda: {"a": Counter(), "b": Counter(), "decisions": 0})
    for a, b in zip(rows_a, rows_b):
        assert (a["k"], a["Delta_s"], a["delta_s"]) == (b["k"], b["Delta_s"], b["delta_s"])
        if not a.get("posed"):
            continue
        out["posed"] += 1
        if a.get("disposition") == "CENSORED" or b.get("disposition") == "CENSORED":
            out["excluded_censored"] += 1
            continue
        cell = by_delay[a["delta_s"]]
        cell["decisions"] += 1
        for side, row in (("a", a), ("b", b)):
            kind = outcome(row, labeller, family)[0]
            kind = "not executed" if kind in ("declined", "expired") else kind
            kinds[side][kind] += 1
            cell[side][kind] += 1
    out["decisions"] = out["posed"] - out["excluded_censored"]
    out["outcomes"] = {side: dict(sorted(c.items())) for side, c in kinds.items()}
    out["by_dispatch_delay"] = OrderedDict(("%g s" % d, {"decisions": v["decisions"],
                                                         "a": dict(sorted(v["a"].items())),
                                                         "b": dict(sorted(v["b"].items()))})
                                           for d, v in sorted(by_delay.items()))
    return out


# ---------------------------------------------------------------------------------------------------------------
# Receipt-time record
# ---------------------------------------------------------------------------------------------------------------
def receipt_time_model(model):
    """The same records with every valid time moved to the record's availability (see the module docstring)."""
    observations = []
    for o in model.observations:
        if o.observed_at != o.available_at or o.starts_at is not None:
            observations.append(dataclasses.replace(o, observed_at=o.available_at, starts_at=None))
        else:
            observations.append(o)
    facts = []
    for f in model.identity_facts:
        if f.valid_from is not None and f.valid_from != f.available_at:
            facts.append(dataclasses.replace(f, valid_from=f.available_at))
        else:
            facts.append(f)
    return dataclasses.replace(model, observations=tuple(observations), identity_facts=tuple(facts))


def to_receipt_time(ctx):
    ctx.close()
    ctx.model = receipt_time_model(ctx.model)
    ctx._stores, ctx.memo, ctx._schedules, ctx._hind_index = {}, {}, {}, None
    return ctx


# ---------------------------------------------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------------------------------------------
def _rows(cond, ctx, capture, family, *, k1_index=None, name=None):
    out = []
    for delta_cap, delta, k, t_us in requests(capture):
        row = run_request(cond, ctx, capture, family, k, t_us, delta_cap, delta, None, k1_index=k1_index)
        out.append(dict(row, condition=name or cond.name))
    return out


def lagged(rows_tp, rctx, capture) -> list:
    """T_p's decisions with every allow executed at the next answered recheck tick after its dispatch instant (the
    T_p+lag view of ``replays.decisions``); an allow with no such tick by the horizon is censored."""
    out = []
    for tp in rows_tp:
        moved = dict(tp, condition="T_p+lag")
        if tp.get("disposition") == ALLOW and tp.get("dispatch_us") is not None:
            x_r = first_tick_receipt(rctx, tp["dispatch_us"], capture.H)
            moved["dispatch_us"] = x_r
            if x_r is None:
                moved["disposition"] = "CENSORED"
        out.append(moved)
    return out


def sweep_pass(converted, plan_path, out_path, *, raw=None, progress=None) -> dict:
    inputs = read_decision_inputs(converted, raw=raw)
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    conditions = list(BASE) if arm_plan(plan_doc, inputs.scenario_id()).arm == "G" else ["T_p"]
    capture = build_capture(inputs, plan_doc, conditions=conditions)
    arm = capture.plan.arm
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(Path(converted).resolve())
    labeller = Labeller.build(capture, inputs, read_label_inputs(Path(converted).resolve(), raw_dir),
                              manifest_grace_seconds(inputs.configuration))
    Tp, Lk, Rc = ADAPTER_CONDITIONS["T_p"], ADAPTER_CONDITIONS["L-kappa"], ADAPTER_CONDITIONS["R"]
    timing = OrderedDict()

    def note(name, started):
        timing[name] = round(time.perf_counter() - started, 1)
        if progress:
            progress("%s %s %.1f s" % (capture.capture_id, name, timing[name]))

    doc = OrderedDict([("capture", capture.capture_id), ("arm", arm), ("scenario", capture.plan.scenario),
                       ("cells", {"Delta_s": list(capture.plan.deltas), "delta_s": list(capture.plan.dispatch)}),
                       ("H", iso(capture.H))])
    families = ("B", "A") if arm == "G" else ("A",)
    streams = ("S0",) if arm == "G" else D_STREAMS
    base_rows = {}
    if arm == "G":
        started = time.perf_counter()
        ctx, k1_index = poller_context(capture, inputs)
        rctx = RecheckContext(capture, inputs.recheck_ticks, ClampLog(), None)
        rows = {"T_p": _rows(Tp, ctx, capture, "B", k1_index=k1_index),
                "L-kappa": _rows(Lk, ctx, capture, "B"),
                "R": _rows(Rc, rctx, capture, "B")}
        rows["T_p+lag"] = lagged(rows["T_p"], rctx, capture)
        base_rows["B", "S0"] = rows["T_p"]
        m = ctx.model
        doc["store"] = OrderedDict([("observations", len(m.observations)), ("identity_facts", len(m.identity_facts)),
                                    ("keys", len({(o.subject, o.predicate) for o in m.observations}))])
        rctx.close()
        ctx.close()
        note("coverage", started)
        doc["coverage"] = OrderedDict((name, tally(r, labeller, "B")) for name, r in rows.items())
        doc["mutually_evaluable"] = OrderedDict([
            ("T_p vs R", mutually_evaluable(rows["T_p"], rows["R"], labeller, "B")),
            ("L-kappa vs R", mutually_evaluable(rows["L-kappa"], rows["R"], labeller, "B"))])
    sweep = OrderedDict()
    for stream in streams:
        for family in families:
            started = time.perf_counter()
            ctx, k1_index = poller_context(capture, inputs, stream=stream)
            cells = OrderedDict()
            for name, F, N in settings():
                if arm == "G" and family == "A" and F != 30.0:
                    continue        # arm-G rollbacks: R2's window only (the freshness limit is swept on restarts)
                if F == 30.0 and N == 30.0 and (family, stream) in base_rows:
                    rows = base_rows[family, stream]
                else:
                    cond = dataclasses.replace(Tp, name="T_p[%s]" % name, F=F, N=N)
                    rows = _rows(cond, ctx, capture, family, k1_index=k1_index)
                cells[name] = tally(rows, labeller, family)
            ctx.close()
            sweep["%s | %s" % (family, stream)] = cells
            note("sweep %s %s" % (family, stream), started)
    doc["sweep"] = sweep
    if arm == "G":
        audit = OrderedDict()
        for latency in (0,) + LATENCIES:
            started = time.perf_counter()
            if latency == 0:
                truth = base_rows["B", "S0"]
                rctx_, _ = poller_context(capture, inputs)
            else:
                api, k1 = delayed_poller(inputs, latency)
                tctx, k1_index = poller_context(capture, inputs, api=api, k1_rows=k1)
                truth = _rows(Tp, tctx, capture, "B", k1_index=k1_index)
                tctx.close()
                rctx_, _ = poller_context(capture, inputs, api=api, k1_rows=k1)
            replay = _rows(Tp, to_receipt_time(rctx_), capture, "B", name="T_p[receipt-time]")
            rctx_.close()
            audit["%d s" % latency] = OrderedDict([
                ("gate", tally(truth, labeller, "B")),
                ("receipt_time_replay", tally(replay, labeller, "B")),
                ("receipt_time_vs_gate", verdict_agreement(truth, replay))])
            note("audit %d s" % latency, started)
        doc["audit"] = audit
    doc["seconds"] = timing
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc
