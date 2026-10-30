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

``decision_log_pass`` (arm G, action B, stream S0; results/stage2/analyses/decision_log/<capture>.json)
    a log that keeps, with every decision of T_p, the input records behind each of its evaluations (cited records,
    the records behind cited facts and their input records; ``ObserverContext.records_behind``), against the
    questions a retrospective audit asks: the same decisions under every other setting of ``settings()``, and decided
    at the recheck's instants (T_p@R, ``replays.at_recheck_instants``). A decision's re-evaluation can be answered
    from the log only if every input record it needs is in the log: from the decision's own entry, or at best from
    the union of all entries. Per question: posed decisions, decisions whose disposition differs from the gate's,
    and how many of each the decision's own entry and the union of all entries cover; with the log's size against
    the records and versions of the two-clock store.

``check_to_act_pass`` (arm G, action B, stream S0; results/stage2/analyses/check_to_act/<capture>.json)
    the fresh recheck's executions (R decides and executes at the receipt x_R of a response) labelled as if the
    deletion took effect ``ACT_LAGS`` seconds after x_R: how many would then have met an invalid, an uncertain or a
    valid state, i.e. how much a gap between the recheck's read and the action could matter.
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
from .engine2 import RecheckContext, pose, run_request
from .labels import GT2A, GT2B, U, UNSAFE, Labeller
from .mapping2 import ClampLog
from .pipeline import build_capture
from .replays import BASE, at_recheck_instants, delayed_poller, first_tick_receipt, poller_context, verdict_agreement

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


# ---------------------------------------------------------------------------------------------------------------
# A log of each decision's inputs against re-evaluation
# ---------------------------------------------------------------------------------------------------------------
def log_coverage(base: list, other: list, union: frozenset) -> OrderedDict:
    """``base`` and ``other``: (row, input records) per decision, in the same order. Counts over the posed decisions:
    whose disposition differs, and which the decision's own log entry, or the union of all entries, covers."""
    out = OrderedDict((k, 0) for k in ("posed", "own_log", "all_logs", "outcome_changed", "changed_own_log",
                                       "changed_all_logs"))
    for (b, logged), (r, needed) in zip(base, other):
        if not b.get("posed"):
            continue
        own, every = needed <= logged, needed <= union
        out["posed"] += 1
        out["own_log"] += own
        out["all_logs"] += every
        if r.get("disposition") != b.get("disposition"):
            out["outcome_changed"] += 1
            out["changed_own_log"] += own
            out["changed_all_logs"] += every
    return out


def decision_log_pass(converted, plan_path, out_path, *, raw=None, progress=None) -> dict:
    """See the module docstring (``decision_log_pass``)."""
    inputs = read_decision_inputs(converted, raw=raw)
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    capture = build_capture(inputs, plan_doc, conditions=list(BASE))
    if capture.plan.arm != "G":
        raise ValueError("arm-G captures only")
    Tp = ADAPTER_CONDITIONS["T_p"]
    timing = OrderedDict()
    started = time.perf_counter()
    ctx, k1_index = poller_context(capture, inputs)
    rctx = RecheckContext(capture, inputs.recheck_ticks, ClampLog(), None)
    ctx.input_log = {}

    def logged(run):
        ctx.trace = []
        row = run()
        keys, ctx.trace = ctx.trace, None
        needed = set()
        for key in keys:
            needed |= ctx.input_log.get(key, frozenset())
        return row, frozenset(needed)

    reqs = list(requests(capture))

    def decide(cond):
        return [logged(lambda q=q: run_request(cond, ctx, capture, "B", q[2], q[3], q[0], q[1], None,
                                               k1_index=k1_index)) for q in reqs]
    base = decide(Tp)
    union = frozenset().union(*(needed for _, needed in base))
    sizes = sorted(len(needed) for row, needed in base if row.get("posed"))
    questions = OrderedDict()
    for name, F, N in settings():
        if (F, N) == (30.0, 30.0):
            continue
        questions[name] = log_coverage(base, decide(dataclasses.replace(Tp, name="T_p[%s]" % name, F=F, N=N)),
                                       union)
    at_r = []
    for q, (tp, _) in zip(reqs, base):
        if not tp.get("posed"):
            at_r.append((tp, frozenset()))
            continue
        act = pose(capture, "B", q[2], q[3], q[0])[2]
        at_r.append(logged(lambda tp=tp, act=act: at_recheck_instants(Tp, ctx, rctx, capture, act, tp)))
    questions["at the recheck's instants"] = log_coverage(base, at_r, union)
    m = ctx.model
    store_records = len(m.availability)
    ctx.close()
    rctx.close()
    timing["decision log"] = round(time.perf_counter() - started, 1)
    if progress:
        progress("%s decision log %.1f s" % (capture.capture_id, timing["decision log"]))
    doc = OrderedDict([
        ("capture", capture.capture_id), ("arm", capture.plan.arm), ("scenario", capture.plan.scenario),
        ("decisions", len(reqs)), ("posed", len(sizes)),
        ("log", OrderedDict([("records_per_decision", OrderedDict([
                                 ("median", sizes[len(sizes) // 2] if sizes else 0),
                                 ("max", sizes[-1] if sizes else 0)])),
                             ("record_references", sum(sizes)), ("distinct_records", len(union))])),
        ("store", OrderedDict([("records", store_records), ("versions", len(m.observations))])),
        ("questions", questions), ("seconds", timing)])
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc



ACT_LAGS = (0.0, 0.1, 0.5, 1.0)


def check_to_act_pass(converted, plan_path, out_path, *, raw=None, progress=None) -> dict:
    """See the module docstring (``check_to_act_pass``)."""
    inputs = read_decision_inputs(converted, raw=raw)
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    capture = build_capture(inputs, plan_doc, conditions=list(BASE))
    if capture.plan.arm != "G":
        raise ValueError("arm-G captures only")
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(Path(converted).resolve())
    labeller = Labeller.build(capture, inputs, read_label_inputs(Path(converted).resolve(), raw_dir),
                              manifest_grace_seconds(inputs.configuration))
    started = time.perf_counter()
    rctx = RecheckContext(capture, inputs.recheck_ticks, ClampLog(), None)
    rows = _rows(ADAPTER_CONDITIONS["R"], rctx, capture, "B")
    rctx.close()
    counts = OrderedDict(("%g s" % lag, Counter()) for lag in ACT_LAGS)
    for row in rows:
        if not row.get("posed") or row.get("disposition") != ALLOW or row.get("dispatch_us") is None:
            continue
        for lag in ACT_LAGS:
            label, _, _ = labeller.label_b(row["dispatch_us"] + int(round(lag * 1e6)), row["target_uid"])
            kind = "invalid" if label in UNSAFE["B"] else "uncertain" if label == U else "valid"
            counts["%g s" % lag][kind] += 1
    seconds = round(time.perf_counter() - started, 1)
    if progress:
        progress("%s check to act %.1f s" % (capture.capture_id, seconds))
    doc = OrderedDict([("capture", capture.capture_id), ("scenario", capture.plan.scenario),
                       ("executions_by_lag", OrderedDict((k, OrderedDict((x, v.get(x, 0)) for x in (
                           "invalid", "uncertain", "valid"))) for k, v in counts.items())),
                       ("seconds", {"check to act": seconds})])
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc
