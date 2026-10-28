"""One converted capture end to end.

Order, so that no label can reach a verdict (the outcomes are labelled after the decision logs are written):

1. the validity fields (exclusion from validity fields only, before any condition is evaluated);
2. the decision phase, under the decision guard: per observer (poller, watch, recheck) one streamed decision log;
   every condition, stream, action, Delta, delta and request; reconstruction check 3 and the causality guard on every
   evaluation, check 4 counted by the dual engines;
3. the record-timing phase: transitions, contested decisions and late-correction counts, from record timing and the
   logs alone;
4. reconstruction checks 1 and 2 (check 2 on the contested decisions' evaluations plus a 10 % sample of the rest
   drawn with random.Random(0) for the capture) and cross-observer agreement, re-reading the closed logs;
5. the decision-log index is closed and written;
6. the evaluation phase: ground truth and fault records are read only now; labels, T1-T4, the per-capture sums over
   the primary cells, the measured lags; results.json and SUMMARY.md.
"""
from __future__ import annotations

import json
import platform
import sys
import time
import tracemalloc
from pathlib import Path

from . import ADAPTER_VERSION
from .capture import (DecisionInputs, arm_plan, describe_band, included, manifest_grace_seconds,
                      read_decision_inputs, read_label_inputs, validity_fields)
from .common import AdapterError, Refused, canonical, iso, json_dump, rel, sha256_file
from .conditions import CONDITIONS, OBSERVER_ORDER, conditions_for
from .engine2 import (DecisionLogWriter, LogIndex, ObserverContext, RecheckContext, Stage2Capture, run_request)
from .mapping2 import ClampLog, gate_records, k1_for_store, snapshot_pod_rows
from govpilot.inputs import API, STREAM_BY_NAME, bind  # noqa: E402  (read-only)
from govpilot.views import capture_model  # noqa: E402

LOGS_DIR = "decision_logs"
INDEX_FILE = "decision_log_index.json"
RESULTS_FILE = "results.json"
SUMMARY_FILE = "SUMMARY.md"
PRIMARY_CELLS = {
    "G": {"conditions": ("T_p", "L-kappa", "R", "T_w"), "streams": ("S0",), "actions": ("B",)},
    "D": {"conditions": ("T_p", "T_w"), "streams": ("S30", "Snever"), "actions": ("A",)},
}


# ---------------------------------------------------------------------------------------------------------------
# The capture as the decision side sees it
# ---------------------------------------------------------------------------------------------------------------
def build_capture(inputs: DecisionInputs, plan_doc: dict, *, conditions=None, cells: str = "all") -> Stage2Capture:
    scenario = inputs.scenario_id()
    if not scenario:
        raise AdapterError("the configuration row names no incident id (scenario)")
    ap = arm_plan(plan_doc, scenario)
    poller_records = tuple(inputs.base_records) + tuple(inputs.poller_api)
    if not inputs.poller_api:
        raise AdapterError("no poller api_observation rows")
    model0 = capture_model(inputs.capture_id, poller_records, inputs.requests)
    H_by = {"poller": model0.H}
    if "watch" in ap.observers:
        if not inputs.watch_api:
            raise AdapterError("the arm has a watch observer but the capture has no watch cache-snapshot rows")
        H_by["watch"] = max(r.available_at for r in inputs.watch_api)
    if "recheck" in ap.observers:
        if not inputs.recheck_ticks:
            raise AdapterError("the arm has a recheck observer but the capture has no answered tick")
        from .common import ts_us
        H_by["recheck"] = max(ts_us(p["available_at"]) for _, p in inputs.recheck_ticks)
    changed = inputs.changed_service()
    if model0.binding is not None and changed != model0.binding.service:
        raise AdapterError(f"planned service {changed} differs from the binding's {model0.binding.service}")
    notes = {}
    if model0.binding is not None and inputs.watch_api:
        try:
            watch_binding = bind(tuple(inputs.base_records) + tuple(inputs.watch_api), model0.P)
            notes["watch_binding_equals_poller_binding"] = watch_binding.deployment_uid == model0.binding.deployment_uid \
                and watch_binding.revision == model0.binding.revision \
                and watch_binding.generation == model0.binding.generation
        except Exception as error:     # recorded, never a decision input
            notes["watch_binding_error"] = repr(error)
    b_targets = {}
    for k, _ in inputs.requests:
        spans = inputs.spans.server_spans(k, changed) if changed else []
        if not spans:
            b_targets[k] = {"why": f"no server span of {changed} in request {k}'s trace"}
            continue
        first = spans[0]
        if not first.pod_uid:
            b_targets[k] = {"why": f"request {k}'s server span of {changed} has no k8s.pod.uid"}
            continue
        b_targets[k] = {"uid": first.pod_uid, "a_us": first.acquired_us, "span": first.evidence_id,
                        "server_spans": len(spans)}
    names = list(ap.conditions)
    streams, actions = list(ap.streams), list(ap.actions)
    if cells == "primary":
        primary = PRIMARY_CELLS[ap.arm]
        names = [n for n in names if n in primary["conditions"]]
        streams = [s for s in streams if s in primary["streams"]]
        actions = [a for a in actions if a in primary["actions"]]
    elif cells != "all":
        raise AdapterError("--cells must be primary or all")
    if conditions:
        unknown = [c for c in conditions if c not in ap.conditions]
        if unknown:
            raise AdapterError(f"conditions {unknown} are not in arm {ap.arm}'s plan ({', '.join(ap.conditions)})")
        names = [n for n in names if n in conditions]
    for name in names:
        if CONDITIONS[name].observer not in ap.observers:
            raise AdapterError(f"{name} needs the {CONDITIONS[name].observer} observer, absent from arm {ap.arm}")
    observers = tuple(o for o in OBSERVER_ORDER if any(CONDITIONS[n].observer == o for n in names))
    return Stage2Capture(inputs.capture_id, ap, model0.binding, model0.P, min(H_by.values()), H_by,
                         dict(model0.service_deployments), changed, dict(ap.floors), tuple(inputs.requests),
                         b_targets, observers, tuple(names), tuple(streams), tuple(ap.deltas), tuple(ap.dispatch),
                         tuple(actions), notes)


def service_pod_uids(inputs: DecisionInputs, service: str | None) -> frozenset:
    """UIDs of the changed service's Pods in any observer's K1-ready rows (label app)."""
    out = set()
    for rows in inputs.k1_rows.values():
        for row in rows:
            if (row["pod"]["metadata"].get("labels") or {}).get("app") == service:
                out.add(row["pod_uid"])
    return frozenset(out)


def k1_table_rows(extraction: dict, observer: str) -> list[dict]:
    rows = []
    for o in extraction["observations"]:
        rows.append({"observer": observer, "observation_id": o["observation_id"], "pod_uid": o["pod_uid"],
                     "state": o["state"], "stamp": o["stamp"], "stamp_us": o["stamp_us"],
                     "observed_at_us": o["observed_at_us"], "available_at_us": o["available_at_us"],
                     "source_record": o["source_record"], "source_field": o["source_field"],
                     "clock_clamped": o["clock_clamped"], "clamps": o["clamps"]})
    return rows


# ---------------------------------------------------------------------------------------------------------------
# Phase 2: decisions
# ---------------------------------------------------------------------------------------------------------------
def decision_phase(capture: Stage2Capture, inputs: DecisionInputs, logs_dir: Path, index: LogIndex,
                   meta: dict, *, progress=None) -> dict:
    out = {"units": [], "k1": {}, "clamps": {}, "dropped_kinds": {}, "r2_starts": None}
    service_uids = service_pod_uids(inputs, capture.changed_service)
    conds = conditions_for(capture.condition_names)
    for observer in capture.observers:
        mine = [c for c in conds if c.observer == observer]
        path = logs_dir / f"{capture.capture_id}.{observer}.jsonl.gz"
        log = DecisionLogWriter(path, dict(meta, observer=observer, conditions=[c.config() for c in mine]))
        clamps = ClampLog()
        started = time.perf_counter()
        if observer in ("poller", "watch"):
            api, dropped = gate_records(inputs.observer_api(observer))
            out["dropped_kinds"][observer] = dropped
            records = tuple(inputs.base_records) + tuple(api)
            k1_obs, extraction = k1_for_store(inputs.k1_rows[observer], snapshot_pod_rows(api, observer),
                                              band_us=inputs.band_us)
            out["k1"][observer] = extraction["counts"]
            log.table("k1", k1_table_rows(extraction, observer))
            k1_index = sorted((o["stamp_us"], o["available_at_us"]) for o in extraction["observations"]
                              if o["pod_uid"] in service_uids)
            for stream in capture.stream_names:
                ctx = ObserverContext(capture, observer, STREAM_BY_NAME[stream], records, k1_obs, clamps, log)
                try:
                    for cond in mine:
                        if cond.streams_only and stream not in cond.streams_only:
                            continue
                        for family in capture.actions:
                            for delta_cap in capture.deltas:
                                for delta in capture.dispatch:
                                    for k, t_us in capture.requests:
                                        run_request(cond, ctx, capture, family, k, t_us, delta_cap, delta, log,
                                                    k1_index=k1_index)
                    out["units"].append({"observer": observer, "stream": stream,
                                         "provenance": dict(ctx.provenance), "engines": ctx.engine_counts(),
                                         "evaluations": len(ctx.memo),
                                         "relevant_subjects": None if ctx.relevant is None else len(ctx.relevant)})
                finally:
                    ctx.close()
                if progress:
                    progress(f"{capture.capture_id} {observer} {stream}: {len(ctx.memo)} evaluations")
        else:
            rows = inputs.k1_rows.get("recheck") or []
            k1_index = []
            if rows:
                from aiops_kg import fault_control_kill as K
                extraction = K.k1_extract(rows, band_us=inputs.band_us)
                out["k1"][observer] = extraction["counts"]
                log.table("k1", k1_table_rows(extraction, observer))
                k1_index = sorted((o["stamp_us"], o["available_at_us"]) for o in extraction["observations"]
                                  if o["pod_uid"] in service_uids)
            ctx = RecheckContext(capture, inputs.recheck_ticks, clamps, log)
            try:
                for cond in mine:
                    for family in capture.actions:
                        for delta_cap in capture.deltas:
                            for delta in capture.dispatch:
                                for k, t_us in capture.requests:
                                    run_request(cond, ctx, capture, family, k, t_us, delta_cap, delta, log,
                                                k1_index=k1_index)
                log.table("r2_start", ctx.r2_starts)
                out["r2_starts"] = len(ctx.r2_starts)
                out["units"].append({"observer": observer, "stream": "*", "provenance": dict(ctx.provenance),
                                     "engines": ctx.engine_counts(), "evaluations": len(ctx.memo)})
            finally:
                ctx.close()
        log.table("clamp", clamps.rows())
        out["clamps"][observer] = len(clamps.rows())
        entry = log.close()
        index.add(observer, entry, {"evaluations": log.evaluations, "requests": log.requests,
                                    "facts": len(log.facts_written), "seconds": None})
        out.setdefault("seconds", {})[observer] = round(time.perf_counter() - started, 3)
    return out


# ---------------------------------------------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------------------------------------------
def run_capture(converted, plan_path, out_dir, *, raw=None, conditions=None, cells: str = "all",
                allow_excluded: bool = False, measure: bool = False, progress=None) -> dict:
    """The adapter on one converted capture; writes ``out_dir`` (which must not exist). Returns the results doc."""
    from . import checks2, design, labels, tables
    converted = Path(converted).resolve()
    from .capture import raw_capture_of
    raw = Path(raw).resolve() if raw else raw_capture_of(converted)
    validity = validity_fields(raw)
    excluded_mark = None
    if not included(validity):
        if not allow_excluded:
            raise Refused(f"refused: the capture is excluded by its validity fields {validity}; an excluded "
                          "attempt is never analysed for outcomes")
        excluded_mark = ("EXCLUDED: the validity fields exclude this capture; analysed with --allow-excluded "
                         "for diagnostics only, never for outcomes")
    out_dir = Path(out_dir)
    if out_dir.exists():
        raise Refused(f"refused: {out_dir} exists; outputs are never overwritten")
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    if measure:
        tracemalloc.start()
    wall = time.perf_counter()
    inputs = read_decision_inputs(converted, raw=raw)
    capture = build_capture(inputs, plan_doc, conditions=conditions, cells=cells)
    out_dir.mkdir(parents=True)
    logs_dir = out_dir / LOGS_DIR
    logs_dir.mkdir()
    plan_record = {"path": rel(plan_path)}
    meta = {"kind": "Stage-2 governance adapter decision log (one per capture and observer)",
            "capture": capture.capture_id, "plan": plan_record, "adapter": ADAPTER_VERSION,
            "binding": capture.binding.to_dict() if capture.binding else None, "P": iso(capture.P),
            "H": iso(capture.H)}
    index = LogIndex(logs_dir, meta=dict(meta))
    decision = decision_phase(capture, inputs, logs_dir, index, meta, progress=progress)
    timing = design.transitions(inputs, capture)
    contested = design.contested(index, capture, timing)
    checks = checks2.q1_checks(index, capture, inputs, contested, progress=progress)
    agreement = checks2.cross_observer_agreement(capture, inputs)
    index.seal()
    index.write(out_dir / INDEX_FILE)
    # ---- evaluation phase: only now are ground truth and fault records read ----
    label_inputs = read_label_inputs(converted, raw)
    labeller = labels.Labeller.build(capture, inputs, label_inputs, manifest_grace_seconds(inputs.configuration))
    evaluation = tables.evaluate(index, capture, labeller, contested)
    lags = design.measured_lags(inputs, capture, timing, label_inputs)
    results = {
        "adapter": ADAPTER_VERSION, **({"excluded_mark": excluded_mark} if excluded_mark else {}),
        "plan": plan_record, "python": "{}.{}".format(*sys.version_info[:2]),
        "validity_fields": validity, "capture": capture.summary(), "plan_cells": capture.plan.to_dict(),
        "cells": cells, "inputs": inputs.notes, "clock_band": describe_band(inputs.clock_band),
        "decision_logs": {"directory": LOGS_DIR, "index_file": INDEX_FILE,
                          "per_observer": [{k: v for k, v in index.entries[o].items()
                                            if "sha256" not in k and k not in ("text_bytes", "gzip_bytes")}
                                           for o in sorted(index.entries)]},
        "decision_phase": {k: v for k, v in decision.items() if k != "seconds"},
        "k1": decision["k1"], "creation_ceiling_clamps": decision["clamps"],
        "transitions": timing.summary(), "design_check": contested.summary(),
        "late_corrections": evaluation.pop("late_corrections"),
        "T3_q1_checks": checks, "cross_observer_agreement": agreement,
        "labels": labeller.summary(), "measured_lags": lags, **evaluation,
    }
    json_dump(out_dir / RESULTS_FILE, results)
    (out_dir / SUMMARY_FILE).write_text(tables.render_summary(results), encoding="utf-8", newline="\n")
    runtime = {"seconds_wall": round(time.perf_counter() - wall, 3), "seconds_by_observer": decision.get("seconds")}
    if measure:
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        runtime["python_heap_peak_bytes"] = peak
    results["_runtime_not_written"] = runtime
    return results


# ---------------------------------------------------------------------------------------------------------------
# The fixture self-check (--check) and the byte comparison of two runs (reconstruction check 5)
# ---------------------------------------------------------------------------------------------------------------
EXPECTED_KEYS = ("capture", "plan_cells", "k1", "creation_ceiling_clamps", "transitions", "design_check",
                 "late_corrections", "T1_cells", "T2_comparisons", "T4_sensitivities", "primary_sums", "U_executions",
                 "cross_observer_agreement", "measured_lags", "labels")


def run_check_fixture(target, *, conditions=None, progress=None) -> dict:
    """tiny_g2 under the narrowed plan (fixtures.check_plan), written and run under ``target`` (out: target/out)."""
    from .fixtures import write_check_fixture
    converted, plan_path = write_check_fixture(target)
    return run_capture(converted, plan_path, Path(target) / "out", conditions=conditions, progress=progress)


def expectation_view(results: dict) -> dict:
    """The parts of results.json the committed expectation pins: every count and label, never a hash, a version or
    a path (those change with any code edit)."""
    view = {k: results[k] for k in EXPECTED_KEYS}
    view["T3_q1_checks"] = {k: v for k, v in results["T3_q1_checks"].items() if k != "check_1_note"}
    view["decision_phase"] = {k: results["decision_phase"][k] for k in ("units", "k1", "clamps", "dropped_kinds",
                                                                        "r2_starts")}
    view["decision_logs"] = [{k: e[k] for k in ("observer", "evaluations", "requests", "facts", "lines_by_kind")}
                             for e in results["decision_logs"]["per_observer"]]
    return json.loads(json.dumps(view, sort_keys=True))


def diff_docs(expected, actual, path: str = "") -> list[str]:
    """Paths at which two JSON documents differ (at most one line per differing leaf)."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in sorted(set(expected) | set(actual)):
            if key not in actual:
                out.append(f"{path}/{key}: missing in this run")
            elif key not in expected:
                out.append(f"{path}/{key}: not in the expectation")
            else:
                out += diff_docs(expected[key], actual[key], f"{path}/{key}")
        return out
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return [f"{path}: {len(expected)} items expected, {len(actual)} found"]
        out = []
        for i, (a, b) in enumerate(zip(expected, actual)):
            out += diff_docs(a, b, f"{path}[{i}]")
        return out
    return [] if expected == actual else [f"{path}: expected {expected!r}, found {actual!r}"]


def compare_trees(first, second) -> dict:
    """Byte comparison of two output directories (reconstruction check 5: deterministic replay)."""
    first, second = Path(first), Path(second)
    a = {p.relative_to(first).as_posix() for p in first.rglob("*") if p.is_file()}
    b = {p.relative_to(second).as_posix() for p in second.rglob("*") if p.is_file()}
    differing = sorted(name for name in a & b if (first / name).read_bytes() != (second / name).read_bytes())
    return {"files": len(a | b), "identical": not differing and a == b, "differing": differing,
            "only_first": sorted(a - b), "only_second": sorted(b - a)}
