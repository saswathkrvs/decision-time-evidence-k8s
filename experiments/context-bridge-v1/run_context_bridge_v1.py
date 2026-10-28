#!/usr/bin/env python3
"""context-bridge v1: context policy -> entity attribution -> per-entity aggregates -> unchanged anomaly ranker.

Default mode (no arguments): a mechanism demonstration on the 22 Sep 2026 rollout of recommendationservice
(rollout-telemetry pilot-001, 120 requests, no fault). It is not an accuracy result: there is no faulty entity, so
no true-entity rank exists; the "anomalous" window is the 20 s after the rollout patch.

For every stream (complete, delayed_api_{1,3,10,30}s, missing_switch_poll, corrected_late_{3,10}s; built by
experiments/replay-policy-v1's own build_perturbations, imported read-only), every decision time
c = onset + Delta (Delta in {0, 5, 30, 60} s; onset = host receipt of the rollout-patch response) and every policy
(latest_state, temporal_join, bitemporal_abstain F = 600 s and 30 s) it runs src/aiops_kg/context_bridge.py:
attribution of each observed window request to a Pod (replay.attribute_instance at cutoff c), candidate set,
per-Pod aggregates, graph_rank anomaly scores (unchanged), and the same for the hindsight reference (span-verified
serving Pods; evaluator only).

    PYTHONDONTWRITEBYTECODE=1 python3 experiments/context-bridge-v1/run_context_bridge_v1.py

Writes results.json, results.csv and SUMMARY.md into this folder (or --output DIR). The grid is computed twice
in-process (the run aborts if the passes differ); unless --skip-rerun is given, a second, separate process writes
the outputs to a temporary directory and SUMMARY.md records whether results.json and results.csv are byte-identical.

Capture mode (the development captures; phase3/CAPTURE_FORMAT.md):

    PYTHONDONTWRITEBYTECODE=1 python3 experiments/context-bridge-v1/run_context_bridge_v1.py --capture phase3/captures/<name>

applies the bridge's inclusion rule (context_bridge.inclusion) first; an excluded capture gets
<capture>/context_bridge/{exclusion.json, SUMMARY.md} and no grid. An included capture gets the same grid as the
default mode, scored against the fault's truth Pod from ground_truth/ (evaluator only), in
<capture>/context_bridge/{results.json, results.csv, SUMMARY.md} (never overwritten; or --output DIR).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True  # before any project import
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

import networkx  # noqa: E402
import numpy  # noqa: E402

from aiops_kg import context_bridge as B  # noqa: E402
from aiops_kg import replay as R  # noqa: E402

RPV1_SCRIPT = ROOT / "experiments/replay-policy-v1/run_replay_policy_v1.py"
RPV1_RESULTS = ROOT / "experiments/replay-policy-v1/results.json"
STREAMS = B.PROTOCOL["streams"]
DELTAS = tuple((f"{d} s", d) for d in B.PROTOCOL["deltas_seconds"])
W_BEFORE, W_AFTER = B.PROTOCOL["window_before_seconds"], B.PROTOCOL["window_after_seconds"]
LS, TJ, BA, B30 = "latest_state", "temporal_join", "bitemporal_abstain_F600", "bitemporal_abstain_F30"
POLICY_ORDER = (LS, TJ, BA, B30)
POLICY_LABEL = {LS: "latest_state", TJ: "temporal_join", BA: "bitemporal_abstain F=600 s",
                B30: "bitemporal_abstain F=30 s", B.HINDSIGHT: "hindsight (reference)"}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("verification failed: " + message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def rel(path: Path) -> str:
    return Path(path).resolve().relative_to(ROOT).as_posix()      # POSIX separators on every platform


def write_text_lf(path: Path, text: str) -> None:
    """Write UTF-8 text with LF line endings on every platform (Windows write_text would emit CRLF and change the
    byte-level fingerprints that the identity checks and tests compare)."""
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def number(request_id: str) -> int:
    return int(request_id.split("/", 1)[1])


def fmt_list(items) -> str:
    items = sorted(items)
    if not items:
        return "none"
    out, start, prev = [], items[0], items[0]
    for x in items[1:] + [None]:
        if x is not None and x == prev + 1:
            prev = x
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        if x is not None:
            start = prev = x
    return ", ".join(out)


def rpv1_module():
    return R.import_script(RPV1_SCRIPT, "replay_policy_v1_readonly_for_context_bridge")


# ---------------------------------------------------------------------------
# Streams: replay-policy-v1's own perturbation builders over the union of every service's Pod records
# ---------------------------------------------------------------------------
def rollout_streams(rpv1, bridge):
    task = bridge.primary_task
    proxy = SimpleNamespace(records=bridge.records, candidates=task.candidates, events=task.events)
    built = {p["name"]: p for p in rpv1.build_perturbations(proxy)}
    return [built[name] for name in STREAMS], []


def capture_streams(rpv1, bridge):
    task = bridge.primary_task
    proxy = SimpleNamespace(records=bridge.records, candidates=task.candidates if task else (),
                            events=task.events if task else (), predicate="STATE", serving_value="ready",
                            retired_values=B.RETIRED,
                            context={"service": bridge.changed_service or "(no changed service)"})
    built, skipped = rpv1.build_capture_perturbations(proxy)
    by_name = {p["name"]: p for p in built}
    return [by_name[n] for n in STREAMS if n in by_name], [s for s in skipped if s["name"] in STREAMS]


def usable_records(stream, bridge, c) -> dict:
    return {svc.service: sum(len(stream.visible(cand.key, svc.predicate, c)) for cand in svc.candidates)
            for svc in bridge.services}


# ---------------------------------------------------------------------------
# The grid
# ---------------------------------------------------------------------------
def run_grid(bridge, streams, policies, onset, truth_entity):
    windows = B.Windows.seconds(onset, W_BEFORE, W_AFTER)
    requests, served_by = bridge.spans.requests, bridge.spans.served_by
    base = R.Stream(bridge.records)
    hindsight = {}
    for label, d in DELTAS:
        c = B.decision_cutoff(onset, d)
        hindsight[label] = {"delta": label, "delta_seconds": d,
                            **B.evaluate_cell(base, bridge.services, requests, c, windows, None, served_by,
                                              truth_entity)}
    cells = []
    for s in streams:
        stream = R.Stream(s["records"])
        for label, d in DELTAS:
            c = B.decision_cutoff(onset, d)
            usable = usable_records(stream, bridge, c)
            for policy in policies:
                cell = B.evaluate_cell(stream, bridge.services, requests, c, windows, policy, served_by,
                                       truth_entity)
                cells.append({"stream": s["name"], "delta": label, "delta_seconds": d, **cell,
                              "usable_records": usable})
    return hindsight, cells


def fingerprint(hindsight, cells) -> str:
    return sha256_bytes(json.dumps([hindsight, cells], sort_keys=True, default=list).encode("utf-8"))


# ---------------------------------------------------------------------------
# Cross-checks (default mode)
# ---------------------------------------------------------------------------
def crosscheck_attribution_vs_rpv1(bridge, streams, policies) -> dict:
    """Per-request cutoffs c = t_req + Delta (replay-policy-v1's task): the bridge's attribution call for the
    rollout service must reproduce replay-policy-v1's recorded answer and status strings cell by cell."""
    reference = json.loads(RPV1_RESULTS.read_text(encoding="utf-8"))
    ref = {(c["policy"], c["perturbation"], c["delta"]): c for c in reference["cells"]}
    task = bridge.primary_task
    svc = next(s for s in bridge.services if s.service == bridge.changed_service)
    events = sorted(task.events, key=lambda e: task.request_index[e.record_id])
    codes = {"old": "O", "new": "N", None: "?"}
    total = equal = decisions = 0
    differing = []
    for s in streams:
        stream = R.Stream(s["records"])
        for policy in policies:
            for label, delta in task.deltas:
                answers, statuses = [], []
                for event in events:
                    t = event.observed_at
                    c = R.HINDSIGHT if delta is None else t + R.seconds_to_us(delta)
                    d = B.attribute_one(stream, svc, t, c, policy)
                    answers.append(codes[d.answer])
                    statuses.append(d.status[0])
                    decisions += 1
                theirs = ref[(policy.name, s["name"], label)]
                total += 1
                if "".join(answers) == theirs["answers"] and "".join(statuses) == theirs["statuses"]:
                    equal += 1
                else:
                    differing.append([policy.name, s["name"], label])
    return {"cells": total, "cells_equal": equal, "decisions": decisions, "differing": differing[:10],
            "streams": len(streams), "policies": len(policies), "deltas": [label for label, _ in task.deltas],
            "scope": "rollout service (recommendationservice), every stream of this run x policy x replay-policy-v1 "
                     "Delta (0, 5, 30, 120 s, hindsight) with per-request cutoffs c = t_req + Delta; compared with "
                     "the answers/statuses strings in experiments/replay-policy-v1/results.json"}


def crosscheck_streams_vs_rpv1(rpv1, bridge, streams) -> dict:
    """The rollout service's records in each stream equal replay-policy-v1's own stream built from its own task."""
    own = {p["name"]: p for p in rpv1.build_perturbations(bridge.primary_task)}
    keys = {c.key for c in bridge.primary_task.candidates}
    out = {}
    for s in streams:
        mine = sorted((r.record_id, r.subject, r.value, r.observed_at, r.available_at, r.corrects)
                      for r in s["records"] if r.subject in keys)
        theirs = sorted((r.record_id, r.subject, r.value, r.observed_at, r.available_at, r.corrects)
                        for r in own[s["name"]]["records"])
        out[s["name"]] = mine == theirs
    return out


def crosscheck_requests_vs_task(bridge) -> dict:
    """Request numbering, valid times and span-verified truth of the bridge equal the rollout task's."""
    task = bridge.primary_task
    spans = bridge.spans
    t_of = {task.request_index[e.record_id]: e.observed_at for e in task.events}
    label_of = {c.key: c.label for c in task.candidates}
    same_index = all(spans.index_of[r.request_id] == number(r.request_id) for r in spans.requests)
    same_t = all(t_of[number(r.request_id)] == r.t for r in spans.requests)
    same_truth = all(label_of.get(spans.served_by[r.request_id][bridge.changed_service]) ==
                     task.truth[f"request/{number(r.request_id)}"] for r in spans.requests)
    return {"requests": len(spans.requests), "index_equals_aiops_request_index": same_index,
            "t_equals_task_t_req": same_t, "span_truth_equals_task_truth": same_truth}


# ---------------------------------------------------------------------------
# Output shaping
# ---------------------------------------------------------------------------
def compact_cell(cell) -> dict:
    out = json.loads(json.dumps(cell, default=list))
    for svc in out["services"].values():
        for key in ("request_ids", "wrong_request_ids", "abstained_request_ids"):
            svc[key] = fmt_list(number(x) for x in svc[key])
    for ent in out["entities"].values():
        for w in B.WINDOWS:
            ent[w]["requests"] = fmt_list(number(x) for x in ent[w].pop("request_ids"))
    return out


def attach_hindsight(cells, hindsight) -> None:
    """Copy the hindsight n / median / score of every entity into each policy cell (for side-by-side reading)."""
    for cell in cells:
        ref = hindsight[cell["delta"]]
        for key, ent in cell["entities"].items():
            h = ref["entities"].get(key)
            for w in B.WINDOWS:
                ent[w]["hindsight_n"] = h[w]["n"] if h else 0
                ent[w]["hindsight_median"] = h[w]["median"] if h else {}
            ent["hindsight_anomaly_score"] = (h["anomaly"] or {}).get("score") if h else None
        for key, h in ref["entities"].items():
            if key not in cell["entities"]:
                cell["entities"][key] = {"service": h["service"], "label": h["label"], "in_view": None,
                                         "candidate": False, "hindsight_candidate": h["hindsight_candidate"],
                                         "not_shown_by_policy": True,
                                         **{w: {"n": 0, "hindsight_n": h[w]["n"], "hindsight_median": h[w]["median"]}
                                            for w in B.WINDOWS},
                                         "anomaly": None, "hindsight_anomaly_score": (h["anomaly"] or {}).get("score")}


def entity_names(bridge) -> dict:
    """Display names of the candidate Pods, plus the unsighted Pods (evaluator-only reporting rows)."""
    short = {"recommendationservice": "recommendation", "productcatalogservice": "catalog"}
    names = {c.key: f"{short.get(s.service, s.service)} {c.label} {c.key.split('/', 1)[1][:8]}"
             for s in bridge.services for c in s.candidates}
    for u in B.unsighted_entities(bridge.services, bridge.spans.requests, bridge.spans.served_by):
        names.setdefault(u["entity"], f"{short.get(u['service'], u['service'])} unsighted "
                                      f"{u['entity'].split('/', 1)[1][:8]}")
    return names


def unsighted_report(bridge, names, onset) -> list:
    """The per-capture list of unsighted Pods: requests served, in total and per analysis window (evaluator only)."""
    windows = B.Windows.seconds(onset, W_BEFORE, W_AFTER)
    return [{**u, "name": names[u["entity"]]}
            for u in B.unsighted_entities(bridge.services, bridge.spans.requests, bridge.spans.served_by, windows)]


def stream_entries(streams, skipped) -> list:
    out = []
    for s in streams:
        m = s["manifest"]
        entry = {"name": s["name"], "family": s["family"], "description": s["description"],
                 "records": len(s["records"]), "perturbation": m.get("perturbation")}
        if m.get("perturbation") == "delay":
            entry["changed_records"] = m["changed"]
        elif m.get("perturbation") == "drop_transition":
            entry["dropped"] = [{k: e[k] for k in ("record_id", "subject", "from", "to", "observed_at", "available_at")}
                                for e in m["records"]]
        elif m.get("perturbation") == "correct_late":
            entry["corrected"] = [{"original": e["original"], "subject": e["subject"],
                                   "stale": e["stale"], "corrected": e["corrected"]} for e in m["records"]]
        out.append(entry)
    return out + [{"name": s["name"], "not_applicable": s["reason"]} for s in skipped]


def base_results(bridge, streams, skipped, policies, onset, onset_source, hindsight, cells, checks):
    hindsight = {label: compact_cell(h) for label, h in hindsight.items()}
    cells = [compact_cell(c) for c in cells]
    attach_hindsight(cells, hindsight)
    names = entity_names(bridge)
    windows = B.Windows.seconds(onset, W_BEFORE, W_AFTER)
    spans = bridge.spans
    candidate_services = {s.service for s in bridge.services}
    split = {}
    for r in spans.requests:
        w = windows.of(r.t)
        if w is None:
            continue
        for svc, key in spans.served_by[r.request_id].items():
            label = names.get(key) or (f"{svc} unverified" if svc in candidate_services
                                       else f"{svc} (not a candidate service)")
            split.setdefault(w, {}).setdefault(label, []).append(number(r.request_id))
    return {
        "setup": {
            "onset": R.iso(onset), "onset_source": onset_source,
            "windows": {"normal": [R.iso(onset - windows.before_us), R.iso(onset)],
                        "anomalous": [R.iso(onset), R.iso(onset + windows.after_us)]},
            "deltas": [{"delta": label, "cutoff": R.iso(B.decision_cutoff(onset, d))} for label, d in DELTAS],
            "services": [{"service": s.service, "role": "frontend" if s.service == spans.frontend_service else
                          "downstream", "candidates": [{"key": c.key, "label": c.label, "name": names[c.key],
                                                        "created_floor": R.iso(c.created_floor)}
                                                       for c in s.candidates]} for s in bridge.services],
            "features": {s: list(v) for s, v in B.service_features(spans.requests).items()},
            "requests": len(spans.requests),
            "window_requests_by_true_pod": {w: {k: fmt_list(v) for k, v in sorted(d.items())}
                                            for w, d in sorted(split.items())},
            "window_request_counts_by_true_pod": {w: {k: len(v) for k, v in sorted(d.items())}
                                                  for w, d in sorted(split.items())},
            "records": len(bridge.records),
            "records_by_service": {s.service: sum(1 for r in bridge.records if r.subject in set(s.keys))
                                   for s in bridge.services},
            "t_req": {str(number(r.request_id)): R.iso(r.t) for r in spans.requests},
            "changed_service": bridge.changed_service,
            "notes": list(bridge.notes),
        },
        "entity_names": names,
        "unsighted_entities": unsighted_report(bridge, names, onset),
        "policies": [{"name": p.name, "abstains_by_design": p.abstains, "uses_observation_time": p.valid_time,
                      "params": dict(p.params)} for p in policies],
        "streams": stream_entries(streams, skipped),
        "cross_checks": checks,
        "hindsight": hindsight,
        "cells": cells,
    }


LIMITATIONS = [
    "One rollout of one single-replica service (maxSurge 1, maxUnavailable 0) on a single-node kind cluster, NO fault. "
    "No true faulty entity exists, so no rank of a true entity, Top-1 or accuracy can be computed or is claimed.",
    "The 'anomalous' window is the 20 s after the rollout patch was accepted; its anomaly scores describe a rollout, "
    "not a fault. Every ranking returns some order because the ranker has no threshold.",
    "Record-stream perturbations are simulated on top of measured timestamps (replay-policy-v1's definitions); the "
    "measured record-delivery lag was sub-millisecond.",
    "Telemetry is assumed usable the moment a request's root span ends (optimistic). The measured trace-export and "
    "evidence-index ingestion times are different availability boundaries and are not used.",
    "Request times (node clock) and the onset / API receipt times (host clock) are not calibrated against each other; "
    "window membership of requests within about a second of the onset could change with a clock offset.",
    "n is tiny: 120 requests of one rollout, 67 of them in the analysis window. Streams, Deltas and policies are "
    "replays of the same requests, not independent incidents.",
    "Features overlap: the frontend-observed request duration contains the downstream call. The per-Pod medians "
    "describe this rollout only.",
]


# ---------------------------------------------------------------------------
# Default mode: the 22 Sep 2026 rollout
# ---------------------------------------------------------------------------
def compute_default():
    rpv1 = rpv1_module()
    bridge = B.load_rollout_input(ROOT)
    onset, onset_source = B.rollout_onset(bridge)
    policies = rpv1.make_policies()
    check([p.name for p in policies] == list(POLICY_ORDER), "policy set differs from replay-policy-v1")
    check([(p.name.split("_F")[0], dict(p.params).get("freshness_seconds")) for p in policies] ==
          [tuple(x) for x in B.PROTOCOL["policies"]], "policies differ from the bridge configuration")
    streams, skipped = rollout_streams(rpv1, bridge)
    hindsight, cells = run_grid(bridge, streams, policies, onset, None)
    return rpv1, bridge, onset, onset_source, policies, streams, skipped, hindsight, cells


def run_default(output: Path | None, skip_rerun: bool) -> int:
    rpv1, bridge, onset, onset_source, policies, streams, skipped, hindsight, cells = compute_default()
    again = compute_default()
    check(fingerprint(hindsight, cells) == fingerprint(again[7], again[8]), "two in-process passes differ")
    checks = {
        "attribution_vs_replay_policy_v1": crosscheck_attribution_vs_rpv1(bridge, streams, policies),
        "streams_vs_replay_policy_v1": crosscheck_streams_vs_rpv1(rpv1, bridge, streams),
        "requests_vs_rollout_task": crosscheck_requests_vs_task(bridge),
        "two_in_process_passes_identical": True,
    }
    a = checks["attribution_vs_replay_policy_v1"]
    check(a["cells_equal"] == a["cells"], f"attribution differs from replay-policy-v1: {a['differing']}")
    check(all(checks["streams_vs_replay_policy_v1"].values()), "a stream differs from replay-policy-v1's")
    q = checks["requests_vs_rollout_task"]
    check(all(v for k, v in q.items() if k != "requests"), f"requests differ from the rollout task: {q}")
    results = {
        "kind": "context_to_ranking_bridge_mechanism_demonstration_one_rollout_no_fault_not_accuracy",
        "scope": ("Mechanism demonstration, one rollout, no fault. Shows how each context policy changes entity "
                  "attribution, candidate membership and per-Pod aggregates that an unchanged anomaly ranker "
                  "consumes. No faulty entity exists; no rank of a true entity or accuracy is computed or claimed."),
        **base_results(bridge, streams, skipped, policies, onset, onset_source, hindsight, cells, checks),
        "environment": {"python": platform.python_version(), "numpy": numpy.__version__,
                        "networkx": networkx.__version__},
        "limitations": LIMITATIONS,
    }
    results = json.loads(json.dumps(results, default=list))  # exactly what results.json holds
    results_bytes = (json.dumps(results, indent=1) + "\n").encode("utf-8")
    csv_bytes = results_csv(results).encode("utf-8")
    rerun = None
    if not skip_rerun:
        rerun = separate_process_rerun(results_bytes, csv_bytes)
        check(rerun["results_json_identical"] and rerun["results_csv_identical"],
              f"a separate process produced different outputs: {rerun}")
    summary = render_summary(results, rerun)  # checks every stated claim before anything is written
    out = (output or HERE).resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_bytes(results_bytes)
    (out / "results.csv").write_bytes(csv_bytes)
    write_text_lf(out / "SUMMARY.md", summary)
    for c in results["cells"]:
        if c["delta"] in ("0 s", "30 s") and c["stream"] in ("complete", "delayed_api_30s"):
            print(f"{c['stream']:18s} {c['delta']:5s} {c['policy']:24s} mis {c['mis_attributed_total']:3d} "
                  f"abstained {c['abstained_total']:3d} missing {len(c['candidates']['missing_vs_hindsight'])}")
    print("cross-checks:", json.dumps({"attribution_vs_replay_policy_v1": f"{a['cells_equal']}/{a['cells']} cells",
                                       "streams": all(checks["streams_vs_replay_policy_v1"].values()),
                                       "requests": q}))
    print("outputs:", out)
    return 0


def separate_process_rerun(results_bytes: bytes, csv_bytes: bytes) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        command = [sys.executable, str(Path(__file__).resolve()), "--output", tmp, "--skip-rerun"]
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        check(done.returncode == 0, "separate-process rerun failed:\n" + done.stdout + done.stderr)
        other_json = (Path(tmp) / "results.json").read_bytes()
        other_csv = (Path(tmp) / "results.csv").read_bytes()
    return {"command": "python3 experiments/context-bridge-v1/run_context_bridge_v1.py --output <temporary "
                       "directory> --skip-rerun (a fresh interpreter)",
            "results_json_sha256_this_run": sha256_bytes(results_bytes),
            "results_json_sha256_separate_run": sha256_bytes(other_json),
            "results_json_identical": other_json == results_bytes,
            "results_csv_sha256_this_run": sha256_bytes(csv_bytes),
            "results_csv_sha256_separate_run": sha256_bytes(other_csv),
            "results_csv_identical": other_csv == csv_bytes}


CSV_COLUMNS = ("stream", "delta", "cutoff", "policy", "entity", "service", "in_view", "candidate",
               "hindsight_candidate", "n_normal", "n_anomalous", "mis_attributed_normal", "mis_attributed_anomalous",
               "lost_to_other_anomalous", "lost_to_abstain_anomalous", "duration_median_normal_ms",
               "duration_median_anomalous_ms", "hindsight_n_normal", "hindsight_n_anomalous",
               "hindsight_duration_median_normal_ms", "hindsight_duration_median_anomalous_ms", "anomaly_score",
               "hindsight_anomaly_score", "usable_indicators", "unscorable_reason", "anomaly_only_position",
               "service_mis_attributed", "service_abstained", "service_coverage", "truth_rank_pessimistic",
               "truth_outcome")


def results_csv(results) -> str:
    """One row per stream x Delta x policy (hindsight rows: stream '-') x entity."""
    names = results["entity_names"]
    buffer = io.StringIO()
    w = csv.writer(buffer, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    rows = [("-", h) for h in results["hindsight"].values()] + [(c["stream"], c) for c in results["cells"]]
    for stream, cell in rows:
        position = {e: i + 1 for i, (e, _) in enumerate(cell["ranking"]["anomaly_only"])}
        for key in sorted(cell["entities"], key=lambda k: names[k]):
            ent = cell["entities"][key]
            svc = cell["services"][ent["service"]]
            dur = next(f for f in B.DURATION_FEATURES if f in results["setup"]["features"][ent["service"]])
            med = lambda slot, k: (slot.get(k) or {}).get(dur)
            nw, aw = ent[B.NORMAL], ent[B.ANOMALOUS]
            is_h = cell["policy"] == B.HINDSIGHT
            w.writerow([stream, cell["delta"], cell["cutoff"], cell["policy"], names[key], ent["service"],
                        ent["in_view"], ent["candidate"], ent["hindsight_candidate"], nw["n"], aw["n"],
                        nw.get("mis_attributed", 0), aw.get("mis_attributed", 0), aw.get("lost_to_other", 0),
                        aw.get("lost_to_abstain", 0), med(nw, "median"), med(aw, "median"),
                        nw["n"] if is_h else nw.get("hindsight_n"), aw["n"] if is_h else aw.get("hindsight_n"),
                        med(nw, "median") if is_h else med(nw, "hindsight_median"),
                        med(aw, "median") if is_h else med(aw, "hindsight_median"),
                        (ent["anomaly"] or {}).get("score"),
                        (ent["anomaly"] or {}).get("score") if is_h else ent.get("hindsight_anomaly_score"),
                        (ent["anomaly"] or {}).get("usable_indicators"), ent.get("unscorable_reason"),
                        position.get(key), svc["mis_attributed"], svc["abstained"], svc["coverage"],
                        cell["truth"]["rank_pessimistic"], cell["truth"]["outcome"]])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# SUMMARY.md (default mode): every number is read from results.json; every stated pattern is checked first
# ---------------------------------------------------------------------------
def f3(value) -> str:
    return "-" if value is None else f"{value:.3f}"


def render_summary(res, rerun) -> str:
    cells, names = res["cells"], res["entity_names"]
    setup = res["setup"]

    def C(stream, policy, delta):
        found = [c for c in cells if (c["stream"], c["policy"], c["delta"]) == (stream, policy, delta)]
        check(len(found) == 1, f"cell {stream} {policy} {delta}")
        return found[0]

    H = lambda delta: res["hindsight"][delta]
    front = next(s for s in setup["services"] if s["role"] == "frontend")
    down = next(s for s in setup["services"] if s["role"] == "downstream")
    old = next(c["key"] for c in front["candidates"] if c["label"] == "old")
    new = next(c["key"] for c in front["candidates"] if c["label"] == "new")
    cat = down["candidates"][0]["key"]
    fs, ds = front["service"], down["service"]
    short = {old: "old", new: "new", cat: "catalog", None: "none"}
    dur = {fs: "frontend_request_duration_ms", ds: "downstream_server_duration_ms"}
    deltas = [d["delta"] for d in setup["deltas"]]
    streams = [s["name"] for s in res["streams"]]
    rows_of = lambda stream, delta: [C(stream, p, delta) for p in POLICY_ORDER] + [H(delta)]
    score = lambda cell, key: ((cell["entities"].get(key) or {}).get("anomaly") or {}).get("score")
    hscore = lambda delta, key: score(H(delta), key)
    med = lambda cell, key, w: ((cell["entities"].get(key) or {}).get(w, {}).get("median") or {}).get(
        dur[cell["entities"][key]["service"]]) if key in cell["entities"] else None
    top1 = lambda cell: cell["ranking"]["top1_entity"]
    counts = setup["window_request_counts_by_true_pod"]
    n_norm = H("0 s")["requests"]["normal"]["observed"]
    n_anom_total = H("0 s")["requests"]["anomalous"]["not_yet_observed"]

    # ---- claim checks (every pattern stated below is verified here first) ----------------------------------
    # 1. Delta = 0: no anomalous-window request has ended; every score is 0; only membership changes.
    for s in streams:
        for c in rows_of(s, "0 s"):
            check(c["requests"]["anomalous"]["observed"] == 0, f"{s}: anomalous request observed at Delta 0")
            check(all(v == 0 for _, v in c["ranking"]["anomaly_only"]) and top1(c) is None, f"{s}: score at 0")
    d30z = rows_of("delayed_api_30s", "0 s")[:4]
    check(all(v == 0 for v in d30z[0]["usable_records"].values()), "delayed_api_30s has usable records at 0")
    check(all(c["candidates"]["in_view"] == [] and c["candidates"]["policy"] == [] and
              c["abstained_total"] == 2 * n_norm for c in d30z), "delayed_api_30s at 0: all abstain")
    zero_other = [s for s in streams if s != "delayed_api_30s"]
    check(all(C(s, p, "0 s")["mis_attributed_total"] == 0 and C(s, p, "0 s")["abstained_total"] == 0
              for s in zero_other for p in POLICY_ORDER), "other streams at 0 s: no error, no abstention")
    # 2. complete, Delta = 30 s.
    ls = C("complete", LS, "30 s")
    rec_ls = ls["services"][fs]
    check(rec_ls["mis_attributed"] == counts["normal"][names[old]] + counts["anomalous"][names[old]]
          and rec_ls["wrong_request_ids"] == f"1-{counts['normal'][names[old]] + counts['anomalous'][names[old]]}",
          "LS complete 30: all old-Pod requests mis-attributed")
    e_new = ls["entities"][new]
    check(e_new["normal"]["n"] == e_new["normal"]["mis_attributed"] == counts["normal"][names[old]]
          and e_new["normal"]["hindsight_n"] == 0, "LS: new Pod normal window = old-Pod requests only")
    check(e_new["anomalous"]["mis_attributed"] == counts["anomalous"][names[old]], "LS: anomalous mis-attributed")
    check(ls["candidates"]["missing_vs_hindsight"] == [old] and ls["entities"][old]["in_view"]
          and not ls["entities"][old]["candidate"], "LS: old Pod in view but not a candidate")
    check(H("30 s")["entities"][new]["unscorable_reason"] == "empty_normal_window" and hscore("30 s", new) == 0,
          "hindsight: new Pod unscorable")
    check(score(ls, new) > 0 and top1(ls) == new and top1(H("30 s")) == cat, "LS: Top-1 flips to the new Pod")
    tj = C("complete", TJ, "30 s")
    check(tj["mis_attributed_total"] == 0 and tj["abstained_total"] == 0 and
          tj["ranking"]["anomaly_only"] == H("30 s")["ranking"]["anomaly_only"], "TJ complete 30 = hindsight")
    ba = C("complete", BA, "30 s")
    check(ba["mis_attributed_total"] == 0 and ba["services"][fs]["abstained_request_ids"] == "31-32, 39-43"
          and ba["services"][fs]["abstain_reasons"] == {"two_pods_possible": 7} and top1(ba) == top1(H("30 s")),
          "BA complete 30: 7 abstentions, same Top-1")
    check(C("complete", B30, "30 s")["services"] == ba["services"], "F=30 equals F=600 on complete at 30 s")
    # 3. delayed_api_30s, Delta = 30 s.
    dl = [C("delayed_api_30s", p, "30 s") for p in POLICY_ORDER]
    check(dl[0]["usable_records"] == C("complete", LS, "0 s")["usable_records"],
          "delayed_api_30s at 30 s sees exactly the records usable at the onset")
    for c in dl:
        r = c["services"][fs]
        check(r["mis_attributed"] == counts["anomalous"][names[new]] and r["wrong_request_ids"] == "44-67"
              and r["abstained"] == 0, f"{c['policy']}: 24 new-Pod requests to the old Pod")
        check(c["candidates"]["missing_vs_hindsight"] == [new] and not c["entities"][new]["candidate"]
              and c["entities"][new]["in_view"] is False, f"{c['policy']}: new Pod not in view")
        check(c["entities"][old]["anomalous"]["mis_attributed"] == counts["anomalous"][names[new]], "old A mis")
        check(score(c, old) > 0 and hscore("30 s", old) == 0 and top1(c) == old, f"{c['policy']}: Top-1 old")
    n_new = counts["anomalous"][names[new]]
    check(all(c["services"][fs]["mis_attributed_fallback"] == n_new for c in dl[2:]) and
          all(c["services"][fs]["mis_attributed_confirmed"] == n_new for c in dl[:2]), "status labels of wrong answers")
    key4 = lambda c: (c["mis_attributed_total"], c["abstained_total"], c["candidates"]["missing_vs_hindsight"], top1(c))
    check(all(key4(C("delayed_api_30s", p, "60 s")) == key4(C("complete", p, "30 s")) for p in POLICY_ORDER),
          "delayed_api_30s at 60 s behaves like complete at 30 s")
    # 4. The collapsed entity equals the pooled service traffic in both cases.
    check(score(ls, new) == score(dl[0], old) and ls["entities"][new]["normal"]["requests"] ==
          dl[0]["entities"][old]["normal"]["requests"] and ls["entities"][new]["anomalous"]["requests"] ==
          dl[0]["entities"][old]["anomalous"]["requests"] == f"30-{29 + 38}", "pooled windows")
    # 5. missing switch poll.
    for d in ("30 s", "60 s"):
        check(C("missing_switch_poll", TJ, d)["services"][fs]["wrong_request_ids"] == "44-49", f"TJ missing {d}")
        for p in (BA, B30):
            m = C("missing_switch_poll", p, d)
            check(m["mis_attributed_total"] == 0 and m["services"][fs]["abstained_request_ids"] == "31-32, 39-49",
                  f"{p} missing {d}")
        check(C("missing_switch_poll", LS, d)["mis_attributed_total"] == 43, f"LS missing {d}")
    # 6. corrected-late streams equal complete in every cell.
    same = lambda a, b: (a["services"], a["entities"], a["ranking"], a["candidates"]) == \
        (b["services"], b["entities"], b["ranking"], b["candidates"])
    corr = [s for s in streams if s.startswith("corrected_late_")]
    for s in corr:
        check(all(same(C(s, p, d), C("complete", p, d)) for p in POLICY_ORDER for d in deltas), f"{s} = complete")
    corr_entries = [e for s in res["streams"] if s["name"] in corr for e in s["corrected"]]
    cut = {d["delta"]: us_of(d["cutoff"]) for d in setup["deltas"]}
    check(all(us_of(e["stale"]["available_at"]) > cut["5 s"] and us_of(e["corrected"]["available_at"]) <= cut["30 s"]
              for e in corr_entries), "corrected poll after c at 5 s, correction usable by 30 s")
    switch_at = min(us_of(e["stale"]["available_at"]) for e in corr_entries)
    # 7. catalog.
    check(all(c["services"][ds]["mis_attributed"] == 0 for c in cells), "catalog never mis-attributed")
    cat_abst = [(c["stream"], c["policy"], c["delta"], c["services"][ds]["abstained"]) for c in cells
                if c["services"][ds]["abstained"]]
    check({(s, d) for s, _, d, _ in cat_abst} == {("delayed_api_30s", "0 s"), ("delayed_api_30s", "5 s")},
          f"catalog abstentions {cat_abst}")
    # 8. smaller delays at 30 / 60 s behave like complete; nothing is mis-attributed at 5 s.
    small = [s for s in streams if s in ("delayed_api_1s", "delayed_api_3s", "delayed_api_10s")]
    for s in small:
        check(all(key4(C(s, p, d)) == key4(C("complete", p, d)) for p in POLICY_ORDER for d in ("30 s", "60 s")),
              f"{s} like complete at 30/60 s")
    check(all(C(s, p, "5 s")["mis_attributed_total"] == 0 for s in streams for p in POLICY_ORDER), "no error at 5 s")
    t_req = {int(k): us_of(v) for k, v in setup["t_req"].items()}
    first_new = min(int(x) for x in setup["window_requests_by_true_pod"]["anomalous"][names[new]].split("-")[:1])
    check(first_new == 44 and t_req[first_new] > cut["5 s"], "the new Pod's first request starts after c at 5 s")
    # 9. secondary PPR.
    check(ls["ranking"]["ppr_top1_entity"] == cat and H("30 s")["ranking"]["ppr_top1_entity"] == cat, "PPR Top-1")
    ppr_ls = {e: p for e, p, _ in ls["ranking"]["ppr"]}
    # 10. hindsight Top-1 and observed counts per Delta.
    check(all(top1(H(d)) == cat for d in deltas if d != "0 s"), "hindsight Top-1 is the catalog Pod from 5 s")

    # ---- document ------------------------------------------------------------------------------------------
    cc = res["cross_checks"]
    a = cc["attribution_vs_replay_policy_v1"]
    L = ["# context-bridge v1: context policy -> Pod attribution -> per-Pod aggregates -> unchanged anomaly ranker", "",
         "**Mechanism demonstration, one rollout, no fault. Not an accuracy result.** The 22 Sep 2026 rollout of "
         "recommendationservice (pilot-001) is the only real capture. It has no fault, so no true faulty entity, no "
         "rank of a true entity, no Top-1 hit and no accuracy exist here; the \"anomalous\" window is simply the 20 s "
         "after the rollout patch was accepted. What is measured is how each context policy changes which Pod each "
         "request is attributed to, which Pods are candidates, and what each Pod's aggregate and anomaly score look "
         "like, compared with the span-verified hindsight reference. Streams, cutoffs and policies are replays of the "
         "same 120 requests, not independent incidents.", "",
         "`run_context_bridge_v1.py` generates this file from `results.json` (values rounded to 3 decimals). Every "
         "stated pattern is checked in code before the file is written; the grid is computed twice in-process and "
         "once more in a separate process.", "",
         "## Setup", "",
         f"- **Mechanism** (`src/aiops_kg/context_bridge.py`). "
         f"Decision time c = onset + Δ. Every policy gets the record versions usable at c. A request counts once its "
         f"root span has ended by c and its start t lies in the normal window [onset − {W_BEFORE} s, onset) or the "
         f"anomalous window [onset, onset + {W_AFTER} s). Each such request is attributed, per service, to a Pod by "
         "`replay.attribute_instance` at cutoff c (an abstention drops it from every aggregate). The candidates are the "
         "Pods that receive at least one request. Per Pod and window the features are collected into graph_rank "
         "indicator records, and `graph_rank.node_anomaly_scores` (p90 robust one-sided n-sigma, unchanged) plus "
         "`anomaly_only_rank` order them. The hindsight reference attributes each request to its span-verified "
         "serving Pod (evaluator only, never a policy input).",
         f"- **Onset:** {setup['onset'][11:26]} UTC ({setup['onset_source']}). Normal window "
         f"{setup['windows']['normal'][0][11:26]}–{setup['windows']['normal'][1][11:26]}, anomalous window "
         f"{setup['windows']['anomalous'][0][11:26]}–{setup['windows']['anomalous'][1][11:26]}.",
         "- **Decision times:** " + "; ".join(f"Δ = {d['delta']} → c = {d['cutoff'][11:26]} "
                                              f"({H(d['delta'])['requests']['anomalous']['observed']} of "
                                              f"{H(d['delta'])['requests']['anomalous']['observed'] + H(d['delta'])['requests']['anomalous']['not_yet_observed']}"
                                              " anomalous-window requests ended)" for d in setup["deltas"]) + ".",
         "- **Who truly served the window requests** (span-verified, evaluator only): normal window "
         + ", ".join(f"{k} {v}" for k, v in setup["window_requests_by_true_pod"]["normal"].items()) + "; anomalous "
         "window " + ", ".join(f"{k} {v}" for k, v in setup["window_requests_by_true_pod"]["anomalous"].items())
         + ". No normal-window request was served by the new Pod: it did not exist before the onset.",
         f"- **Pods:** {names[old]} and {names[new]} ({fs}; new Pod creation floor "
         f"{front['candidates'][1]['created_floor'][11:19]}), {names[cat]} ({ds}, unchanged). {setup['records']} Pod "
         f"STATE records: the recommendation Pods' {setup['records_by_service'][fs]} (replay-policy-v1's records) "
         f"and the catalog Pod's {setup['records_by_service'][ds]}.",
         f"- **Features:** {fs} Pods: `frontend_request_duration_ms` and `frontend_request_error` (the client root "
         f"span); {ds} Pod: `downstream_server_duration_ms` and `downstream_server_error` (its own SERVER span). No "
         "error occurred, so every error indicator has a constant normal window and graph_rank excludes it.",
         "- **Policies:** " + ", ".join(POLICY_LABEL[p] for p in POLICY_ORDER) + " (replay-policy-v1's "
         "`make_policies()`), plus the hindsight reference.", "",
         "| Stream | What changed (replay-policy-v1 definitions, applied to every Pod record) |", "| --- | --- |"]
    for s in res["streams"]:
        if s.get("perturbation") == "delay":
            what = f"available_at + {s['name'].split('_')[-1][:-1]} s on all {s['changed_records']} records"
        elif s.get("perturbation") == "drop_transition":
            what = "dropped " + ", ".join(f"`api/{e['record_id'].rsplit('/', 1)[-1]}` ({short[e['subject']]} "
                                          f"{e['from']} -> {e['to']}, observed {e['observed_at'][11:26]})"
                                          for e in s["dropped"])
        elif s.get("perturbation") == "correct_late":
            what = "; ".join(f"`api/{e['original'].rsplit('/', 1)[-1]}` ({short[e['subject']]}) first as "
                             f"{e['stale']['value']}, corrected to {e['corrected']['value']} available "
                             f"{e['corrected']['available_at'][11:26]}" for e in s["corrected"])
        else:
            what = "none (as measured)"
        L.append(f"| `{s['name']}` | {what} |")
    L += ["", "## Consistency checks (all passed; the run aborts otherwise)", "",
          f"- **Attribution equals replay-policy-v1.** With replay-policy-v1's per-request cutoffs (c = t_req + Δ), the "
          f"bridge's attribution call reproduces its recorded answer and status strings in {a['cells_equal']}/"
          f"{a['cells']} cells ({a['decisions']} decisions: {a['streams']} streams x {a['policies']} policies x "
          f"Δ ∈ {{{', '.join(a['deltas'])}}}).",
          f"- **Streams equal replay-policy-v1's.** The recommendation Pods' records in all "
          f"{sum(cc['streams_vs_replay_policy_v1'].values())} streams equal the streams replay-policy-v1 builds "
          "from its own task.",
          f"- **Requests equal the rollout task's.** {cc['requests_vs_rollout_task']['requests']} requests: numbering, "
          "valid times and span-verified Pods equal `replay.load_attribution_lag_task`.",
          "- **Determinism.** Two in-process passes are identical. " + (
              f"A separate process wrote byte-identical `results.json` (SHA-256 "
              f"`{rerun['results_json_sha256_separate_run'][:16]}…`) and `results.csv` (SHA-256 "
              f"`{rerun['results_csv_sha256_separate_run'][:16]}…`)." if rerun else
              "The separate-process rerun was skipped in this invocation (`--skip-rerun`)."), ""]

    # (a) key cells
    L += ["## (a) Key cells: `complete` and `delayed_api_30s` at Δ = 0 and Δ = 30 s", "",
          "Recommendation-service attribution and candidate membership. Mis-attributed = attributed to a Pod other than "
          "the span-verified one (in brackets: marked CONFIRMED / FALLBACK by the policy). Missing = hindsight "
          "candidates that are not candidates under the policy. Top-1 = the anomaly-only first place if its score is "
          "positive and not tied with the second (else none).", "",
          "| Stream | Δ | Policy | Usable records at c (recommendation / catalog) | Mis-attributed [requests] | "
          "Abstained [requests] | Coverage | Missing vs hindsight | Top-1 |",
          "| --- | --- | --- | --- | --- | --- | ---: | --- | --- |"]
    for s in ("complete", "delayed_api_30s"):
        for d in ("0 s", "30 s"):
            for c in rows_of(s, d):
                r = c["services"][fs]
                usable = (f"{c['usable_records'][fs]} / {c['usable_records'][ds]}" if "usable_records" in c else "-")
                mis = (f"{r['mis_attributed']} ({r['mis_attributed_confirmed']} / {r['mis_attributed_fallback']}) "
                       f"[{r['wrong_request_ids']}]" if r["mis_attributed"] else "0")
                abst = f"{r['abstained']} [{r['abstained_request_ids']}]" if r["abstained"] else "0"
                miss = ", ".join(short[k] for k in c["candidates"]["missing_vs_hindsight"]) or "none"
                L.append(f"| `{s}` | {d} | {POLICY_LABEL[c['policy']]} | {usable} | {mis} | {abst} | "
                         f"{100 * r['coverage']:.1f}% | {miss} | {short[top1(c)]} |")
    L += ["", "Per-Pod aggregates in the same cells. Requests = normal / anomalous window (in brackets: how many of "
          "them another Pod actually served). Median = median frontend request duration (ms; catalog: its server span "
          "duration) in the normal / anomalous window. a(u) = graph_rank p90 anomaly score. \"-\" = no request.", "",
          "| Stream | Δ | Policy | Pod | Candidate | Requests N / A [mis-attributed] | Median N / A (policy) | "
          "Median N / A (hindsight) | a(u) policy | a(u) hindsight |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: |"]
    for s in ("complete", "delayed_api_30s"):
        for d in ("0 s", "30 s"):
            for c in rows_of(s, d)[:4]:
                for key in (old, new, cat):
                    e = c["entities"].get(key)
                    if e is None:
                        continue
                    nw, aw = e["normal"], e["anomalous"]
                    L.append(f"| `{s}` | {d} | {POLICY_LABEL[c['policy']]} | {short[key]} | "
                             f"{'yes' if e['candidate'] else ('in view, no request' if e['in_view'] else 'not in view')}"
                             f" | {nw['n']} / {aw['n']} [{nw.get('mis_attributed', 0)} / {aw.get('mis_attributed', 0)}]"
                             f" | {f3(med(c, key, 'normal'))} / {f3(med(c, key, 'anomalous'))} | "
                             f"{f3((nw.get('hindsight_median') or {}).get(dur[e['service']]))} / "
                             f"{f3((aw.get('hindsight_median') or {}).get(dur[e['service']]))} | "
                             f"{f3(score(c, key))} | {f3(e.get('hindsight_anomaly_score'))} |")
    # (b) all streams
    cell_txt = lambda c: (f"{c['services'][fs]['mis_attributed']}/{c['services'][fs]['abstained']}"
                          + (", missing " + "+".join(short[k] for k in c["candidates"]["missing_vs_hindsight"])
                             if c["candidates"]["missing_vs_hindsight"] else "") + f", Top-1 {short[top1(c)]}")
    L += ["", "## (b) All streams at Δ = 5, 30 and 60 s", "",
          "Cells: recommendation requests mis-attributed / abstained, candidates missing vs hindsight, anomaly-only "
          "Top-1. Hindsight Top-1: " + "; ".join(f"Δ = {d} {short[top1(H(d))]}" for d in deltas) + ". At Δ = 0 no "
          "anomalous-window request has ended, so every score is 0 (finding 1).", ""]
    for d in ("5 s", "30 s", "60 s"):
        L += [f"**Δ = {d}**", "", "| Stream | " + " | ".join(POLICY_LABEL[p] for p in POLICY_ORDER) + " |",
              "| --- | " + " | ".join("---" for _ in POLICY_ORDER) + " |"]
        for s in streams:
            L.append(f"| `{s}` | " + " | ".join(cell_txt(C(s, p, d)) for p in POLICY_ORDER) + " |")
        L.append("")
    # (c) findings
    lsn = ls["entities"][new]
    dln = dl[0]["entities"][old]
    L += ["## (c) What the cells show (each pattern is checked in code)", "",
          f"1. **At Δ = 0 there is nothing to rank.** None of the {n_anom_total} anomalous-window requests has ended "
          "by c = onset, so every Pod's anomalous window is empty and every score is 0 in every stream and policy. "
          "Context changes only membership: with `delayed_api_30s` no record is usable yet, no Pod is in view, and "
          f"all {2 * n_norm} attributions ({n_norm} per service) are abstentions, so the candidate set is empty. The "
          "other streams attribute every normal-window request correctly at Δ = 0.",
          f"2. **`latest_state` merges the two Pods once the switch is visible (complete, Δ = 30 s).** It attributes "
          f"all {rec_ls['mis_attributed']} old-Pod requests (1-43) to the new Pod, because it reads the newest record "
          f"and ignores t. The old Pod is in view but receives no request, so it drops out of the candidates. The new "
          f"Pod's normal window becomes {lsn['normal']['n']} requests that the old Pod served (hindsight: "
          f"{lsn['normal']['hindsight_n']}, the new Pod did not exist yet). Its anomalous median moves to "
          f"{f3(med(ls, new, 'anomalous'))} ms from {f3(lsn['anomalous']['hindsight_median'][dur[fs]])} ms. Its "
          f"score becomes a(u) = {f3(score(ls, new))}, where hindsight leaves it unscorable (empty normal window, "
          f"a(u) = 0). Top-1 moves from the catalog Pod (hindsight) to the new Pod. `temporal_join` reproduces "
          f"hindsight exactly. `bitemporal_abstain` (F = 600 s and 30 s) makes no mis-attribution but abstains on 7 "
          f"requests (31-32, 39-43, `two_pods_possible`), which shrinks the old Pod's anomalous window to "
          f"{ba['entities'][old]['anomalous']['n']} requests (median {f3(med(ba, old, 'anomalous'))} ms against "
          f"{f3(ba['entities'][old]['anomalous']['hindsight_median'][dur[fs]])} ms from "
          f"{ba['entities'][old]['anomalous']['hindsight_n']}); its Top-1 is unchanged.",
          f"3. **A 30 s record delay hides the new Pod from every policy (`delayed_api_30s`, Δ = 30 s).** The usable "
          f"records at c are exactly those usable at the onset ({dl[0]['usable_records'][fs]} / "
          f"{dl[0]['usable_records'][ds]}). The new Pod is not in view, so it is absent from all four candidate "
          f"sets. Its {counts['anomalous'][names[new]]} requests (44-67) feed the old Pod's anomalous aggregate under "
          "every policy: `latest_state` and `temporal_join` mark them CONFIRMED; `bitemporal_abstain` marks all 24 "
          f"FALLBACK but still uses them (the last usable sighting is within F). The old Pod's anomalous median "
          f"becomes {f3(med(dl[0], old, 'anomalous'))} ms instead of "
          f"{f3(dln['anomalous']['hindsight_median'][dur[fs]])} ms and its score a(u) = {f3(score(dl[0], old))} "
          f"instead of {f3(hscore('30 s', old))}, making Top-1 a Pod that served none of 44-67. Had the new Pod "
          "carried a fault, no policy could have named it at this cutoff (\"cannot be found\"). At Δ = 60 s the "
          "delayed records have arrived and the stream behaves like `complete` at Δ = 30 s.",
          f"4. **The same score in findings 2 and 3 is pooled service traffic.** In both cells one Pod receives every "
          f"recommendation request of both windows (normal {ls['entities'][new]['normal']['requests']}, anomalous "
          f"{ls['entities'][new]['anomalous']['requests']}), so its aggregate is the whole service's and its score "
          f"({f3(score(ls, new))}) is the same number. The positive score belongs to neither Pod. It comes from pooling "
          "their requests.",
          "5. **A missing switch record misleads the plain temporal join; the two-clock rule abstains.** Without the "
          "switch poll, `temporal_join` attributes 44-49 to the old Pod at Δ = 30 and 60 s (6 mis-attributed), "
          "`bitemporal_abstain` abstains on 13 (31-32, 39-49) with none mis-attributed, and `latest_state` again "
          "mis-attributes 43.",
          f"6. **The corrected-late streams equal `complete` in every cell (a timing null of this Δ grid).** The "
          f"switch poll's stale versions become usable at {R.iso(switch_at)[11:26]}, after c at Δ = 5 s, and both "
          "corrections (3 s and 10 s later) are usable by Δ = 30 s. The exposure window of a few seconds lies "
          "between the declared cutoffs; replay-policy-v1's per-request cutoffs do probe it.",
          "7. **Smaller delays (1, 3, 10 s) behave like `complete` at Δ = 30 and 60 s, and nothing is mis-attributed at "
          f"Δ = 5 s in any stream** (the new Pod's first request, {first_new}, starts at "
          f"{setup['t_req'][str(first_new)][11:26]}, after c = onset + 5 s). The catalog Pod is never "
          "mis-attributed; it has abstentions only in `delayed_api_30s` at Δ = 0 (no record usable) and at Δ = 5 s "
          f"under F = 30 s ({next(n for s_, p, d, n in cat_abst if d == '5 s')} requests, last sighting older than "
          "30 s).",
          f"8. **Secondary ranker (personalized PageRank over the as-attributed edges).** In the `latest_state` "
          f"complete Δ = 30 s cell the walk moves mass from the new Pod to its callee, so the catalog Pod keeps PPR "
          f"first place ({f3(ppr_ls[cat])} against {f3(ppr_ls[new])}), as in hindsight. A graph walk can therefore "
          "hide or amplify an attribution error. This is one cell, not a property of the method.", ""]
    L += ["## (d) What this demonstration shows and does not show", "",
          "- **Shows:** on real timestamps and unchanged telemetry, the context policy and the availability of records "
          "change (i) which Pod each request is attributed to, (ii) which Pods are candidates at all, (iii) the "
          "samples in each Pod's baseline and anomalous windows, hence (iv) the anomaly scores and the Top-1 entity of "
          "an unchanged ranker. This is the mechanism the Phase 3 evaluation needs; without it, replaying record delays "
          "could not change a ranking.",
          "- **Does not show:** any diagnosis accuracy (there is no fault), that any policy diagnoses better, "
          "behaviour on other services, faults or topologies, online operation (this is retrospective replay), or "
          "telemetry-ingestion lag (telemetry is assumed usable when a request ends).",
          "- **Next:** `--capture` applies this script unchanged to the Phase 3 captures (I1-I4, I6).", ""]
    L += ["## (e) Limitations", ""] + [f"- {x}" for x in res["limitations"]] + [""]
    L += ["## Files", "",
          "- `run_context_bridge_v1.py`: this experiment (reads only; writes only into this folder, or `--output`).",
          "- `results.json`: protocol, setup, streams (manifests), every policy x stream x Δ cell (per-service "
          "attribution strings O/N/1/?, per-Pod windows with request lists, medians, mis-attributed counts, anomaly "
          "scores, candidate sets, anomaly-only and PPR orders, max-statistic sensitivity) and the hindsight "
          "reference per Δ, cross-checks, input and code SHA-256.",
          "- `results.csv`: one row per stream x Δ x policy (hindsight rows: stream `-`) x Pod.", ""]
    return "\n".join(L)


def us_of(text: str) -> int:
    return B._us(text)


def status_line(cap) -> str:
    marker = cap["status_marker"]
    marker = ", ".join(marker) if isinstance(marker, list) else marker
    validity = cap["runner_validity"]
    return (f"- Status marker: {marker} (status={cap['status']}); status problems: "
            f"{'; '.join(cap['status_problems']) or 'none'}; invalid markers: "
            f"{', '.join(cap['invalid_markers']) or 'none'}; runner validity: "
            f"{json.dumps(validity, sort_keys=True) if validity is not None else 'not recorded'}.")


def unsighted_line(entries) -> str:
    return ("- Unsighted Pods (in the spans but never sighted by the API poller as a Pod of their service; no policy "
            "and not the hindsight reference can attribute a request to them; never a model input): "
            + ("; ".join(f"{u['name']} ({u['service']}): {u['requests']} requests, window normal "
                         f"{u['window_requests']['normal']} / anomalous {u['window_requests']['anomalous']}"
                         for u in entries) or "none") + ".")


def render_capture_summary(res) -> str:
    """Capture mode: the primary metric table (truth rank per policy x Delta x stream) plus membership."""
    names, cells = res["entity_names"], res["cells"]
    cap, ev = res["capture"], res["evaluator_only"]
    truth = ev["truth_entity"]
    front = next(s for s in res["setup"]["services"] if s["role"] == "frontend")["service"]
    short = lambda k: "none" if k is None else names.get(k, k)
    L = [f"# context-bridge v1 on capture `{cap['directory']}` ({cap['incident_id']})", "",
         "**One capture = one incident. Streams, Δ and policies are replays of it, not independent incidents.** "
         "Generated by `experiments/context-bridge-v1/run_context_bridge_v1.py --capture` from `evidence/` (model "
         "input) and `ground_truth/` (onset yardstick, truth entity, inclusion; scoring only).", "",
         "## Inclusion", "",
         status_line(cap),
         f"- **Included in the primary analysis: {'yes' if cap['protocol_inclusion']['included'] else 'NO'}**"
         + ("" if cap["protocol_inclusion"]["included"] else " — " + "; ".join(cap["protocol_inclusion"]["reasons"]))
         + ".",
         f"- Truth entity (evaluator only): {short(truth)} ({ev['truth_source']}); labels: "
         f"{json.dumps(ev['labels'], sort_keys=True)}.",
         f"- Onset: {res['setup']['onset']} ({res['setup']['onset_source']}); changed service: "
         f"{cap['changed_service'] or 'none'}.",
         unsighted_line(res["unsighted_entities"]),
         "- Streams not applicable: " + (", ".join(f"`{s['name']}` ({s['not_applicable']})" for s in res["streams"]
                                                  if "not_applicable" in s) or "none") + ".",
         "- Notes: " + ("; ".join(res["setup"]["notes"]) or "none") + ".", "",
         "## Primary metric: rank of the truth entity (pessimistic under ties) and Top-1", "",
         f"Mis-attributed / abstained = {front} requests in the observed window; unsighted = observed window "
         "requests of every service served by an unsighted Pod (counted, never attributable); missing = hindsight "
         "candidates absent under the policy; wrong decision = a positive, untied Top-1 that is not the truth "
         "entity. An absent truth entity shows its reason (`not_a_candidate` or `unsighted`).", "",
         "| Stream | Δ | Policy | Truth rank (of candidates) | Top-1 | Outcome | Top-1 entity | Wrong decision | "
         "Mis-attributed | Abstained | Unsighted | Coverage | Missing |",
         "| --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |"]
    rows = [("-", h) for h in res["hindsight"].values()] + [(c["stream"], c) for c in cells]
    for stream, c in rows:
        t, r = c["truth"], c["services"][front]
        rank = "-" if t["rank_pessimistic"] is None else f"{t['rank_pessimistic']} of {t['candidates']}"
        outcome = t["outcome"] + (f" ({t['reason']})" if t.get("reason") else "")
        coverage = "-" if r["coverage"] is None else f"{100 * r['coverage']:.1f}%"
        missing = ", ".join(short(k) for k in c["candidates"]["missing_vs_hindsight"]) or "none"
        L.append(f"| `{stream}` | {c['delta']} | {POLICY_LABEL.get(c['policy'], c['policy'])} | {rank} | "
                 f"{t['top1']} | {outcome} | {short(c['ranking']['top1_entity'])} | "
                 f"{c['wrong_entity_decision']} | {r['mis_attributed']} | {r['abstained']} | "
                 f"{c['unattributable_unsighted_total']} | {coverage} | {missing} |")
    L += ["", "Per-Pod windows, medians and scores for every cell are in `results.json` / `results.csv`.", ""]
    return "\n".join(L)


def render_exclusion_summary(rec) -> str:
    """Capture mode, excluded capture: the reasons under the rule; no grid exists."""
    cap, ev = rec["capture"], rec["evaluator_only"]
    L = [f"# context-bridge v1 on capture `{cap['directory']}` ({cap['incident_id']}): excluded", "",
         "**Excluded from the primary analysis by the inclusion rule"
         ". No grid was computed. An exclusion is a documented outcome of the inclusion rule, not an error.** "
         "Generated by `experiments/context-bridge-v1/run_context_bridge_v1.py --capture`; details in "
         "`exclusion.json`.", "", "## Reasons", ""]
    L += [f"- {r}" for r in cap["protocol_inclusion"]["reasons"]]
    L += ["", "## Capture facts", "", status_line(cap),
          f"- Truth entity (evaluator only): {ev['truth_entity'] or 'none'} ({ev['truth_source']}); labels: "
          f"{json.dumps(ev['labels'], sort_keys=True)}.",
          f"- Onset: {rec['onset']} ({rec['onset_source']}); changed service: {cap['changed_service'] or 'none'}.",
          unsighted_line(rec["unsighted_entities"]),
          "- Notes: " + ("; ".join(rec["notes"]) or "none") + ".", ""]
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Capture mode
# ---------------------------------------------------------------------------
def compute_capture(capture: Path):
    rpv1 = rpv1_module()
    bridge = B.load_capture_input(capture, root=ROOT)          # model input: <capture>/evidence/ only
    truth = B.load_capture_truth(capture)                      # evaluator only: onset, truth entity, status
    policies = rpv1.make_policies()
    check([p.name for p in policies] == list(POLICY_ORDER), "policy set differs from replay-policy-v1")
    streams, skipped = capture_streams(rpv1, bridge)
    hindsight, cells = run_grid(bridge, streams, policies, truth["onset"], truth["truth_entity"])
    return bridge, truth, policies, streams, skipped, hindsight, cells


def capture_facts(capture: Path, truth, bridge, included) -> dict:
    return {"directory": capture.name, "incident_id": truth["incident_id"],
            "status_marker": truth["status_marker"], "status": truth["status"],
            "status_problems": truth["status_problems"], "status_error": truth["status_error"],
            "invalid_markers": truth["invalid_markers"], "runner_validity": truth["runner_validity"],
            "protocol_inclusion": included, "changed_service": bridge.changed_service}


def evaluator_facts(truth) -> dict:
    return {"truth_entity": truth["truth_entity"], "truth_source": truth["truth_source"],
            "labels": truth["labels"], "fault_target": truth["fault_target"],
            "evaluation_summary": truth["evaluation_summary"],
            "note": "read from ground_truth/ for scoring only; never passed to a policy"}


def provenance(capture: Path) -> dict:
    return {"environment": {"python": platform.python_version(), "numpy": numpy.__version__,
                            "networkx": networkx.__version__}}


def write_json(path: Path, doc) -> None:
    write_text_lf(path, json.dumps(json.loads(json.dumps(doc, default=list)), indent=1) + "\n")


def run_capture(capture: Path, output: Path | None) -> int:
    capture = capture.resolve()
    out = (output or capture / "context_bridge").resolve()
    if out.exists():
        raise SystemExit(f"output directory exists; remove it or pass --output: {out}")
    # The inclusion rule comes first: an excluded capture is a documented outcome, written as exclusion.json +
    # SUMMARY.md with exit status 0, and no grid is computed.
    bridge = B.load_capture_input(capture, root=ROOT)          # model input: <capture>/evidence/ only
    truth = B.load_capture_truth(capture)                      # evaluator only: onset, truth entity, status
    included = B.inclusion(truth, bridge)
    facts = capture_facts(capture, truth, bridge, included)
    unsighted = unsighted_report(bridge, entity_names(bridge), truth["onset"])
    if not included["included"]:
        record = {"kind": "excluded_by_protocol", "protocol_version": B.PROTOCOL["version"],
                  "rule": "context_bridge.inclusion",
                  "grid_computed": False, "capture": facts, "evaluator_only": evaluator_facts(truth),
                  "onset": R.iso(truth["onset"]), "onset_source": truth["onset_source"],
                  "unsighted_entities": unsighted, "notes": list(bridge.notes), **provenance(capture)}
        out.mkdir(parents=True)
        write_json(out / "exclusion.json", record)
        write_text_lf(out / "SUMMARY.md", render_exclusion_summary(record))
        print(json.dumps({"capture": capture.name, "included": included, "truth_entity": truth["truth_entity"],
                          "outputs": str(out)}, indent=1))
        return 0
    try:
        bridge, truth, policies, streams, skipped, hindsight, cells = compute_capture(capture)
        again = compute_capture(capture)
        check(fingerprint(hindsight, cells) == fingerprint(again[5], again[6]), "two in-process passes differ")
        results = {
            "kind": "context_to_ranking_bridge_one_capture",
            "scope": ("One capture = one incident. Replay variants (streams, Deltas, policies) of it are not "
                      "independent incidents. Scored against ground_truth/ only after the policies have decided."),
            "capture": facts,
            "evaluator_only": evaluator_facts(truth),
            **base_results(bridge, streams, skipped, policies, truth["onset"], truth["onset_source"], hindsight,
                           cells, {"two_in_process_passes_identical": True}),
            **provenance(capture),
        }
        results = json.loads(json.dumps(results, default=list))
        texts = {"results.json": json.dumps(results, indent=1) + "\n", "results.csv": results_csv(results),
                 "SUMMARY.md": render_capture_summary(results)}
        out.mkdir(parents=True)
        for name, text in texts.items():
            write_text_lf(out / name, text)
    except (Exception, SystemExit) as error:
        # Never leave an included capture without a record: the failure is written, then raised again.
        out.mkdir(parents=True, exist_ok=True)
        write_json(out / "exclusion.json", {
            "kind": "analysis_error", "protocol_version": B.PROTOCOL["version"],
            "note": "the analysis of an included capture failed; no file in this directory is a valid result",
            "error": f"{type(error).__name__}: {error}", "traceback": traceback.format_exc(), "capture": facts,
            "unsighted_entities": unsighted, **provenance(capture)})
        raise
    print(json.dumps({"capture": capture.name, "included": included, "truth_entity": truth["truth_entity"],
                      "unsighted_entities": len(unsighted), "outputs": str(out)}, indent=1))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="context-bridge v1 (context -> attribution -> aggregates -> ranker)")
    parser.add_argument("--capture", type=Path, help="a converted Phase 3 capture directory")
    parser.add_argument("--output", type=Path, help="output directory (default: this folder, or "
                                                    "<capture>/context_bridge with --capture; never overwritten "
                                                    "in capture mode)")
    parser.add_argument("--skip-rerun", action="store_true", help="default mode: skip the separate-process rerun")
    args = parser.parse_args(argv)
    if args.capture is not None:
        return run_capture(args.capture, args.output)
    return run_default(args.output, args.skip_rerun)


if __name__ == "__main__":
    raise SystemExit(main())
