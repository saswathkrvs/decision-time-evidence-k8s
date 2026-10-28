#!/usr/bin/env python3
"""Diagnosis control of the follow-up study (arm D), part 2: the context bridge per observer, the H-D rule and the
diagnosis tables.

Question: does the development diagnosis effect (the poller's polling gap hiding a replacement Pod from the temporal
join and the two-clock policy) disappear when the Pod context comes from the watch?

- H-D: with watch-sourced context, temporal_join and bitemporal_abstain (F = 600 s) rank the truth Pod as hindsight
  does in every included D1 capture, complete stream, Delta in {30, 60} s. E_P / E_W = the included D1 captures in
  which either policy ranks the truth Pod worse than hindsight with poller / watch context in those cells. Verdict
  (``hd_rule``): refuted if E_W is non-empty; else confirmed as a poller artefact if E_P is non-empty; else untested.
- Arm D is single-replica (the bridge attributes requests from API context; with several ready replicas every policy
  would abstain or tie-break); a capture that is not arm D is not analysed.
- Conditions: the bridge v1 (context_bridge.PROTOCOL, version context-bridge-v1), policies latest_state,
  temporal_join, bitemporal_abstain F = 600 s and 30 s, the hindsight reference, each run twice: on poller-sourced and
  on watch-sourced Pod records (loader: load_stage2_task.py); Delta in {0, 5, 30, 60} s; a secondary row with each
  span's measured trace-tail receipt as its availability (``receipt_requests``).
- Streams: complete, delayed_api_{1,3,10,30}s (the same delay on both observers), and the switch-based streams; for
  the poller the bridge's own missing_switch_poll / corrected_late_{3,10}s, for the watch the event-level variants
  missing_switch_event / corrected_late_event_{3,10}s (``watch_switch_streams``; the definition is printed beside
  every row).
- Counts and paired comparisons only ("Top-1 in k of n included D1 captures"), never a rate.
- Inclusion: rules 1-2 read from the runner's capture.json section10 record (validity fields only); rule 3 = the
  bridge's inclusion rule (context_bridge.inclusion) on both observers' inputs, the truth Pod sighted by both
  observers; the secondary rule (context_bridge.inclusion_secondary) in its own table; pilots are never analysed.

Reproduced, not imported: the grid and output shaping of experiments/context-bridge-v1/run_context_bridge_v1.py, the
bridge streams of experiments/replay-policy-v1/run_replay_policy_v1.py and the input builder
context_bridge.load_capture_input (with the observer's loader). Imported unchanged: src/aiops_kg/context_bridge.py
and src/aiops_kg/replay.py.

Commands (from the repository root; nothing needs the cluster):

    python3 experiments/diagnosis-control-v1/run_diagnosis_control_v1.py --out <new dir> \
        --captures phase3/captures_stage2/D1-001 phase3/captures_stage2/D1-002 ...   # converted arm-D captures
    python3 experiments/diagnosis-control-v1/run_diagnosis_control_v1.py --check     # the fixture expectation
    python3 experiments/diagnosis-control-v1/run_diagnosis_control_v1.py --fixture-run --out <new dir>
    python3 experiments/diagnosis-control-v1/run_diagnosis_control_v1.py --validity-only \
        --captures phase3/captures_stage2/D1-001 --out <new dir>          # inclusion rule 3 only, no ranking

Outputs (never overwritten; --out must not exist): <out>/<capture>/{results.json, cells.csv, SUMMARY.md},
<out>/summary.json, <out>/SUMMARY.md. Deterministic: no wall clock, no randomness, no absolute path in any output;
two processes give identical bytes (tested). ``--validity-only`` takes each capture through the steps of the full
analysis up to the inclusion decision and stops there; it writes <out>/validity.json and <out>/validity.md only.

Standard library in this file; the bridge it runs needs numpy, networkx and pandas (src/aiops_kg/graph_rank.py).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import platform
import sys
import tempfile
import time
import traceback
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True      # before any project import (as every script of this repository)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _path in (ROOT / "src", HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import load_stage2_task as L  # noqa: E402
from aiops_kg import context_bridge as B  # noqa: E402
from aiops_kg import fault_control_kill as K  # noqa: E402  (clock_band only)
from aiops_kg import replay as R  # noqa: E402

VERSION = "stage2-diagnosis-control-v1"
STREAMS = B.PROTOCOL["streams"]
DELTAS = tuple((f"{d} s", d) for d in B.PROTOCOL["deltas_seconds"])
W_BEFORE, W_AFTER = B.PROTOCOL["window_before_seconds"], B.PROTOCOL["window_after_seconds"]
LS, TJ, BA, B30 = "latest_state", "temporal_join", "bitemporal_abstain_F600", "bitemporal_abstain_F30"
POLICY_ORDER = (LS, TJ, BA, B30)
POLICY_LABEL = {LS: "latest_state", TJ: "temporal_join", BA: "bitemporal_abstain F=600 s",
                B30: "bitemporal_abstain F=30 s", B.HINDSIGHT: "hindsight (reference)"}
# experiments/replay-policy-v1/run_replay_policy_v1.py POLICY_SPECS (make_policies), the bridge's policy set (3.6)
POLICY_SPECS = (("latest_state", {}), ("temporal_join", {}),
                ("bitemporal_abstain", {"freshness_seconds": 600.0}),
                ("bitemporal_abstain", {"freshness_seconds": 30.0}))
FEED_DELAYS = (1, 3, 10, 30)                      # the bridge's delayed_api streams (PROTOCOL["streams"])
CORRECTION_DELAYS = (3, 10)                       # the bridge's corrected_late streams
API_KINDS = ("api", "absence")
POLLER, WATCH, WATCH_EVENT = L.POLLER, L.WATCH, L.WATCH_EVENT
PRIMARY_OBSERVERS = (POLLER, WATCH)
HD_STREAM, HD_DELTAS, HD_POLICIES = "complete", (30, 60), (TJ, BA)
WATCH_SWITCH = ("missing_switch_event", "corrected_late_event_3s", "corrected_late_event_10s")
# stream family: the poller's (and the event log's) switch streams and the watch's event-level variants pair up
FAMILY = {"missing_switch_poll": "missing_switch", "missing_switch_event": "missing_switch",
          "corrected_late_3s": "corrected_late_3s", "corrected_late_event_3s": "corrected_late_3s",
          "corrected_late_10s": "corrected_late_10s", "corrected_late_event_10s": "corrected_late_10s"}
FAMILIES = ("complete", "delayed_api_1s", "delayed_api_3s", "delayed_api_10s", "delayed_api_30s", "missing_switch",
            "corrected_late_3s", "corrected_late_10s")
REPORTED_FAMILIES = ("complete", "missing_switch", "delayed_api_30s", "corrected_late_10s")   # as Phase 3's summary
SHORT = {"recommendationservice": "recommendation", "productcatalogservice": "catalog"}
VERDICTS = ("confirmed as a poller artefact", "untested", "refuted")
EXPECTED_FREQUENCY = ("Expected frequency: under the poller the effect appeared in 1 of 5 "
                      "included Phase-3 captures on complete records at Delta = 30 s and in 3 of 4 with the switch "
                      "record missing (L-4). With 6 D1 captures E_P may well "
                      "be small or empty on the complete stream; the missing-switch rows are secondary.")
HD_STATEMENT = ("H-D, applied mechanically. Cells: stream complete, Delta in "
                "{30, 60} s, policies temporal_join and bitemporal_abstain F = 600 s. A capture is in E_P (E_W) if, "
                "with poller (watch) context, either policy ranks the truth Pod worse than hindsight in any of those "
                "cells: the pessimistic truth rank is higher than the hindsight reference's at the same Delta, or "
                "the truth Pod is absent while hindsight ranks it (summarize_captures.compare; 'absent counts as "
                "worse'); each observer is compared with its own hindsight reference. Verdict: refuted if E_W is "
                "non-empty (each capture's mechanism listed); else confirmed as a poller artefact if E_P is "
                "non-empty; else untested (never support).")
EXPECTATION = HERE / "fixture_expectation.json"
CLOCK_FILE = "stage2/clock_probe.jsonl"
UTC = timezone.utc
# --validity-only: the label every output of that mode carries, and the only files it writes
VALIDITY_LABEL = ("VALIDITY ONLY: inclusion rule 3 (bridge inclusion items 2-3); no ranking, "
                  "condition or label computed")
VALIDITY_FILES = ("validity.json", "validity.md")
PILOT_NOTE = "PILOT: a tooling check only; never in a results table, never counted toward a slot"
VALIDITY_READING = (
    "Rule (inclusion rule 3, arm D): bridge rule 3.1 items 2-3 as written (context_bridge.inclusion, which "
    "re-checks item 1 too), on the poller's AND on the watch's bridge input: activation and effect established, the "
    "truth Pod sighted by both observers, the change verified. Rules 1-2 are read first from capture.json section10 "
    "(nothing is loaded when they fail). The secondary rule (context_bridge.inclusion_secondary) on both inputs, on its own "
    "line. A capture outside arm D is not evaluated; a pilot is checked as a tooling fact only and marked PILOT. This "
    "file records no exclusion: exclusions are recorded in the attempt log by the capture runner.")


# ---------------------------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------------------------
def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("verification failed: " + message)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def rel(path: Path) -> str:
    """Repository-relative POSIX path when inside the repository, else the bare name (no absolute path is written)."""
    path = Path(path).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def number(request_id: str) -> int:
    return int(request_id.split("/", 1)[1])


def fmt_list(items) -> str:
    """run_context_bridge_v1.fmt_list: 1, 2, 3, 7 -> '1-3, 7'."""
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


def hms(value_us: int | None) -> str:
    return "-" if value_us is None else R.from_us(value_us).strftime("%H:%M:%S.%f")


def jsonable(doc):
    return json.loads(json.dumps(doc, default=list))


def json_text(doc) -> str:
    return json.dumps(jsonable(doc), indent=1, ensure_ascii=False) + "\n"


def write_lf(path: Path, text: str) -> None:
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def delta_seconds(label: str) -> int:
    return int(label.split()[0])


def scrub(text: str, capture: Path) -> str:
    """An error text without absolute paths (no output names a path of the machine that ran it)."""
    capture = Path(capture).resolve()
    for path, label in ((capture, "<capture>"), (capture.parent, "<captures>"), (ROOT, "<root>")):
        text = text.replace(str(path), label)
    return text


# ---------------------------------------------------------------------------------------------------------------
# Policies and streams
# ---------------------------------------------------------------------------------------------------------------
def make_policies():
    """replay-policy-v1 make_policies(), checked against context_bridge.PROTOCOL["policies"]."""
    policies = tuple(R.make_policy(name, **params) for name, params in POLICY_SPECS)
    check([p.name for p in policies] == list(POLICY_ORDER), "policy set differs from replay-policy-v1")
    check([(p.name.split("_F")[0], dict(p.params).get("freshness_seconds")) for p in policies] ==
          [tuple(x) for x in B.PROTOCOL["policies"]], "policies differ from the bridge configuration")
    return policies


def bridge_streams(bridge) -> tuple[list, list]:
    """The bridge's eight streams, built exactly as
    run_context_bridge_v1.capture_streams builds them through replay-policy-v1's build_capture_perturbations (the
    same record selectors, descriptions and skip reasons; only the bridge's streams are built). Applied to the union of
    every service's Pod records; the switch is the first record revealing a Pod of the changed service leaving ready
    (by observed time, then record id) and the 'poll' is every revealing record at that observed instant."""
    task = bridge.primary_task
    base = bridge.records
    keys = {c.key for c in task.candidates} if task else set()
    service = bridge.changed_service or "(no changed service)"
    out = [{"name": "complete", "family": "complete", "records": base,
            "description": "as captured (capture-era availability)", "manifest": {"perturbation": "none"}}]
    skipped = []
    for d in FEED_DELAYS:
        records, manifest = R.delay(base, d, kinds=API_KINDS)
        out.append({"name": f"delayed_api_{d}s", "family": "delayed", "records": records,
                    "description": f"every API record (sightings and derived absences) available {d} s later; "
                                   "valid times unchanged (simulated)", "manifest": manifest})
    switch = sorted((r for r, prev in R.revealing_records(base, mode="change")
                     if r.subject in keys and prev == "ready" and r.value in B.RETIRED),
                    key=lambda r: (r.observed_at, r.record_id))
    targets = frozenset()
    if switch:
        at = switch[0].observed_at
        records, manifest = R.drop_transition(base, mode="change", where=lambda r: r.observed_at == at)
        targets = frozenset(e["record_id"] for e in manifest["records"])
        out.append({"name": "missing_switch_poll", "family": "missing", "records": records,
                    "description": f"the poll at {hms(at)} that first shows a {service} Pod leaving ready is never "
                                   f"delivered ({len(targets)} revealing records dropped)", "manifest": manifest})
    else:
        skipped.append({"name": "missing_switch_poll",
                        "reason": f"no ready -> retired transition of a {service} Pod in the capture"})
    for s in CORRECTION_DELAYS:
        if targets:
            records, manifest = R.correct_late(base, s, where=lambda r: r.record_id in targets)
            out.append({"name": f"corrected_late_{s}s", "family": "corrected", "records": records,
                        "description": f"the switch poll's revealing records first arrive with the preceding state; "
                                       f"corrected versions arrive {s} s later", "manifest": manifest})
        else:
            skipped.append({"name": f"corrected_late_{s}s", "reason": "no switch poll to correct"})
    by_name = {s["name"]: s for s in out}
    return [by_name[n] for n in STREAMS if n in by_name], [s for s in skipped if s["name"] in STREAMS]


def watch_switch_streams(bridge, index: L.WatchIndex) -> tuple[list, list, dict]:
    """The watch variants of the switch streams, defined on the event before cache materialisation ("because a
    cache snapshot taken after the event would re-reveal it at the next tick").

    The switch is found with the bridge's own rule on the watch store's Records: the first record revealing a Pod of
    the changed service leaving ready (ready -> terminating / failed / succeeded / absent), by observed time then
    record id. Its snapshot row names its carrier e* (source_record: the watch event, or the relisted object, that put
    that version into the cache).

      missing_switch_event         e* is withheld: the snapshot e* triggered is not taken (all its records go), and
                                   every later snapshot row of the Pod materialised from e* shows the Pod's preceding
                                   version instead (record id + '#withheld', the preceding value) until the Pod's next
                                   event or relist; nothing else changes.
      corrected_late_event_{s}s    e* carries the preceding state: every snapshot row of the Pod materialised from e*
                                   at a snapshot instant earlier than e*'s receipt + s is a stale version (id +
                                   '#stale', the preceding value) corrected by a version with the revealed value (id +
                                   '#corrected', corrects the stale one), available at e*'s acceptance + s (and after
                                   the stale version); rows at or after receipt + s carry the revealed value as
                                   captured.

    Not constructed (listed with the reason) when the watch store has no such transition, or when it is first
    revealed by an absence (the Pod vanished from a snapshot after a DELETED event or a relist: withholding it would
    leave a ghost cache entry until the next relist, which section 6.3 does not define)."""
    task = bridge.primary_task
    base = bridge.records
    keys = {c.key for c in task.candidates} if task else set()
    service = bridge.changed_service or "(no changed service)"
    reveal = sorted(((r, prev) for r, prev in R.revealing_records(base, mode="change")
                     if r.subject in keys and prev == "ready" and r.value in B.RETIRED),
                    key=lambda item: (item[0].observed_at, item[0].record_id))

    def skip(reason):
        return [], [{"name": name, "reason": reason} for name in WATCH_SWITCH], {"constructed": False,
                                                                                "reason": reason}
    if not reveal:
        return skip(f"no ready -> retired transition of a {service} Pod in the watch store")
    switch, prev = reveal[0]
    meta = index.row_meta.get(switch.record_id)
    if switch.kind != "api" or meta is None:
        return skip(f"the switch ({switch.subject} ready -> {switch.value} at {hms(switch.observed_at)}, record "
                    f"{switch.record_id}) is first revealed by an absence, not by an object version: withholding it "
                    "would leave a ghost cache entry until the next relist (not defined)")
    snapshot_id, trigger, trigger_sequence, carrier_id = meta
    carrier = index.carriers.get(carrier_id)
    if carrier is None:
        return skip(f"the carrier {carrier_id} of the switch record {switch.record_id} is not in the watch rows")
    check(L.pod_state(carrier.resource_data) == switch.value, f"carrier {carrier_id} does not carry {switch.value}")
    subject = switch.subject
    affected = {r.record_id for r in base if r.subject == subject and r.kind == "api"
                and (index.row_meta.get(r.record_id) or (None,) * 4)[3] == carrier_id}
    dropped_snapshot = None
    if carrier.record_type == "api_watch_event":
        dropped_snapshot = next((m[0] for m in index.row_meta.values()
                                 if m[1] == "event" and m[2] == carrier.sequence), None)
    facts = {"constructed": True, "switch_record": switch.record_id, "subject": subject, "preceding_value": prev,
             "revealed_value": switch.value, "carrier": carrier_id, "carrier_type": carrier.record_type,
             "carrier_event_type": carrier.event_type, "carrier_received_at": R.iso(carrier.observed_us),
             "carrier_available_at": R.iso(carrier.available_us), "snapshot_rows_from_carrier": len(affected),
             "snapshot_triggered_by_carrier": dropped_snapshot}
    streams = []
    missing = []
    withheld = dropped = 0
    for r in base:
        if dropped_snapshot is not None and r.group == dropped_snapshot:
            dropped += 1
            continue
        if r.record_id in affected:
            missing.append(replace(r, record_id=r.record_id + "#withheld", value=prev))
            withheld += 1
        else:
            missing.append(r)
    streams.append({"name": "missing_switch_event", "family": "missing", "records": tuple(missing),
                    "description": (f"watch variant: the {carrier.event_type or 'relisted'} "
                                    f"{carrier.record_type} {carrier_id} received {hms(carrier.observed_us)}, the first "
                                    f"to show a {service} Pod leaving ready, is withheld before cache materialisation: "
                                    f"its snapshot is not taken ({dropped} records dropped) and {withheld} later "
                                    f"snapshot records of the Pod show its preceding state ({prev})"),
                    "manifest": dict(facts, perturbation="withhold_event", records_dropped=dropped,
                                     records_withheld=withheld)})
    for s in CORRECTION_DELAYS:
        shift = R.seconds_to_us(s)
        cut, corrected_at = carrier.observed_us + shift, carrier.available_us + shift
        out, pairs = [], 0
        for r in base:
            if r.record_id in affected and r.observed_at < cut:
                stale = replace(r, record_id=r.record_id + "#stale", value=prev)
                corrected = replace(r, record_id=r.record_id + "#corrected",
                                    available_at=max(corrected_at, r.available_at + 1), corrects=stale.record_id)
                out.extend((stale, corrected))
                pairs += 1
            else:
                out.append(r)
        streams.append({"name": f"corrected_late_event_{s}s", "family": "corrected", "records": tuple(out),
                        "description": (f"watch variant: {carrier_id} first carries the "
                                        f"preceding state ({prev}); the {pairs} snapshot records of the Pod "
                                        f"materialised from it within {s} s of its receipt are stale versions, "
                                        f"corrected by versions with {switch.value} available {s} s after its "
                                        "acceptance"),
                        "manifest": dict(facts, perturbation="event_carries_preceding_state", seconds=s,
                                         corrected_pairs=pairs, corrected_available_at=R.iso(corrected_at))})
    for s in streams:
        R.Stream(s["records"])                 # validates unique ids and the correction links
    return streams, [], facts


SWITCH_DEFINITIONS = {
    POLLER: ("replay-policy-v1 build_capture_perturbations: missing_switch_poll drops every "
             "record revealing a transition at the instant of the first record showing a Pod of the changed service "
             "leaving ready (one poll); corrected_late_{3,10}s let those records arrive with the preceding state and "
             "add corrected versions available 3 / 10 s later"),
    WATCH: ("defined on the event before cache materialisation: missing_switch_event withholds "
            "the first watch event revealing a Pod of the changed service leaving ready (its snapshot is not taken; "
            "later snapshots show the Pod's preceding version until its next event); corrected_late_event_{3,10}s let "
            "that event carry the preceding state, every snapshot materialised from it within 3 / 10 s being "
            "corrected at the event's acceptance + 3 / 10 s"),
    WATCH_EVENT: ("the bridge's own record-level rule applied to the event log (secondary observer): the revealing "
                  "records at the switch instant (one socket read) are dropped / carry the preceding state"),
}


# ---------------------------------------------------------------------------------------------------------------
# Bridge input per observer (context_bridge.load_capture_input, reproduced with the observer's loader)
# ---------------------------------------------------------------------------------------------------------------
def load_bridge_input(capture: Path, observer: str, *, root: Path = ROOT):
    """context_bridge.load_capture_input (src/aiops_kg/context_bridge.py lines 981-1020) with
    load_stage2_task.task_for_service in place of replay.load_capture_task. Model input: <capture>/evidence/ only.
    Returns (BridgeInput, ObserverStore)."""
    capture = Path(capture).resolve()
    evidence_file = capture / "evidence" / "accepted_evidence.jsonl"
    if not evidence_file.exists():
        raise FileNotFoundError(f"{evidence_file} not found: run phase3/convert_capture.py --capture {capture} first")
    protocol = json.loads((capture / "evidence" / "protocol.json").read_text(encoding="utf-8"))
    store = L.load_observer(capture, observer, root=root)
    spans = B.requests_from_span_rows(store.rows)
    services, records, tasks, notes = [], [], {}, list(spans.notes)
    changed = protocol.get("replacement_service") or None
    for name in spans.services:
        try:
            task = L.task_for_service(store, name)
        except ValueError as error:
            if name in (spans.frontend_service, changed):
                raise
            notes.append(f"{name}: not a candidate service ({error}); its features are not used")
            continue
        tasks[name] = task
        services.append(B.ServiceContext(name, task.candidates, task.predicate, task.serving_value,
                                         task.retired_values))
        records.extend(task.records)
        mine = {spans.trace_of[r.request_id]: r for r in spans.requests}
        for r in task.context["requests"]:
            req = mine.get(r["trace_id"])
            if req is None or req.t != r["t_req_us"] or \
                    spans.served_by[req.request_id].get(name) != "Pod/" + r["truth_uid"]:
                raise ValueError(f"{name}: request {r['trace_id']} disagrees with replay.load_capture_task")
        notes.extend(f"{name}: {n}" for n in task.context["notes"])
    R.Stream(records)
    if changed is not None and changed not in tasks:
        raise ValueError(f"changed service {changed!r} has no workload span in the capture")
    return B.BridgeInput(capture.name, tuple(services), tuple(records), spans, changed,
                         tasks.get(changed) if changed else None, tasks, tuple(notes)), store


def receipt_requests(rows: list, spans) -> tuple[tuple, dict]:
    """The secondary row: each span's measured trace-tail receipt instead of its end as its availability (the bridge
    calls span-end availability "optimistic"). A request becomes observable at the latest acquisition (span_claim
    available_ns: the live trace-tail line receipt, else the final trace-export receipt; phase3/CAPTURE_FORMAT.md)
    of the spans that feed its features: the client root span (the frontend's features) and every SERVER span of a
    downstream service with a feature in it. t, the features and the truth are unchanged; RequestTelemetry.end
    carries the availability (it is read only by the observed-request rule, root span end <= c). A receipt earlier
    than t (only possible under a clock offset) is clamped to t and counted."""
    by_trace = defaultdict(list)
    for row in rows:
        record = row["record"]
        if record["kind"] == "span_claim":
            by_trace[record["payload"]["trace_id"]].append((record["payload"], row["available_ns"] // 1000))
    out, clamped, basis = [], 0, Counter()
    for req in spans.requests:
        items = by_trace[spans.trace_of[req.request_id]]
        feeding = [(p, a) for p, a in items
                   if (not p["span"].get("parentSpanId") and "aiops.request.index" in (p.get("span_attributes") or {}))
                   or (p["span"].get("kind") == B.SPAN_SERVER
                       and (p.get("resource_attributes") or {}).get("service.name") in req.features
                       and (p.get("resource_attributes") or {}).get("service.name") != spans.frontend_service)]
        available = max(a for _, a in feeding)
        basis.update(str(p.get("acquisition_basis")) for p, _ in feeding)
        if available < req.t:
            clamped += 1
            available = req.t
        out.append(replace(req, end=available))
    return tuple(out), {"rule": "a request is observed at c iff every span feeding its features was acquired by c "
                                "(span_claim available_ns)", "requests": len(out),
                        "receipt_before_start_clamped": clamped,
                        "feeding_spans_by_acquisition_basis": dict(sorted(basis.items()))}


# ---------------------------------------------------------------------------------------------------------------
# The grid and its shaping (run_context_bridge_v1.py lines 166-388, reproduced)
# ---------------------------------------------------------------------------------------------------------------
def usable_records(stream, bridge, c) -> dict:
    return {svc.service: sum(len(stream.visible(cand.key, svc.predicate, c)) for cand in svc.candidates)
            for svc in bridge.services}


def run_grid(bridge, streams, policies, onset, truth_entity, requests=None):
    """run_context_bridge_v1.run_grid: hindsight per Delta on the complete records, then stream x Delta x policy.
    ``requests`` replaces the span-end telemetry (the receipt row); default: the bridge's requests."""
    windows = B.Windows.seconds(onset, W_BEFORE, W_AFTER)
    requests = bridge.spans.requests if requests is None else requests
    served_by = bridge.spans.served_by
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
    names = {c.key: f"{SHORT.get(s.service, s.service)} {c.label} {c.key.split('/', 1)[1][:8]}"
             for s in bridge.services for c in s.candidates}
    for u in B.unsighted_entities(bridge.services, bridge.spans.requests, bridge.spans.served_by):
        names.setdefault(u["entity"], f"{SHORT.get(u['service'], u['service'])} unsighted "
                                      f"{u['entity'].split('/', 1)[1][:8]}")
    return names


def unsighted_report(bridge, names, onset) -> list:
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
        elif m.get("perturbation") in ("withhold_event", "event_carries_preceding_state"):
            entry["watch_variant"] = {k: v for k, v in m.items() if k != "perturbation"}
        out.append(entry)
    return out + [{"name": s["name"], "not_applicable": s["reason"]} for s in skipped]


def base_results(bridge, streams, skipped, policies, onset, onset_source, hindsight, cells, checks) -> dict:
    """run_context_bridge_v1.base_results (the per-capture result block of the runner)."""
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


# ---------------------------------------------------------------------------------------------------------------
# L-4 rows and paired comparisons (experiments/context-bridge-v1/summarize_captures.py compare / row_of, reproduced)
# ---------------------------------------------------------------------------------------------------------------
def compare(rank, reference) -> str:
    """summarize_captures.compare: lower is better, absent counts as worse."""
    if rank is None and reference is None:
        return "both absent"
    if rank is None:
        return "worse"
    if reference is None:
        return "better"
    return "better" if rank < reference else "equal" if rank == reference else "worse"


def family_of(stream: str) -> str:
    return FAMILY.get(stream, stream)


def l4_rows(block: dict) -> list:
    """One row per hindsight Delta and per stream x Delta x policy of a shaped block (summarize_captures.row_of and
    diagnosis_of): truth outcome and pessimistic rank, Top-1 entity, wrong decision, frontend mis-attributed /
    abstained / coverage, unsighted, missing candidates, rank vs temporal_join and vs hindsight."""
    names = block["entity_names"]
    front = next((s["service"] for s in block["setup"]["services"] if s["role"] == "frontend"), None)

    def row(cell, stream, policy):
        t, svc = cell["truth"], cell["services"].get(front) or {}
        top1 = cell["ranking"]["top1_entity"]
        return {"stream": stream, "family": family_of(stream), "delta": cell["delta"],
                "delta_seconds": delta_seconds(cell["delta"]), "policy": policy,
                "outcome": t["outcome"], "reason": t.get("reason"), "rank": t["rank_pessimistic"],
                "candidates": t["candidates"], "top1": t["top1"], "top1_entity": top1,
                "top1_name": None if top1 is None else names.get(top1, top1),
                "wrong_decision": cell["wrong_entity_decision"], "mis_attributed": svc.get("mis_attributed"),
                "abstained": svc.get("abstained"), "coverage": svc.get("coverage"),
                "unsighted": cell["unattributable_unsighted_total"],
                "missing_vs_hindsight": [names.get(k, k) for k in cell["candidates"]["missing_vs_hindsight"]]}
    hind = {h["delta"]: h for h in block["hindsight"].values()}
    rows = [dict(row(h, "-", B.HINDSIGHT), vs_temporal_join=None, vs_hindsight=None) for h in hind.values()]
    cells = {(c["stream"], c["delta"], c["policy"]): c for c in block["cells"]}
    for s in [e["name"] for e in block["streams"] if "not_applicable" not in e]:
        for label, _ in DELTAS:
            tj = cells.get((s, label, TJ))
            for p in POLICY_ORDER:
                c = cells.get((s, label, p))
                if c is None:
                    continue
                r = row(c, s, p)
                r["vs_temporal_join"] = None if p == TJ or tj is None else compare(r["rank"],
                                                                                 tj["truth"]["rank_pessimistic"])
                r["vs_hindsight"] = compare(r["rank"], hind[label]["truth"]["rank_pessimistic"])
                rows.append(r)
    return rows


def paired_rows(rows_a: list, rows_b: list, label_a: str, label_b: str) -> list:
    """Per stream family x Delta x policy present in both: compare(rank under b, rank under a) (b relative to a)."""
    index = {(r["family"], r["delta"], r["policy"]): r for r in rows_a}
    out = []
    for r in rows_b:
        a = index.get((r["family"], r["delta"], r["policy"]))
        if a is None:
            continue
        out.append({"family": r["family"], "delta": r["delta"], "policy": r["policy"],
                    f"stream_{label_a}": a["stream"], f"stream_{label_b}": r["stream"],
                    f"outcome_{label_a}": a["outcome"], f"rank_{label_a}": a["rank"],
                    f"outcome_{label_b}": r["outcome"], f"rank_{label_b}": r["rank"],
                    "comparison": compare(r["rank"], a["rank"]),
                    "reading": f"{label_b} relative to {label_a}: better / equal / worse / both absent"})
    return out


# ---------------------------------------------------------------------------------------------------------------
# Inclusion: rules 1-3 and the secondary rule
# ---------------------------------------------------------------------------------------------------------------
def capture_record(capture: Path) -> dict:
    """The runner's own record (<capture>/capture.json): arm, scenario, attempt kind and the inputs of
    inclusion rules 1-2 (its validity fields only). Never a model input."""
    path = capture / "capture.json"
    doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    stage2 = doc.get("stage2") or {}
    return {"capture_json": path.exists(), "incident_id": doc.get("incident_id"), "arm": stage2.get("arm"),
            "scenario": stage2.get("scenario") or doc.get("incident_id"), "kind": stage2.get("kind"),
            "pilot": stage2.get("pilot"), "mode": stage2.get("mode"), "slot": stage2.get("slot"),
            "attempt": stage2.get("attempt"), "section10": doc.get("section10")}


def rules_1_2(record: dict) -> dict:
    section10 = record.get("section10")
    if not isinstance(section10, dict) or "excluded_by_rules_1_2" not in section10:
        return {"passed": False, "reasons": ["capture.json has no section10 record (inclusion rules 1-2 "
                                             "are read from the runner's validity fields)"]}
    reasons = []
    for number_, rule in ((1, section10.get("rule_1") or {}), (2, section10.get("rule_2") or {})):
        if rule.get("passed") is not True:
            failed = [k for k, v in sorted((rule.get("checks") or {}).items()) if v is not True]
            reasons.append(f"inclusion rule {number_} not passed" + (": " + ", ".join(failed) if failed else ""))
    rule2 = section10.get("rule_2") or {}
    if section10.get("excluded_by_rules_1_2") is not False and not reasons:
        reasons.append("capture.json section10 excluded_by_rules_1_2 is not false")
    return {"passed": not reasons, "reasons": reasons,
            "rule_2": {k: rule2.get(k) for k in ("passed", "checks") if k in rule2}}


def inclusion_of(truth: dict, bridges: dict, record: dict) -> dict:
    """Primary: rules 1-2 passed, and context_bridge.inclusion (items 1-3) true on the poller's AND the
    watch's bridge input (so the truth Pod is sighted by both observers, and the change verified by both). Secondary:
    rules 1-2 passed, not primary, and context_bridge.inclusion_secondary admitted on both inputs."""
    r12 = rules_1_2(record)
    rule3 = {o: B.inclusion(truth, bridges[o]) for o in PRIMARY_OBSERVERS}
    primary = r12["passed"] and all(v["included"] for v in rule3.values())
    a1 = {o: B.inclusion_secondary(truth, bridges[o]) for o in PRIMARY_OBSERVERS}
    secondary = r12["passed"] and not primary and all(v["admitted"] for v in a1.values())
    reasons = list(r12["reasons"]) + [f"{o}: {reason}" for o in PRIMARY_OBSERVERS for reason in rule3[o]["reasons"]]
    return {"rules_1_2": r12, "rule_3": rule3, "primary": primary, "secondary_rule": a1, "secondary": secondary,
            "reasons": [] if primary else reasons,
            "rule": "rules 1-2 from capture.json section10; rule 3 = context_bridge.inclusion "
                    "on the poller's and on the watch's input (truth Pod sighted by both); the secondary rule "
                    "(context_bridge.inclusion_secondary) on both, in its own secondary table"}


# ---------------------------------------------------------------------------------------------------------------
# H-D: per-capture facts, the mechanism of a worse cell, and the rule over captures
# ---------------------------------------------------------------------------------------------------------------
def hd_cells(rows: list) -> list:
    return [r for r in rows if r["stream"] == HD_STREAM and r["delta_seconds"] in HD_DELTAS
            and r["policy"] in HD_POLICIES]


def first_seen(records, subject, value) -> dict | None:
    rows = [r for r in records if r.subject == subject and r.value == value]
    if not rows:
        return None
    first = min(rows, key=lambda r: (r.available_at, r.observed_at, r.record_id))
    return {"record_id": first.record_id, "observed_at": R.iso(first.observed_at),
            "available_at": R.iso(first.available_at)}


def record_gap_at(records, subject, t_us) -> dict | None:
    """The truth Pod's records around instant t (its first served window request): the last record at or before t
    and the first after it, with the interval between them (the observer's record gap at the switch)."""
    rows = sorted((r for r in records if r.subject == subject), key=lambda r: (r.observed_at, r.record_id))
    before = [r for r in rows if r.observed_at <= t_us]
    after = [r for r in rows if r.observed_at > t_us]
    if not before and not after:
        return None
    b, a = (before[-1] if before else None), (after[0] if after else None)
    return {"last_before": None if b is None else {"value": b.value, "observed_at": R.iso(b.observed_at)},
            "first_after": None if a is None else {"value": a.value, "observed_at": R.iso(a.observed_at),
                                                   "available_at": R.iso(a.available_at)},
            "interval_seconds": None if a is None or b is None else round((a.observed_at - b.observed_at) / R.US, 6)}


def mechanism_of(block: dict, row: dict, truth: str, records, first_served_us, gaps) -> dict:
    """What, mechanically, put the truth Pod below hindsight in one cell ("each such capture's mechanism is reported"):
    the truth Pod's entity row (in view, candidate, window counts and where its requests went), the frontend service's
    abstentions, the Top-1 entity, the truth Pod's first 'ready' record in the observer's complete stream, the
    observer's record gap around the truth Pod's first served window request and, for the watch, its continuity gaps
    (stage2/continuity_gap.jsonl) overlapping [that request - 30 s, c]."""
    cell = next(c for c in block["cells"] if (c["stream"], c["delta"], c["policy"]) ==
                (row["stream"], row["delta"], row["policy"]))
    hind = block["hindsight"][row["delta"]]
    ent = cell["entities"].get(truth) or {}
    hent = hind["entities"].get(truth) or {}
    nw, aw = ent.get(B.NORMAL) or {}, ent.get(B.ANOMALOUS) or {}
    hn, ha = (hent.get(B.NORMAL) or {}).get("n", 0), (hent.get(B.ANOMALOUS) or {}).get("n", 0)
    front = next((s["service"] for s in block["setup"]["services"] if s["role"] == "frontend"), None)
    svc = cell["services"].get(front) or {}
    if row["outcome"] == "absent" and not ent.get("in_view"):
        what = "truth Pod not in view at c: no usable record of it"
    elif row["outcome"] == "absent":
        what = (f"truth Pod in view but no observed window request attributed to it ({nw.get('lost_to_other', 0) + aw.get('lost_to_other', 0)} "
                f"went to another Pod, {nw.get('lost_to_abstain', 0) + aw.get('lost_to_abstain', 0)} were abstained on)")
    elif nw.get("n", 0) == 0 and hn > 0:
        what = (f"truth Pod has no baseline: its {hn} normal-window requests went to another Pod "
                f"({nw.get('lost_to_other', 0)}) or were abstained on ({nw.get('lost_to_abstain', 0)}); it is "
                "unscorable")
    elif aw.get("n", 0) < ha:
        what = (f"truth Pod lost anomalous-window requests ({ha - aw.get('n', 0)} of {ha}: "
                f"{aw.get('lost_to_other', 0)} to another Pod, {aw.get('lost_to_abstain', 0)} abstained)")
    else:
        what = (f"truth Pod's aggregates differ from hindsight (normal n {nw.get('n', 0)} vs {hn}, anomalous n "
                f"{aw.get('n', 0)} vs {ha}; {nw.get('mis_attributed', 0) + aw.get('mis_attributed', 0)} requests of "
                "other Pods fed into it)")
    c_us = B._us(cell["cutoff"]) if cell.get("cutoff") else None
    window_gaps = []
    if first_served_us is not None and c_us is not None:
        lo, hi = first_served_us - 30 * R.US, c_us
        for g in gaps or []:
            start = B._us(g["gap_from_at"]) if g.get("gap_from_at") else None
            end = B._us(g["gap_to_at"]) if g.get("gap_to_at") else None
            if (start is None or start < hi) and (end is None or end > lo):
                window_gaps.append(g)
    return {"stream": row["stream"], "delta": row["delta"], "policy": row["policy"], "classification": what,
            "outcome": row["outcome"], "reason": row["reason"], "rank": row["rank"],
            "hindsight_rank": hind["truth"]["rank_pessimistic"], "candidates": row["candidates"],
            "in_view": ent.get("in_view"), "candidate": ent.get("candidate"),
            "normal_n": nw.get("n", 0), "hindsight_normal_n": hn, "anomalous_n": aw.get("n", 0),
            "hindsight_anomalous_n": ha,
            "normal_lost_to_other": nw.get("lost_to_other", 0), "normal_lost_to_abstain": nw.get("lost_to_abstain", 0),
            "anomalous_lost_to_other": aw.get("lost_to_other", 0),
            "anomalous_lost_to_abstain": aw.get("lost_to_abstain", 0),
            "fed_by_other_pods": nw.get("mis_attributed", 0) + aw.get("mis_attributed", 0),
            "frontend_mis_attributed": svc.get("mis_attributed"), "frontend_abstained": svc.get("abstained"),
            "frontend_abstain_reasons": svc.get("abstain_reasons"), "top1_entity": row["top1_name"],
            "wrong_decision": row["wrong_decision"],
            "truth_first_ready_record": first_seen(records, truth, "ready"),
            "record_gap_at_first_served_request": (None if first_served_us is None else
                                                   record_gap_at(records, truth, first_served_us)),
            "watch_continuity_gaps_overlapping": window_gaps}


def clock_band_of(capture: Path) -> dict | None:
    """The capture's clock band b_c from evidence/stage2/clock_probe.jsonl, by fault_control_kill.clock_band; None
    without clock-probe rows. Descriptive here: the bridge compares request times (node clock, span start) with
    record times (host clock), so a transition the watch records within b_c of a request can fall on either side of
    it."""
    path = Path(capture) / "evidence" / CLOCK_FILE
    if not path.exists():
        return None
    documents = [json.loads(line)["record"]["payload"] for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
    band = K.clock_band(documents)
    return {k: band.get(k) for k in ("band_available", "band_ns", "widest_bound_ns", "union_ns",
                                     "intersection_empty", "readings_used")}


def capture_hd(name: str, blocks: dict, rows: dict, truth: str, bridges: dict, first_served_us, gaps,
               band: dict | None = None) -> dict:
    """Per included D1 capture: the H-D cells per observer, which are worse than hindsight, and their mechanisms
    (with the capture's clock band beside each, for reading a sub-second record gap)."""
    hindsight = {o: {r["delta"]: [r["outcome"], r["rank"]] for r in rows[o] if r["stream"] == "-"}
                 for o in PRIMARY_OBSERVERS}
    out = {"capture": name, "hindsight_by_observer": hindsight,
           "hindsight_agree": hindsight[POLLER] == hindsight[WATCH]}
    for o in PRIMARY_OBSERVERS:
        cells = hd_cells(rows[o])
        worse = [r for r in cells if r["vs_hindsight"] == "worse"]
        out[o] = {"cells": [{k: r[k] for k in ("stream", "delta", "policy", "outcome", "rank", "vs_hindsight")}
                            for r in cells],
                  "worse": [{k: r[k] for k in ("delta", "policy", "outcome", "rank")} for r in worse],
                  "better": [{k: r[k] for k in ("delta", "policy", "outcome", "rank")} for r in cells
                             if r["vs_hindsight"] == "better"],
                  "in_E": bool(worse),
                  "mechanisms": [mechanism_of(blocks[o], r, truth, bridges[o].records, first_served_us,
                                              gaps if o == WATCH else None) for r in worse]}
        ready = first_seen(bridges[o].records, truth, "ready")
        for m in out[o]["mechanisms"]:
            m["clock_band_seconds"] = None if not (band or {}).get("band_available") else band["band_ns"] / 1e9
            m["first_ready_record_minus_first_served_request_seconds"] = (
                None if ready is None or first_served_us is None else
                round((B._us(ready["observed_at"]) - first_served_us) / R.US, 6))
    return out


def hd_rule(captures: list) -> dict:
    """The H-D rule of over the included D1 captures (each the capture_hd() record)."""
    names = [c["capture"] for c in captures]
    e_p = [c["capture"] for c in captures if c[POLLER]["in_E"]]
    e_w = [c["capture"] for c in captures if c[WATCH]["in_E"]]
    if e_w:
        verdict = "refuted"
    elif e_p:
        verdict = "confirmed as a poller artefact"
    else:
        verdict = "untested"
    reading = {
        "refuted": ("E_W is non-empty: the watch did not remove the effect in at least one capture"
                    + (" (E_P is empty as well: the poller showed no effect, the watch did)" if not e_p else "")
                    + "; each capture's mechanism is listed and the boundary wording (L-4, C-H) is to be revised in "
                      "the claim table"),
        "confirmed as a poller artefact": "E_P non-empty and E_W empty: boundary confirmed as a poller artefact",
        "untested": ("E_P is empty: the poller effect did not occur on these captures, so the watch had nothing to "
                     "remove; reported as untested, never as support"
                     + (" (no included D1 capture)" if not names else "")),
    }[verdict]
    return {"statement": HD_STATEMENT, "n_included_d1": len(names), "included_d1": names,
            "E_P": e_p, "E_W": e_w, "verdict": verdict, "reading": reading,
            "E_P_text": f"E_P = {{{', '.join(e_p)}}} ({len(e_p)} of {len(names)} included D1 captures)",
            "E_W_text": f"E_W = {{{', '.join(e_w)}}} ({len(e_w)} of {len(names)} included D1 captures)",
            "mechanisms_E_W": {c["capture"]: c[WATCH]["mechanisms"] for c in captures if c[WATCH]["in_E"]},
            "mechanisms_E_P": {c["capture"]: c[POLLER]["mechanisms"] for c in captures if c[POLLER]["in_E"]},
            "better_than_hindsight": {o: {c["capture"]: c[o]["better"] for c in captures if c[o]["better"]}
                                      for o in PRIMARY_OBSERVERS},
            "hindsight_differs_between_observers": [c["capture"] for c in captures if not c["hindsight_agree"]],
            "expected_frequency": EXPECTED_FREQUENCY}


# ---------------------------------------------------------------------------------------------------------------
# One capture
# ---------------------------------------------------------------------------------------------------------------
def observer_block(bridge, store, streams, skipped, policies, truth, *, requests=None, extra=None) -> dict:
    hindsight, cells = run_grid(bridge, streams, policies, truth["onset"], truth["truth_entity"], requests=requests)
    block = base_results(bridge, streams, skipped, policies, truth["onset"], truth["onset_source"], hindsight, cells,
                         {"determinism": "not recomputed in process; two separate processes are compared in "
                                         "tests/test_stage2_diagnosis_control.py"})
    block = jsonable(block)
    block["loader"] = jsonable(store.report)
    if extra:
        block.update(jsonable(extra))
    block["rows"] = l4_rows(block)
    return block


def provenance(capture: Path) -> dict:
    import networkx
    import numpy
    return {"environment": {"python": platform.python_version(), "numpy": numpy.__version__,
                            "networkx": networkx.__version__}}


def mode_field(mode: str) -> dict:
    """The run marker written into every output of a fixture run (none for a run on study captures)."""
    return {} if mode == "study" else {"mode": mode}


def analyse_capture(capture: Path, *, mode: str, allow_other_kinds: bool) -> dict:
    """Everything for one capture: arm and attempt-kind checks, inclusion, the grids per observer, the
    receipt row, the event-log secondary, the paired observer rows and the per-capture H-D facts."""
    capture = Path(capture).resolve()
    record = capture_record(capture)
    head = {"kind": "stage2_diagnosis_control_one_capture", "version": VERSION, **mode_field(mode),
            "capture": {"directory": capture.name, **{k: v for k, v in record.items() if k != "section10"}},
            "section10": record.get("section10")}
    if record["kind"] == "pilot" or record["pilot"] is True:
        return dict(head, category="not_analysed", reasons=["pilot attempt: no condition is evaluated and no "
                                                            "label is computed on a pilot"])
    if record["arm"] != "D":
        return dict(head, category="not_analysed", reasons=[f"not an arm-D capture (arm {record['arm']!r}): the "
                                                            "diagnosis control runs on arm D only (section 3.1)"])
    if record["kind"] != "study" and not allow_other_kinds:
        return dict(head, category="not_analysed", reasons=[f"attempt kind {record['kind']!r}: only study "
                                                            "attempts enter the analysis (--any-kind: all)"])
    r12 = rules_1_2(record)
    if not r12["passed"]:                                   # section 10: validity fields first, nothing loaded
        return dict(head, category="excluded", reasons=r12["reasons"],
                    inclusion={"rules_1_2": r12, "primary": False, "secondary": False, "reasons": r12["reasons"]})
    policies = make_policies()
    truth = B.load_capture_truth(capture)                  # evaluator only: onset, truth entity, status
    bridges, stores = {}, {}
    for o in PRIMARY_OBSERVERS:
        bridges[o], stores[o] = load_bridge_input(capture, o)
    inclusion = inclusion_of(truth, bridges, record)
    scenario = record["scenario"]
    if inclusion["primary"]:
        category = f"primary_{scenario}" if scenario in ("D1", "D2") else "primary_other"
    elif inclusion["secondary"]:
        category = "secondary"
    else:
        category = "excluded"
    head.update(category=category, reasons=inclusion["reasons"], inclusion=inclusion,
                evaluator_only={"truth_entity": truth["truth_entity"], "truth_source": truth["truth_source"],
                                "onset": R.iso(truth["onset"]), "onset_source": truth["onset_source"],
                                "labels": truth["labels"], "fault_target": truth["fault_target"],
                                "evaluation_summary": truth["evaluation_summary"],
                                "note": "read from ground_truth/ for scoring only; never passed to a policy"},
                loaders={o: jsonable(stores[o].report) for o in PRIMARY_OBSERVERS},
                clock_band=clock_band_of(capture), provenance=provenance(capture))
    if category == "excluded":
        return head                                         # never analysed for outcomes
    index = L.WatchIndex.load(capture)
    blocks, rows = {}, {}
    streams, skipped = bridge_streams(bridges[POLLER])
    blocks[POLLER] = observer_block(bridges[POLLER], stores[POLLER], streams, skipped, policies, truth,
                                    extra={"switch_definition": SWITCH_DEFINITIONS[POLLER]})
    w_streams, w_skipped = bridge_streams(bridges[WATCH])
    w_streams = [s for s in w_streams if s["family"] in ("complete", "delayed")]
    w_skipped = [s for s in w_skipped if s["name"] not in FAMILY]
    switch_streams, switch_skipped, switch_facts = watch_switch_streams(bridges[WATCH], index)
    blocks[WATCH] = observer_block(bridges[WATCH], stores[WATCH], w_streams + switch_streams,
                                   w_skipped + switch_skipped, policies, truth,
                                   extra={"switch_definition": SWITCH_DEFINITIONS[WATCH], "watch_switch": switch_facts,
                                          "watch_continuity_gaps": index.gaps})
    for o in PRIMARY_OBSERVERS:
        rows[o] = blocks[o]["rows"]
    secondary = {}
    try:                                                    # SECONDARY: the watch as an event log (no cache)
        bridge_e, store_e = load_bridge_input(capture, WATCH_EVENT)
        e_streams, e_skipped = bridge_streams(bridge_e)
        secondary[WATCH_EVENT] = observer_block(bridge_e, store_e, e_streams, e_skipped, policies, truth,
                                                extra={"switch_definition": SWITCH_DEFINITIONS[WATCH_EVENT]})
    except (Exception, SystemExit) as error:               # reported; never changes the primary analysis
        secondary[WATCH_EVENT] = {"error": scrub(f"{type(error).__name__}: {error}", capture)}
    receipt = {}
    for o in PRIMARY_OBSERVERS:                             # SECONDARY: telemetry at its trace-tail receipt
        requests, facts = receipt_requests(stores[o].rows, bridges[o].spans)
        complete = [s for s in (streams if o == POLLER else w_streams) if s["name"] == "complete"]
        receipt[o] = observer_block(bridges[o], stores[o], complete, [], policies, truth, requests=requests,
                                    extra={"availability": facts})
    windows = B.Windows.seconds(truth["onset"], W_BEFORE, W_AFTER)
    first_served = None
    if truth["truth_entity"]:
        served = [r.t for r in bridges[POLLER].spans.requests if windows.of(r.t) is not None
                  and truth["truth_entity"] in bridges[POLLER].spans.served_by[r.request_id].values()]
        first_served = min(served) if served else None
    head.update(observers=blocks, secondary_observers=secondary, receipt_availability=receipt,
                paired_poller_watch=paired_rows(rows[POLLER], rows[WATCH], POLLER, WATCH),
                paired_receipt={o: paired_rows(rows[o], receipt[o]["rows"], "span_end", "receipt")
                                for o in PRIMARY_OBSERVERS},
                h_d=None if truth["truth_entity"] is None else capture_hd(
                    capture.name, blocks, rows, truth["truth_entity"], bridges, first_served, index.gaps,
                    head.get("clock_band")))
    return head


# ---------------------------------------------------------------------------------------------------------------
# Across captures (the L-4 convention: counts of captures, never rates)
# ---------------------------------------------------------------------------------------------------------------
def counts(results: list, rows_of) -> dict:
    """The development-results counts over the given captures, per stream family x Delta x policy
    (hindsight first): Top-1 / not Top-1 / absent / no cell / wrong decision / rank worse than hindsight / vs
    temporal_join, with the capture lists. rows_of(result) -> that capture's L-4 rows."""
    names = [r["capture"]["directory"] for r in results]
    by_key = defaultdict(list)
    for res in results:
        for row in rows_of(res) or []:
            by_key[(row["family"], row["delta"], row["policy"])].append((res["capture"]["directory"], row))
    order = [("-", label, B.HINDSIGHT) for label, _ in DELTAS] + \
            [(f, label, p) for f in FAMILIES for label, _ in DELTAS for p in POLICY_ORDER]
    out = []
    for key in order:
        present = by_key.get(key, [])
        if not present and key[0] != "-" and not any(by_key.get((key[0], d, p)) for d, _ in DELTAS
                                                     for p in POLICY_ORDER):
            continue
        row = {"family": key[0], "delta": key[1], "policy": key[2], "n": len(names),
               "streams": sorted({r["stream"] for _, r in present}),
               "top1": sum(r["outcome"] == "top1" for _, r in present),
               "not_top1": sum(r["outcome"] == "not_top1" for _, r in present),
               "absent": sum(r["outcome"] == "absent" for _, r in present),
               "no_cell": len(names) - len(present),
               "wrong_decision": sum(r["wrong_decision"] is True for _, r in present),
               "top1_in": [c for c, r in present if r["outcome"] == "top1"],
               "wrong_decision_in": [c for c, r in present if r["wrong_decision"] is True]}
        if key[2] != B.HINDSIGHT:
            row["rank_worse_than_hindsight"] = sum(r["vs_hindsight"] == "worse" for _, r in present)
            row["rank_worse_than_hindsight_in"] = [c for c, r in present if r["vs_hindsight"] == "worse"]
            if key[2] != TJ:
                row["vs_temporal_join"] = {k: sum(r["vs_temporal_join"] == k for _, r in present)
                                           for k in ("better", "equal", "worse", "both absent")}
        row["text"] = f"Top-1 in {row['top1']} of {len(names)}"
        out.append(row)
    return {"n": len(names), "captures": names, "rows": out}


def paired_counts(results: list, pairs_of) -> list:
    by_key = defaultdict(list)
    for res in results:
        for p in pairs_of(res) or []:
            by_key[(p["family"], p["delta"], p["policy"])].append((res["capture"]["directory"], p["comparison"]))
    out = []
    for f in FAMILIES:
        for label, _ in DELTAS:
            for policy in POLICY_ORDER:
                items = by_key.get((f, label, policy))
                if items:
                    out.append({"family": f, "delta": label, "policy": policy,
                                **{k: sum(c == k for _, c in items) for k in ("better", "equal", "worse",
                                                                             "both absent")},
                                "worse_in": [n for n, c in items if c == "worse"],
                                "better_in": [n for n, c in items if c == "better"]})
    return out


def e_set(results: list, rows_of, *, family: str = HD_STREAM, policies: tuple = HD_POLICIES) -> list:
    """The captures in which any of the given policies ranks the truth Pod worse than hindsight in the given stream
    family at Delta in {30, 60} s (the H-D rule's membership test, on other rows)."""
    return [res["capture"]["directory"] for res in results
            if any(r["family"] == family and r["delta_seconds"] in HD_DELTAS and r["policy"] in policies
                   and r["vs_hindsight"] == "worse" for r in rows_of(res) or [])]


def summarise(results: list, *, mode: str) -> dict:
    by_category = defaultdict(list)
    for r in results:
        by_category[r.get("category", "analysis_error")].append(r)
    d1, d2, a1 = by_category.get("primary_D1", []), by_category.get("primary_D2", []), by_category.get(
        "secondary", [])

    def obs_rows(o):
        return lambda res: res["observers"][o]["rows"]

    def receipt_rows(o):
        return lambda res: res["receipt_availability"][o]["rows"]

    def event_rows(res):
        block = res["secondary_observers"].get(WATCH_EVENT) or {}
        return block.get("rows")

    register = [{"capture": r["capture"]["directory"], "scenario": r["capture"].get("scenario"),
                 "kind": r["capture"].get("kind"), "category": r.get("category", "analysis_error"),
                 "reasons": r.get("reasons") or ([r["error"]] if r.get("error") else []),
                 "truth_entity": (r.get("evaluator_only") or {}).get("truth_entity"),
                 "watch_clamps": len(((r.get("loaders") or {}).get(WATCH) or {}).get("clamps") or []),
                 "poller_clamps": len(((r.get("loaders") or {}).get(POLLER) or {}).get("clamps") or [])}
                for r in results]
    hd = hd_rule([r["h_d"] for r in d1 if r.get("h_d")])
    sets = {"reading": ("DESCRIPTIVE ONLY, never the H-D verdict: the H-D membership test applied to the secondary "
                        "and sensitivity rows, over the same included D1 captures; "
                        "a capture without the row (e.g. a watch switch variant not constructed) is in no set"),
            "bitemporal_F30_in_place_of_F600": {"E_P": e_set(d1, obs_rows(POLLER), policies=(TJ, B30)),
                                                "E_W": e_set(d1, obs_rows(WATCH), policies=(TJ, B30))},
            "telemetry_at_receipt": {"E_P": e_set(d1, receipt_rows(POLLER)), "E_W": e_set(d1, receipt_rows(WATCH))},
            "watch_event_log": {"E_E": e_set(d1, event_rows)}}
    for family in ("missing_switch", "corrected_late_3s", "corrected_late_10s"):
        sets[family] = {"E_P": e_set(d1, obs_rows(POLLER), family=family),
                        "E_W": e_set(d1, obs_rows(WATCH), family=family),
                        "watch_rows_in": [r["capture"]["directory"] for r in d1
                                          if any(x["family"] == family for x in r["observers"][WATCH]["rows"])]}
    return {
        "kind": "stage2_diagnosis_control_summary", "version": VERSION, **mode_field(mode),
        "scope": ("Counts on the listed captures, never rates"
                  ". One capture = one incident; streams, Delta and policies are replays of it."),
        "register": register,
        "h_d": hd,
        "h_d_secondary_rows": sets,
        "primary_d1": {o: counts(d1, obs_rows(o)) for o in PRIMARY_OBSERVERS},
        "primary_d1_paired_poller_watch": paired_counts(d1, lambda res: res["paired_poller_watch"]),
        "primary_d2": {o: counts(d2, obs_rows(o)) for o in PRIMARY_OBSERVERS},
        "secondary": {o: counts(a1, obs_rows(o)) for o in PRIMARY_OBSERVERS},
        "secondary_receipt_d1": {o: counts(d1, receipt_rows(o)) for o in PRIMARY_OBSERVERS},
        "secondary_watch_event_d1": counts([r for r in d1 if event_rows(r)], event_rows),
        "switch_stream_definitions": SWITCH_DEFINITIONS,
        "watch_switch_variants": {r["capture"]["directory"]: r["observers"][WATCH].get("watch_switch")
                                  for r in d1 + d2 + a1},
    }


# ---------------------------------------------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------------------------------------------
BANNER = {"FIXTURE": "**FIXTURE run on synthetic captures built by this script: no result, a tooling check only.**"}
CELL_COLUMNS = ("observer", "availability", "stream", "family", "delta", "policy", "outcome", "reason",
                "rank", "candidates", "top1", "top1_entity", "wrong_decision", "mis_attributed", "abstained", "coverage",
                "unsighted", "missing_vs_hindsight", "vs_temporal_join", "vs_hindsight")


def cells_csv(res: dict) -> str:
    buffer = io.StringIO()
    w = csv.writer(buffer, lineterminator="\n")
    w.writerow(CELL_COLUMNS)
    blocks = [(o, "span_end", res["observers"][o]) for o in PRIMARY_OBSERVERS]
    blocks += [(o, "span_end", b) for o, b in res["secondary_observers"].items() if b.get("rows")]
    blocks += [(o, "receipt", res["receipt_availability"][o]) for o in PRIMARY_OBSERVERS]
    for observer, availability, block in blocks:
        for r in block["rows"]:
            w.writerow([observer, availability, r["stream"], r["family"], r["delta"], r["policy"],
                        r["outcome"],
                        r["reason"] or "", "" if r["rank"] is None else r["rank"], r["candidates"], r["top1"],
                        r["top1_name"] or "", r["wrong_decision"], r["mis_attributed"], r["abstained"], r["coverage"],
                        r["unsighted"], "; ".join(r["missing_vs_hindsight"]), r["vs_temporal_join"] or "",
                        r["vs_hindsight"] or ""])
    return buffer.getvalue()


def row_text(r: dict) -> str:
    rank = "-" if r["rank"] is None else f"{r['rank']} of {r['candidates']}"
    outcome = r["outcome"] + (f" ({r['reason']})" if r.get("reason") else "")
    coverage = "-" if r["coverage"] is None else f"{100 * r['coverage']:.1f}%"
    missing = ", ".join(r["missing_vs_hindsight"]) or "none"
    return (f"| `{r['stream']}` | {r['delta']} | {POLICY_LABEL.get(r['policy'], r['policy'])} | {outcome} | {rank} | "
            f"{r['top1_name'] or 'none'} | {'yes' if r['wrong_decision'] else 'no'} | {r['mis_attributed']} | "
            f"{r['abstained']} | {r['unsighted']} | {coverage} | {missing} | {r['vs_temporal_join'] or '-'} | "
            f"{r['vs_hindsight'] or '-'} |")


ROW_HEAD = ["| Stream | Δ | Policy | Truth outcome | Rank (pessimistic) | Top-1 entity | Wrong decision | "
            "Mis-attributed | Abstained | Unsighted | Coverage | Missing vs hindsight | vs temporal_join | "
            "vs hindsight |", "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |"]


def render_capture(res: dict) -> str:
    cap = res["capture"]
    L_ = [f"# Stage-2 diagnosis control on `{cap['directory']}` ({cap.get('scenario')})", ""]
    if res.get("mode") in BANNER:
        L_ += [BANNER[res["mode"]], ""]
    L_ += [f"Category: **{res.get('category')}**" + (" — " + "; ".join(res.get("reasons") or []) if res.get("reasons")
                                                     else "") + ".", ""]
    if res.get("category") == "analysis_error":
        L_ += ["The analysis of this capture failed; no file here is a result. Error: " + res["error"], "",
               "Traceback (paths replaced by <capture>, <captures>, <root>):", "", "```", res["traceback"].rstrip(),
               "```", ""]
        return "\n".join(L_)
    if "observers" not in res:
        L_ += ["No grid was computed (an excluded attempt is listed with its reasons and never analysed for "
               "outcomes; a capture outside arm D, a pilot, or an attempt of another kind than 'study' is "
               "not analysed).", ""]
        if res.get("loaders"):
            L_ += ["Loader facts: " + "; ".join(f"{o}: {len(v.get('clamps') or [])} creation-ceiling clamps"
                                               for o, v in res["loaders"].items()) + ".", ""]
        return "\n".join(L_)
    ev = res["evaluator_only"]
    names = res["observers"][POLLER]["entity_names"]
    L_ += [f"- Truth entity (evaluator only): {names.get(ev['truth_entity'], ev['truth_entity'])}; onset "
           f"{ev['onset']} ({ev['onset_source']}).",
           "- Loaders: " + "; ".join(f"{o}: {v['sightings']} sightings from {', '.join(v['files'])}, "
                                     f"{len(v['clamps'])} creation-ceiling clamps" for o, v in res["loaders"].items())
           + ".", ""]
    hd = res.get("h_d")
    if hd:
        L_ += ["## H-D cells (complete stream, Δ ∈ {30, 60} s, temporal_join and bitemporal_abstain F = 600 s)", ""]
        for o in PRIMARY_OBSERVERS:
            worse = hd[o]["worse"]
            L_.append(f"- {o}: " + ("worse than hindsight in " + ", ".join(f"{w['policy']} at {w['delta']} "
                                                                          f"({w['outcome']}, rank {w['rank']})"
                                                                          for w in worse) if worse else
                                   "every cell ranks the truth Pod as hindsight does or better")
                      + (f" — in E_{'P' if o == POLLER else 'W'}" if hd[o]["in_E"] else "") + ".")
            for m in hd[o]["mechanisms"]:
                L_.append(f"  - mechanism ({m['policy']}, {m['delta']}): {m['classification']}; Top-1 "
                          f"{m['top1_entity'] or 'none'}; record gap at the truth Pod's first served window request: "
                          f"{json.dumps(m['record_gap_at_first_served_request'], sort_keys=True)}"
                          + (f"; watch gaps {json.dumps(m['watch_continuity_gaps_overlapping'], sort_keys=True)}"
                             if m["watch_continuity_gaps_overlapping"] else "") + ".")
        L_.append("")
    for o in PRIMARY_OBSERVERS:
        block = res["observers"][o]
        L_ += [f"## {o}: rank of the truth entity (pessimistic under ties), Top-1, absent", "",
               f"Switch streams: {block['switch_definition']}.", ""]
        if o == WATCH:
            L_ += [f"Watch switch variant: {json.dumps(block.get('watch_switch'), sort_keys=True)}.", ""]
        L_ += ROW_HEAD
        L_ += [row_text(r) for r in block["rows"] if r["family"] in REPORTED_FAMILIES + ("-",)]
        L_.append("")
    L_ += ["## Paired: watch relative to poller (same stream family, Δ, policy)", "",
           "| Family | Δ | Policy | Poller | Watch | Watch vs poller |", "| --- | --- | --- | --- | --- | --- |"]
    for p in res["paired_poller_watch"]:
        if p["family"] in REPORTED_FAMILIES:
            L_.append(f"| {p['family']} | {p['delta']} | {POLICY_LABEL[p['policy']]} | {p['outcome_poller']} "
                      f"({p['rank_poller'] or '-'}) | {p['outcome_watch']} ({p['rank_watch'] or '-'}) | "
                      f"{p['comparison']} |")
    L_ += ["", "## Secondary rows", "",
           "- Telemetry at its trace-tail receipt (complete stream): see `results.json` `receipt_availability` and "
           "`cells.csv` (availability = receipt).",
           "- The watch as an event log (no cache): `results.json` `secondary_observers.watch_event`" +
           (f" (error: {res['secondary_observers'][WATCH_EVENT]['error']})"
            if "error" in res["secondary_observers"].get(WATCH_EVENT, {}) else "") + ".",
           "- Every other stream, Δ and policy: `cells.csv`.", ""]
    return "\n".join(L_)


def counts_table(c: dict, families=REPORTED_FAMILIES) -> list:
    n = c["n"]
    out = [f"| Family | Δ | Policy | Top-1 | not Top-1 | absent | no cell | wrong decision | rank worse than "
           f"hindsight | vs temporal_join (b/e/w/both absent) | Top-1 in | rank worse in |",
           "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |"]
    for r in c["rows"]:
        if r["family"] not in families + ("-",):
            continue
        vs = r.get("vs_temporal_join")
        out.append(f"| {r['family']} | {r['delta']} | {POLICY_LABEL.get(r['policy'], r['policy'])} | "
                   f"{r['top1']} of {n} | {r['not_top1']} | {r['absent']} | {r['no_cell']} | {r['wrong_decision']} | "
                   f"{r.get('rank_worse_than_hindsight', '-')} | "
                   f"{' / '.join(str(vs[k]) for k in ('better', 'equal', 'worse', 'both absent')) if vs else '-'} | "
                   f"{', '.join(r['top1_in']) or 'none'} | {', '.join(r.get('rank_worse_than_hindsight_in') or []) or '-'} |")
    return out


def render_summary(s: dict) -> str:
    hd = s["h_d"]
    L_ = ["# Stage-2 diagnosis control (arm D): summary across captures", ""]
    if s.get("mode") in BANNER:
        L_ += [BANNER[s["mode"]], ""]
    L_ += [s["scope"], "",
           "## H-D", "", hd["statement"], "",
           f"- Included D1 captures: n = {hd['n_included_d1']} ({', '.join(hd['included_d1']) or 'none'}).",
           f"- {hd['E_P_text']}.", f"- {hd['E_W_text']}.",
           f"- **Verdict: {hd['verdict']}.** {hd['reading']}.", f"- {hd['expected_frequency']}", ""]
    for label, key in (("E_W (refuting captures)", "mechanisms_E_W"), ("E_P", "mechanisms_E_P")):
        if hd[key]:
            L_ += [f"Mechanisms, {label}:", ""]
            for name, items in hd[key].items():
                for m in items:
                    L_.append(f"- {name}, {POLICY_LABEL[m['policy']]} at {m['delta']}: {m['classification']} "
                              f"(rank {m['rank']} vs hindsight {m['hindsight_rank']}; Top-1 {m['top1_entity'] or 'none'}"
                              f"; record gap {json.dumps(m['record_gap_at_first_served_request'], sort_keys=True)}"
                              + (f"; watch gaps {json.dumps(m['watch_continuity_gaps_overlapping'], sort_keys=True)}"
                                 if m["watch_continuity_gaps_overlapping"] else "") + ").")
            L_.append("")
    better = {o: v for o, v in hd["better_than_hindsight"].items() if v}
    if better:
        L_ += ["Cells better than hindsight (reported; they do not enter E_P or E_W): "
               + json.dumps(better, sort_keys=True), ""]
    L_ += ["Hindsight references differing between the poller and the watch (each observer is scored against its "
           "own; they differ only if the observers sighted different Pods): "
           + (", ".join(hd["hindsight_differs_between_observers"]) or "none") + ".", ""]
    sets = s["h_d_secondary_rows"]
    L_ += ["Secondary and sensitivity rows. " + sets["reading"] + ":", ""]
    for key, value in sets.items():
        if key != "reading":
            L_.append(f"- {key}: " + "; ".join(f"{k} = {{{', '.join(v)}}}" for k, v in value.items()) + ".")
    L_.append("")
    L_ += ["## Capture register", "", "| Capture | Scenario | Kind | Category | Reasons | Clamps (poller / watch) |",
           "| --- | --- | --- | --- | --- | --- |"]
    for r in s["register"]:
        L_.append(f"| {r['capture']} | {r['scenario']} | {r['kind']} | {r['category']} | "
                  f"{'; '.join(r['reasons']) or '-'} | {r['poller_clamps']} / {r['watch_clamps']} |")
    for title, key in (("Included D1 captures", "primary_d1"), ("Included D2 captures (control; not in H-D)",
                                                                 "primary_d2"),
                       ("SECONDARY: secondary-rule captures (own n, never pooled)", "secondary"),
                       ("SECONDARY: telemetry at its trace-tail receipt, included D1 captures",
                        "secondary_receipt_d1")):
        for o in PRIMARY_OBSERVERS:
            c = s[key][o]
            L_ += ["", f"## {title}: {o} (n = {c['n']}: {', '.join(c['captures']) or 'none'})", ""]
            if c["n"]:
                L_ += counts_table(c)
    c = s["secondary_watch_event_d1"]
    L_ += ["", f"## SECONDARY: the watch as an event log, included D1 captures (n = {c['n']})", ""]
    if c["n"]:
        L_ += counts_table(c)
    L_ += ["", "## Paired: watch relative to poller, included D1 captures", "",
           "| Family | Δ | Policy | better | equal | worse | both absent | worse in | better in |",
           "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |"]
    for p in s["primary_d1_paired_poller_watch"]:
        if p["family"] in REPORTED_FAMILIES:
            L_.append(f"| {p['family']} | {p['delta']} | {POLICY_LABEL[p['policy']]} | {p['better']} | {p['equal']} | "
                      f"{p['worse']} | {p['both absent']} | {', '.join(p['worse_in']) or '-'} | "
                      f"{', '.join(p['better_in']) or '-'} |")
    L_ += ["", "## Switch-based streams: definitions (printed beside the rows)", ""]
    L_ += [f"- {o}: {text}." for o, text in s["switch_stream_definitions"].items()]
    L_ += ["", "Every family, Δ and policy: `summary.json`; per capture: `<capture>/results.json`, `cells.csv`.", ""]
    return "\n".join(L_)


# ---------------------------------------------------------------------------------------------------------------
# A run over captures
# ---------------------------------------------------------------------------------------------------------------
def run(captures: list, out: Path, *, mode: str, allow_other_kinds: bool) -> dict:
    """Analyse every capture and write <out>/<capture>/..., <out>/summary.json and <out>/SUMMARY.md (out must not
    exist). A capture whose analysis fails is recorded (category analysis_error, with the traceback) and the run
    goes on; the exit status is then 2."""
    out = Path(out).resolve()
    if out.exists():
        raise SystemExit(f"output directory exists; choose a new one: {out}")
    names = [Path(c).resolve().name for c in captures]
    check(len(set(names)) == len(names), "two captures share a directory name")
    results, errors, timings = [], 0, {}
    for capture in sorted((Path(c).resolve() for c in captures), key=lambda p: p.name):
        started = time.monotonic()
        try:
            res = analyse_capture(capture, mode=mode,
                                  allow_other_kinds=allow_other_kinds)
        except (Exception, SystemExit) as error:
            errors += 1
            try:
                facts = {k: v for k, v in capture_record(capture).items() if k != "section10"}
            except (OSError, ValueError):
                facts = {}
            res = {"kind": "stage2_diagnosis_control_one_capture", "version": VERSION, **mode_field(mode),
                   "capture": {"directory": capture.name, **facts}, "category": "analysis_error",
                   "error": scrub(f"{type(error).__name__}: {error}", capture),
                   "traceback": scrub(traceback.format_exc(), capture)}
        timings[capture.name] = round(time.monotonic() - started, 2)
        results.append(jsonable(res))
    summary = jsonable(summarise(results, mode=mode))
    out.mkdir(parents=True)
    for res in results:
        folder = out / res["capture"]["directory"]
        folder.mkdir()
        write_lf(folder / "results.json", json_text(res))
        if "observers" in res:
            write_lf(folder / "cells.csv", cells_csv(res))
        write_lf(folder / "SUMMARY.md", render_capture(res))
    write_lf(out / "summary.json", json_text(summary))
    write_lf(out / "SUMMARY.md", render_summary(summary))
    return {"summary": summary, "errors": errors, "seconds_per_capture": timings}


# ---------------------------------------------------------------------------------------------------------------
# Fixtures: tiny converted arm-D captures (3 Pods, a switch record, a fault window), built in code
# ---------------------------------------------------------------------------------------------------------------
FIX_BASE_US = R.to_us(datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC))
FIX_NS, FIX_CLUSTER = "aiops-s2-fixture-d1", "fixture-cluster"
FIX_COLLECTIONS = {POLLER: "f0000000-0000-4000-8000-0000000000a1", WATCH: "f0000000-0000-4000-8000-0000000000a2"}
REC, CAT = "recommendationservice", "productcatalogservice"
FIX_UID = {"OLD": "a0000000-0000-4000-8000-00000000000a", "NEW": "b0000000-0000-4000-8000-00000000000b",
           "CAT": "c0000000-0000-4000-8000-00000000000c", "RS1": "e1000000-0000-4000-8000-000000000001",
           "RS2": "e2000000-0000-4000-8000-000000000002", "RS3": "e3000000-0000-4000-8000-000000000003",
           "D1": "d1000000-0000-4000-8000-000000000001", "D2": "d2000000-0000-4000-8000-000000000002",
           "CLIENT": "f0000000-0000-4000-8000-00000000000f"}
FIX_T0, FIX_ONSET, FIX_NEW_CREATED, FIX_NEW_RUNNING, FIX_RS2_CREATED = 100.0, 120.0, 100.4, 101.5, 100.3
FIX_FAULT_END = 140.0
FIX_REQUESTS = 200                       # t_i = 80.0 + 0.5 i, i = 0 .. 199
FIX_WATCH_LIST, FIX_WATCH_WINDOW = 88.0, (90.0, 185.0)
ODD = tuple(float(x) for x in range(81, 200, 2))
FIXTURES = {
    "D1-F01": {"label": "poller Pod lists 15 s apart over the switch (111 s -> 126 s): the poller effect; the watch "
                        "sees the switch within 0.1 s",
               "ready_new": 112.0, "old_deleting": 112.1, "old_deleted": 114.0,
               "poller": tuple(x for x in ODD if x <= 111.0) + tuple(float(x) for x in range(126, 200, 2)),
               "watch_gap": None},
    "D1-F02": {"label": "poller Pod lists every 2 s: no effect under either observer",
               "ready_new": 112.0, "old_deleting": 112.1, "old_deleted": 114.0, "poller": ODD, "watch_gap": None},
    "D1-F03": {"label": "a 4.9 s watch pods continuity gap (115.5 s -> 120.4 s) over the switch: the watch keeps "
                        "the effect (within the inclusion rule-2 threshold of 5 s)",
               "ready_new": 116.0, "old_deleting": 116.1, "old_deleted": 118.0, "poller": ODD,
               "watch_gap": (115.5, 120.4)},
}


def fix_us(seconds: float) -> int:
    return FIX_BASE_US + R.seconds_to_us(seconds, allow_negative=True)


def fix_iso(seconds: float) -> str:
    """ISO with nine fractional digits (the Stage-2 collectors' format; whole microseconds here)."""
    return R.from_us(fix_us(seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def fix_stamp(seconds: float) -> str:
    """An API-server stamp: whole seconds, truncated (creationTimestamp, deletionTimestamp)."""
    return R.from_us(fix_us(seconds) - fix_us(seconds) % R.US).strftime("%Y-%m-%dT%H:%M:%SZ")


class FixtureWorld:
    """The namespace over time for one fixture spec: three Pods (old and new recommendation Pod, one catalog Pod),
    their ReplicaSets and Deployments; every object version with its change instant."""

    def __init__(self, spec: dict, rs2_created: float = FIX_RS2_CREATED):
        self.spec, self.rs2_created = spec, rs2_created
        self.changes = []                            # (t, resource, key, event type, object)
        self.version = 1000
        self._build()

    def _meta(self, key, name, app, created, owner_kind=None, owner=None, deleting=None, generation=None):
        self.version += 1
        meta = {"uid": FIX_UID[key], "name": name, "namespace": FIX_NS, "resourceVersion": str(self.version),
                "creationTimestamp": fix_stamp(created), "labels": {"app": app}}
        if owner:
            meta["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": owner_kind, "name": name.rsplit("-", 1)[0],
                                        "uid": FIX_UID[owner], "controller": True}]
        if deleting is not None:
            meta["deletionTimestamp"] = fix_stamp(deleting)
        if generation is not None:
            meta["generation"] = generation
        return meta

    def _pod(self, key, name, app, rs, created, phase, ready, deleting=None):
        return {"apiVersion": "v1", "kind": "Pod",
                "metadata": self._meta(key, name, app, created, "ReplicaSet", rs, deleting),
                "spec": {"nodeName": "fixture-node", "containers": [{"name": "server", "image": "fixture"}]},
                "status": {"phase": phase, "containerStatuses": [{"name": "server", "ready": ready,
                                                                  "restartCount": 0}]}}

    def _owned(self, key, kind, name, app, created, owner_kind=None, owner=None, generation=1):
        return {"apiVersion": "apps/v1", "kind": kind,
                "metadata": self._meta(key, name, app, created, owner_kind, owner, generation=generation),
                "spec": {"replicas": 1}, "status": {"replicas": 1}}

    def put(self, t, resource, key, obj, event):
        self.changes.append((t, resource, key, event, obj))

    def _build(self):
        s = self.spec
        old, new, cat = f"{REC}-aaaaa-old", f"{REC}-bbbbb-new", f"{CAT}-ccccc-one"
        self.put(-300.0, "pods", "OLD", self._pod("OLD", old, REC, "RS1", -300.0, "Running", True), "ADDED")
        self.put(-300.0, "pods", "CAT", self._pod("CAT", cat, CAT, "RS3", -300.0, "Running", True), "ADDED")
        self.put(-300.0, "replicasets", "RS1", self._owned("RS1", "ReplicaSet", f"{REC}-aaaaa", REC, -300.0,
                                                           "Deployment", "D1"), "ADDED")
        self.put(-300.0, "replicasets", "RS3", self._owned("RS3", "ReplicaSet", f"{CAT}-ccccc", CAT, -300.0,
                                                           "Deployment", "D2"), "ADDED")
        self.put(-300.0, "deployments", "D1", self._owned("D1", "Deployment", REC, REC, -300.0), "ADDED")
        self.put(-300.0, "deployments", "D2", self._owned("D2", "Deployment", CAT, CAT, -300.0), "ADDED")
        self.put(FIX_T0 + 0.05, "deployments", "D1", self._owned("D1", "Deployment", REC, REC, -300.0,
                                                                 generation=2), "MODIFIED")
        self.put(self.rs2_created, "replicasets", "RS2", self._owned("RS2", "ReplicaSet", f"{REC}-bbbbb", REC,
                                                                     self.rs2_created, "Deployment", "D1"), "ADDED")
        self.put(FIX_NEW_CREATED, "pods", "NEW", self._pod("NEW", new, REC, "RS2", FIX_NEW_CREATED, "Pending",
                                                           False), "ADDED")
        self.put(FIX_NEW_RUNNING, "pods", "NEW", self._pod("NEW", new, REC, "RS2", FIX_NEW_CREATED, "Running",
                                                           False), "MODIFIED")
        self.put(s["ready_new"], "pods", "NEW", self._pod("NEW", new, REC, "RS2", FIX_NEW_CREATED, "Running", True),
                 "MODIFIED")
        self.put(s["ready_new"] + 0.05, "replicasets", "RS1", self._owned("RS1", "ReplicaSet", f"{REC}-aaaaa", REC,
                                                                          -300.0, "Deployment", "D1"), "MODIFIED")
        self.put(s["old_deleting"], "pods", "OLD", self._pod("OLD", old, REC, "RS1", -300.0, "Running", True,
                                                             deleting=s["old_deleting"]), "MODIFIED")
        self.put(s["old_deleting"] + 1.0, "pods", "OLD", self._pod("OLD", old, REC, "RS1", -300.0, "Running", False,
                                                                   deleting=s["old_deleting"]), "MODIFIED")
        self.put(s["old_deleted"], "pods", "OLD", self._pod("OLD", old, REC, "RS1", -300.0, "Running", False,
                                                            deleting=s["old_deleting"]), "DELETED")
        self.changes.sort(key=lambda c: (c[0], c[1], c[2]))

    def state(self, t: float) -> dict:
        """(resource, key) -> object version current at t (deleted objects removed)."""
        current = {}
        for when, resource, key, event, obj in self.changes:
            if when > t:
                break
            if event == "DELETED":
                current.pop((resource, key), None)
            else:
                current[(resource, key)] = obj
        return current


def _row(evidence_id, kind, subject, payload, acquired_seconds, source_ref):
    available = fix_us(acquired_seconds) * 1000
    return {"available_ns": available, "logical_confirmation_ns": available,
            "record": {"evidence_id": evidence_id, "logical_id": evidence_id, "kind": kind, "subject": subject,
                       "payload": payload, "supports": [], "supersedes": [], "source_ref": source_ref,
                       "source_sha256": "0" * 64, "acquired_at": fix_iso(acquired_seconds)}}


def _subject(obj) -> str:
    group = "" if obj["kind"] == "Pod" else "apps"
    return json.dumps([FIX_CLUSTER, group, obj["kind"], FIX_NS, obj["metadata"]["uid"]], separators=(",", ":"))


def _poller_rows(world: FixtureWorld, times) -> list:
    rows, seq = [], 0
    for k, at in enumerate(times):
        for resource, offset in (("pods", 0.0), ("replicasets", 0.1), ("deployments", 0.2)):
            observed = at + offset
            state = world.state(observed)
            for (res, key), obj in sorted(state.items(), key=lambda item: item[0][1]):
                if res != resource:
                    continue
                seq += 1
                payload = {"record_type": "resource_observation", "observation_basis": "snapshot_receipt",
                           "collection_id": FIX_COLLECTIONS[POLLER], "snapshot_id": f"{k:03d}-{resource}",
                           "resource": resource, "resource_data": obj, "observed_at": fix_iso(observed),
                           "available_at": fix_iso(observed + 0.25), "clock_adjusted": False,
                           "_source_record_sha256": "0" * 64}
                rows.append(_row(f"api:{FIX_COLLECTIONS[POLLER]}/{seq}", "api_observation", _subject(obj), payload,
                                 observed + 0.25, f"fixture/context/observations.jsonl#L{seq}"))
    return rows


def _watch_rows(world: FixtureWorld, gap) -> tuple[list, list, list, list]:
    """The watch collector's records as converter v4 writes them: list objects (initial LIST and, after a pods gap,
    the relist), ADDED / MODIFIED / DELETED events, cache snapshots at every event and every 1 s (only rows inside
    FIX_WATCH_WINDOW are kept, as the converter keeps the decision window), pods rows omitted inside the gap."""
    coll = FIX_COLLECTIONS[WATCH]
    seq = [0]
    lists, events, snaps, gaps = [], [], [], []
    cache = {}                                   # uid -> (object, carrier record id, carrier record type, sequence)
    snapshot_index = [0]

    def next_seq():
        seq[0] += 1
        return seq[0]

    def list_objects(at, resources):
        list_seq = next_seq()                    # the watch_list record itself (not a row)
        for (resource, key), obj in sorted(world.state(at).items(), key=lambda i: (i[0][0], i[0][1])):
            if resource not in resources:
                continue
            s = next_seq()
            rid = f"{coll}/{s}"
            payload = {"record_type": "watch_list_object", "observation_basis": "watch_list", "sequence": s,
                       "record_id": rid, "collection_id": coll, "collector": "watch-v1", "list_sequence": list_seq,
                       "resource": resource, "kind": obj["kind"], "uid": obj["metadata"]["uid"],
                       "name": obj["metadata"]["name"], "namespace": FIX_NS,
                       "resource_version": obj["metadata"]["resourceVersion"], "resource_data": obj,
                       "observed_at": fix_iso(at), "response_received_at": fix_iso(at),
                       "available_at": fix_iso(at + 0.000001)}
            lists.append(_row(f"watchlist:{rid}", "api_watch_list_object", _subject(obj), payload, at + 0.000001,
                              f"fixture/context/watch_events.jsonl#L{s}"))
            cache[obj["metadata"]["uid"]] = (obj, rid, "watch_list_object", s, resource)
        return list_seq

    def in_gap(at):
        return gap is not None and gap[0] < at < gap[1]

    def snapshot(at, trigger, trigger_sequence):
        s = next_seq()
        snapshot_index[0] += 1
        if not (FIX_WATCH_WINDOW[0] <= at <= FIX_WATCH_WINDOW[1]):
            return
        sid = f"{coll}/{s}"
        for uid in sorted(cache, key=lambda u: (cache[u][0]["kind"], u)):
            obj, carrier, carrier_type, carrier_seq, resource = cache[uid]
            if resource == "pods" and in_gap(at):
                continue                         # the kind is unusable inside its gap
            payload = {"record_type": "resource_observation", "observation_basis": "watch_cache_snapshot",
                       "collector": "watch-v1", "collection_id": coll, "snapshot_id": sid, "snapshot_sequence": s,
                       "snapshot_index": snapshot_index[0], "snapshot_trigger": trigger,
                       "trigger_sequence": trigger_sequence, "snapshot_at": fix_iso(at), "observed_at": fix_iso(at),
                       "available_at": fix_iso(at + 0.00001), "clock_adjusted": False, "resource": resource,
                       "resource_data": obj, "source_record": carrier, "source_record_type": carrier_type,
                       "source_record_sequence": carrier_seq, "_source_record_sha256": "0" * 64}
            snaps.append(_row(f"watchsnap:{sid}/{uid}", "api_observation", _subject(obj), payload, at + 0.00001,
                              f"fixture/context/watch_snapshots.jsonl#L{s}"))

    actions = [(FIX_WATCH_LIST, 0, "list", None)]
    for t, resource, key, event, obj in world.changes:
        receipt = round(t + 0.02, 6)
        if receipt > FIX_WATCH_LIST and not (resource == "pods" and gap is not None and gap[0] < receipt < gap[1]):
            actions.append((receipt, 1, "event", (resource, event, obj)))
    if gap is not None:
        actions.append((gap[1], 0, "relist", None))
        gaps.append(({"observer": "watch", "reason": "watch_interrupted", "resource": "pods",
                      "cause": "eof_unterminated", "gap_from_at": fix_iso(gap[0]), "gap_to_at": fix_iso(gap[1]),
                      "duration_seconds": round(gap[1] - gap[0], 6)}, gap[1]))
    k = 0
    while FIX_WATCH_LIST + 0.3 + k <= FIX_WATCH_WINDOW[1]:
        actions.append((round(FIX_WATCH_LIST + 0.3 + k, 6), 2, "periodic", None))
        k += 1
    actions.sort(key=lambda a: (a[0], a[1]))
    for at, _, action, data in actions:
        if action == "list":
            list_seq = list_objects(at, ("pods", "replicasets", "deployments"))
            snapshot(at + 0.0001, "list", list_seq)
        elif action == "relist":
            for uid in [u for u, v in cache.items() if v[4] == "pods"]:
                del cache[uid]
            list_seq = list_objects(at, ("pods",))
            snapshot(at + 0.0001, "list", list_seq)
        elif action == "event":
            resource, event, obj = data
            s = next_seq()
            rid = f"{coll}/{s}"
            uid = obj["metadata"]["uid"]
            effect = "delete" if event == "DELETED" else ("update" if uid in cache else "insert")
            payload = {"record_type": "api_watch_event", "observation_basis": "watch_event", "sequence": s,
                       "record_id": rid, "collection_id": coll, "collector": "watch-v1", "event_type": event,
                       "resource": resource, "kind": obj["kind"], "uid": uid, "name": obj["metadata"]["name"],
                       "namespace": FIX_NS, "resource_version": obj["metadata"]["resourceVersion"],
                       "resource_data": obj, "received_at": fix_iso(at), "observed_at": fix_iso(at),
                       "available_at": fix_iso(at + 0.000001), "cache_effect": effect}
            events.append(_row(f"watch:{rid}", "api_watch_event", _subject(obj), payload, at + 0.000001,
                               f"fixture/context/watch_events.jsonl#L{s}"))
            if event == "DELETED":
                cache.pop(uid, None)
            else:
                cache[uid] = (obj, rid, "api_watch_event", s, resource)
            snapshot(round(at + 0.0001, 6), "event", s)
        else:
            snapshot(at, "periodic", None)
    gap_rows = [_row(f"gap:watch:{coll}/{i + 1}", "continuity_gap", "[]", g, at, "fixture/context/watch_events.jsonl")
                for i, (g, at) in enumerate(gaps)]
    return lists, events, snaps, gap_rows


def _span_rows(spec: dict) -> list:
    rows = []

    def span(trace, sid, parent, name, kind, start, end, service, uid, receipt, attrs=None):
        body = {"traceId": trace, "spanId": sid, "name": name, "kind": kind,
                "startTimeUnixNano": str(fix_us(start) * 1000), "endTimeUnixNano": str(fix_us(end) * 1000),
                "status": {}}
        if parent:
            body["parentSpanId"] = parent
        payload = {"trace_id": trace, "span_id": sid, "span": body,
                   "resource_attributes": {"service.name": service, "k8s.pod.uid": uid},
                   "span_attributes": attrs or {}, "acquisition_basis": "live_tail_line"}
        rows.append(_row(f"span:{trace}:{sid}", "span_claim", "[]", payload, receipt, "fixture/raw/trace-tail"))

    switch = spec["ready_new"] + 0.05
    for i in range(FIX_REQUESTS):
        t = 80.0 + 0.5 * i
        serving = "OLD" if t < switch else "NEW"
        faulty = serving == "NEW" and FIX_ONSET <= t < FIX_FAULT_END
        front_ms = 80.0 if faulty else 5.0 + 0.1 * (i % 4)
        end = t + front_ms / 1000
        trace = f"{i + 1:032x}"
        root, srv, cli, back = (f"{i:08x}0001", f"{i:08x}0002", f"{i:08x}0003", f"{i:08x}0004")
        span(trace, root, None, "pilot.ListRecommendations", 3, t, end, "pilot-client", FIX_UID["CLIENT"], end + 2.0,
             {"aiops.request.index": str(i + 1)})
        span(trace, srv, root, "/hipstershop.RecommendationService/ListRecommendations", 2, t + 0.0001, end - 0.0001,
             REC, FIX_UID[serving], end + 2.0)
        span(trace, cli, srv, "/hipstershop.ProductCatalogService/ListProducts", 3, t + 0.0002, t + 0.0013, REC,
             FIX_UID[serving], end + 2.0)
        span(trace, back, cli, "hipstershop.ProductCatalogService/ListProducts", 2, t + 0.00025, t + 0.00125, CAT,
             FIX_UID["CAT"], t + 0.00125 + 3.0)
    return rows


def _clock_rows() -> list:
    """Two clock-probe documents (labels start and end), ten pairs each, in the smoke kit's shape: the node clock
    equals the host clock and every pair is 0.1 s wide (send, node = send + 0.05 s, receive = send + 0.1 s), so each
    pair bounds the offset to [-0.05, +0.05] s and b_c = 1 s + 0.05 s = 1.05 s."""
    rows = []
    for label, start in (("start", 70.0), ("end", 190.0)):
        pairs = []
        for k in range(10):
            send = fix_us(start + k * 0.2) * 1000
            pairs.append({"index": k + 1, "send_ns": send, "node_ns": send + 50_000_000,
                          "receive_ns": send + 100_000_000, "exit_code": 0, "error": None})
        document = {"label": label, "pairs": pairs, "node": "fixture-node"}
        rows.append(_row(f"clock:fixture:{label}", "clock_probe", "[]", document, start + 1.9 + 0.1,
                         "fixture/context/clock_probes.json"))
    return rows


def _write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda r: (r["available_ns"], r["record"]["evidence_id"]))
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def build_fixture_capture(target: Path, name: str, *, rs2_created: float = FIX_RS2_CREATED,
                          extra_poll: float | None = None, poller_only: bool = False) -> Path:
    """Write one converted arm-D fixture capture (FIXTURES[name]) into target (which must not exist): evidence/
    (poller rows and spans in accepted_evidence.jsonl, protocol.json, capture.json; the watch rows under stage2/),
    ground_truth/ground_truth.json, COMPLETE.txt and the runner's capture.json with its section10 record.
    ``extra_poll`` adds one poller sample (Pods at t, ReplicaSets at t + 0.1 s); ``rs2_created`` moves the new
    ReplicaSet's creation (the clamp tests); ``poller_only`` writes no stage2/ rows."""
    spec = FIXTURES[name]
    target = Path(target)
    if target.exists():
        raise ValueError(f"fixture target exists: {target}")
    world = FixtureWorld(spec, rs2_created)
    times = tuple(sorted(spec["poller"] + ((extra_poll,) if extra_poll is not None else ())))
    evidence = target / "evidence"
    _write_jsonl(evidence / "accepted_evidence.jsonl", _poller_rows(world, times) + _span_rows(spec))
    if not poller_only:
        lists, events, snaps, gaps = _watch_rows(world, spec["watch_gap"])
        _write_jsonl(evidence / L.LIST_OBJECT_FILE, lists)
        _write_jsonl(evidence / L.EVENT_FILE, events)
        _write_jsonl(evidence / L.SNAPSHOT_FILE, snaps)
        _write_jsonl(evidence / L.GAP_FILE, gaps)
        _write_jsonl(evidence / CLOCK_FILE, _clock_rows())
    (evidence / "protocol.json").write_text(json.dumps(
        {"namespace": FIX_NS, "cluster_incarnation_id": FIX_CLUSTER, "capture_id": name, "incident_id": "D1",
         "replacement_service": REC}, indent=2) + "\n", encoding="utf-8")
    (evidence / "capture.json").write_text(json.dumps({"run_id": name, "namespace": FIX_NS}, indent=2) + "\n",
                                           encoding="utf-8")
    timeline = {mark: {"host_utc": fix_iso(at)} for mark, at in (("T0_trigger", FIX_T0), ("fault_launch", FIX_ONSET),
                                                                ("pre_fault_end", FIX_ONSET),
                                                                ("recovery_end", FIX_FAULT_END + 35.0))}
    (target / "ground_truth").mkdir()
    (target / "ground_truth" / "ground_truth.json").write_text(json.dumps(
        {"EVALUATION_ONLY": "fixture", "incident_id": "D1", "capture_id": name,
         "validity": {"valid": True, "reasons": [], "notes": []},
         "planned": {"labels": {"fault_present": True, "root_cause_service": REC, "change_services": [REC]}},
         "observed": {"fault_target": {"service": REC, "pod_name": f"{REC}-bbbbb-new", "pod_uid": FIX_UID["NEW"],
                                       "selected_by": "replacement_uid"}},
         "timeline_host": timeline,
         "evaluation_summary": {"activation_verified": True, "latency_effect_established": True,
                                "recovery_established": True, "fault_control_passed": True},
         "stage2": {"scenario": "D1", "arm": "D"}}, indent=2) + "\n", encoding="utf-8")
    gap = spec["watch_gap"]
    poller_gap = max(b - a for a, b in zip(times, times[1:]))
    (target / "capture.json").write_text(json.dumps(
        {"capture_id": name, "incident_id": "D1", "namespace": FIX_NS, "timeline": timeline,
         "stage2": {"scenario": "D1", "arm": "D", "kind": "tooling", "pilot": False, "mode": "fixture"},
         "section10": {"rule_1": {"passed": True, "checks": {"status_finished": True}},
                       "rule_2": {"passed": True, "checks": {"poller": True, "watch": True},
                                  "poller": {"max_pod_list_gap_in_window_seconds": poller_gap},
                                  "watch": {"max_gap_overlap_in_window_seconds": 0.0 if gap is None
                                            else round(gap[1] - gap[0], 6)}},
                       "excluded_by_rules_1_2": False},
         "fixture": spec["label"]}, indent=2) + "\n", encoding="utf-8")
    with (target / "COMPLETE.txt").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("status=finished\nfixture=true\n")
    return target


def build_fixtures(folder: Path) -> list:
    folder = Path(folder)
    return [build_fixture_capture(folder / name, name) for name in FIXTURES]


# ---------------------------------------------------------------------------------------------------------------
# The fixture expectation (--check)
# ---------------------------------------------------------------------------------------------------------------
def semantic_table(summary: dict, results: list) -> dict:
    """What --check compares: integers and labels only (no floating-point score), so that a numpy or platform
    difference in the 12th decimal cannot pass for a code change, nor a code change hide behind a float."""
    cells = {}
    for res in results:
        name = res["capture"]["directory"]
        cells[name] = {"category": res.get("category"),
                       "clamps": {o: len(v.get("clamps") or []) for o, v in (res.get("loaders") or {}).items()}}
        for o in PRIMARY_OBSERVERS:
            for r in ((res.get("observers") or {}).get(o) or {}).get("rows") or []:
                cells[name][f"{o}|{r['stream']}|{r['delta']}|{r['policy']}"] = [
                    r["outcome"], r["rank"], r["candidates"], r["top1_name"], r["wrong_decision"], r["mis_attributed"],
                    r["abstained"], r["vs_hindsight"]]
            for r in ((res.get("receipt_availability") or {}).get(o) or {}).get("rows") or []:
                cells[name][f"{o}@receipt|{r['stream']}|{r['delta']}|{r['policy']}"] = [
                    r["outcome"], r["rank"], r["mis_attributed"], r["abstained"]]
        for r in (((res.get("secondary_observers") or {}).get(WATCH_EVENT)) or {}).get("rows") or []:
            cells[name][f"watch_event|{r['stream']}|{r['delta']}|{r['policy']}"] = [r["outcome"], r["rank"],
                                                                                  r["abstained"]]
    hd = summary["h_d"]
    return {"h_d": {"verdict": hd["verdict"], "E_P": hd["E_P"], "E_W": hd["E_W"],
                    "n_included_d1": hd["n_included_d1"]}, "cells": cells}


def fixture_run(out: Path) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        captures = build_fixtures(Path(tmp) / "captures")
        outcome = run(captures, out, mode="FIXTURE", allow_other_kinds=True)
    results = [json.loads((Path(out) / name / "results.json").read_text(encoding="utf-8")) for name in FIXTURES]
    files = {p.relative_to(out).as_posix(): sha256(p) for p in sorted(Path(out).rglob("*")) if p.is_file()}
    return {"outcome": outcome, "semantic": semantic_table(outcome["summary"], results), "files": files}


def expectation_doc(result: dict) -> dict:
    return {"kind": "stage2_diagnosis_control_fixture_expectation", "version": VERSION,
            "fixtures": {name: spec["label"] for name, spec in FIXTURES.items()},
            "written_by": "run_diagnosis_control_v1.py --write-expectation",
            "semantic": result["semantic"],
            "files_sha256": result["files"],
            "reading": ("--check passes when the semantic table (outcomes, ranks, counts, verdicts; no floats) is "
                        "identical; the per-file SHA-256 are compared too and reported (with --strict, required)")}


def check_expectation(path: Path = EXPECTATION, *, strict: bool = False) -> int:
    expected = json.loads(Path(path).read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        result = fixture_run(Path(tmp) / "out")
    same = result["semantic"] == expected["semantic"]
    differing = sorted(k for k in set(result["files"]) | set(expected["files_sha256"])
                       if result["files"].get(k) != expected["files_sha256"].get(k))
    print(json.dumps({"expectation": rel(path), "semantic_identical": same, "files_identical": not differing,
                      "files_differing": differing[:20], "h_d": result["semantic"]["h_d"],
                      "seconds_per_capture": result["outcome"]["seconds_per_capture"]}, indent=1))
    return 0 if same and (not strict or not differing) else 1


# ---------------------------------------------------------------------------------------------------------------
# Validity only: inclusion rule 3 without any ranking (--validity-only)
# ---------------------------------------------------------------------------------------------------------------
def conversion_facts(capture: Path) -> dict:
    """What the verdict was read from, as recorded (never recomputed; no absolute path): the converter's manifest
    evidence/stage2_manifest.json and the runner's MANIFEST.json. None for a file that is absent (the fixtures
    have neither)."""
    capture = Path(capture)
    converter = manifest = None
    path = capture / "evidence" / "stage2_manifest.json"
    if path.exists():
        doc = json.loads(path.read_text(encoding="utf-8"))
        converter = {"file": "evidence/stage2_manifest.json", "converter": doc.get("converter"),
                     "phase3_converter": doc.get("phase3_converter")}
    if (capture / "MANIFEST.json").exists():
        manifest = {"file": "MANIFEST.json"}
    return {"converter": converter, "manifest": manifest}


def validity_of_capture(capture: Path, *, allow_other_kinds: bool) -> dict:
    """Inclusion rule 3 (arm D) for one converted capture, and nothing after it.

    The steps of analyse_capture() up to inclusion_of(), in its order and with its functions: the runner's record
    (capture_record), rules 1-2 from its section10 validity fields (rules_1_2; when they fail nothing is loaded and the
    block is analyse_capture()'s), the evaluator's truth (context_bridge.load_capture_truth) and the bridge input of
    each primary observer (load_bridge_input); then inclusion_of(): the bridge rule's items 2-3 as written (item 1
    re-checked) on the poller's and on the watch's input, and the secondary rule on both. No policy, stream, grid, cell,
    ranking, L-4 row or H-D fact is computed. The block is analyse_capture()'s 'inclusion' (tested equal on the
    fixtures).

    Which captures are checked (the check itself is analyse_capture()'s): outside arm D, none (rule 3 is arm D's; arm
    G's rule 4 is the runner's); an attempt kind other than study only in an --any-kind run, as there; and a
    pilot too, marked PILOT. A pilot may be read for tooling facts, and rule 3 reads only such facts (activation and
    effect as the runner's evaluator recorded them, the Pods each observer sighted, the change); analyse_capture()
    leaves pilots out because it goes on to rank. A pilot never enters a table of the study."""
    capture = Path(capture).resolve()
    record = capture_record(capture)
    entry = {"verdict": None, "reasons": [], "pilot": record["kind"] == "pilot" or record["pilot"] is True,
             "capture_dir": rel(capture),
             "capture": {"directory": capture.name, **{k: v for k, v in record.items() if k != "section10"}},
             **conversion_facts(capture)}
    if record["arm"] != "D":
        entry.update(verdict="not_evaluated", reasons=[f"not an arm-D capture (arm {record['arm']!r}): section 10 "
                                                       "rule 3 is arm D's (arm G: rule 4, applied by the runner)"])
        return entry
    if record["kind"] != "study" and not allow_other_kinds:
        entry.update(verdict="not_evaluated", reasons=[f"attempt kind {record['kind']!r}: only study "
                                                       "attempts are checked (--any-kind: all)"])
        return entry
    r12 = rules_1_2(record)
    if not r12["passed"]:                                   # section 10: validity fields first, nothing loaded
        entry.update(verdict="excluded", reasons=r12["reasons"],
                     inclusion={"rules_1_2": r12, "primary": False, "secondary": False, "reasons": r12["reasons"]})
        return entry
    truth = B.load_capture_truth(capture)                  # evaluator only: markers, labels, evaluation summary
    bridges = {o: load_bridge_input(capture, o)[0] for o in PRIMARY_OBSERVERS}
    inclusion = inclusion_of(truth, bridges, record)
    entry.update(verdict="primary_included" if inclusion["primary"] else
                 "secondary" if inclusion["secondary"] else "excluded",
                 reasons=inclusion["reasons"], inclusion=inclusion)
    return entry


def validity_line(name: str, entry: dict) -> str:
    """The rule-3 line of validity.md: '<capture>: primary included' or '<capture>: excluded — <reasons>' (also for a
    secondary-rule capture: excluded from the primary analysis), else 'not evaluated' or 'error, no verdict'; a pilot is marked."""
    verdict, reasons = entry["verdict"], "; ".join(entry.get("reasons") or [])
    if verdict == "primary_included":
        line = f"{name}: primary included"
    elif verdict in ("excluded", "secondary"):
        line = f"{name}: excluded — {reasons}"
    elif verdict == "not_evaluated":
        line = f"{name}: not evaluated — {reasons}"
    else:
        line = f"{name}: error, no verdict — {entry.get('error')}"
    return line + (f" [{PILOT_NOTE}]" if entry.get("pilot") else "")


def secondary_line(name: str, entry: dict) -> str:
    """The secondary-rule line of validity.md (context_bridge.inclusion_secondary on both observers' inputs)."""
    inc = entry.get("inclusion")
    if inc is None:
        return f"{name}: secondary rule not evaluated"
    if inc["primary"]:
        return f"{name}: secondary rule not applicable (primary included)"
    if inc["secondary"]:
        return f"{name}: secondary rule admitted (its own secondary table, never pooled)"
    if "secondary_rule" not in inc:
        return f"{name}: secondary rule not admitted — rules 1-2 not passed (nothing loaded)"
    reasons = [f"{o}: {r}" for o in PRIMARY_OBSERVERS if not inc["secondary_rule"][o]["admitted"]
               for r in inc["secondary_rule"][o]["reasons"]]
    return f"{name}: secondary rule not admitted — {'; '.join(reasons)}"


def render_validity(doc: dict) -> str:
    L_ = ["# Stage-2 diagnosis control (arm D): inclusion rule 3, validity only", "",
          f"**{doc['label']}**", ""]
    if doc.get("mode") in BANNER:                          # as SUMMARY.md of a full run
        L_ += [BANNER[doc["mode"]], ""]
    L_ += [doc["reading"], ""]
    for name, entry in doc["captures"].items():
        L_ += [validity_line(name, entry), secondary_line(name, entry)]
    L_ += ["", "Per capture (the inclusion block, the converter and manifest identifiers): `validity.json`.", ""]
    return "\n".join(L_)


def run_validity(captures: list, out: Path, *, mode: str, allow_other_kinds: bool) -> dict:
    """validity_of_capture() for every capture, then <out>/validity.json and <out>/validity.md and nothing else (out
    must not exist, as in run(); it may lie inside a capture directory, since it is created only after every capture
    has been read). A capture whose check fails gets the verdict 'error' (no verdict, the traceback with paths
    replaced) and the run goes on; the exit status is then 2, as in run()."""
    out = Path(out).resolve()
    if out.exists():
        raise SystemExit(f"output directory exists; choose a new one: {out}")
    names = [Path(c).resolve().name for c in captures]
    check(len(set(names)) == len(names), "two captures share a directory name")
    entries, errors, timings = {}, 0, {}
    for capture in sorted((Path(c).resolve() for c in captures), key=lambda p: p.name):
        started = time.monotonic()
        try:
            entry = validity_of_capture(capture, allow_other_kinds=allow_other_kinds)
        except (Exception, SystemExit) as error:
            errors += 1
            try:
                facts = {k: v for k, v in capture_record(capture).items() if k != "section10"}
            except (OSError, ValueError):
                facts = {}
            entry = {"verdict": "error", "reasons": [],
                     "pilot": facts.get("kind") == "pilot" or facts.get("pilot") is True,
                     "capture_dir": rel(capture), "capture": {"directory": capture.name, **facts},
                     "error": scrub(f"{type(error).__name__}: {error}", capture),
                     "traceback": scrub(traceback.format_exc(), capture)}
        timings[capture.name] = round(time.monotonic() - started, 2)
        entries[capture.name] = jsonable(entry)
    doc = {"kind": "stage2_diagnosis_control_validity", "version": VERSION, **mode_field(mode),
           "label": VALIDITY_LABEL, "reading": VALIDITY_READING, "captures": entries}
    out.mkdir(parents=True)
    write_lf(out / VALIDITY_FILES[0], json_text(doc))
    write_lf(out / VALIDITY_FILES[1], render_validity(doc))
    return {"validity": doc, "errors": errors, "seconds_per_capture": timings}


def validity_command(captures: list, out: Path, *, mode: str, allow_other_kinds: bool) -> int:
    """main() for --validity-only: run_validity() and its summary on stdout (the timings go to stdout only)."""
    outcome = run_validity(captures, out, mode=mode, allow_other_kinds=allow_other_kinds)
    print(json.dumps({"out": rel(out), "label": VALIDITY_LABEL,
                      "verdicts": {name: e["verdict"] for name, e in outcome["validity"]["captures"].items()},
                      "errors": outcome["errors"], "seconds_per_capture": outcome["seconds_per_capture"]}, indent=1))
    return 2 if outcome["errors"] else 0


# ---------------------------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Stage-2 diagnosis control (arm D): the bridge per observer "
                                                 "and the H-D rule")
    parser.add_argument("--captures", nargs="*", type=Path, default=[], help="converted arm-D capture directories")
    parser.add_argument("--captures-dir", type=Path, help="every subdirectory holding evidence/ (added to --captures)")
    parser.add_argument("--out", type=Path, help="output directory (must not exist)")
    parser.add_argument("--any-kind", action="store_true",
                        help="also analyse captures whose attempt kind is not 'study' (tooling runs)")
    parser.add_argument("--check", action="store_true", help="rebuild the fixtures and compare with "
                                                             "fixture_expectation.json")
    parser.add_argument("--strict", action="store_true", help="with --check: require identical output bytes too")
    parser.add_argument("--fixture-run", action="store_true", help="run on the built-in fixtures (needs --out)")
    parser.add_argument("--write-expectation", type=Path, help="write the fixture expectation (refuses to overwrite)")
    parser.add_argument("--validity-only", action="store_true",
                        help="inclusion rule 3 only (bridge inclusion items 2-3 and the secondary rule): writes "
                             "<out>/validity.json and <out>/validity.md and nothing else, no ranking, cell or H-D "
                             "rule")
    args = parser.parse_args(argv)
    if args.validity_only and (args.check or args.write_expectation or args.fixture_run):
        parser.error("--validity-only runs on --captures / --captures-dir with --out; it does not combine with "
                     "--check, --write-expectation or --fixture-run (those run the full analysis)")
    if args.check:
        return check_expectation(strict=args.strict)
    if args.write_expectation:
        target = args.write_expectation.resolve()
        if target.exists():
            raise SystemExit(f"refusing to overwrite {target}")
        with tempfile.TemporaryDirectory() as tmp:
            result = fixture_run(Path(tmp) / "out")
        write_lf(target, json_text(expectation_doc(result)))
        print(json.dumps({"written": rel(target), "h_d": result["semantic"]["h_d"]}, indent=1))
        return 0
    if args.out is None:
        parser.error("--out is required")
    if args.fixture_run:
        result = fixture_run(args.out)
        print(json.dumps({"out": rel(args.out), "h_d": result["semantic"]["h_d"],
                          "seconds_per_capture": result["outcome"]["seconds_per_capture"]}, indent=1))
        return 0
    captures = list(args.captures)
    if args.captures_dir:
        captures += sorted(p for p in args.captures_dir.iterdir() if (p / "evidence").is_dir())
    if not captures:
        parser.error("no capture given (--captures or --captures-dir)")
    mode = "study"
    if args.validity_only:                                  # inclusion rule 3 only
        return validity_command(captures, args.out, mode=mode, allow_other_kinds=args.any_kind)
    outcome = run(captures, args.out, mode=mode, allow_other_kinds=args.any_kind)
    hd = outcome["summary"]["h_d"]
    print(json.dumps({"out": rel(args.out), "h_d": {k: hd[k] for k in (
        "n_included_d1", "E_P", "E_W", "verdict")}, "errors": outcome["errors"],
        "seconds_per_capture": outcome["seconds_per_capture"]}, indent=1))
    return 2 if outcome["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
