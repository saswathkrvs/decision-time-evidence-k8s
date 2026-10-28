"""Diagnosis control of the follow-up study (arm D), part 1: the loader. replay.load_capture_task reproduced, plus the
watch stores.

Gate v1's ``load_sightings`` (experiments/policy-gate-v1/run_policy_gate_audit.py) accepts only the observation basis
``snapshot_receipt``, and replay.load_capture_task calls it, so watch records cannot enter the development diagnosis
path; relabelling them snapshot_receipt would be a false label. This loader reproduces that path with the accepted
observation basis as a parameter, so that the context bridge runs twice on each capture: on poller-sourced and on
watch-sourced Pod records. Both stores pass through the same mapping (gate v1's build_observations), so the
poller-watch comparison isolates timing. The watch variants of the switch streams are defined on the event before
cache materialisation (``WatchIndex`` gives each snapshot row its carrier).

What it reproduces, without importing the development scripts (only the libraries aiops_kg.replay and
aiops_kg.policy_gate are imported): ``load_sightings`` and ``build_observations`` of the gate v1 audit (with
include_receipts=False, as load_capture_task calls it, real aiops_kg.policy_gate.Observation objects, and one change:
the creation-ceiling clamp), and the task assembly of replay.load_capture_task. The tests check that on poller rows
its records equal load_capture_task's byte for byte.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from aiops_kg import replay as R  # noqa: E402
from aiops_kg.policy_gate import CONTROLLER, GENERATION, NODE, STATE, Observation  # noqa: E402

LOADER_VERSION = "stage2-diagnosis-loader-v1"
UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
ONE_SECOND = timedelta(seconds=1)

# The constants replay.load_capture_task copies from experiments/attribution-lag-v1/run_attribution_lag.py into its task
# (RETIRED, DELTAS, CARRY_FORWARD_US); reproduced, and checked equal to the script's in the tests.
RETIRED = frozenset({"terminating", "failed", "succeeded", "absent"})
DELTAS = (("0 s", 0), ("5 s", 5), ("30 s", 30), ("120 s", 120), ("hindsight", None))
CARRY_FORWARD_US = 600 * 10**6

POLLER, WATCH, WATCH_EVENT = "poller", "watch", "watch_event"
OBSERVERS = (POLLER, WATCH, WATCH_EVENT)
EVIDENCE_FILE = "accepted_evidence.jsonl"
SNAPSHOT_FILE = "stage2/api_observation.watch_cache_snapshot.jsonl"
LIST_OBJECT_FILE = "stage2/api_watch_list_object.jsonl"
EVENT_FILE = "stage2/api_watch_event.jsonl"
GAP_FILE = "stage2/continuity_gap.jsonl"
OBSERVER_FILES = {POLLER: (EVIDENCE_FILE,), WATCH: (SNAPSHOT_FILE,), WATCH_EVENT: (LIST_OBJECT_FILE, EVENT_FILE)}
OBSERVER_BASIS = {POLLER: ("snapshot_receipt",), WATCH: ("watch_cache_snapshot",),
                  WATCH_EVENT: ("watch_list", "watch_event")}
OBJECT_EVENTS = ("ADDED", "MODIFIED", "DELETED")
CLAMP_RULE = ("non-Pod creation ceiling clamped to the observation time: starts_at = min(creationTimestamp + 1 s, "
              "observed_at); gate v1's build_observations would raise 'starts_at cannot be later than observed_at'")


# ---------------------------------------------------------------------------------------------------------------
# Gate v1's helpers, reproduced (experiments/policy-gate-v1/run_policy_gate_audit.py lines 69-99)
# ---------------------------------------------------------------------------------------------------------------
def ts(text: str | None) -> datetime | None:
    """run_policy_gate_audit.ts: ISO text -> aware UTC datetime (fromisoformat; nine-digit fractions are truncated to
    the microsecond on Python >= 3.11, as in the Phase-3 loader)."""
    if text is None:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def check(condition: bool, message: str) -> None:
    """run_policy_gate_audit.check: the same exception type and message prefix."""
    if not condition:
        raise SystemExit(f"input verification failed: {message}")


def pod_state(resource: dict) -> str:
    """run_policy_gate_audit.pod_state, unchanged (no K1: the bridge (arm D) reads Pod
    STATE without K1 for both observers)."""
    status = resource.get("status", {})
    phase = status.get("phase")
    if phase == "Failed":
        return "failed"
    if phase == "Succeeded":
        return "succeeded"
    if resource["metadata"].get("deletionTimestamp"):
        return "terminating"
    statuses = status.get("containerStatuses") or []
    if phase == "Running" and statuses and all(c.get("ready") is True for c in statuses):
        return "ready"
    return "not_ready"


def _json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _api_sighting(entry: dict, protocol: Mapping, basis: tuple) -> dict:
    """One api_observation row -> one sighting: the body of gate v1's load_sightings (lines 107-128), with the accepted
    observation basis as a parameter (the line 114 accepts only snapshot_receipt)."""
    record = entry["record"]
    payload = record["payload"]
    resource = payload["resource_data"]
    meta = resource["metadata"]
    check(payload["record_type"] == "resource_observation", "unexpected API record type")
    check(payload.get("observation_basis") in basis, "unexpected observation basis")
    if resource["kind"] != "Node":
        check(meta.get("namespace") == protocol["namespace"], "namespace mismatch")
    return {
        "record_id": record["evidence_id"], "collection_id": payload["collection_id"],
        "snapshot_id": payload["snapshot_id"], "resource": payload["resource"],
        "kind": resource["kind"], "uid": meta["uid"], "name": meta["name"],
        "subject": f"{resource['kind']}/{meta['uid']}",
        "created_at": ts(meta["creationTimestamp"]),
        "observed_at": ts(payload["observed_at"]), "available_at": ts(payload["available_at"]),
        "index_available_at": EPOCH + timedelta(microseconds=entry["available_ns"] // 1000),
        "clock_adjusted": payload.get("clock_adjusted"),
        "source_sha256": payload.get("_source_record_sha256"), "resource_data": resource,
    }


def _watch_object_sighting(entry: dict, protocol: Mapping) -> dict:
    """One api_watch_list_object or api_watch_event row -> a sighting of the same shape (observer watch_event).
    snapshot_id: the LIST's record id (<collection>/<list sequence>) for a list object, the event's own record id for
    an event, so that gate v1's grouping by (resource, snapshot_id) puts one LIST, or one event, in one group."""
    record = entry["record"]
    payload = record["payload"]
    resource = payload["resource_data"]
    meta = resource["metadata"]
    kind = record["kind"]
    check(kind in ("api_watch_list_object", "api_watch_event"), "unexpected watch row kind")
    check(payload.get("observation_basis") == ("watch_list" if kind == "api_watch_list_object" else "watch_event"),
          "unexpected observation basis")
    check(meta.get("namespace") == protocol["namespace"], "namespace mismatch")
    snapshot_id = (f"{payload['collection_id']}/{payload['list_sequence']}" if kind == "api_watch_list_object"
                   else payload["record_id"])
    return {
        "record_id": record["evidence_id"], "collection_id": payload["collection_id"],
        "snapshot_id": snapshot_id, "resource": payload["resource"],
        "kind": resource["kind"], "uid": meta["uid"], "name": meta["name"],
        "subject": f"{resource['kind']}/{meta['uid']}",
        "created_at": ts(meta["creationTimestamp"]),
        "observed_at": ts(payload["observed_at"]), "available_at": ts(payload["available_at"]),
        "index_available_at": EPOCH + timedelta(microseconds=entry["available_ns"] // 1000),
        "clock_adjusted": payload.get("clock_adjusted"),
        "source_sha256": payload.get("_source_record_sha256"), "resource_data": resource,
    }


def _check_sightings(rows: list) -> list:
    """The closing checks of gate v1's load_sightings (lines 129-131): one collection, observation <= availability;
    sorted by (observed_at, record_id)."""
    check(len({r["collection_id"] for r in rows}) == 1, "API sightings span several collections")
    check(all(r["observed_at"] <= r["available_at"] for r in rows), "availability precedes observation")
    return sorted(rows, key=lambda r: (r["observed_at"], r["record_id"]))


def read_sightings(path: Path, protocol: Mapping, basis: tuple) -> tuple[list, dict]:
    """gate v1's load_sightings on one file, every api_observation row, the basis a parameter. The file is read line
    by line exactly as the function reads it (a blank line refuses, as json.loads refuses it there). Returns
    (sightings, available_ns by evidence id) so that the file is parsed once."""
    rows, available_ns = [], {}
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            entry = json.loads(line)
            if entry["record"]["kind"] != "api_observation":
                continue
            rows.append(_api_sighting(entry, protocol, basis))
            available_ns[entry["record"]["evidence_id"]] = entry["available_ns"]
    return _check_sightings(rows), available_ns


# ---------------------------------------------------------------------------------------------------------------
# Gate v1's mapping, reproduced, with the clamp (run_policy_gate_audit.py build_observations, lines 142-227)
# ---------------------------------------------------------------------------------------------------------------
def map_sightings(sightings: list, *, complete: Callable[[str], bool] | None = None,
                  deleted: list | tuple = ()) -> tuple[list, dict, list]:
    """build_observations(sightings, None, protocol, include_receipts=False), with the creation-ceiling clamp.

    Returns (observations, identities, clamps). With complete=None and no deleted rows it is the function's output
    for every input the function accepts. ``complete`` (observer watch_event): the snapshots that are complete
    lists; gate v1's absence rule emits absences only there, while every snapshot still counts as "seen".
    ``deleted`` (observer watch_event): DELETED event rows, each an "absent" observation at its own receipt."""
    observations: list[Observation] = []
    identities: dict[str, dict] = {}
    clamps: list[dict] = []
    snapshots: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in sightings:
        snapshots[(row["resource"], row["snapshot_id"])].append(row)
        subject, resource, meta = row["subject"], row["resource_data"], row["resource_data"]["metadata"]
        rid, observed, available = row["record_id"], row["observed_at"], row["available_at"]
        created_ceiling = row["created_at"] + ONE_SECOND  # creationTimestamp has 1 s resolution
        known = identities.get(subject)
        if known is None:
            identities[subject] = {"name": row["name"], "created_at": row["created_at"],
                                   "available_at": available, "record_id": rid}
        else:
            check(known["name"] == row["name"] and known["created_at"] == row["created_at"],
                  f"identity changed for {subject}")

        def add(predicate, value, starts=None, rid=rid, subject=subject, observed=observed, available=available):
            observations.append(Observation(rid, subject, predicate, value, observed, available, starts))

        if row["kind"] == "Pod":
            add(STATE, pod_state(resource))
            owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
            check(len(owners) == 1, f"{subject} lacks a single controller reference")
            add(CONTROLLER, f"{owners[0]['kind']}/{owners[0]['uid']}")
            node = resource.get("spec", {}).get("nodeName")
            if node:
                add(NODE, f"NodeName/{node}")
        else:
            starts = created_ceiling
            clamped = []
            if starts > observed:                       # THE CLAMP (this layer; the mapping raises here)
                starts = observed
                clamped.append(STATE)
            add(STATE, "present", starts)
            if row["kind"] in ("ReplicaSet", "Deployment"):
                generation = meta["generation"]
                if generation == 1 and starts != created_ceiling:
                    clamped.append(GENERATION)
                add(GENERATION, str(generation), starts if generation == 1 else None)
            if row["kind"] == "ReplicaSet":
                owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
                check(len(owners) == 1, f"{subject} lacks a single controller reference")
                add(CONTROLLER, f"{owners[0]['kind']}/{owners[0]['uid']}")
            if clamped:
                clamps.append({"record_id": rid, "kind": row["kind"], "subject": subject, "name": row["name"],
                               "snapshot_id": row["snapshot_id"], "predicates": clamped,
                               "creation_timestamp": R.iso(R.to_us(row["created_at"])),
                               "creation_ceiling": R.iso(R.to_us(created_ceiling)),
                               "observed_at": R.iso(R.to_us(observed)),
                               "ceiling_minus_observed_us": R.to_us(created_ceiling) - R.to_us(observed)})
    # Absence: a previously seen UID missing from a later complete list of its kind (lines 189-203).
    by_resource: dict[str, list] = defaultdict(list)
    for (resource, snapshot_id), rows in snapshots.items():
        check(len({r["observed_at"] for r in rows}) == 1, f"{snapshot_id} has several receipt times")
        by_resource[resource].append((rows[0]["observed_at"], snapshot_id, rows))
    for resource, items in by_resource.items():
        seen: dict[str, str] = {}
        for observed, snapshot_id, rows in sorted(items, key=lambda item: (item[0], item[1])):
            present = {r["subject"] for r in rows}
            if complete is None or complete(snapshot_id):
                list_available = max(r["available_at"] for r in rows)  # the list is complete once all rows arrived
                for subject in sorted(set(seen) - present):
                    observations.append(Observation(f"absence:{snapshot_id}:{subject.split('/', 1)[1]}", subject,
                                                    STATE, "absent", observed, list_available))
            for r in rows:
                seen[r["subject"]] = r["kind"]
    for row in deleted:                                 # observer watch_event only
        known = identities.get(row["subject"])
        if known is not None:
            check(known["name"] == row["name"] and known["created_at"] == row["created_at"],
                  f"identity changed for {row['subject']}")
        observations.append(Observation(f"absence:{row['snapshot_id']}:{row['uid']}", row["subject"], STATE, "absent",
                                        row["observed_at"], row["available_at"]))
    return observations, identities, clamps


# ---------------------------------------------------------------------------------------------------------------
# One observer's store (read once), and the per-service task (replay.load_capture_task, reproduced)
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class ObserverStore:
    """Everything load_capture_task reads, for one observer: the evidence rows (spans, client rows; always
    accepted_evidence.jsonl), the observer's API sightings and their mapping. ``report`` holds the observer facts this
    layer adds (basis, files, clamps, row counts); it never enters a task."""
    capture: Path
    observer: str
    root: Path
    evidence_file: Path
    protocol: dict
    capture_doc: dict
    rows: list
    kinds: dict
    sightings: list
    observations: list
    identities: dict
    clamps: list
    lag_mismatch: list
    report: dict = field(default_factory=dict)


def _evidence(capture: Path) -> tuple[Path, Path, dict, dict]:
    evidence_dir = capture / "evidence"
    evidence_file = evidence_dir / EVIDENCE_FILE
    if not evidence_file.exists():
        raise FileNotFoundError(f"{evidence_file} not found: run phase3/convert_capture.py --capture {capture} first")
    protocol = _json(evidence_dir / "protocol.json")
    capture_doc = _json(evidence_dir / "capture.json") if (evidence_dir / "capture.json").exists() else {}
    return evidence_dir, evidence_file, protocol, capture_doc


def _read_rows(path: Path) -> list:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def load_observer(capture: Path | str, observer: str = POLLER, *, root: Path | str | None = None) -> ObserverStore:
    """Read and map one observer's API rows of a converted Stage-2 (or Phase-3) capture. Model input only:
    <capture>/evidence/ (accepted_evidence.jsonl, protocol.json, capture.json and, for the watch observers, stage2/)."""
    if observer not in OBSERVERS:
        raise ValueError(f"observer must be one of {OBSERVERS}, not {observer!r}")
    capture = Path(capture).resolve()
    root = Path(root).resolve() if root is not None else ROOT
    evidence_dir, evidence_file, protocol, capture_doc = _evidence(capture)
    rows = _read_rows(evidence_file)
    kinds: dict[str, int] = {}
    for row in rows:
        kinds[row["record"]["kind"]] = kinds.get(row["record"]["kind"], 0) + 1
    deleted, complete, files = [], None, [evidence_dir / name for name in OBSERVER_FILES[observer]]
    for path in files:
        if not path.exists():
            raise FileNotFoundError(f"{path} not found: the {observer} observer needs phase3/convert_stage2.py output")
    if observer in (POLLER, WATCH):
        sightings, api_rows = read_sightings(files[0], protocol, OBSERVER_BASIS[observer])
    else:
        raw, api_rows, lists = [], {}, set()
        for path in files:
            for entry in _read_rows(path):
                payload = entry["record"]["payload"]
                if entry["record"]["kind"] == "api_watch_event" and payload.get("event_type") not in OBJECT_EVENTS:
                    continue
                sighting = _watch_object_sighting(entry, protocol)
                api_rows[sighting["record_id"]] = entry["available_ns"]
                if entry["record"]["kind"] == "api_watch_list_object":
                    lists.add(sighting["snapshot_id"])
                if payload.get("event_type") == "DELETED":
                    deleted.append(sighting)
                else:
                    raw.append(sighting)
        sightings = _check_sightings(raw)
        deleted = sorted(deleted, key=lambda r: (r["observed_at"], r["record_id"]))
        complete = lists.__contains__
    observations, identities, clamps = map_sightings(sightings, complete=complete, deleted=deleted)
    lag_mismatch = [s["record_id"] for s in sightings + list(deleted)
                    if api_rows[s["record_id"]] // 1000 != R.to_us(s["available_at"])]
    report = {"observer": observer, "loader": LOADER_VERSION, "basis": list(OBSERVER_BASIS[observer]),
              "files": [p.relative_to(capture).as_posix() for p in files],
              "sightings": len(sightings), "deleted_events": len(deleted),
              "complete_lists": None if complete is None else len(lists),
              "collection_id": sightings[0]["collection_id"] if sightings else None,
              "clamps": clamps, "clamp_rule": CLAMP_RULE,
              "api_rows_available_mismatch": len(lag_mismatch)}
    return ObserverStore(capture, observer, root, evidence_file, protocol, capture_doc, rows, kinds, sightings,
                         observations, identities, clamps, lag_mismatch, report)


def task_for_service(store: ObserverStore, service: str | None = None) -> R.RolloutTask:
    """replay.load_capture_task (src/aiops_kg/replay.py lines 853-967) on one observer's store, for one service."""
    capture = store.capture
    service, service_source = R.capture_service(capture, store.protocol, service)
    notes: list[str] = []
    sightings, observations, info_identities = store.sightings, store.observations, store.identities
    if store.lag_mismatch:
        notes.append(f"{len(store.lag_mismatch)} api rows: available_ns // 1000 != payload available_at; payload used")

    labels, owners, rs_owner, deployment_name = {}, {}, {}, {}
    for s in sightings:
        meta = s["resource_data"]["metadata"]
        controller = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
        if s["kind"] == "Pod":
            app = meta.get("labels", {}).get("app")
            if labels.setdefault(s["subject"], app) != app:
                raise ValueError(f"label changed for {s['subject']}")
            if controller:
                owners[s["subject"]] = controller[0]["uid"]
        elif s["kind"] == "ReplicaSet" and controller:
            rs_owner[meta["uid"]] = controller[0]["uid"]
        elif s["kind"] == "Deployment":
            deployment_name[meta["uid"]] = meta["name"]
    by_label = sorted(k for k, app in labels.items() if app == service)
    by_chain = sorted(k for k, rs in owners.items() if deployment_name.get(rs_owner.get(rs)) == service)
    if by_label != by_chain:
        raise ValueError(f"{service}: Pods by label {by_label} and by owner chain {by_chain} disagree")
    if not by_label:
        raise ValueError(f"no Pod of service {service!r} in the capture's API sightings")

    snapshot_of = {s["record_id"]: s["snapshot_id"] for s in sightings}
    wanted = set(by_label)
    records = []
    for o in observations:
        if o.subject in wanted and o.predicate == "STATE":
            kind = "absence" if o.record_id.startswith("absence:") else "api"
            group = o.record_id.split(":")[1] if kind == "absence" else snapshot_of.get(o.record_id)
            records.append(R.Record(o.record_id, o.subject, "STATE", o.value, R.to_us(o.observed_at),
                                    R.to_us(o.available_at), kind=kind, group=group))
    records.sort(key=lambda r: (r.subject, r.observed_at, r.record_id))
    created = {k: R.to_us(info_identities[k]["created_at"]) for k in by_label}
    order = sorted(by_label, key=lambda k: (created[k], k))
    names = ["old", "new"] if len(order) == 2 else [f"p{i}" for i in range(1, len(order) + 1)]
    if len(order) > 9:
        raise ValueError("more than 9 candidate Pods; widen the answer codes first")
    candidates = tuple(R.Candidate(k, names[i], created[k]) for i, k in enumerate(order))
    label_of_uid = {c.key.split("/", 1)[1]: c.label for c in candidates}

    spans_by_trace: dict[str, list[dict]] = {}
    block_of_trace: dict[str, str] = {}
    for row in store.rows:
        record = row["record"]
        if record["kind"] == "span_claim":
            spans_by_trace.setdefault(record["payload"]["trace_id"], []).append(record["payload"])
        elif record["kind"] == "client_request":
            payload = record["payload"]
            if payload.get("trace_id"):
                block_of_trace[payload["trace_id"]] = payload.get("block") or payload.get("source") or "client"
    requests, unverified = [], []
    for trace_id, spans in spans_by_trace.items():
        for p in spans:
            span = p["span"]
            if span.get("parentSpanId") or "aiops.request.index" not in (p.get("span_attributes") or {}):
                continue
            mine = [q for q in spans if (q.get("resource_attributes") or {}).get("service.name") == service]
            servers = [q for q in mine if q["span"].get("kind") == 2]
            uids = {(q.get("resource_attributes") or {}).get("k8s.pod.uid") for q in mine}
            item = {"trace_id": trace_id, "block": block_of_trace.get(trace_id),
                    "index": int(p["span_attributes"]["aiops.request.index"]),
                    "root_service": (p.get("resource_attributes") or {}).get("service.name"),
                    "t_req_us": int(span["startTimeUnixNano"]) // 1000}
            if len(servers) == 1 and len(uids) == 1 and next(iter(uids)) in label_of_uid:
                item["truth_uid"] = next(iter(uids))
                requests.append(item)
            else:
                item["why"] = (f"{len(servers)} server spans of {service}, Pod UIDs {sorted(u or '-' for u in uids)}"
                               + ("" if uids <= set(label_of_uid) else " (not a sighted candidate)"))
                unverified.append(item)
    requests.sort(key=lambda r: (r["t_req_us"], r["block"] or "", r["index"]))
    events, truth, index = [], {}, {}
    for number, r in enumerate(requests, start=1):
        event_id = f"request/{number}"
        r["event"] = number
        r["label"] = f"{r['block']}:{r['index']}" if r["block"] else str(r["index"])
        events.append(R.Record(event_id, event_id, "T_REQ", r["label"], r["t_req_us"], r["t_req_us"], kind="request"))
        truth[event_id] = label_of_uid[r["truth_uid"]]
        index[event_id] = number
    if unverified:
        notes.append(f"{len(unverified)} requests without a span-verified {service} Pod are not scored")
    ground_truth = capture / "ground_truth" / "ground_truth.json"
    return R.RolloutTask(module=None, records=tuple(records), events=tuple(events), truth=truth,
                         candidates=candidates, predicate="STATE", serving_value="ready",
                         retired_values=frozenset(RETIRED), default_freshness_seconds=CARRY_FORWARD_US / R.US,
                         deltas=tuple(DELTAS), request_index=index,
                         context={"capture_dir": capture, "evidence_file": store.evidence_file,
                                  "protocol": store.protocol, "capture": store.capture_doc, "service": service,
                                  "service_source": service_source, "sightings": sightings,
                                  "rows_by_kind": dict(sorted(store.kinds.items())), "requests": requests,
                                  "unverified_requests": unverified, "owner_chain_agrees": True,
                                  "api_rows_available_mismatch": len(store.lag_mismatch),
                                  "ground_truth": _json(ground_truth) if ground_truth.exists() else None,
                                  "notes": notes})


def load_stage2_task(capture: Path | str, service: str | None = None, *, observer: str = POLLER,
                     root: Path | str | None = None) -> R.RolloutTask:
    """Drop-in for replay.load_capture_task(capture, service, root=root) with the observer as an argument ("poller" |
    "watch" | "watch_event"). For "poller" it returns the Phase-3 loader's task byte for byte (task_fingerprint),
    with module=None. Errors are the Phase-3 loader's (FileNotFoundError, ValueError, SystemExit with "input
    verification failed: ..."), raised in the same order, except that the creation-ceiling refusal of the mapping is
    replaced by a recorded clamp (load_observer(...).clamps)."""
    capture = Path(capture).resolve()
    _, _, protocol, _ = _evidence(capture)
    R.capture_service(capture, protocol, service)          # the Phase-3 loader resolves the service before reading
    return task_for_service(load_observer(capture, observer, root=root), service)


# ---------------------------------------------------------------------------------------------------------------
# The carriers of watch snapshot rows (the switch variants are defined on the event)
# ---------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Carrier:
    """The watch record that carried an object version into the cache: an api_watch_event or a watch_list_object."""
    record_id: str          # <collection>/<sequence>
    record_type: str        # api_watch_event | watch_list_object
    sequence: int
    event_type: str | None
    uid: str
    resource: str
    observed_us: int        # the line (event) or LIST (list object) receipt
    available_us: int
    resource_data: Mapping


@dataclass
class WatchIndex:
    """For observer "watch": every snapshot row's snapshot facts and carrier, and every carrier by record id.

    row_meta[evidence_id] = (snapshot_id, snapshot_trigger, trigger_sequence, carrier record id). Read from
    stage2/api_observation.watch_cache_snapshot.jsonl (payload snapshot_*, trigger_sequence, source_record*), with the
    carriers from stage2/api_watch_event.jsonl and api_watch_list_object.jsonl (every
    snapshot row names the record (source_record) its object was resolved from)."""
    row_meta: dict
    carriers: dict
    gaps: list

    @classmethod
    def load(cls, capture: Path | str) -> "WatchIndex":
        evidence_dir = Path(capture).resolve() / "evidence"
        carriers = {}
        for name in (LIST_OBJECT_FILE, EVENT_FILE):
            path = evidence_dir / name
            if not path.exists():
                raise FileNotFoundError(f"{path} not found: the watch switch variants need the carriers")
            for entry in _read_rows(path):
                p = entry["record"]["payload"]
                if entry["record"]["kind"] == "api_watch_event" and p.get("event_type") not in OBJECT_EVENTS:
                    continue
                carriers[p["record_id"]] = Carrier(p["record_id"], p["record_type"], int(p["sequence"]),
                                                   p.get("event_type"), p["uid"], p["resource"],
                                                   R.to_us(ts(p["observed_at"])), R.to_us(ts(p["available_at"])),
                                                   p.get("resource_data") or {})
        row_meta = {}
        for entry in _read_rows(evidence_dir / SNAPSHOT_FILE):
            if entry["record"]["kind"] != "api_observation":
                continue
            p = entry["record"]["payload"]
            row_meta[entry["record"]["evidence_id"]] = (p["snapshot_id"], p.get("snapshot_trigger"),
                                                        p.get("trigger_sequence"), p.get("source_record"))
        gaps = []
        if (evidence_dir / GAP_FILE).exists():
            for entry in _read_rows(evidence_dir / GAP_FILE):
                p = entry["record"]["payload"]
                if p.get("observer") == "watch" and p.get("reason") == "watch_interrupted":
                    gaps.append({"resource": p.get("resource"), "cause": p.get("cause"),
                                 "gap_from_at": p.get("gap_from_at"), "gap_to_at": p.get("gap_to_at"),
                                 "duration_seconds": p.get("duration_seconds")})
        return cls(row_meta, carriers, gaps)


# ---------------------------------------------------------------------------------------------------------------
# Deterministic serialisation (the identity test compares these bytes)
# ---------------------------------------------------------------------------------------------------------------
def _default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"not serialisable: {type(value).__name__}")


def record_row(record: R.Record) -> list:
    """Every field of a Record, in declaration order (integer microseconds, not ISO text)."""
    return [getattr(record, f.name) for f in fields(R.Record)]


def task_fingerprint(task: R.RolloutTask, *, context: bool = True) -> bytes:
    """Canonical bytes of a RolloutTask: every Record field of every record and event, truth, candidates (key, label,
    creation floor), the constants and, with context=True, the whole task context (sightings with their datetimes,
    the span-verified requests, notes, ...). The field ``module`` is left out (see the module docstring)."""
    doc = {"records": [record_row(r) for r in task.records],
           "events": [record_row(e) for e in task.events],
           "truth": sorted(task.truth.items()),
           "candidates": [[c.key, c.label, c.created_floor] for c in task.candidates],
           "predicate": task.predicate, "serving_value": task.serving_value,
           "retired_values": sorted(task.retired_values),
           "default_freshness_seconds": task.default_freshness_seconds,
           "deltas": [list(d) for d in task.deltas],
           "request_index": sorted(task.request_index.items())}
    if context:
        doc["context"] = task.context
    return json.dumps(doc, sort_keys=True, default=_default, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
