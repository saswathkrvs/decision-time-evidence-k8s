"""Synthetic scenarios (no real capture is read): development-format evidence rows, ground truth and capture
directories.

A scenario is an invented single-replica rollout on a one-node cluster, written in the exact row format of
``evidence/accepted_evidence.jsonl`` (phase3/CAPTURE_FORMAT.md), so the fixtures exercise the same parsing the
decision reader uses on captures. Times are seconds after BASE (2026-10-01T10:00:00Z, an arbitrary fixture origin).
Lists: Pods at 3n, ReplicaSets at 3n + 0.4, Deployments at 3n + 0.8, the Node at 3n + 1.2 seconds; each row is
available 0.5 ms after the previous row of its list.

Standard rollout of the changed service (``Scenario`` defaults):

=========  ===================================================================================================
time (s)   event
=========  ===================================================================================================
29.2       patch request P (receipt row available 29.6005)
29.6       patch response R
30.8       Deployment sighting: generation 2, observedGeneration 1, revision 1 (spec update not yet observed)
31         new ReplicaSet (revision 2) and new Pod created (first listed 33.4 / 33.0, Pod not ready)
33.8       Deployment: revision 2, observedGeneration 2, replicas 2, updated 1, available 1 (incomplete surge)
36         new Pod ready; 36.8 Deployment: replicas 2, updated 1, available 2 (old replica not terminated)
39.5       rollout-wait response W (exit 0; row available 39.5005)
39         old Pod terminating (39.0, 42.0 lists); absent from 45.0; old ReplicaSet scaled to 0 (39.4)
39.8       Deployment: replicas 1, updated 1, available 1 (COMPLETE at revision 2)
60-80      active window (ground truth only)
250        last list (H = the last availability, about 251.2 s; S150 and S180 receipts arrive before H, S300 and
           S1200 after it, as in the eight change-bearing captures)
=========  ===================================================================================================

Requests k = 1..80 of the target block at t_k = 20 + (k - 1) s (span clock = host clock in the fixtures).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from .common import R, canonical, s_to_us, sha256_text, ts_us
from .environment import KUBECTL_VERSION_FILE
from .inputs import CaptureInputs, InputRecord, freeze_record, records_from_rows, requests_from_rows
from .rollout import KUBECTL_CLIENT_PIN, KUBERNETES_SERVER_PIN

BASE_US = ts_us("2026-10-01T10:00:00Z")
INCARNATION = "fixture-incarnation-0001"
NODE = "fixture-node"
SERVICES = ("recommendationservice", "productcatalogservice")


def T(seconds: float) -> int:
    """Fixture time: seconds after BASE -> integer microseconds."""
    return BASE_US + s_to_us(seconds) if seconds >= 0 else BASE_US - s_to_us(-seconds)


def iso(seconds: float) -> str:
    return R.iso(T(seconds))


def k8s_time(seconds: float) -> str:
    """creationTimestamp / deletionTimestamp text: whole seconds (1 s resolution, floored)."""
    us = T(seconds)
    return R.iso(us - (us % 1_000_000))[:19] + "Z"


@dataclass(frozen=True)
class Scenario:
    name: str
    changed_service: str | None = "recommendationservice"   # None: no planned change (A never posed)
    fault: str = "changed"           # "changed": replacement Pod of the changed service; "other"; "none" (sham)
    effect: bool = True              # latency_effect_established
    failed_rollout: bool = False     # the new Pod never becomes ready; wait exits 1 at W_failed
    conditions_recorded: bool = False
    P: float = 29.2
    R: float = 29.6
    W: float = 39.5
    W_failed: float = 130.0
    active: tuple = (60.0, 80.0)
    last_list: float = 250.0
    deployment_lists_until: float | None = None    # stop Deployment lists after this time (freshness tests)
    workload_lists_until: float | None = None      # stop Pod/ReplicaSet/Deployment lists (Node lists go on)
    requests: tuple = tuple(range(20, 100))         # t_k in seconds, k = 1..
    extra_u_windows: tuple = ()                     # evaluation-only U intervals (e.g. the I4 catalog disruption)
    deployment_overrides: tuple = ()                # ((list time, {"metadata"/"spec"/"status": {...}}), ...)
    with_wait: bool = True
    with_patch: bool = True

    @property
    def capture_id(self) -> str:
        return f"FX-{self.name}"

    @property
    def namespace(self) -> str:
        return f"aiops-fx-{self.name.lower()}"


def _uid(kind: str, service: str, n: int = 1) -> str:
    return f"{kind}{n}-{service}"


def _hash(service: str, n: int) -> str:
    return f"{abs(hash_stable(service)) % 10 ** 9:09d}{n}"[-10:]


def hash_stable(text: str) -> int:
    return int(sha256_text(text)[:12], 16)


# ---------------------------------------------------------------------------------------------------------------
# Object states over time
# ---------------------------------------------------------------------------------------------------------------
def deployment_resource(sc: Scenario, service: str, t: float) -> dict:
    changed = service == sc.changed_service
    generation, revision, observed = 1, "1", 1
    replicas = updated = ready = available = 1
    conditions = [{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable"},
                  {"type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable"}]
    if changed and t >= sc.R:
        generation = 2
        if t < 31.0:
            observed = 1
            conditions[1]["reason"] = "NewReplicaSetAvailable"
        else:
            revision, observed = "2", 2
            if sc.failed_rollout:
                replicas, updated, ready, available = 2, 1, 1, 1
                conditions[1] = ({"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}
                                 if t >= 45.0 else {"type": "Progressing", "status": "True",
                                                    "reason": "ReplicaSetUpdated"})
            elif t < 36.0:
                replicas, updated, ready, available = 2, 1, 1, 1
                conditions[1]["reason"] = "ReplicaSetUpdated"
            elif t < 39.0:
                replicas, updated, ready, available = 2, 1, 2, 2
                conditions[1]["reason"] = "ReplicaSetUpdated"
    meta = {"annotations": {"deployment.kubernetes.io/revision": revision}, "creationTimestamp": k8s_time(-100),
            "generation": generation, "labels": {"app": service}, "name": service, "namespace": sc.namespace,
            "ownerReferences": [], "resourceVersion": str(int(t * 10) + 1000), "uid": _uid("dep", service)}
    status = {"availableReplicas": available, "observedGeneration": observed, "readyReplicas": ready,
              "replicas": replicas, "updatedReplicas": updated}
    if sc.conditions_recorded:
        status["conditions"] = conditions
    resource = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta,
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": service}}}, "status": status}
    for when, override in sc.deployment_overrides:
        if service == (sc.changed_service or SERVICES[0]) and abs(when - t) < 1e-9:
            resource = _apply_override(resource, override)
    return resource


def _apply_override(resource: dict, override: dict) -> dict:
    out = json.loads(json.dumps(resource))
    for part, changes in override.items():
        for key, value in changes.items():
            if value is _DELETE:
                out[part].pop(key, None)
            elif part == "metadata" and key == "annotations":
                out[part][key] = value
            else:
                out[part][key] = value
    return out


class _Delete:
    def __repr__(self):
        return "DELETE"


_DELETE = _Delete()
DELETE = _DELETE


def replicaset_resources(sc: Scenario, service: str, t: float) -> list[dict]:
    changed = service == sc.changed_service
    out = []
    old_replicas = 1
    if changed and t >= 39.0 and not sc.failed_rollout:
        old_replicas = 0
    out.append(_rs(sc, service, 1, "1", -100, old_replicas, old_replicas))
    if changed and t >= 33.0:
        ready = 1 if (t >= 36.0 and not sc.failed_rollout) else 0
        out.append(_rs(sc, service, 2, "2", 31.0, 1, 1, ready))
    return out


def _rs(sc, service, n, revision, created, spec_replicas, replicas, ready=None):
    ready = replicas if ready is None else ready
    meta = {"annotations": {"deployment.kubernetes.io/revision": revision}, "creationTimestamp": k8s_time(created),
            "generation": 1, "labels": {"app": service, "pod-template-hash": _hash(service, n)},
            "name": f"{service}-{_hash(service, n)}", "namespace": sc.namespace,
            "ownerReferences": [{"apiVersion": "apps/v1", "blockOwnerDeletion": True, "controller": True,
                                 "kind": "Deployment", "name": service, "uid": _uid("dep", service)}],
            "resourceVersion": "1", "uid": _uid("rs", service, n)}
    status = {"observedGeneration": 1, "replicas": replicas}
    if ready:
        status.update(readyReplicas=ready, availableReplicas=ready)
    return {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": meta,
            "spec": {"replicas": spec_replicas}, "status": status}


def pod_resources(sc: Scenario, service: str, t: float) -> list[dict]:
    changed = service == sc.changed_service
    out = []
    old_state = "ready"
    if changed and not sc.failed_rollout:
        if t >= 45.0:
            old_state = None
        elif t >= 39.0:
            old_state = "terminating"
    if old_state is not None:
        out.append(_pod(sc, service, 1, -100, old_state))
    if changed and t >= 33.0:
        out.append(_pod(sc, service, 2, 31.0, "ready" if (t >= 36.0 and not sc.failed_rollout) else "not_ready"))
    return out


def _pod(sc, service, n, created, state):
    meta = {"creationTimestamp": k8s_time(created), "generation": 1,
            "labels": {"app": service, "pod-template-hash": _hash(service, n)},
            "name": f"{service}-{_hash(service, n)}-pod{n}", "namespace": sc.namespace,
            "ownerReferences": [{"apiVersion": "apps/v1", "blockOwnerDeletion": True, "controller": True,
                                 "kind": "ReplicaSet", "name": f"{service}-{_hash(service, n)}",
                                 "uid": _uid("rs", service, n)}],
            "resourceVersion": "1", "uid": _uid("pod", service, n)}
    if state == "terminating":
        meta["deletionTimestamp"] = k8s_time(39.0)
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta,
            "spec": {"containers": [{"image": "fixture", "name": "server"}], "initContainers": [], "nodeName": NODE},
            "status": {"containerStatuses": [{"name": "server", "ready": state == "ready", "restartCount": 0}],
                       "phase": "Running", "startTime": k8s_time(created)}}


def node_resource() -> dict:
    return {"apiVersion": "v1", "kind": "Node", "metadata": {"creationTimestamp": k8s_time(-10000), "name": NODE,
                                                             "ownerReferences": [], "uid": "node-uid-1"}}


# ---------------------------------------------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------------------------------------------
def _row(evidence_id: str, kind: str, payload: dict, available_us: int, subject: str, supports=()) -> dict:
    record = {"acquired_at": R.iso(available_us), "evidence_id": evidence_id, "kind": kind,
              "logical_id": evidence_id, "payload": payload, "source_ref": f"fixture#{evidence_id}",
              "source_sha256": sha256_text(canonical(payload)), "subject": subject, "supersedes": [],
              "supports": list(supports)}
    return {"available_ns": available_us * 1000, "logical_confirmation_ns": available_us * 1000, "record": record}


def _subject(kind: str, uid: str, namespace: str) -> str:
    group = "apps" if kind in ("ReplicaSet", "Deployment") else ""
    return canonical([INCARNATION, group, kind, "" if kind == "Node" else namespace, uid])


def _list_times(sc: Scenario):
    n = 0
    while 3.0 * n <= sc.last_list:
        yield n, 3.0 * n
        n += 1


def scenario_rows(sc: Scenario, *, extra_rows: Callable | None = None) -> list[tuple[int, dict]]:
    """Accepted-evidence rows of the scenario, in availability order, numbered like file lines."""
    collection = f"coll-{sc.name}"
    rows, seq = [], 0
    manifests = {"applications.json": {"kind": "List", "items": [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": s, "labels": {"app": s}}}
        for s in SERVICES]}}
    incident = {"id": sc.name, "runnable": True}
    if sc.changed_service:
        incident["change"] = {"at": "T0", "kind": "rollout", "service": sc.changed_service}
    config_payload = {"acquisition_semantics": "fixture", "deployment_manifests": manifests, "incident": incident,
                      "rollout_patch": {"spec": {"template": {"metadata": {"annotations": {
                          "aiops.project/revision": "2"}}}}}, "source_sha256": {}}
    rows.append(_row(f"configuration:{sha256_text(canonical(config_payload))}", "configuration", config_payload,
                     T(-50), canonical([INCARNATION, "configuration"])))
    for n, t0 in _list_times(sc):
        for offset, resource_name, builder in (
                (0.0, "pods", lambda t: [p for s in SERVICES for p in pod_resources(sc, s, t)]),
                (0.4, "replicasets", lambda t: [r for s in SERVICES for r in replicaset_resources(sc, s, t)]),
                (0.8, "deployments", lambda t: [deployment_resource(sc, s, t) for s in SERVICES]),
                (1.2, "nodes", lambda t: [node_resource()])):
            t = t0 + offset
            if t > sc.last_list + 1.2:
                continue
            if resource_name == "deployments" and sc.deployment_lists_until is not None \
                    and t > sc.deployment_lists_until:
                continue
            if resource_name != "nodes" and sc.workload_lists_until is not None and t > sc.workload_lists_until:
                continue
            for i, resource in enumerate(builder(t)):
                seq += 1
                observed = T(t)
                available = observed + 500 * (i + 1)
                payload = {"_source_record_hash_semantics": "fixture", "_source_record_sha256":
                           sha256_text(canonical(resource)), "available_at": R.iso(available),
                           "clock_adjusted": False, "collection_id": collection, "confirmed_at": None,
                           "known_open": False, "observation_basis": "snapshot_receipt", "observed_at": R.iso(observed),
                           "record_id": f"{collection}/{seq}", "record_type": "resource_observation",
                           "resource": resource_name, "resource_data": resource,
                           "snapshot_id": f"{n:03d}-{resource_name}", "valid_from": None,
                           "valid_to": None, "validity_status": "unknown; fixture"}
                rows.append(_row(f"api:{collection}/{seq}", "api_observation", payload, available,
                                 _subject(resource["kind"], resource["metadata"]["uid"], sc.namespace)))
    if sc.changed_service and sc.with_patch:
        service = sc.changed_service
        uid = _uid("dep", service)
        patch_available = T(sc.R) + 500
        patch = {"args": ["patch", "deployment", service, "--type=merge", "--patch-file", "rollout-patch.json", "-o",
                          "json"], "collector_available_at": R.iso(patch_available), "exit_code": 0,
                 "id": "change-patch", "request_started_at": iso(sc.P), "response_received_at": iso(sc.R)}
        rows.append(_row(f"change:{sc.capture_id}:{service}:patch", "change_receipt",
                         {"deployment_uid": uid, "patch_receipt": patch, "semantics": "fixture patch receipt",
                          "service": service}, patch_available, _subject("Deployment", uid, sc.namespace)))
        if sc.with_wait:
            W = sc.W_failed if sc.failed_rollout else sc.W
            exit_code = 1 if sc.failed_rollout else 0
            wait_available = T(W) + 500
            wait = {"args": ["rollout", "status", f"deployment/{service}", "--timeout=120s"],
                    "collector_available_at": R.iso(wait_available), "exit_code": exit_code, "id": "change-wait",
                    "request_started_at": R.iso(T(sc.R) + 1500), "response_received_at": iso(W)}
            rows.append(_row(f"change:{sc.capture_id}:{service}:rollout-wait", "change_receipt",
                             {"semantics": "fixture rollout-wait receipt", "service": service,
                              "wait_exit_code": exit_code, "wait_receipt": wait}, wait_available,
                             _subject("Deployment", uid, sc.namespace),
                             supports=[f"change:{sc.capture_id}:{service}:patch"]))
    for k, t in enumerate(sc.requests, start=1):
        trace = f"trace-{sc.name}-{k:04d}"
        start_ns = T(t) * 1000
        span = {"parentSpanId": "", "startTimeUnixNano": str(start_ns), "endTimeUnixNano": str(start_ns + 10 ** 7),
                "kind": 3, "name": "pilot.ListRecommendations", "spanId": f"s{k:04d}", "traceId": trace}
        rows.append(_row(f"span:{trace}:s{k:04d}", "span_claim",
                         {"trace_id": trace, "span_id": f"s{k:04d}", "span": span,
                          "span_attributes": {"aiops.request.index": k},
                          "resource_attributes": {"service.name": "pilot-client"}}, T(t) + 20_000,
                         canonical(["span", trace])))
        rows.append(_row(f"client-target:{k}", "client_request",
                         {"block": "client-target", "request_index": k, "trace_id": trace},
                         T(t) + 30_000, canonical(["client", trace])))
    # a reference-block request with index 1, which the reader must ignore
    ref = f"trace-{sc.name}-ref"
    rows.append(_row(f"span:{ref}:r1", "span_claim",
                     {"trace_id": ref, "span_id": "r1", "span_attributes": {"aiops.request.index": 1},
                      "span": {"parentSpanId": "", "startTimeUnixNano": str(T(5.0) * 1000), "spanId": "r1"},
                      "resource_attributes": {"service.name": "pilot-client"}}, T(5.0) + 20_000,
                     canonical(["span", ref])))
    rows.append(_row("client-reference:1", "client_request", {"block": "client-reference", "request_index": 1,
                                                              "trace_id": ref}, T(5.0) + 30_000,
                     canonical(["client", ref])))
    if extra_rows is not None:
        rows.extend(extra_rows(sc))
    rows.sort(key=lambda r: (r["available_ns"], r["record"]["evidence_id"]))
    return list(enumerate(rows, start=1))


def scenario_inputs(sc: Scenario, *, extra_rows: Callable | None = None, extra_records=()) -> CaptureInputs:
    """The same pure parsing the decision reader applies to a capture's rows (no file access)."""
    rows = scenario_rows(sc, extra_rows=extra_rows)
    records, notes = records_from_rows(rows, f"fixture:{sc.name}")
    requests = requests_from_rows(rows)
    protocol = {"namespace": sc.namespace, "cluster_incarnation_id": INCARNATION, "capture_id": sc.capture_id,
                "incident_id": sc.name, "replacement_service": sc.changed_service, "request_trigger_index": None}
    return CaptureInputs(sc.capture_id, canonical(protocol), tuple(records) + tuple(extra_records), requests,
                         canonical(notes), f"fixture:{sc.name}")


def deployment_row(sc: Scenario, t: float, resource: dict, *, seq_suffix: str, snapshot: int | None = None,
                   available_offset_us: int = 500) -> dict:
    """An extra Deployment api_observation row (e.g. a contradictory same-instant sighting)."""
    collection = f"coll-{sc.name}"
    observed = T(t)
    available = observed + available_offset_us
    payload = {"_source_record_hash_semantics": "fixture", "_source_record_sha256": sha256_text(canonical(resource)),
               "available_at": R.iso(available), "clock_adjusted": False, "collection_id": collection,
               "confirmed_at": None, "known_open": False, "observation_basis": "snapshot_receipt",
               "observed_at": R.iso(observed), "record_id": f"{collection}/{seq_suffix}",
               "record_type": "resource_observation", "resource": "deployments", "resource_data": resource,
               "snapshot_id": f"{snapshot if snapshot is not None else int(t // 3):03d}-deployments",
               "valid_from": None, "valid_to": None, "validity_status": "unknown; fixture"}
    return _row(f"api:{collection}/{seq_suffix}", "api_observation", payload, available,
                _subject("Deployment", resource["metadata"]["uid"], sc.namespace))


def correction_of(record: InputRecord, *, available_at: int, resource_changes: dict, suffix: str = "corr") \
        -> InputRecord:
    """A later version of an api_observation record (same observed_at), ``corrects`` = the original."""
    payload = record.payload()
    resource = _apply_override(payload["resource_data"], resource_changes)
    payload["resource_data"] = resource
    payload["available_at"] = R.iso(available_at)
    payload["SIMULATED"] = "fixture correction"
    return replace(record, id=f"{record.id}#{suffix}", available_at=available_at, payload_json=canonical(payload),
                   corrects=record.id, simulated=True, source=record.source + f" ({suffix})")


# ---------------------------------------------------------------------------------------------------------------
# Ground truth (evaluation only)
# ---------------------------------------------------------------------------------------------------------------
def scenario_ground_truth(sc: Scenario) -> dict:
    """A ground_truth.json-shaped document with the fields the evaluator reads."""
    change = None
    if sc.changed_service:
        W = sc.W_failed if sc.failed_rollout else sc.W
        change = {"patch_request_started_at": iso(sc.P), "patch_response_received_at": iso(sc.R),
                  "rollout_reported_complete_at": iso(W) if sc.with_wait else None,
                  "service": sc.changed_service, "wait_exit_code": 1 if sc.failed_rollout else 0}
    fault_target = None
    if sc.fault == "changed":
        fault_target = {"service": sc.changed_service, "selected_by": "replacement_uid",
                        "pod_uid": _uid("pod", sc.changed_service, 2)}
    elif sc.fault == "other":
        other = next(s for s in SERVICES if s != sc.changed_service)
        fault_target = {"service": other, "selected_by": "newest_ready_pod", "pod_uid": _uid("pod", other, 1)}
    return {"EVALUATION_ONLY": "fixture ground truth", "capture_id": sc.capture_id,
            "observed": {"change": change, "fault_target": fault_target},
            "timeline_host": {"active_start": {"host_utc": iso(sc.active[0])},
                              "active_end": {"host_utc": iso(sc.active[1])}},
            "evaluation_summary": {"latency_effect_established": sc.effect if sc.fault != "none" else None},
            "planned": {"labels": {"fault_present": sc.fault != "none"}},
            "fixture_extra_u_windows": [[iso(a), iso(b), why] for a, b, why in sc.extra_u_windows]}


def write_capture(sc: Scenario, directory: Path, *, extra_rows: Callable | None = None,
                  kubectl_client: str = KUBECTL_CLIENT_PIN) -> Path:
    """A Phase-3-shaped capture directory, including the files the reader must never open and the runner's
    ``raw/kubectl-version.stdout`` (the pinned versions unless ``kubectl_client`` says otherwise)."""
    directory = Path(directory)
    evidence = directory / "evidence"
    (evidence / "evaluation_only").mkdir(parents=True)
    (directory / "ground_truth").mkdir()
    rows = scenario_rows(sc, extra_rows=extra_rows)
    with open(evidence / "accepted_evidence.jsonl", "w", encoding="utf-8", newline="\n") as handle:
        for _, row in rows:
            handle.write(canonical(row) + "\n")
    protocol = {"namespace": sc.namespace, "cluster_incarnation_id": INCARNATION, "capture_id": sc.capture_id,
                "incident_id": sc.name, "replacement_service": sc.changed_service, "request_trigger_index": None,
                "services": list(SERVICES) + ["pilot-client"]}
    (evidence / "protocol.json").write_text(json.dumps(protocol, indent=2) + "\n", encoding="utf-8")
    receipts = []
    patch_rows = [row for _, row in rows if row["record"]["kind"] == "change_receipt"
                  and "patch_receipt" in row["record"]["payload"]]
    if patch_rows:
        receipts.append(dict(patch_rows[0]["record"]["payload"]["patch_receipt"], id="rollout-patch"))
    (evidence / "capture.json").write_text(json.dumps({"run_id": sc.capture_id, "namespace": sc.namespace,
                                                       "started_at": iso(-60), "finished_at": iso(200),
                                                       "command_receipts": receipts}, indent=2) + "\n",
                                           encoding="utf-8")
    (evidence / "evaluation_only" / "incident_entry.json").write_text(
        json.dumps({"fault": {"service": "evaluation only"}}) + "\n", encoding="utf-8")
    (directory / "ground_truth" / "ground_truth.json").write_text(
        json.dumps(scenario_ground_truth(sc), indent=2) + "\n", encoding="utf-8")
    (directory / "capture.json").write_text(json.dumps({"capture_id": sc.capture_id}) + "\n", encoding="utf-8")
    (directory / "incident.json").write_text(json.dumps({"incident": {"id": sc.name}}) + "\n", encoding="utf-8")
    (directory / KUBECTL_VERSION_FILE).parent.mkdir(exist_ok=True)
    (directory / KUBECTL_VERSION_FILE).write_text(json.dumps(
        {"clientVersion": {"gitVersion": kubectl_client}, "kustomizeVersion": "fixture",
         "serverVersion": {"gitVersion": KUBERNETES_SERVER_PIN}}, indent=2) + "\n", encoding="utf-8")
    return directory


# ---------------------------------------------------------------------------------------------------------------
# The standard development set (run_dev.py)
# ---------------------------------------------------------------------------------------------------------------
STANDARD = {
    "fault": Scenario("fault"),                                            # relevant fault + rollout (GT-2 role)
    "benign": Scenario("benign", fault="none", effect=False),              # sham schedule, no worker
    "unrelated": Scenario("unrelated", changed_service="productcatalogservice", fault="other",
                          extra_u_windows=((39.5, 59.5, "catalog rollout disruption (fixture)"),)),
    "noeffect": Scenario("noeffect", effect=False),                        # effect not established -> U
    "failed": Scenario("failed", failed_rollout=True, conditions_recorded=True),
    "nochange": Scenario("nochange", changed_service=None, fault="other"),  # A never posed
}


def x1_records(kind: str, sc: Scenario) -> tuple[InputRecord, ...]:
    """Constructed (SIMULATED) freezes over [55, 90) s for the freeze-rule tests and the fixture run.

    ``intime``: declared and available at 50 s. ``X1a``: declared at the patch request P, shipped 150 s late.
    ``X1b``: declared (and available) at 100 s, after every decision it covers."""
    start, end = T(55.0), T(90.0)
    if kind == "intime":
        return (freeze_record("X1-intime", start, end, T(50.0), T(50.0)),)
    if kind == "X1a":
        return (freeze_record("X1a", start, end, T(sc.P), T(sc.P + 150.0)),)
    if kind == "X1b":
        return (freeze_record("X1b", start, end, T(100.0), T(100.0)),)
    raise KeyError(kind)
