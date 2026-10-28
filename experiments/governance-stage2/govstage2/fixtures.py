"""Fixtures: tiny hand-specified worlds written as converted follow-up captures, and the synthetic arm-G capture.

1. ``World`` + ``write_capture``: an invented namespace whose every object version is set by hand at a stated
   instant (seconds after ``BASE``), sampled by the three observers at stated instants and written in exactly the
   layout converter v4 writes (accepted_evidence.jsonl with configuration, poller api_observation, change_receipt,
   span_claim and client_request rows; stage2/ snapshot, event, list-object, live_recheck, clock_probe and K1-ready
   rows; evaluation_only/stage2/host_command.jsonl; the raw capture's capture.json, COMPLETE.txt and
   ground_truth/ground_truth.json). The rows go through the same readers as a real conversion. ``tiny_g2`` is the
   small end-to-end world of the tests and of ``--check``; the hand-computed unit tests build their own smaller worlds
   with the same API.

   Conventions (as the collectors and the converter write them): kubelet / API stamps are RFC 3339 whole seconds
   (floored); host receipts carry microseconds. Poller: one list per kind (pods at t, replicasets at t + 0.4 s,
   deployments at t + 0.8 s), each row available 0.5 ms after the previous one. Watch: one LIST at the first
   instant, then an event row 20 ms after every change (accepted 1 us later), a cache snapshot 2 us after every
   event and every second, every snapshot's rows available 10 us after it. Recheck: request started at the tick,
   x_R = start + 60 ms, accepted 1 us later; the objects are the state 30 ms after the start. Deletion: the API sets
   deletionTimestamp = the deletion request + the Pod's grace period (the manifests' terminationGracePeriodSeconds).

2. ``synthetic_arm_g``: converter v4's own synthetic G2 capture (phase3/convert_stage2.py build_synthetic_capture:
   every observer file written by the collectors' own code with fake clocks; a 3-replica rollout at T0 = 60 s and a
   container kill at T0 + 15 s), with what it lacks for the governance arm added before conversion: the
   applications manifest (both Deployments, their app labels, replicas and PDBs), a client-target block of 180
   requests (one every 0.75 s from 49 s) with OTLP spans (client root span, recommendationservice server span on a
   Ready replica chosen round-robin at t_k, catalog server span) exported with live trace-tail arrivals 0.8 s after
   t_k, and the client's streamed request lines. The converter (imported read-only) then converts it unchanged.

No randomness, no wall clock.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .common import ROOT, R, canonical, s_to_us, ts_us

BASE_US = ts_us("2026-10-19T12:00:00Z")
CLUSTER = "fixture-stage2-cluster"
NAMESPACE = "aiops-s2-fixture"
SERVICES = {"recommendationservice": {"replicas": 3, "grace": 20, "port": 8080},
            "productcatalogservice": {"replicas": 2, "grace": 5, "port": 3550}}
COLLECTIONS = {"poller": "fx000003-0000-4000-8000-000000000003", "watch": "fx000001-0000-4000-8000-000000000001",
               "recheck": "fx000002-0000-4000-8000-000000000002"}
KIND_ORDER = ("Pod", "Deployment", "ReplicaSet", "EndpointSlice", "PodDisruptionBudget")
RESOURCES = {"Pod": ("pods", "", "v1"), "ReplicaSet": ("replicasets", "apps", "apps/v1"),
             "Deployment": ("deployments", "apps", "apps/v1"),
             "EndpointSlice": ("endpointslices", "discovery.k8s.io", "discovery.k8s.io/v1"),
             "PodDisruptionBudget": ("poddisruptionbudgets", "policy", "policy/v1")}


def T(seconds: float) -> int:
    """Fixture time: seconds after BASE -> integer microseconds."""
    return BASE_US + s_to_us(seconds) if seconds >= 0 else BASE_US - s_to_us(-seconds)


def iso_us(seconds: float) -> str:
    return R.iso(T(seconds))


def iso9(us: int) -> str:
    """Nine-digit ISO, as the Stage-2 collectors write their receipts."""
    return R.iso(us)[:-1] + "000Z"


def stamp(seconds: float) -> str:
    """A kubelet / API-server stamp: whole seconds, floored."""
    us = T(seconds)
    return R.iso(us - us % 1_000_000)[:19] + "Z"


def sha(text) -> str:
    data = text if isinstance(text, bytes) else text.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def uid(key: str) -> str:
    """A deterministic UUID-shaped identifier for a fixture object."""
    digest = sha("fixture/" + key)
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


# ---------------------------------------------------------------------------------------------------------------
# Objects (the projected shapes of phase3/CAPTURE_FORMAT_STAGE2.md)
# ---------------------------------------------------------------------------------------------------------------
def _meta(p, rv, labels, owners=None, annotations=None, generation=None, deletion=None):
    meta = {"name": p["name"], "namespace": NAMESPACE, "uid": p["uid"], "resourceVersion": str(rv),
            "creationTimestamp": stamp(p["created"]), "labels": labels}
    if annotations:
        meta["annotations"] = annotations
    if generation is not None:
        meta["generation"] = generation
    if owners:
        meta["ownerReferences"] = owners
    if deletion is not None:
        meta["deletionTimestamp"] = deletion
    return meta


def build_pod(p: dict, rv: int) -> dict:
    owners = [{"apiVersion": "apps/v1", "blockOwnerDeletion": True, "controller": True, "kind": "ReplicaSet",
               "name": p["rs_name"], "uid": p["rs_uid"]}]
    deletion = None if p.get("deleting") is None else stamp(p["deleting"] + SERVICES[p["app"]]["grace"])
    meta = _meta(p, rv, {"app": p["app"], "pod-template-hash": p["hash"]}, owners, deletion=deletion)
    ready = "True" if p["ready"] else "False"
    container = {"name": "server", "image": "fixture/" + p["app"], "ready": p["ready"],
                 "restartCount": p.get("restarts", 0)}
    if p.get("started") is not None:
        container["state"] = {"running": {"startedAt": stamp(p["started"])}}
    else:
        container["state"] = {"waiting": {"reason": "ContainerCreating"}}
    if p.get("last_finished") is not None:
        container["lastState"] = {"terminated": {"exitCode": 137, "reason": "Error",
                                                 "startedAt": stamp(p.get("last_started", p["created"])),
                                                 "finishedAt": stamp(p["last_finished"])}}
    else:
        container["lastState"] = {}
    status = {"phase": p.get("phase", "Running"), "startTime": stamp(p["created"]),
              "conditions": [{"type": "Ready", "status": ready, "lastProbeTime": None,
                              "lastTransitionTime": stamp(p["ready_since"])},
                             {"type": "ContainersReady", "status": ready, "lastProbeTime": None,
                              "lastTransitionTime": stamp(p["ready_since"])}],
              "containerStatuses": [container]}
    if p.get("ip"):
        status["podIP"] = p["ip"]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta,
            "spec": {"nodeName": "fixture-node", "containers": [{"name": "server", "image": "fixture/" + p["app"]}],
                     "initContainers": []}, "status": status}


def build_replicaset(p: dict, rv: int) -> dict:
    owners = [{"apiVersion": "apps/v1", "blockOwnerDeletion": True, "controller": True, "kind": "Deployment",
               "name": p["app"], "uid": p["dep_uid"]}]
    meta = _meta(p, rv, {"app": p["app"], "pod-template-hash": p["hash"]}, owners,
                 {"deployment.kubernetes.io/revision": p["revision"]}, generation=p.get("generation", 1))
    status = {"observedGeneration": p.get("generation", 1), "replicas": p["replicas"]}
    if p.get("ready"):
        status.update(readyReplicas=p["ready"], availableReplicas=p["ready"])
    return {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": meta,
            "spec": {"replicas": p["replicas"], "selector": {"matchLabels": {"app": p["app"],
                                                                             "pod-template-hash": p["hash"]}}},
            "status": status}


def build_deployment(p: dict, rv: int) -> dict:
    meta = _meta(p, rv, {"app": p["name"]}, annotations={"deployment.kubernetes.io/revision": p["revision"]},
                 generation=p["generation"])
    status = {"observedGeneration": p["observed"], "replicas": p["status_replicas"], "updatedReplicas": p["updated"],
              "readyReplicas": p["ready"], "availableReplicas": p["available"],
              "conditions": [{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable",
                              "lastUpdateTime": stamp(p["created"] + 5), "lastTransitionTime": stamp(p["created"] + 5)},
                             {"type": "Progressing", "status": "True", "reason": p["progressing"],
                              "lastUpdateTime": stamp(p["progressing_since"]),
                              "lastTransitionTime": stamp(p["created"])}]}
    if p.get("unavailable"):
        status["unavailableReplicas"] = p["unavailable"]
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta,
            "spec": {"replicas": p["replicas"], "selector": {"matchLabels": {"app": p["name"]}},
                     "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}}},
            "status": status}


def build_endpointslice(p: dict, rv: int) -> dict:
    owners = [{"apiVersion": "v1", "blockOwnerDeletion": True, "controller": True, "kind": "Service",
               "name": p["service"], "uid": uid("svc-" + p["service"])}]
    meta = _meta(p, rv, {"kubernetes.io/service-name": p["service"]}, owners)
    return {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "metadata": meta, "addressType": "IPv4",
            "endpoints": [dict(e) for e in p["endpoints"]],
            "ports": [{"name": "grpc", "port": SERVICES[p["service"]]["port"], "protocol": "TCP"}]}


def build_pdb(p: dict, rv: int) -> dict:
    meta = _meta(p, rv, {"app": p["app"]}, generation=1)
    return {"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": meta,
            "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": p["app"]}}},
            "status": {"observedGeneration": 1, "disruptionsAllowed": p["allowed"], "currentHealthy": p["healthy"],
                       "desiredHealthy": p["desired"], "expectedPods": p["expected"]}}


BUILDERS = {"Pod": build_pod, "ReplicaSet": build_replicaset, "Deployment": build_deployment,
            "EndpointSlice": build_endpointslice, "PodDisruptionBudget": build_pdb}


# ---------------------------------------------------------------------------------------------------------------
# The world: object versions over time
# ---------------------------------------------------------------------------------------------------------------
class World:
    """Every change is (t, sequence, key, kind, object or None for a deletion); the state at t is the latest version
    of every object changed at or before t and not deleted."""

    def __init__(self):
        self.params: dict = {}
        self.changes: list = []
        self.rv = 1000

    def put(self, t: float, key: str, kind: str | None = None, **changes):
        if key in self.params:
            kind = self.params[key][0]
            params = dict(self.params[key][1])
        else:
            params = {}
        params.update(changes)
        params.setdefault("uid", uid(key))
        self.params[key] = (kind, params)
        self.rv += 1
        self.changes.append((t, len(self.changes), key, kind, BUILDERS[kind](params, self.rv)))
        self.changes.sort(key=lambda c: (c[0], c[1]))

    def delete(self, t: float, key: str):
        kind, _ = self.params[key]
        self.rv += 1
        self.changes.append((t, len(self.changes), key, kind, None))
        self.changes.sort(key=lambda c: (c[0], c[1]))

    def state(self, t: float, kinds=None) -> list[tuple[str, dict]]:
        current = {}
        for when, _, key, kind, obj in self.changes:
            if when > t:
                break
            if kinds is not None and kind not in kinds:
                continue
            if obj is None:
                current.pop(key, None)
            else:
                current[key] = obj
        return sorted(current.items(), key=lambda item: (KIND_ORDER.index(item[1]["kind"]),
                                                         item[1]["metadata"]["name"]))

    def obj(self, key: str, t: float):
        for k, o in self.state(t):
            if k == key:
                return o
        return None

    def pods_of(self, service: str, t: float) -> list[tuple[str, dict]]:
        return [(k, o) for k, o in self.state(t, ("Pod",)) if o["metadata"]["labels"]["app"] == service]

    def refresh_slice(self, t: float, service: str):
        """The EndpointSlice the controller derives from the service's Pods at t."""
        endpoints = []
        for _, pod in self.pods_of(service, t):
            ip = pod["status"].get("podIP")
            if not ip:
                continue
            terminating = "deletionTimestamp" in pod["metadata"]
            ready = pod["status"]["containerStatuses"][0]["ready"] and not terminating
            endpoints.append({"addresses": [ip], "conditions": {"ready": ready, "serving": ready,
                                                                  "terminating": terminating},
                              "targetRef": {"kind": "Pod", "name": pod["metadata"]["name"],
                                            "uid": pod["metadata"]["uid"], "namespace": NAMESPACE}})
        self.put(t, "eps-" + service, "EndpointSlice", name=service + "-eps", service=service, created=-500.0,
                 endpoints=endpoints)


def pod(world: World, t: float, key: str, service: str, rs_key: str, **fields):
    rs = world.params[rs_key][1]
    defaults = {"name": f"{rs['name']}-{key.split('-')[-1] * 5}", "app": service, "rs_name": rs["name"],
                "rs_uid": rs["uid"], "hash": rs["hash"]}
    if key not in world.params:
        world.put(t, key, "Pod", **{**defaults, **fields})
    else:
        world.put(t, key, **fields)


# ---------------------------------------------------------------------------------------------------------------
# Observers -> converted rows
# ---------------------------------------------------------------------------------------------------------------
def _row(evidence_id: str, kind: str, payload: dict, available_us: int, subject: str, source_ref: str) -> dict:
    record = {"acquired_at": iso9(available_us), "evidence_id": evidence_id, "kind": kind, "logical_id": evidence_id,
              "payload": payload, "source_ref": source_ref, "source_sha256": sha(source_ref), "subject": subject,
              "supersedes": [], "supports": []}
    return {"available_ns": available_us * 1000, "logical_confirmation_ns": available_us * 1000, "record": record}


def _subject(kind: str, object_uid: str) -> str:
    return canonical([CLUSTER, RESOURCES[kind][1], kind, NAMESPACE, object_uid])


@dataclass
class Observers:
    """When each observer looks (seconds after BASE)."""
    poller_lists: tuple = ()
    poller_kinds: tuple = ("Pod", "ReplicaSet", "Deployment")
    watch_start: float | None = None
    watch_snapshots: tuple = ()          # periodic snapshot instants
    watch_stop: float | None = None
    recheck_ticks: tuple = ()
    clock_offset_s: float = 0.0          # host - node
    clock_halfwidth_s: float = 0.25      # probe send/receive are node -/+ this (band = 1 s + widest bound)


@dataclass
class Plan:
    scenario: str = "G2"
    changed_service: str = "recommendationservice"
    P: float | None = None
    R: float | None = None
    W: float | None = None
    requests: tuple = ()                 # (k, t_k, serving pod key, acquisition delay s)
    fault: dict | None = None            # ground truth: {"service", "pod_key", "selected_by", "active": (s, e),
    #                                      "effect": bool | None, "kill": (start, end) | None}
    valid: bool = True


def poller_rows(world: World, obs: Observers) -> tuple[list, list]:
    rows, k1 = [], []
    collection = COLLECTIONS["poller"]
    seq = 0
    offsets = {"Pod": 0.0, "ReplicaSet": 0.4, "Deployment": 0.8}
    for n, t0 in enumerate(obs.poller_lists):
        for kind in obs.poller_kinds:
            t = t0 + offsets[kind]
            resource = RESOURCES[kind][0]
            for i, (_, o) in enumerate(world.state(t, (kind,))):
                seq += 1
                observed = T(t)
                available = observed + 500 * (i + 1)
                payload = {"_source_record_hash_semantics": "fixture", "_source_record_sha256": sha(canonical(o)),
                           "available_at": R.iso(available), "clock_adjusted": False, "collection_id": collection,
                           "collector": "collect_deployment_history_v1_1", "confirmed_at": None, "known_open": False,
                           "observation_basis": "snapshot_receipt", "observed_at": R.iso(observed),
                           "record_id": f"{collection}/{seq}", "record_type": "resource_observation",
                           "resource": resource, "resource_data": o, "snapshot_id": f"{n:03d}-{resource}",
                           "valid_from": None, "valid_to": None, "validity_status": "unknown; fixture"}
                evidence_id = f"api:{collection}/{seq}"
                rows.append(_row(evidence_id, "api_observation", payload, available, _subject(kind, o["metadata"]["uid"]),
                                 f"fixture/context/observations.jsonl#L{seq}"))
                if kind == "Pod":
                    k1.append({"record_id": evidence_id, "observer": "poller", "collector": "collect_deployment_history_v1_1",
                               "collection_id": collection, "observation_basis": "snapshot_receipt",
                               "event_type": None, "observed_at": R.iso(observed), "observed_at_ns": observed * 1000,
                               "available_at": R.iso(available), "available_at_ns": available * 1000,
                               "pod_uid": o["metadata"]["uid"], "pod_name": o["metadata"]["name"], "pod": o,
                               "source_record": f"{collection}/{seq}",
                               "source_ref": f"fixture/context/observations.jsonl#L{seq}"})
    return rows, k1


def watch_rows(world: World, obs: Observers) -> dict:
    """Event and list-object rows (every kind), cache-snapshot rows (every kind), K1-ready Pod rows."""
    out = {"events": [], "lists": [], "snapshots": [], "k1": []}
    if obs.watch_start is None:
        return out
    collection = COLLECTIONS["watch"]
    seq = [0]

    def next_seq():
        seq[0] += 1
        return seq[0]

    cache: dict = {}
    snapshot_index = [0]

    def snapshot(at: float, trigger: str):
        snapshot_index[0] += 1
        s = next_seq()
        snap_us = T(at)
        available = snap_us + 10
        for key in sorted(cache, key=lambda k: (KIND_ORDER.index(cache[k][0]["kind"]), cache[k][0]["metadata"]["name"])):
            o, ref = cache[key]
            payload = {"record_type": "resource_observation", "observation_basis": "watch_cache_snapshot",
                       "collector": "watch-v1", "collection_id": collection, "snapshot_id": f"{collection}/{s}",
                       "snapshot_sequence": s, "snapshot_index": snapshot_index[0], "snapshot_trigger": trigger,
                       "snapshot_at": iso9(snap_us), "snapshot_at_ns": snap_us * 1000, "observed_at": iso9(snap_us),
                       "available_at": iso9(available), "available_at_ns": available * 1000, "clock_adjusted": False,
                       "resource": RESOURCES[o["kind"]][0], "resource_data": o, "source_record": f"{collection}/{ref}",
                       "source_record_sequence": ref}
            out["snapshots"].append(_row(f"watchsnap:{collection}/{s}/{o['metadata']['uid']}", "api_observation",
                                         payload, available, _subject(o["kind"], o["metadata"]["uid"]),
                                         f"fixture/context/watch_snapshots.jsonl#S{s}"))

    def carrier(kind_name, o, received_us, event_type):
        s = next_seq()
        available = received_us + 1
        evidence = ("watchlist:" if kind_name == "list" else "watch:") + f"{collection}/{s}"
        payload = {"record_type": "watch_list_object" if kind_name == "list" else "api_watch_event",
                   "observation_basis": "watch_list" if kind_name == "list" else "watch_event",
                   "collector": "watch-v1", "collection_id": collection, "record_id": f"{collection}/{s}",
                   "sequence": s, "event_type": event_type, "resource": RESOURCES[o["kind"]][0],
                   "uid": o["metadata"]["uid"], "resource_version": o["metadata"]["resourceVersion"],
                   "resource_data": o, "observed_at": iso9(received_us), "available_at": iso9(available),
                   "available_at_ns": available * 1000}
        key = "lists" if kind_name == "list" else "events"
        out[key].append(_row(evidence, "api_watch_list_object" if kind_name == "list" else "api_watch_event", payload,
                             available, _subject(o["kind"], o["metadata"]["uid"]),
                             f"fixture/context/watch_events.jsonl#S{s}"))
        if o["kind"] == "Pod":
            out["k1"].append({"record_id": evidence, "observer": "watch", "collector": "watch-v1",
                              "collection_id": collection,
                              "observation_basis": payload["observation_basis"], "event_type": event_type,
                              "observed_at": iso9(received_us), "observed_at_ns": received_us * 1000,
                              "available_at": iso9(available), "available_at_ns": available * 1000,
                              "pod_uid": o["metadata"]["uid"], "pod_name": o["metadata"]["name"], "pod": o,
                              "source_record": f"{collection}/{s}",
                              "source_ref": f"fixture/context/watch_events.jsonl#S{s}"})
        return s

    start = obs.watch_start
    listed_us = T(start)
    for key, o in world.state(start):
        cache[key] = (o, carrier("list", o, listed_us, None))
    snapshot(start + 0.000002, "list")
    events = [(t, n, key, kind, o) for t, n, key, kind, o in world.changes if t > start
              and (obs.watch_stop is None or t + 0.02 <= obs.watch_stop)]
    periodic = [t for t in obs.watch_snapshots if t > start]
    timeline = sorted([(t + 0.02, 0, n, key, kind, o) for t, n, key, kind, o in events]
                      + [(t, 1, i, None, None, None) for i, t in enumerate(periodic)], key=lambda x: (x[0], x[1], x[2]))
    for when, typ, _, key, kind, o in timeline:
        if typ == 1:
            snapshot(when, "periodic")
            continue
        if o is None:
            previous = cache.pop(key)[0]
            carrier("event", previous, T(when), "DELETED")
        else:
            cache[key] = (o, carrier("event", o, T(when), "ADDED" if key not in cache else "MODIFIED"))
        snapshot(when + 0.000002, "event")
    return out


def recheck_rows(world: World, obs: Observers) -> tuple[list, list]:
    rows, k1 = [], []
    collection = COLLECTIONS["recheck"]
    order = {"Pod": 0, "Deployment": 1, "ReplicaSet": 2, "EndpointSlice": 3, "PodDisruptionBudget": 4}
    for tick, t in enumerate(obs.recheck_ticks):
        started = T(t)
        x_r = started + 60_000
        available = x_r + 1
        objects = [o for _, o in world.state(t + 0.03)]
        objects.sort(key=lambda o: (order[o["kind"]], o["metadata"]["name"], o["metadata"]["uid"]))
        evidence = f"recheck:{collection}/{tick}"
        payload = {"record_type": "live_recheck", "status": "answered", "answered": True, "tick": tick,
                   "collector": "recheck-v1", "collection_id": collection, "record_id": f"{collection}/{tick + 1}",
                   "scheduled_at": iso9(started), "request_started_at": iso9(started),
                   "request_started_at_ns": started * 1000, "response_received_at": iso9(x_r),
                   "response_received_at_ns": x_r * 1000, "observed_at": iso9(x_r), "available_at": iso9(available),
                   "available_at_ns": available * 1000, "objects": objects, "object_count": len(objects),
                   "gets": [{"resource": r, "outcome": "ok"} for r in ("deployments", "replicasets", "pods",
                                                                       "endpointslices", "poddisruptionbudgets")],
                   "observation_basis": "live_recheck"}
        rows.append(_row(evidence, "live_recheck", payload, available,
                         canonical([CLUSTER, "aiops.project", "LiveRecheck", NAMESPACE, collection]),
                         f"fixture/context/recheck.jsonl#L{tick + 1}"))
        for o in objects:
            if o["kind"] != "Pod":
                continue
            k1.append({"record_id": f"{evidence}#{o['metadata']['uid']}", "observer": "recheck",
                       "collector": "recheck-v1", "collection_id": collection, "observation_basis": "live_recheck",
                       "event_type": None, "observed_at": iso9(x_r), "observed_at_ns": x_r * 1000,
                       "available_at": iso9(available), "available_at_ns": available * 1000,
                       "pod_uid": o["metadata"]["uid"], "pod_name": o["metadata"]["name"], "pod": o,
                       "source_record": f"{collection}/{tick + 1}", "tick": tick,
                       "source_ref": f"fixture/context/recheck.jsonl#L{tick + 1}"})
    return rows, k1


def clock_documents(obs: Observers, at: tuple = (-5.0, 60.0)) -> list:
    """Ten readings per document; node = host - offset; send/receive = node + offset -/+ halfwidth."""
    docs = []
    for label, t in zip(("start", "end"), at):
        pairs = []
        for i in range(10):
            host = T(t + 0.5 * i) * 1000
            node = host - s_to_us(obs.clock_offset_s) * 1000 if obs.clock_offset_s >= 0 else \
                host + s_to_us(-obs.clock_offset_s) * 1000
            half = s_to_us(obs.clock_halfwidth_s) * 1000
            pairs.append({"send_ns": host - half, "node_ns": node, "receive_ns": host + half, "exit_code": 0})
        docs.append({"label": label, "pairs": pairs, "test": "fixture clock probe"})
    return docs


def configuration_payload(plan: Plan, world: World) -> dict:
    items = []
    for service, spec in SERVICES.items():
        items.append({"apiVersion": "apps/v1", "kind": "Deployment",
                      "metadata": {"name": service, "labels": {"app": service}},
                      "spec": {"replicas": spec["replicas"], "template": {
                          "metadata": {"labels": {"app": service}},
                          "spec": {"terminationGracePeriodSeconds": spec["grace"],
                                   "containers": [{"name": "server", "image": "fixture/" + service}]}}}})
        items.append({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
                      "metadata": {"name": service, "labels": {"app": service}},
                      "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": service}}}})
    incident = {"id": plan.scenario, "runnable": True}
    if plan.changed_service:
        incident["change"] = {"service": plan.changed_service, "kind": "rollout", "at": "T0"}
    return {"acquisition_semantics": "fixture", "deployment_manifests": {
        "applications.json": {"apiVersion": "v1", "kind": "List", "items": items}}, "incident": incident,
        "rollout_patch": {"spec": {"template": {"metadata": {"annotations": {"aiops.project/revision": "2"}}}}},
        "source_sha256": None}


def change_rows(plan: Plan, world: World, capture_id: str) -> list:
    rows = []
    if not plan.changed_service or plan.P is None:
        return rows
    service = plan.changed_service
    dep_uid = world.params["dep-" + service][1]["uid"]
    subject = _subject("Deployment", dep_uid)
    patch_available = T(plan.R) + 500
    patch = {"args": ["patch", "deployment", service, "--type=merge", "--patch-file", "rollout-patch.json", "-o",
                      "json"], "collector_available_at": R.iso(patch_available), "exit_code": 0, "id": "change-patch",
             "request_started_at": iso_us(plan.P), "response_received_at": iso_us(plan.R)}
    rows.append(_row(f"change:{capture_id}:{service}:patch", "change_receipt",
                     {"deployment_uid": dep_uid, "patch_receipt": patch, "service": service,
                      "semantics": "fixture patch receipt"}, patch_available, subject,
                     f"{capture_id}/capture.json#change-patch"))
    if plan.W is not None:
        wait_available = T(plan.W) + 500
        wait = {"args": ["rollout", "status", f"deployment/{service}", "--timeout=120s"],
                "collector_available_at": R.iso(wait_available), "exit_code": 0, "id": "change-wait",
                "request_started_at": R.iso(T(plan.R) + 1500), "response_received_at": iso_us(plan.W)}
        rows.append(_row(f"change:{capture_id}:{service}:rollout-wait", "change_receipt",
                         {"service": service, "wait_exit_code": 0, "wait_receipt": wait,
                          "semantics": "fixture rollout-wait receipt"}, wait_available, subject,
                         f"{capture_id}/capture.json#change-wait"))
    return rows


def span_rows(plan: Plan, world: World, capture_id: str) -> list:
    """Per request: the client root span (pilot-client, aiops.request.index) and one server span (kind 2) per
    service; the server spans carry the serving Pod's k8s.pod.uid; every span row is acquired at t_k + delay."""
    rows = []
    for k, t_k, serving, delay in plan.requests:
        trace = sha(f"{capture_id}/trace/{k}")[:32]
        acquired = T(t_k + delay)
        spans = [("pilot-client", None, 3, f"c{k:04d}", None, t_k, t_k + 0.02)]
        for service, pod_key in sorted(serving.items()):
            pod_uid = world.params[pod_key][1]["uid"] if pod_key else None
            spans.append((service, pod_uid, 2, f"{service[:3]}{k:04d}", f"c{k:04d}", t_k + 0.002, t_k + 0.015))
        for service, pod_uid, kind, span_id, parent, start, end in spans:
            span = {"traceId": trace, "spanId": span_id, "kind": kind, "name": f"{service}.call",
                    "startTimeUnixNano": str(T(start) * 1000), "endTimeUnixNano": str(T(end) * 1000)}
            if parent:
                span["parentSpanId"] = parent
            attributes = {"service.name": service}
            if pod_uid:
                attributes["k8s.pod.uid"] = pod_uid
            payload = {"trace_id": trace, "span_id": span_id, "span": span, "resource_attributes": attributes,
                       "span_attributes": {"aiops.request.index": k} if parent is None else {}}
            rows.append(_row(f"span:{trace}:{span_id}", "span_claim", payload, acquired,
                             canonical([CLUSTER, "", "Pod", NAMESPACE, pod_uid or "unknown-pod"]),
                             f"{capture_id}/raw/trace-export.stdout#{k}"))
        rows.append(_row(f"client-target:{k}", "client_request",
                         {"block": "client-target", "request_index": k, "trace_id": trace, "record_type":
                          "client_request"}, T(t_k) + 30_000, canonical([CLUSTER, "client", trace]),
                         f"{capture_id}/raw/client-target.stdout#L{k}"))
    return rows


def _write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda r: (r["available_ns"], r["record"]["evidence_id"])) \
        if rows and "available_ns" in rows[0] else rows
    with open(path, "xb") as handle:
        for row in rows:
            handle.write((canonical(row) + "\n").encode("utf-8"))


def write_capture(target, world: World, obs: Observers, plan: Plan, *, capture_id: str = "FX-G2-001") -> Path:
    """Write the raw capture skeleton (capture.json, COMPLETE.txt, ground_truth/) at ``target`` and the converted
    layout at ``target/evidence``; returns the converted directory."""
    target = Path(target)
    converted = target / "evidence"
    if target.exists():
        raise FileExistsError(target)
    converted.mkdir(parents=True)
    config = configuration_payload(plan, world)
    accepted = [_row(f"configuration:{sha(canonical(config))}", "configuration", config, T(-30.0),
                     canonical([CLUSTER, "aiops.project", "Configuration", NAMESPACE, sha(canonical(config))]),
                     f"{capture_id}/manifests")]
    poller, k1_poller = poller_rows(world, obs)
    accepted += poller + change_rows(plan, world, capture_id) + span_rows(plan, world, capture_id)
    _write_jsonl(converted / "accepted_evidence.jsonl", accepted)
    protocol = {"namespace": NAMESPACE, "cluster_incarnation_id": CLUSTER, "capture_id": capture_id,
                "incident_id": plan.scenario, "replacement_service": plan.changed_service,
                "request_trigger_index": None, "services": list(SERVICES) + ["pilot-client"]}
    (converted / "protocol.json").write_text(json.dumps(protocol, indent=2) + "\n", encoding="utf-8")
    watch = watch_rows(world, obs)
    _write_jsonl(converted / "stage2/api_observation.watch_cache_snapshot.jsonl", watch["snapshots"])
    _write_jsonl(converted / "stage2/api_watch_event.jsonl", watch["events"])
    _write_jsonl(converted / "stage2/api_watch_list_object.jsonl", watch["lists"])
    recheck, k1_recheck = recheck_rows(world, obs)
    _write_jsonl(converted / "stage2/live_recheck.jsonl", recheck)
    clock = [_row(f"clock:{capture_id}:{d['label']}", "clock_probe", d, max(p["receive_ns"] for p in d["pairs"]) // 1000,
                  canonical([CLUSTER, "aiops.project", "ClockProbe", NAMESPACE, d["label"]]),
                  f"{capture_id}/context/clock_probes.json#{i}") for i, d in enumerate(clock_documents(obs))]
    _write_jsonl(converted / "stage2/clock_probe.jsonl", clock)
    for observer, rows in (("poller", k1_poller), ("watch", watch["k1"]), ("recheck", k1_recheck)):
        path = converted / f"stage2/k1_pod_records.{observer}.jsonl"
        with open(path, "xb") as handle:
            for row in rows:
                handle.write((canonical(row) + "\n").encode("utf-8"))
    kills = []
    if plan.fault and plan.fault.get("kill"):
        start, end = plan.fault["kill"]
        receipt = {"id": "kill-001", "kind": "host_command", "executed": True, "exit_code": 0,
                   "args": ["docker", "--context", "desktop-linux", "exec", "fixture-node", "crictl", "stop",
                            "--timeout", "0", "abc123def456abc123"],
                   "request_started_at": iso_us(start), "response_received_at": iso_us(end),
                   "collector_available_at": iso_us(end + 0.001)}
        kills.append(_row(f"host:{capture_id}:kill-001", "host_command", receipt, T(end + 0.001),
                          canonical([CLUSTER, "aiops.project", "HostCommand", NAMESPACE, "kill-001"]),
                          f"{capture_id}/ground_truth/raw/kill-001.receipt.json"))
    _write_jsonl(converted / "evaluation_only/stage2/host_command.jsonl", kills)
    (converted / "stage2_manifest.json").write_text(json.dumps({"converter": "fixture (govstage2.fixtures)",
                                                                "capture_id": capture_id}, indent=2) + "\n",
                                                    encoding="utf-8")
    # the raw capture: validity fields and ground truth
    (target / "COMPLETE.txt").write_text("status=finished\nfixture=true\n" if plan.valid else
                                         "status=failed\nfixture=true\n", encoding="utf-8")
    doc = {"capture_id": capture_id, "incident_id": plan.scenario, "namespace": NAMESPACE,
           "validity": {"valid": plan.valid, "reasons": [] if plan.valid else ["fixture: invalid"]}}
    (target / "capture.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (target / "ground_truth").mkdir()
    fault = plan.fault or {}
    truth = {"EVALUATION_ONLY": "fixture ground truth", "capture_id": capture_id,
             "planned": {"labels": {"fault_present": bool(fault)}},
             "observed": {"change": None if plan.P is None else {
                 "patch_request_started_at": iso_us(plan.P), "patch_response_received_at": iso_us(plan.R),
                 "rollout_reported_complete_at": iso_us(plan.W) if plan.W is not None else None,
                 "service": plan.changed_service, "wait_exit_code": 0},
                 "fault_target": None if not fault else {
                     "service": fault["service"], "pod_uid": world.params[fault["pod_key"]][1]["uid"],
                     "selected_by": fault.get("selected_by", "random_ready_replica")}},
             "timeline_host": {} if not fault else {"active_start": {"host_utc": iso_us(fault["active"][0])},
                                                    "active_end": {"host_utc": iso_us(fault["active"][1])}},
             "evaluation_summary": None if not fault else {"latency_effect_established": fault.get("effect")}}
    (target / "ground_truth" / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    return converted


CHECK_GRID = {"knowledge_cutoff_offsets_seconds": [0], "dispatch_delays_seconds": {"D": [0], "G": [0, 10]}}


def check_plan() -> dict:
    """The plan of ``--check`` and of the end-to-end tests: phase3/stage2_plan.json with Delta = {0} s and, in arm
    G, delta = {0, 10} s (every condition, both streams, both actions)."""
    return fixture_plan(**CHECK_GRID)


def write_check_fixture(target) -> tuple[Path, Path]:
    """tiny_g2 written as a capture under ``target`` plus the narrowed plan beside it: (converted dir, plan path)."""
    target = Path(target)
    world, obs, plan = tiny_g2()
    converted = write_capture(target / "FX-G2-001", world, obs, plan)
    plan_path = target / "fixture_plan.json"
    plan_path.write_text(json.dumps(check_plan(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return converted, plan_path


def fixture_plan(scenario_overrides: dict | None = None, **posing) -> dict:
    """The capture plan (phase3/stage2_plan.json, read-only) with the posing grid optionally narrowed."""
    plan = json.loads((ROOT / "phase3/stage2_plan.json").read_text(encoding="utf-8"))
    for key, value in posing.items():
        plan["posing"][key] = value
    for path, value in (scenario_overrides or {}).items():
        node = plan
        *head, last = path.split("/")
        for part in head:
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[last] = value
    return plan


# ---------------------------------------------------------------------------------------------------------------
# The standard worlds
# ---------------------------------------------------------------------------------------------------------------
def base_world() -> World:
    """Two services before any change: recommendationservice 3 replicas (rec-a/b/c, revision 1), catalog 2."""
    w = World()
    for service, replicas in (("recommendationservice", 3), ("productcatalogservice", 2)):
        short = service[:3]
        w.put(-500.0, "dep-" + service, "Deployment", name=service, created=-600.0, generation=1, observed=1,
              revision="1", replicas=replicas, status_replicas=replicas, updated=replicas, ready=replicas,
              available=replicas, unavailable=0, progressing="NewReplicaSetAvailable", progressing_since=-595.0)
        w.put(-500.0, f"rs-{short}-1", "ReplicaSet", name=f"{service}-{short}h1", app=service, hash=f"{short}h1",
              dep_uid=w.params["dep-" + service][1]["uid"], revision="1", created=-600.0, replicas=replicas,
              ready=replicas, generation=1)
        w.put(-500.0, "pdb-" + service, "PodDisruptionBudget", name=service, app=service, created=-600.0,
              allowed=1, healthy=replicas, desired=replicas - 1, expected=replicas)
    for key, service, rs, ip in (("rec-a", "recommendationservice", "rs-rec-1", "10.0.0.11"),
                                 ("rec-b", "recommendationservice", "rs-rec-1", "10.0.0.12"),
                                 ("rec-c", "recommendationservice", "rs-rec-1", "10.0.0.13"),
                                 ("cat-a", "productcatalogservice", "rs-pro-1", "10.0.0.31"),
                                 ("cat-b", "productcatalogservice", "rs-pro-1", "10.0.0.32")):
        pod(w, -500.0, key, service, rs, created=-599.0, started=-598.0, ready=True, ready_since=-590.0, ip=ip,
            restarts=0, phase="Running")
    w.refresh_slice(-499.0, "recommendationservice")
    w.refresh_slice(-499.0, "productcatalogservice")
    return w


def tiny_g2() -> tuple[World, Observers, Plan]:
    """The end-to-end fixture (``--check`` and the determinism test): a 3-replica rollout at P = 10 s with one
    container kill mid-rollout, five requests. Timeline (s after BASE):

    10.0 patch request P; 10.1 Deployment generation 2; 10.15 observed, revision 2, new ReplicaSet rs-rec-2 (created
    10.15); 10.2 patch response R. Step 1: rec-d created 10.2, running 11.0, Ready 13.0; rec-a deleting 13.1 (Ready
    False), gone 14.0. Step 2: rec-e created 13.2, running 14.0, Ready 16.0; rec-b deleting 16.1, gone 17.0. Kill:
    rec-d's container killed at 15.0 (Ready False since 15, reported 15.4); restarted 16.0 (restartCount 1,
    lastState.terminated.finishedAt 15); Ready again 18.0 (reported 18.3). Step 3: rec-f created 16.2, running 17.0,
    Ready 19.0; rec-c deleting 19.1, gone 20.0; Deployment complete 19.2; rollout wait returns W = 19.5.
    Requests k = 1..5 at t_k = 9, 12, 15.5, 18.5, 24 s, served by rec-a, rec-b, rec-c, rec-e, rec-f (spans acquired
    t_k + 1 s). Poller lists every 2 s from 0 to 40 s; watch from 0.1 s, snapshots every second at .3; recheck ticks
    every second from 8 to 40 s. Clock band 1.25 s. The kill's host command ran 14.9-15.05 s."""
    w = base_world()
    rec = "recommendationservice"
    dep = "dep-" + rec
    w.put(10.1, dep, generation=2)
    w.put(10.15, dep, observed=2, revision="2", status_replicas=4, updated=1, unavailable=1,
          progressing="ReplicaSetUpdated", progressing_since=10.15)
    w.put(10.15, "rs-rec-2", "ReplicaSet", name=f"{rec}-rech2", app=rec, hash="rech2",
          dep_uid=w.params[dep][1]["uid"], revision="2", created=10.15, replicas=1, ready=0, generation=1)
    steps = (("rec-d", "10.0.0.21", 10.2, "rec-a", 1), ("rec-e", "10.0.0.22", 13.2, "rec-b", 2),
             ("rec-f", "10.0.0.23", 16.2, "rec-c", 3))
    for key, ip, start, old, number in steps:
        pod(w, start, key, rec, "rs-rec-2", created=start, ready=False, ready_since=start, phase="Pending",
            restarts=0)
        pod(w, start + 0.8, key, rec, "rs-rec-2", phase="Running", started=start + 0.8, ip=ip)
        pod(w, start + 2.8, key, rec, "rs-rec-2", ready=True, ready_since=start + 2.8)
        w.refresh_slice(start + 2.85, rec)
        w.put(start + 2.86, "rs-rec-2", ready=number, replicas=min(3, number + (number < 3)),
              generation=1 + number)
        w.put(start + 2.88, "rs-rec-1", replicas=3 - number, ready=3 - number, generation=1 + number)
        w.put(start + 2.9, dep, updated=number, ready=3, available=3, status_replicas=4 - (number == 3))
        pod(w, start + 2.9, old, rec, "rs-rec-1", deleting=start + 2.9, ready=False, ready_since=start + 2.9)
        w.refresh_slice(start + 2.95, rec)
        w.delete(start + 3.8, old)
        w.refresh_slice(start + 3.85, rec)
    # the kill of rec-d at 15.0: reported 15.4, restarted 16.0, Ready again 18.0 (reported 18.3)
    pod(w, 15.4, "rec-d", rec, "rs-rec-2", ready=False, ready_since=15.0)
    w.refresh_slice(15.45, rec)
    pod(w, 16.0, "rec-d", rec, "rs-rec-2", restarts=1, last_finished=15.0, last_started=11.0, started=16.0)
    pod(w, 18.3, "rec-d", rec, "rs-rec-2", ready=True, ready_since=18.0)
    w.refresh_slice(18.35, rec)
    w.put(19.2, dep, status_replicas=3, updated=3, ready=3, available=3, unavailable=0,
          progressing="NewReplicaSetAvailable", progressing_since=19.2)
    obs = Observers(poller_lists=tuple(2.0 * n for n in range(21)), watch_start=0.1,
                    watch_snapshots=tuple(n + 0.3 for n in range(1, 41)), watch_stop=41.0,
                    recheck_ticks=tuple(float(t) for t in range(8, 41)))
    plan = Plan(scenario="G2", P=10.0, R=10.2, W=19.5,
                requests=((1, 9.0, {rec: "rec-a", "productcatalogservice": "cat-a"}, 1.0),
                          (2, 12.0, {rec: "rec-b", "productcatalogservice": "cat-b"}, 1.0),
                          (3, 15.5, {rec: "rec-c", "productcatalogservice": "cat-a"}, 1.0),
                          (4, 18.5, {rec: "rec-e", "productcatalogservice": "cat-b"}, 1.0),
                          (5, 24.0, {rec: "rec-f", "productcatalogservice": "cat-a"}, 1.0)),
                fault={"service": rec, "pod_key": "rec-d", "selected_by": "random_ready_replica",
                       "active": (14.9, 15.05), "effect": None, "kill": (14.9, 15.05)})
    return w, obs, plan


# ---------------------------------------------------------------------------------------------------------------
# The synthetic arm-G capture (converter v4's self-test capture with spans)
# ---------------------------------------------------------------------------------------------------------------
def _converter():
    for directory in (ROOT / "src", ROOT / "phase3"):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    import convert_stage2  # noqa: E402  (read-only; it registers itself under its own name)
    return convert_stage2


def synthetic_arm_g(target, *, requests: int = 180, spacing: float = 0.75, first: float = 49.0,
                    tail_delay: float = 0.8) -> dict:
    """Build converter v4's synthetic G2 capture in ``target/SYNTH-G2-001``, add the manifests, spans and client
    lines described in the module docstring, and convert it (converter v4, unchanged) into
    ``target/SYNTH-G2-001/evidence``. Returns {"capture", "converted", "info", "manifest"}."""
    S = _converter()
    target = Path(target)
    info = S.build_synthetic_capture(target / S.SYNTHETIC_CAPTURE_ID)
    capture = info["capture"]
    world = info["world"]
    # 1. the applications manifest the configuration row maps services through
    items = []
    for service, spec in SERVICES.items():
        items.append({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": service,
                                                                                  "labels": {"app": service}},
                      "spec": {"replicas": spec["replicas"], "template": {
                          "metadata": {"labels": {"app": service}},
                          "spec": {"terminationGracePeriodSeconds": 30,
                                   "containers": [{"name": "server", "image": "synthetic/" + service}]}}}})
        items.append({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
                      "metadata": {"name": service, "labels": {"app": service}},
                      "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": service}}}})
    (capture / "manifests" / "applications.json").unlink()
    (capture / "manifests" / "applications.json").write_text(
        json.dumps({"apiVersion": "v1", "kind": "List", "items": items}, indent=2) + "\n", encoding="utf-8")
    # 2. spans, trace-tail arrivals and the client stream
    export, arrivals, client_lines, client_arrivals = [], [], [], []
    turn = {"recommendationservice": 0, "productcatalogservice": 0}
    for k in range(1, requests + 1):
        t_k = first + (k - 1) * spacing
        trace = sha(f"synthetic/trace/{k}")[:32]
        resource_spans = []
        root = {"traceId": trace, "spanId": f"c{k:015d}", "kind": 3, "name": "pilot.ListRecommendations",
                "startTimeUnixNano": str((S.SYNTHETIC_START_NS + S._ns(t_k))),
                "endTimeUnixNano": str((S.SYNTHETIC_START_NS + S._ns(t_k + 0.02))),
                "attributes": [{"key": "aiops.request.index", "value": {"intValue": str(k)}}]}
        resource_spans.append({"resource": {"attributes": [{"key": "service.name",
                                                            "value": {"stringValue": "pilot-client"}}]},
                               "scopeSpans": [{"scope": {"name": "pilot"}, "spans": [root]}]})
        for service, name in (("recommendationservice", "/hipstershop.RecommendationService/ListRecommendations"),
                              ("productcatalogservice", "hipstershop.ProductCatalogService/ListProducts")):
            ready = [o for o in world.state("pods", t_k)
                     if o["metadata"]["labels"].get("app") == service and o["status"]["containerStatuses"][0]["ready"]
                     and "deletionTimestamp" not in o["metadata"]]
            ready.sort(key=lambda o: o["metadata"]["uid"])
            if not ready:
                continue
            chosen = ready[turn[service] % len(ready)]
            turn[service] += 1
            span = {"traceId": trace, "spanId": f"{service[:3]}{k:013d}", "parentSpanId": root["spanId"], "kind": 2,
                    "name": name, "startTimeUnixNano": str(S.SYNTHETIC_START_NS + S._ns(t_k + 0.002)),
                    "endTimeUnixNano": str(S.SYNTHETIC_START_NS + S._ns(t_k + 0.015)), "attributes": []}
            resource_spans.append({"resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": service}},
                {"key": "k8s.pod.uid", "value": {"stringValue": chosen["metadata"]["uid"]}},
                {"key": "k8s.pod.name", "value": {"stringValue": chosen["metadata"]["name"]}}]},
                "scopeSpans": [{"scope": {"name": service}, "spans": [span]}]})
        line = (json.dumps({"resourceSpans": resource_spans}, separators=(",", ":"), sort_keys=True) + "\n")
        export.append(line)
        arrivals.append({"line_index": k, "line_sha256": sha(line),
                         "collector_available_at": S.synthetic_iso_us(t_k + tail_delay),
                         "host_received_at": S.synthetic_iso_us(t_k + tail_delay)})
        client = json.dumps({"record_type": "client_request", "request_index": k, "trace_id": trace,
                             "started_at": S.synthetic_iso_us(t_k), "finished_at": S.synthetic_iso_us(t_k + 0.02)},
                            sort_keys=True) + "\n"
        client_lines.append(client)
        client_arrivals.append({"line_index": k, "line_sha256": sha(client),
                                "collector_available_at": S.synthetic_iso_us(t_k + 0.03),
                                "host_received_at": S.synthetic_iso_us(t_k + 0.03)})
    raw = capture / "raw"
    (raw / "trace-export.stdout").write_text("".join(export), encoding="utf-8")
    (raw / "trace-tail.arrivals.jsonl").write_text("".join(json.dumps(a, sort_keys=True) + "\n" for a in arrivals),
                                                   encoding="utf-8")
    (raw / "client-target.stdout").write_text("".join(client_lines), encoding="utf-8")
    (raw / "client-target.arrivals.jsonl").write_text(
        "".join(json.dumps(a, sort_keys=True) + "\n" for a in client_arrivals), encoding="utf-8")
    doc = json.loads((capture / "capture.json").read_text(encoding="utf-8"))
    end = first + (requests - 1) * spacing + 5.0
    doc["command_receipts"].append({"id": "trace-export", "args": ["exec", "otel-collector", "--", "cat"],
                                    "request_started_at": S.synthetic_iso_us(end),
                                    "response_received_at": S.synthetic_iso_us(end + 0.5),
                                    "collector_available_at": S.synthetic_iso_us(end + 0.501), "exit_code": 0,
                                    "stdout_file": "raw/trace-export.stdout",
                                    "stdout_sha256": sha("".join(export))})
    doc["command_receipts"].append({"id": "client-target", "streamed": True, "args": ["exec", "client"],
                                    "request_started_at": S.synthetic_iso_us(first - 1.0),
                                    "response_received_at": S.synthetic_iso_us(end),
                                    "collector_available_at": S.synthetic_iso_us(end), "exit_code": 0,
                                    "stdout_file": "raw/client-target.stdout",
                                    "arrivals_file": "raw/client-target.arrivals.jsonl",
                                    "stdout_sha256": sha("".join(client_lines)),
                                    "pod_uid": "synthetic-client-pod"})
    (capture / "capture.json").unlink()
    (capture / "capture.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    ground = {"EVALUATION_ONLY": "synthetic", "capture_id": S.SYNTHETIC_CAPTURE_ID,
              "planned": {"labels": {"fault_present": True}},
              "observed": {"change": {"service": "recommendationservice"},
                           "fault_target": {"service": "recommendationservice", "pod_uid": info["kill_target_uid"],
                                            "selected_by": "random_ready_replica"}},
              "timeline_host": {k: {"host_utc": S.synthetic_iso_us(v)} for k, v in S.SYNTHETIC_TIMELINE.items()},
              "evaluation_summary": None}
    (capture / "ground_truth" / "ground_truth.json").write_text(json.dumps(ground, indent=2) + "\n",
                                                                encoding="utf-8")
    converted = capture / "evidence"
    manifest = S.convert(capture, converted)
    return {"capture": capture, "converted": converted, "info": info, "manifest": manifest}


def copy_tree(source, target):
    shutil.copytree(source, target)
