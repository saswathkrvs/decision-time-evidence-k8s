"""Observer rows -> gate observations, with the creation-ceiling clamp.

Both stores pass through the same mapping (gate v1's build_observations, plus K1, plus ROLLOUT_STATUS as in the
development adapter), so the poller-watch comparison isolates timing. This module applies that mapping to the rows of
any observer:

- poller v1.1 rows (accepted_evidence.jsonl, observation_basis snapshot_receipt),
- watch cache-snapshot rows (stage2/api_observation.watch_cache_snapshot.jsonl, observation_basis
  watch_cache_snapshot),
- one live_recheck tick (stage2/live_recheck.jsonl) as one snapshot, observed and available at its receipt x_R
  (condition (R)).

Only the kinds gate v1 maps (Pod, ReplicaSet, Deployment, Node) enter a decision store; EndpointSlices and
PodDisruptionBudgets are read by the labels and the floor check only (counted, never mapped).

The creation-ceiling clamp. Gate v1's ``build_observations`` (experiments/policy-gate-v1/run_policy_gate_audit.py)
gives every non-Pod object ``starts_at = creationTimestamp + 1 s`` (its creation ceiling) and an Observation refuses
``starts_at > observed_at``; the watch sees a new ReplicaSet within milliseconds of its creation, so v1 raises on
real follow-up rows (and on about one poller list in five). ``clamped_build_observations`` runs gate v1's own
``build_observations`` code object, unchanged, with one name of its globals rebound: ``Observation`` becomes a factory
that replaces a ceiling later than the observation by the observation instant and records the clamp. The gate v1
module is not edited and its globals are not modified (the function runs on a copy of its globals mapping). Every
clamp is recorded with its record, subject, predicate, ceiling and observation instant. The development adapter's
``build_model_inputs`` (receipt GENERATION, ROLLOUT_STATUS, absences, provenance) runs the same way.

K1. Each observer's kubelet-stamped transitions come from ``fault_control_kill.k1_extract`` on that observer's
K1-ready Pod rows; each becomes a point observation of the Pod's STATE (observed_at = the placed kubelet stamp,
available_at = the record's acceptance by that observer) merged into that observer's store. For the watch, whose store
holds cache snapshots while its K1 rows are the events and list objects, the store's own snapshot sightings of each
Pod are passed to k1_extract with the K1 rows, so that a stamp is clamped after the last snapshot of the store that
contradicts it. (R) reads one response as one snapshot; no K1 point is added to it.

(R)'s R2 start: in a tick store every GENERATION observation of a Deployment starts at the creation ceiling of its
current ReplicaSet (the owned ReplicaSet whose revision annotation equals the Deployment's) and every GENERATION
observation of a ReplicaSet at its own creation ceiling, each clamped to x_R; every such start is recorded.
"""
from __future__ import annotations

import dataclasses
import types
from collections import defaultdict
from datetime import timedelta

from aiops_kg import fault_control_kill as K
from aiops_kg.policy_gate import GENERATION, STATE, Observation

from .common import AdapterError, R, canonical, dt, iso, ts_us
from govpilot import mapping as GM  # noqa: E402  (read-only)
from govpilot.inputs import API, InputRecord  # noqa: E402
from govpilot.mapping import ModelInputs  # noqa: E402

GATE_KINDS = ("Pod", "ReplicaSet", "Deployment", "Node")
LABEL_ONLY_KINDS = ("EndpointSlice", "PodDisruptionBudget")
RESOURCE_OF_KIND = {"Pod": "pods", "ReplicaSet": "replicasets", "Deployment": "deployments", "Node": "nodes",
                    "EndpointSlice": "endpointslices", "PodDisruptionBudget": "poddisruptionbudgets"}
ONE_SECOND = timedelta(seconds=1)
REVISION = "deployment.kubernetes.io/revision"


# ---------------------------------------------------------------------------------------------------------------
# The clamped gate v1 mapping
# ---------------------------------------------------------------------------------------------------------------
class ClampLog:
    """Every creation ceiling replaced by the observation instant (one entry per record and predicate)."""

    def __init__(self):
        self.entries: dict[tuple, dict] = {}

    def add(self, record_id, subject, predicate, value, ceiling, observed):
        key = (record_id, predicate)
        if key not in self.entries:
            self.entries[key] = {"record_id": record_id, "subject": subject, "predicate": predicate, "value": value,
                                 "ceiling": iso(R.to_us(ceiling)), "observed_at": iso(R.to_us(observed)),
                                 "starts_at_used": iso(R.to_us(observed)),
                                 "shift_us": R.to_us(ceiling) - R.to_us(observed),
                                 "rule": "creation ceiling (creationTimestamp + 1 s) later than the observation: "
                                         "clamped to the observation instant"}

    def rows(self) -> list[dict]:
        return [self.entries[k] for k in sorted(self.entries)]


def _clamping_observation(clamps: ClampLog):
    def make(record_id, subject, predicate, value, observed_at, available_at, starts_at=None):
        if starts_at is not None and starts_at > observed_at:
            clamps.add(record_id, subject, predicate, value, starts_at, observed_at)
            starts_at = observed_at
        return Observation(record_id, subject, predicate, value, observed_at, available_at, starts_at)
    return make


def _rebound(function, **names):
    """A copy of ``function`` (same code object, defaults and closure) whose globals are a copy of its module's
    globals with ``names`` rebound; the module itself is not touched."""
    namespace = dict(function.__globals__)
    namespace.update(names)
    clone = types.FunctionType(function.__code__, namespace, function.__name__, function.__defaults__,
                               function.__closure__)
    clone.__kwdefaults__ = function.__kwdefaults__
    clone.__doc__ = function.__doc__
    return clone


def clamped_build_observations(sightings, clamps: ClampLog, *, include_receipts: bool = False):
    """Gate v1's build_observations with the creation ceiling clamped to the observation instant."""
    frozen = GM.pga().build_observations
    run = _rebound(frozen, Observation=_clamping_observation(clamps))
    return run(sightings, None, {}, include_receipts=include_receipts)


class _GateShim:
    """Stands in for gate v1's module inside a rebound copy of govpilot's ``_gate_v1_observations``."""

    def __init__(self, clamps: ClampLog):
        self.clamps = clamps

    def build_observations(self, sightings, patch, protocol, *, include_receipts=True, **kwargs):
        if kwargs or patch is not None:
            raise AdapterError("the clamped mapping is used without receipts only (as Stage 1 used it)")
        return clamped_build_observations(sightings, self.clamps, include_receipts=include_receipts)


def clamped_gate_v1_observations(rows, clamps: ClampLog):
    """govpilot.mapping._gate_v1_observations (generation sentinel, SystemExit -> InputError) over the clamped map."""
    shim = _GateShim(clamps)
    run = _rebound(GM._gate_v1_observations, pga=lambda: shim)
    return run(rows)


def build_model_inputs_clamped(records, binding, clamps: ClampLog) -> ModelInputs:
    """govpilot.mapping.build_model_inputs (Stage 1, unchanged code) over the clamped gate v1 mapping."""
    run = _rebound(GM.build_model_inputs,
                   _gate_v1_observations=lambda rows: clamped_gate_v1_observations(rows, clamps))
    return run(records, binding)


def gate_records(records):
    """Only api_observation records of the kinds gate v1 maps (plus every non-API record); the rest are counted."""
    kept, dropped = [], defaultdict(int)
    for r in records:
        if r.kind == API:
            kind = r.payload_view()["resource_data"]["kind"]
            if kind not in GATE_KINDS:
                dropped[kind] += 1
                continue
        kept.append(r)
    return tuple(kept), dict(sorted(dropped.items()))


# ---------------------------------------------------------------------------------------------------------------
# K1 point observations, through fault_control_kill only
# ---------------------------------------------------------------------------------------------------------------
def snapshot_pod_rows(records, observer: str) -> list[dict]:
    """K1-ready rows (fault_control_kill.pod_records shape) for the Pod sightings of a store's own records."""
    out = []
    for r in records:
        if r.kind != API:
            continue
        resource = r.payload_view()["resource_data"]
        if resource["kind"] != "Pod":
            continue
        out.append({"record_id": r.id, "observer": observer, "observed_at_us": r.observed_at,
                    "available_at_us": r.available_at, "pod": resource, "pod_uid": resource["metadata"]["uid"],
                    "pod_name": resource["metadata"].get("name"), "store_sighting": True})
    return out


def k1_for_store(k1_rows, store_rows, *, band_us):
    """k1_extract over an observer's K1-ready rows plus the store's own Pod sightings (same observer).

    Returns (observations, extraction): Observation objects ready for the store, and k1_extract's full result (the
    K1 observations with their source record, source field, stamp, placement and clamps; the dropped and skipped
    transitions; the counts)."""
    seen = {row["record_id"] for row in k1_rows}
    merged = list(k1_rows) + [row for row in store_rows if row["record_id"] not in seen]
    extraction = K.k1_extract(merged, band_us=band_us)
    observations = []
    for o in extraction["observations"]:
        observations.append(Observation(o["observation_id"], f"Pod/{o['pod_uid']}", STATE, o["state"],
                                        dt(o["observed_at_us"]), dt(o["available_at_us"])))
    return observations, extraction


def merge_k1(model: ModelInputs, k1_observations) -> ModelInputs:
    """The model with K1 point observations added: each is its own input record (provenance -> itself), a cluster
    observation, available at its record's acceptance. Nothing is withdrawn; A1 closes the carried-forward run."""
    if not k1_observations:
        return model
    known = {o.record_id for o in model.observations}
    provenance = dict(model.provenance)
    availability = dict(model.availability)
    cluster = set(model.cluster_observations)
    added = []
    for o in k1_observations:
        if o.record_id in known:
            raise AdapterError(f"K1 observation {o.record_id} collides with a model record")
        added.append(o)
        provenance[o.record_id] = (o.record_id,)
        availability[o.record_id] = R.to_us(o.available_at)
        cluster.add(o.record_id)
    return dataclasses.replace(model, observations=tuple(model.observations) + tuple(added), provenance=provenance,
                               availability=availability, cluster_observations=frozenset(cluster))


# ---------------------------------------------------------------------------------------------------------------
# One live_recheck tick as one snapshot (condition (R))
# ---------------------------------------------------------------------------------------------------------------
def tick_records(payload: dict, evidence_id: str, *, kinds=GATE_KINDS) -> tuple[InputRecord, ...]:
    """InputRecords for the objects of one answered tick, observed and available at its receipt x_R."""
    x_r = ts_us(payload["response_received_at"])
    snapshot = evidence_id
    out = []
    for obj in payload.get("objects") or []:
        kind = obj.get("kind")
        if kind not in kinds:
            continue
        meta = obj["metadata"]
        record_payload = {"resource_data": obj, "observed_at": iso(x_r), "available_at": iso(x_r),
                          "collection_id": payload.get("collection_id"), "snapshot_id": snapshot,
                          "resource": RESOURCE_OF_KIND[kind], "observation_basis": "live_recheck",
                          "tick": payload.get("tick")}
        owner = None
        if kind == "Deployment":
            owner = meta["uid"]
        elif kind == "ReplicaSet":
            owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
            owner = owners[0]["uid"] if owners and owners[0].get("kind") == "Deployment" else None
        revision = None
        if kind in ("Deployment", "ReplicaSet"):
            text = (meta.get("annotations") or {}).get(REVISION)
            revision = int(text) if isinstance(text, str) and text.isdigit() else None
        out.append(InputRecord(f"{evidence_id}#{meta['uid']}", API, f"{kind}/{meta['uid']}", x_r, x_r,
                               canonical(record_payload), evidence_id, deployment_uid=owner, revision=revision))
    return tuple(sorted(out, key=lambda r: r.id))


def current_replicaset_ceilings(records) -> dict[str, tuple[int, str]]:
    """Deployment UID -> (creation ceiling us, ReplicaSet UID) of its current ReplicaSet in one snapshot: the owned
    ReplicaSet whose revision annotation equals the Deployment's."""
    deployments, replicasets = {}, []
    for r in records:
        resource = r.payload_view()["resource_data"]
        meta = resource["metadata"]
        if resource["kind"] == "Deployment":
            deployments[meta["uid"]] = (meta.get("annotations") or {}).get(REVISION)
        elif resource["kind"] == "ReplicaSet":
            replicasets.append((r.deployment_uid, (meta.get("annotations") or {}).get(REVISION),
                                ts_us(meta["creationTimestamp"]), meta["uid"]))
    out = {}
    for uid, revision in deployments.items():
        matches = sorted((created, rs_uid) for owner, rs_revision, created, rs_uid in replicasets
                         if owner == uid and revision is not None and rs_revision == revision)
        if matches:
            created, rs_uid = matches[-1]
            out[uid] = (created + 1_000_000, rs_uid)
    return out


def recheck_r2_starts(observations, records, x_r: int):
    """(observations with (R)'s GENERATION starts, the start records). See the module docstring."""
    ceilings = current_replicaset_ceilings(records)
    own = {}
    for r in records:
        resource = r.payload_view()["resource_data"]
        if resource["kind"] == "ReplicaSet":
            own[r.subject] = ts_us(resource["metadata"]["creationTimestamp"]) + 1_000_000
    out, starts = [], []
    for o in observations:
        if o.predicate != GENERATION:
            out.append(o)
            continue
        kind, uid = o.subject.split("/", 1)
        source, ceiling = None, None
        if kind == "Deployment" and uid in ceilings:
            ceiling, rs_uid = ceilings[uid]
            source = f"current ReplicaSet/{rs_uid} creationTimestamp + 1 s"
        elif kind == "ReplicaSet" and o.subject in own:
            ceiling = own[o.subject]
            source = "own creationTimestamp + 1 s"
        if ceiling is None:
            out.append(o)
            starts.append({"subject": o.subject, "start": None, "source": "no current ReplicaSet in the response; "
                                                                          "gate v1's start kept"})
            continue
        used = min(ceiling, x_r)
        out.append(dataclasses.replace(o, starts_at=dt(used)))
        starts.append({"subject": o.subject, "generation": o.value, "ceiling": iso(ceiling), "start": iso(used),
                       "clamped_to_x_R": ceiling > x_r, "source": source})
    return out, starts


def recheck_model(records, clamps: ClampLog) -> tuple[ModelInputs, list[dict]]:
    """ModelInputs of one tick (no change records: '(R) does not read the change records'), with (R)'s R2 starts
    applied."""
    model = build_model_inputs_clamped(records, None, clamps)
    x_r = records[0].observed_at if records else None
    observations, starts = recheck_r2_starts(model.observations, records, x_r)
    return dataclasses.replace(model, observations=tuple(observations)), starts
