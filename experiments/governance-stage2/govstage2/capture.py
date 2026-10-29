"""The converted follow-up capture: decision inputs per observer (guarded), requests and spans, the plan and the floors,
the clock band; and, behind a separate call made only after the decision logs are written, the evaluation-only inputs
of the labels.

Layout read (``--capture`` is the converter's output directory, by default ``<raw capture>/evidence``):

decision side (``read_decision_inputs``, under ``decision_guard``)
  accepted_evidence.jsonl            configuration, poller api_observation (snapshot_receipt), change_receipt,
                                     span_claim, client_request rows
  protocol.json                      the converter's side file
  stage2/api_observation.watch_cache_snapshot.jsonl   the watch store's rows
  stage2/live_recheck.jsonl          answered recheck ticks (condition (R))
  stage2/k1_pod_records.<observer>.jsonl              K1-ready Pod rows (fault_control_kill.k1_extract input)
  stage2/clock_probe.jsonl           the clock band (K1's clamp labels its shifts with it)
  stage2/continuity_gap.jsonl        not read by any condition (validity is the runner's)
evaluation side (``read_label_inputs``; never during the decision phase)
  stage2/api_watch_event.jsonl, stage2/api_watch_list_object.jsonl     EndpointSlice readiness
  evaluation_only/stage2/host_command.jsonl            the F2 kill receipt (kill window)
  <raw capture>/ground_truth/ground_truth.json         the F1 worker window, fault target, effect
  <raw capture>/ground_truth/fault_control_evaluation.json, target_draw.json   (recorded, not re-derived)

Separation (as the development reader, govpilot/inputs.py): while ``decision_guard`` is active an audit hook refuses
to open anything under ``evaluation_only/`` or ``ground_truth/`` and any file of the capture that is not a decision
input.

Requests and action B's target: t_k = the client root span's start (target block,
``govpilot.inputs.requests_from_rows``); B's target = the ``k8s.pod.uid`` of request k's server span (kind 2) of the
changed service; a_k = that span row's acquisition (its live trace-tail receipt; ``available_ns``). The span's Pod
claim is read only for B's target identity, never for any view's knowledge.
"""
from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from aiops_kg import fault_control_kill as K

from .common import AdapterError, Refused, iso, ns_to_us, ts_us
from govpilot import inputs as GI  # noqa: E402  (read-only)

SNAPSHOT_FILE = "stage2/api_observation.watch_cache_snapshot.jsonl"
RECHECK_FILE = "stage2/live_recheck.jsonl"
CLOCK_FILE = "stage2/clock_probe.jsonl"
GAP_FILE = "stage2/continuity_gap.jsonl"
EVENT_FILE = "stage2/api_watch_event.jsonl"
LIST_FILE = "stage2/api_watch_list_object.jsonl"
K1_FILE = "stage2/k1_pod_records.{}.jsonl"
HOST_COMMAND_FILE = "evaluation_only/stage2/host_command.jsonl"
OBSERVERS = ("poller", "watch", "recheck")
DECISION_FILES = ("accepted_evidence.jsonl", "protocol.json", SNAPSHOT_FILE, RECHECK_FILE, CLOCK_FILE,
                  K1_FILE.format("poller"), K1_FILE.format("watch"), K1_FILE.format("recheck"), "stage2_manifest.json")
SERVER_SPAN_KIND = 2
TARGET_BLOCK = GI.TARGET_BLOCK


# ---------------------------------------------------------------------------------------------------------------
# The decision-side guard
# ---------------------------------------------------------------------------------------------------------------
class SeparationError(PermissionError):
    """The decision phase tried to open an evaluation-only file."""


_GUARD: list[tuple[Path, Path | None]] = []
_HOOK = [False]


def _audit(event, args):
    if event != "open" or not _GUARD:
        return
    target = args[0] if args else None
    if target is None or isinstance(target, int):
        return
    try:
        path = Path(os.path.abspath(os.fsdecode(os.fspath(target))))
    except TypeError:
        return
    for converted, raw in _GUARD:
        parts = path.parts
        if "evaluation_only" in parts or "ground_truth" in parts:
            raise SeparationError(f"the decision phase may not open {path}")
        try:
            inside = path.relative_to(converted).as_posix()
        except ValueError:
            inside = None
        if inside is not None and inside not in DECISION_FILES:
            raise SeparationError(f"{inside} is not a decision input")
        if raw is not None and inside is None:
            try:
                path.relative_to(raw)
            except ValueError:
                continue
            raise SeparationError(f"the decision phase may not open the raw capture's {path.name}")


@contextmanager
def decision_guard(converted: Path, raw: Path | None):
    if not _HOOK[0]:
        sys.addaudithook(_audit)
        _HOOK[0] = True
    _GUARD.append((Path(os.path.abspath(converted)), Path(os.path.abspath(raw)) if raw else None))
    try:
        yield
    finally:
        _GUARD.pop()


# ---------------------------------------------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------------------------------------------
def iter_jsonl(path: Path):
    with open(path, "rb") as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                yield number, json.loads(line)


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class ServerSpan:
    service: str
    pod_uid: str | None
    span_id: str
    start_us: int
    end_us: int
    acquired_us: int
    evidence_id: str
    name: str = ""

    @property
    def health_check(self) -> bool:
        """A gRPC health check (the kubelet's probe), not a request of the workload."""
        return "grpc.health.v1.Health/Check" in self.name


@dataclass
class Spans:
    """Compact span facts: per trace, the server spans by service; the client root spans of the target block."""
    servers_by_trace: dict = field(default_factory=dict)       # trace -> [ServerSpan]
    request_trace: dict = field(default_factory=dict)          # k -> trace id (target block)
    blocks: dict = field(default_factory=dict)                 # trace -> block

    def server_spans(self, k: int, service: str) -> list[ServerSpan]:
        trace = self.request_trace.get(k)
        return sorted((s for s in self.servers_by_trace.get(trace, ()) if s.service == service),
                      key=lambda s: (s.start_us, s.span_id))

    def all_servers(self, service: str) -> list[ServerSpan]:
        return sorted((s for spans in self.servers_by_trace.values() for s in spans if s.service == service),
                      key=lambda s: (s.start_us, s.span_id))


def _span_from_row(row) -> tuple[str, ServerSpan | None, dict]:
    record = row["record"]
    payload = record["payload"]
    span = payload["span"]
    attributes = payload.get("resource_attributes") or {}
    server = None
    if span.get("kind") == SERVER_SPAN_KIND and attributes.get("service.name"):
        server = ServerSpan(attributes["service.name"], attributes.get("k8s.pod.uid"), span["spanId"],
                            int(span["startTimeUnixNano"]) // 1000, int(span.get("endTimeUnixNano") or
                                                                        span["startTimeUnixNano"]) // 1000,
                            ns_to_us(row["available_ns"]), record["evidence_id"], span.get("name") or "")
    return payload["trace_id"], server, payload


# ---------------------------------------------------------------------------------------------------------------
# Decision inputs
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class DecisionInputs:
    capture_id: str
    converted: Path
    raw: Path | None
    protocol: dict
    configuration: dict
    base_records: tuple          # configuration + change rows (shared by every store)
    poller_api: tuple            # poller api_observation records (every kind)
    watch_api: tuple             # watch snapshot api_observation records (every kind)
    recheck_ticks: tuple         # (evidence_id, payload) of answered ticks, in tick order
    k1_rows: dict                # observer -> K1-ready Pod rows
    clock_documents: tuple
    clock_band: dict
    requests: tuple              # (k, t_us) of the target block
    spans: Spans
    notes: dict
    manifest: dict | None

    @property
    def band_us(self):
        return self.clock_band.get("band_us")

    def observer_api(self, observer: str) -> tuple:
        return {"poller": self.poller_api, "watch": self.watch_api}[observer]

    def scenario_id(self) -> str | None:
        return (self.configuration.get("incident") or {}).get("id")

    def changed_service(self) -> str | None:
        return ((self.configuration.get("incident") or {}).get("change") or {}).get("service")


def raw_capture_of(converted: Path) -> Path | None:
    """The raw capture: the converter writes <capture>/evidence by default, so the parent if it has capture.json."""
    parent = Path(converted).resolve().parent
    return parent if (parent / "capture.json").is_file() else None


def read_decision_inputs(converted, *, raw=None) -> DecisionInputs:
    converted = Path(converted).resolve()
    raw = Path(raw).resolve() if raw else raw_capture_of(converted)
    if not (converted / "accepted_evidence.jsonl").is_file():
        raise Refused(f"refused: {converted} is not a converted capture (no accepted_evidence.jsonl)")
    with decision_guard(converted, raw):
        protocol = read_json(converted / "protocol.json")
        manifest = read_json(converted / "stage2_manifest.json") if (converted / "stage2_manifest.json").is_file() \
            else None
        evidence_rows, spans = [], Spans()
        client_blocks = {}
        span_rows = []
        for number, row in iter_jsonl(converted / "accepted_evidence.jsonl"):
            kind = row["record"]["kind"]
            if kind in ("configuration", "api_observation", "change_receipt"):
                evidence_rows.append((number, row))
            elif kind == "client_request":
                payload = row["record"]["payload"]
                if payload.get("trace_id"):
                    client_blocks[payload["trace_id"]] = payload.get("block")
                span_rows.append((number, row))
            elif kind == "span_claim":
                trace, server, _ = _span_from_row(row)
                if server is not None:
                    spans.servers_by_trace.setdefault(trace, []).append(server)
                span_rows.append((number, row))
        requests = GI.requests_from_rows(span_rows)
        spans.blocks = client_blocks
        for _, row in span_rows:
            record = row["record"]
            if record["kind"] != "span_claim":
                continue
            payload = record["payload"]
            span = payload["span"]
            attributes = payload.get("span_attributes") or {}
            if span.get("parentSpanId") or "aiops.request.index" not in attributes:
                continue
            if client_blocks.get(payload["trace_id"]) == TARGET_BLOCK:
                spans.request_trace[int(attributes["aiops.request.index"])] = payload["trace_id"]
        del span_rows
        records, notes = GI.records_from_rows(evidence_rows, f"{converted.name}/accepted_evidence.jsonl")
        del evidence_rows
        configuration = [r for r in records if r.kind == GI.CONFIGURATION]
        if len(configuration) != 1:
            raise AdapterError(f"expected one configuration row, found {len(configuration)}")
        base = tuple(r for r in records if r.kind != GI.API)
        poller = tuple(r for r in records if r.kind == GI.API)
        watch, snapshot_notes = (), {}
        if (converted / SNAPSHOT_FILE).is_file():
            rows = list(iter_jsonl(converted / SNAPSHOT_FILE))
            watch, snapshot_notes = GI.records_from_rows(rows, f"{converted.name}/{SNAPSHOT_FILE}")
            del rows
        ticks = []
        if (converted / RECHECK_FILE).is_file():
            for _, row in iter_jsonl(converted / RECHECK_FILE):
                payload = row["record"]["payload"]
                if payload.get("status") == "answered":
                    ticks.append((row["record"]["evidence_id"], payload))
        ticks.sort(key=lambda item: (item[1]["tick"], item[0]))
        k1_rows = {}
        for observer in OBSERVERS:
            path = converted / K1_FILE.format(observer)
            k1_rows[observer] = [row for _, row in iter_jsonl(path)] if path.is_file() else []
        documents = []
        if (converted / CLOCK_FILE).is_file():
            documents = [row["record"]["payload"] for _, row in iter_jsonl(converted / CLOCK_FILE)]
    band = K.clock_band(documents) if documents else {"band_available": False, "band_us": None,
                                                      "note": "no clock_probe rows"}
    ids = [r.id for r in poller] + [r.id for r in watch]
    if len(ids) != len(set(ids)):
        raise AdapterError("duplicate evidence IDs between the poller and watch rows")
    notes = {"accepted_evidence": notes, "watch_snapshots": snapshot_notes,
             "answered_recheck_ticks": len(ticks), "requests_target_block": len(requests)}
    capture_id = protocol.get("capture_id") or converted.name
    return DecisionInputs(capture_id, converted, raw, protocol, configuration[0].payload(), base, poller,
                          tuple(watch), tuple(ticks), k1_rows, tuple(documents), band, tuple(requests), spans,
                          notes, manifest)


# ---------------------------------------------------------------------------------------------------------------
# The plan: arm, conditions, grid, floors (phase3/stage2_plan.json)
# ---------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ArmPlan:
    arm: str
    scenario: str
    deltas: tuple            # knowledge-cutoff offsets Delta (s)
    dispatch: tuple          # dispatch delays delta (s)
    streams: tuple
    actions: tuple
    conditions: tuple        # condition names as in the plan
    floors: dict             # service -> R3 floor
    replicas: dict
    expiry_s: float
    observers: tuple

    def to_dict(self) -> dict:
        return {"arm": self.arm, "scenario": self.scenario, "Delta_s": list(self.deltas),
                "delta_s": list(self.dispatch), "streams": list(self.streams), "actions": list(self.actions),
                "conditions": list(self.conditions), "replica_floor_by_service": dict(sorted(self.floors.items())),
                "replicas": dict(sorted(self.replicas.items())), "E_s": self.expiry_s,
                "observers": list(self.observers)}


def arm_plan(plan: dict, scenario: str) -> ArmPlan:
    """Grid and floors of one scenario from the plan. Floors come from the plan's PodDisruptionBudgets: replicas -
    maxUnavailable for every service of an arm with PDBs, which must equal the plan's replica_floor_by_service
    (else refused); an arm without PDBs keeps gate v1's default floor 1 (Stage 1)."""
    found = [s for s in plan.get("scenarios") or [] if s.get("id") == scenario]
    if len(found) != 1:
        raise AdapterError(f"scenario {scenario!r} is not in the plan")
    arm_id = found[0]["arm"]
    arm = plan["arms"][arm_id]
    posing = plan["posing"]
    replicas = dict(arm.get("replicas") or {})
    floors = {}
    if arm.get("pod_disruption_budgets"):
        unavailable = arm["pdb_max_unavailable"]
        floors = {service: count - unavailable for service, count in sorted(replicas.items())}
        if floors != dict(arm.get("replica_floor_by_service") or {}):
            raise AdapterError(f"arm {arm_id}: floors from the PDBs {floors} differ from the plan's "
                               f"replica_floor_by_service {arm.get('replica_floor_by_service')}")
    elif arm.get("replica_floor_by_service"):
        raise AdapterError(f"arm {arm_id}: replica floors without PodDisruptionBudgets")
    observers = tuple(name for name in ("poller", "watch", "recheck") if (arm.get("observers") or {}).get(name))
    conditions = tuple(c.split(" ")[0] for c in arm["conditions"])
    return ArmPlan(arm_id, scenario, tuple(posing["knowledge_cutoff_offsets_seconds"]),
                   tuple(posing["dispatch_delays_seconds"][arm_id]), tuple(arm["change_record_streams"]),
                   tuple(arm["actions"]), conditions, floors, replicas, float(posing["expiry_seconds"]), observers)


def manifest_grace_seconds(configuration: dict) -> dict:
    """service -> terminationGracePeriodSeconds of its Deployment template in the configuration row (Kubernetes'
    default 30 s when the manifest omits it); used to place a Pod's deletion request (deletionTimestamp = request +
    grace) for the labels."""
    out = {}
    for name in sorted(configuration.get("deployment_manifests") or {}):
        doc = configuration["deployment_manifests"][name]
        for item in (doc.get("items", []) if isinstance(doc, dict) else []):
            if item.get("kind") != "Deployment":
                continue
            app = (item.get("metadata") or {}).get("labels", {}).get("app")
            spec = ((item.get("spec") or {}).get("template") or {}).get("spec") or {}
            if app:
                out[app] = spec.get("terminationGracePeriodSeconds", 30)
    return out


# ---------------------------------------------------------------------------------------------------------------
# Validity fields (exclusion from validity fields only)
# ---------------------------------------------------------------------------------------------------------------
def validity_fields(raw: Path | None) -> dict:
    """COMPLETE.txt status and the runner's validity, read from the raw capture; nothing else."""
    if raw is None:
        return {"raw_capture": None, "complete_status": None, "runner_valid": None,
                "note": "raw capture not found next to the converted directory"}
    status = None
    complete = raw / "COMPLETE.txt"
    if complete.is_file():
        for line in complete.read_text(encoding="utf-8").splitlines():
            if line.startswith("status="):
                status = line.split("=", 1)[1].strip()
    doc = read_json(raw / "capture.json") if (raw / "capture.json").is_file() else {}
    validity = doc.get("validity") or {}
    return {"raw_capture": raw.name, "complete_status": status, "runner_valid": validity.get("valid"),
            "runner_reasons": validity.get("reasons")}


def included(fields: dict) -> bool:
    return fields.get("complete_status") == "finished" and fields.get("runner_valid") is True


# ---------------------------------------------------------------------------------------------------------------
# Evaluation-only inputs (labels; read after the decision logs are written)
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class LabelInputs:
    k1_rows: dict                # observer -> K1-ready Pod rows (final record versions of every observer)
    endpoint_slices: list        # (receipt us, EndpointSlice object) of the watch's events and list objects
    ground_truth: dict
    kill_receipts: list
    fault_control_evaluation: dict | None


def read_label_inputs(converted, raw) -> LabelInputs:
    converted = Path(converted)
    slices = []
    for name in (LIST_FILE, EVENT_FILE):
        path = converted / name
        if not path.is_file():
            continue
        for _, row in iter_jsonl(path):
            payload = row["record"]["payload"]
            data = payload.get("resource_data")
            if isinstance(data, dict) and data.get("kind") == "EndpointSlice":
                slices.append((ts_us(payload["observed_at"]), row["record"]["evidence_id"], data))
    slices.sort(key=lambda item: (item[0], item[1]))
    k1_rows = {}
    for observer in OBSERVERS:
        path = converted / K1_FILE.format(observer)
        k1_rows[observer] = [row for _, row in iter_jsonl(path)] if path.is_file() else []
    ground_truth, evaluation = {}, None
    if raw is not None and (Path(raw) / "ground_truth/ground_truth.json").is_file():
        ground_truth = read_json(Path(raw) / "ground_truth/ground_truth.json")
        if (Path(raw) / "ground_truth/fault_control_evaluation.json").is_file():
            evaluation = read_json(Path(raw) / "ground_truth/fault_control_evaluation.json")
    kills = []
    if (converted / HOST_COMMAND_FILE).is_file():
        for _, row in iter_jsonl(converted / HOST_COMMAND_FILE):
            payload = row["record"]["payload"]
            argv = payload.get("args") or payload.get("argv") or []
            if "crictl" in argv and "stop" in argv:
                kills.append(payload)
    kills.sort(key=lambda p: (str(p.get("request_started_at")), str(p.get("id"))))
    return LabelInputs(k1_rows, slices, ground_truth, kills, evaluation)


def describe_band(band: dict) -> dict:
    keep = ("band_available", "band_us", "band_ns", "widest_bound_ns", "readings_used", "union_ns",
            "intersection_ns", "intersection_empty", "stamp_resolution_ns")
    out = {k: band.get(k) for k in keep if k in band}
    out["rule"] = K.CLOCK_BAND_RULE
    out["band_s"] = None if band.get("band_us") is None else band["band_us"] / 1e6
    out["readings_rejected"] = len(band.get("readings_rejected") or [])
    return out


def first_t_k_iso(requests) -> str | None:
    return iso(requests[0][1]) if requests else None
