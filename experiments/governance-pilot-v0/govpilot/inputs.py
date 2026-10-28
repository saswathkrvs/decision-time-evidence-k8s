"""Immutable inputs, the change-record mapping, the guarded decision reader, the delay grid and A's binding.

The decision reader opens only ``evidence/accepted_evidence.jsonl`` and ``evidence/protocol.json`` of a capture; an
audit hook makes every other open of a file in the capture, and every open of ``ground_truth/``,
``evidence/evaluation_only/``, any ``capture.json`` or ``incident.json``, fail while the reader runs
(``reader_guard``). The evidence/capture.json side copy of the patch receipt is therefore never read: the change
record comes only from the accepted ``change_receipt`` rows, and every record derived from it carries that row's
(per-stream) availability.

Records (``InputRecord``) are immutable; the payload is kept as canonical JSON text (``payload()`` parses a private
copy, ``payload_view()`` a shared read-only parse), so no caller can change a record. Every record carries its ID
(the source ``evidence_id``; derived records add a suffix), its source line, its subject with the Deployment UID,
the bound revision where one applies, ``observed_at``, the per-stream ``available_at``, any recorded validity,
``corrects`` and a ``simulated`` flag for constructed records. Times are integer microseconds since the epoch (UTC).

``perturb(records, spec)`` applies one change-record stream of the grid (S0, S30, S150, S180, S300, S1200, Snever,
and the constructed Scorr) to the change rows themselves, through ``aiops_kg.replay.delay`` / ``drop``; every
record later derived from a change row inherits the shifted availability, so no undelayed copy can exist. The
capture run uses ``CAPTURE_STREAMS`` (S0 ... Snever); Scorr is a labelled software fixture only.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .common import R, InputError, canonical, ts_us
from .rollout import REVISION_ANNOTATION, Binding

CONFIGURATION = "configuration"
API = "api_observation"
CHANGE_PATCH = "change_patch"
CHANGE_WAIT = "change_wait"
FREEZE = "freeze_declaration"
RECORD_KINDS = (CONFIGURATION, API, CHANGE_PATCH, CHANGE_WAIT, FREEZE)
CHANGE_KINDS = (CHANGE_PATCH, CHANGE_WAIT)
TARGET_BLOCK = "client-target"


# ---------------------------------------------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------------------------------------------
@lru_cache(maxsize=65536)
def _parse(payload_json: str):
    return json.loads(payload_json)


@dataclass(frozen=True, slots=True)
class InputRecord:
    """One immutable input record version."""
    id: str
    kind: str
    subject: str
    observed_at: int | None
    available_at: int
    payload_json: str = "{}"
    source: str = ""
    corrects: str | None = None
    deployment_uid: str | None = None
    revision: int | None = None
    valid_from: int | None = None
    valid_to: int | None = None
    simulated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise InputError("record id must be a nonempty string")
        if self.kind not in RECORD_KINDS:
            raise InputError(f"{self.id}: unknown record kind {self.kind!r}")
        for name in ("available_at", "observed_at", "valid_from", "valid_to"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise InputError(f"{self.id}: {name} must be integer microseconds")
        if self.observed_at is not None and self.available_at < self.observed_at:
            raise InputError(f"{self.id}: available before it was observed")
        if self.corrects == self.id:
            raise InputError(f"{self.id}: a record cannot correct itself")

    def payload(self) -> dict:
        """A fresh copy of the payload (the record itself never changes)."""
        return json.loads(self.payload_json)

    def payload_view(self):
        """The cached parse; callers must not mutate it (use ``payload()`` for a private copy)."""
        return _parse(self.payload_json)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "subject": self.subject, "observed_at": R.iso(self.observed_at),
                "available_at": R.iso(self.available_at), "source": self.source, "corrects": self.corrects,
                "deployment_uid": self.deployment_uid, "revision": self.revision,
                "valid_from": R.iso(self.valid_from), "valid_to": R.iso(self.valid_to), "simulated": self.simulated,
                "payload_sha256": hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest()}


@dataclass(frozen=True, slots=True)
class ChangeRecord:
    """The change record class: a patch receipt or a rollout-wait receipt."""
    record_id: str
    role: str                     # "patch" | "wait"
    deployment_uid: str
    service: str | None
    request_started_at: int
    response_received_at: int
    available_at: int
    exit_code: int
    corrects: str | None
    simulated: bool
    bound_revision: int | None

    def to_dict(self) -> dict:
        return {"record_id": self.record_id, "role": self.role, "deployment_uid": self.deployment_uid,
                "service": self.service, "request_started_at": R.iso(self.request_started_at),
                "response_received_at": R.iso(self.response_received_at), "available_at": R.iso(self.available_at),
                "exit_code": self.exit_code, "corrects": self.corrects, "simulated": self.simulated,
                "bound_revision": self.bound_revision}


def change_record(rec: InputRecord) -> ChangeRecord:
    """Explicit mapping of a change_receipt row: patch request/response, or the rollout-wait completion receipt."""
    if rec.kind not in CHANGE_KINDS:
        raise InputError(f"{rec.id} is not a change record")
    payload = rec.payload_view()
    receipt = payload.get("patch_receipt") if rec.kind == CHANGE_PATCH else payload.get("wait_receipt")
    if not isinstance(receipt, Mapping):
        raise InputError(f"{rec.id}: change row without its receipt")
    if rec.kind == CHANGE_PATCH:
        exit_code = receipt.get("exit_code")
    else:
        exit_code = payload.get("wait_exit_code", receipt.get("exit_code"))
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise InputError(f"{rec.id}: exit code missing")
    if not rec.deployment_uid:
        raise InputError(f"{rec.id}: no Deployment UID")
    return ChangeRecord(rec.id, "patch" if rec.kind == CHANGE_PATCH else "wait", rec.deployment_uid,
                        payload.get("service"), ts_us(receipt["request_started_at"]),
                        ts_us(receipt["response_received_at"]), rec.available_at, exit_code, rec.corrects,
                        rec.simulated, rec.revision)


def freeze_record(label: str, start: int, end: int, declared_valid_at: int, available_at: int, *,
                  source: str = "fixture") -> InputRecord:
    """A constructed (SIMULATED) freeze declaration for the X1 fixtures (the freeze-rule tests).

    ``observed_at`` is the declaration's valid time (when the freeze existed); ``available_at`` when it shipped."""
    payload = {"label": label, "start": R.iso(start), "end": R.iso(end), "SIMULATED": True}
    return InputRecord(f"freeze:{label}", FREEZE, f"freeze/{label}", declared_valid_at, available_at,
                       canonical(payload), source, simulated=True)


# ---------------------------------------------------------------------------------------------------------------
# Accepted-evidence rows -> records (pure; the reader below adds the guarded file access)
# ---------------------------------------------------------------------------------------------------------------
def _subject_uid(subject_text) -> str | None:
    try:
        parts = json.loads(subject_text)
    except (TypeError, ValueError):
        return None
    return parts[4] if isinstance(parts, list) and len(parts) == 5 else None


def _revision_of(meta) -> int | None:
    text = (meta.get("annotations") or {}).get(REVISION_ANNOTATION)
    return int(text) if isinstance(text, str) and text.isdigit() else None


def records_from_rows(rows: Sequence[tuple[int, dict]], source: str) -> tuple[tuple[InputRecord, ...], dict]:
    """Model records from accepted-evidence rows ``(line number, row)``; returns (records, notes).

    Only configuration, api_observation and change_receipt rows become records. Other kinds are counted."""
    records: list[InputRecord] = []
    notes = {"rows_by_kind": {}, "api_available_ns_vs_payload_mismatch": 0, "change_available_vs_receipt_mismatch": 0}
    for line, row in rows:
        record = row["record"]
        kind = record["kind"]
        notes["rows_by_kind"][kind] = notes["rows_by_kind"].get(kind, 0) + 1
        payload = record["payload"]
        row_available = row["available_ns"] // 1000
        where = f"{source}:{line}"
        if kind == "configuration":
            records.append(InputRecord(record["evidence_id"], CONFIGURATION, "configuration", None, row_available,
                                       canonical(payload), where))
        elif kind == "api_observation":
            resource = payload["resource_data"]
            meta = resource["metadata"]
            observed, available = ts_us(payload["observed_at"]), ts_us(payload["available_at"])
            if available != row_available:
                notes["api_available_ns_vs_payload_mismatch"] += 1
            owner = None
            if resource["kind"] == "Deployment":
                owner = meta["uid"]
            elif resource["kind"] == "ReplicaSet":
                owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
                owner = owners[0]["uid"] if owners and owners[0].get("kind") == "Deployment" else None
            revision = _revision_of(meta) if resource["kind"] in ("Deployment", "ReplicaSet") else None
            records.append(InputRecord(record["evidence_id"], API, f"{resource['kind']}/{meta['uid']}", observed,
                                       available, canonical(payload), where, deployment_uid=owner, revision=revision))
        elif kind == "change_receipt":
            if "patch_receipt" in payload:
                receipt, record_kind = payload["patch_receipt"], CHANGE_PATCH
                uid = payload.get("deployment_uid") or _subject_uid(record.get("subject"))
            elif "wait_receipt" in payload:
                receipt, record_kind = payload["wait_receipt"], CHANGE_WAIT
                uid = _subject_uid(record.get("subject"))
            else:
                raise InputError(f"{where}: change_receipt row without a patch or wait receipt")
            if receipt.get("collector_available_at") and ts_us(receipt["collector_available_at"]) != row_available:
                notes["change_available_vs_receipt_mismatch"] += 1
            records.append(InputRecord(record["evidence_id"], record_kind, f"Deployment/{uid}",
                                       ts_us(receipt["response_received_at"]), row_available, canonical(payload),
                                       where, deployment_uid=uid))
    notes["rows_by_kind"] = dict(sorted(notes["rows_by_kind"].items()))
    ids = [r.id for r in records]
    if len(ids) != len(set(ids)):
        raise InputError(f"{source}: duplicate evidence IDs")
    return tuple(records), notes


def requests_from_rows(rows: Sequence[tuple[int, dict]]) -> tuple[tuple[int, int], ...]:
    """Target-block requests (k, t_k in microseconds): client root spans with ``aiops.request.index`` whose trace
    belongs to the ``client-target`` block (``client_request`` rows), t_k = startTimeUnixNano // 1000. Only these
    whitelisted fields are read; span Pod claims are never read."""
    blocks = {}
    for _, row in rows:
        record = row["record"]
        if record["kind"] == "client_request" and record["payload"].get("trace_id"):
            blocks[record["payload"]["trace_id"]] = record["payload"].get("block")
    found = {}
    for _, row in rows:
        record = row["record"]
        if record["kind"] != "span_claim":
            continue
        payload = record["payload"]
        span = payload["span"]
        attributes = payload.get("span_attributes") or {}
        if span.get("parentSpanId") or "aiops.request.index" not in attributes:
            continue
        if blocks.get(payload["trace_id"]) != TARGET_BLOCK:
            continue
        k = int(attributes["aiops.request.index"])
        if k in found:
            raise InputError(f"request {k} appears twice in the target block")
        found[k] = int(span["startTimeUnixNano"]) // 1000
    requests = tuple(sorted(found.items()))
    if any(a[1] >= b[1] for a, b in zip(requests, requests[1:], strict=False)):
        raise InputError("target-block request times are not strictly increasing")
    return requests


# ---------------------------------------------------------------------------------------------------------------
# The guarded decision reader
# ---------------------------------------------------------------------------------------------------------------
class ReaderSeparationError(PermissionError):
    """The decision reader tried to open an evaluation-only or side-channel file."""


READER_ALLOWED = ("evidence/accepted_evidence.jsonl", "evidence/protocol.json")
_FORBIDDEN_DIRS = ("ground_truth", "evaluation_only")
_FORBIDDEN_NAMES = ("capture.json", "incident.json")
_GUARD: list[Path] = []
_HOOK_INSTALLED = False


def forbidden_for_reader(path: str, capture_dirs: Iterable[Path] = ()) -> str | None:
    """Why the reader may not open ``path`` (None if allowed)."""
    p = Path(path)
    parts = p.parts
    if any(part in _FORBIDDEN_DIRS for part in parts):
        return "evaluation-only directory"
    if p.name in _FORBIDDEN_NAMES:
        return f"{p.name} is not a decision input"
    resolved = Path(os.path.abspath(path))
    for capture in capture_dirs:
        try:
            inside = resolved.relative_to(capture).as_posix()
        except ValueError:
            continue
        if inside not in READER_ALLOWED:
            return f"{inside} is not one of the reader's two inputs"
    return None


def _audit(event, args):
    if event != "open" or not _GUARD:
        return
    target = args[0] if args else None
    if target is None or isinstance(target, int):
        return
    try:
        path = os.fsdecode(os.fspath(target))
    except TypeError:
        return
    why = forbidden_for_reader(path, tuple(_GUARD))
    if why is not None:
        raise ReaderSeparationError(f"decision reader may not open {path}: {why}")


def _install_hook() -> None:
    global _HOOK_INSTALLED
    if not _HOOK_INSTALLED:
        sys.addaudithook(_audit)
        _HOOK_INSTALLED = True


@contextmanager
def reader_guard(capture_dir: Path | str):
    """While active, opening any forbidden path (anywhere) or any non-input file of ``capture_dir`` raises."""
    _install_hook()
    _GUARD.append(Path(os.path.abspath(capture_dir)))
    try:
        yield
    finally:
        _GUARD.pop()


@dataclass(frozen=True)
class CaptureInputs:
    """Everything the decision reader extracts from one capture (no evaluation-only field)."""
    capture_id: str
    protocol_json: str
    records: tuple[InputRecord, ...]
    requests: tuple[tuple[int, int], ...]
    notes_json: str
    source: str

    @property
    def protocol(self) -> dict:
        return json.loads(self.protocol_json)

    @property
    def notes(self) -> dict:
        return json.loads(self.notes_json)

    def serialize(self) -> str:
        """Canonical text of every input (used for the byte-identity side-channel check)."""
        return canonical({"capture_id": self.capture_id, "protocol": self.protocol,
                          "records": [dict(r.to_dict(), payload=json.loads(r.payload_json)) for r in self.records],
                          "requests": [list(x) for x in self.requests], "notes": self.notes})


def read_capture(capture_dir: Path | str, *, reader=None) -> CaptureInputs:
    """The decision reader: opens only evidence/accepted_evidence.jsonl and evidence/protocol.json (guarded)."""
    capture_dir = Path(capture_dir).resolve()
    with reader_guard(capture_dir):
        if reader is not None:          # test hook: a reader variant runs under the same guard
            reader(capture_dir)
        text = (capture_dir / "evidence/accepted_evidence.jsonl").read_text(encoding="utf-8")
        protocol = json.loads((capture_dir / "evidence/protocol.json").read_text(encoding="utf-8"))
    rows = [(n, json.loads(line)) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    source = f"{capture_dir.name}/evidence/accepted_evidence.jsonl"     # location-independent provenance
    records, notes = records_from_rows(rows, source)
    requests = requests_from_rows(rows)
    capture_id = protocol.get("capture_id") or capture_dir.name
    return CaptureInputs(capture_id, canonical(protocol), records, requests, canonical(notes), source)


# ---------------------------------------------------------------------------------------------------------------
# Streams: the delay grid applied to every copy of the change record
# ---------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class StreamSpec:
    name: str
    shift_seconds: float = 0.0
    drop: bool = False
    scorr: bool = False
    kinds: tuple[str, ...] = CHANGE_KINDS
    note: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "shift_seconds": self.shift_seconds, "drop": self.drop, "scorr": self.scorr,
                "kinds": list(self.kinds), "note": self.note}


STREAMS = (
    StreamSpec("S0", 0.0, note="measured receipt time (S0 control at Delta = 0)"),
    StreamSpec("S30", 30.0, note="+30 s"),
    StreamSpec("S150", 150.0, note="+150 s"),
    StreamSpec("S180", 180.0, note="+180 s"),
    StreamSpec("S300", 300.0, note="+300 s"),
    StreamSpec("S1200", 1200.0, note="+1200 s"),
    StreamSpec("Snever", drop=True, note="change records dropped"),
    StreamSpec("Scorr", scorr=True, note="constructed (SIMULATED; software fixture only): completion first recorded "
                                         "at the patch response, corrected at the real wait receipt"),
)
STREAM_BY_NAME = {s.name: s for s in STREAMS}
CAPTURE_STREAMS = ("S0", "S30", "S150", "S180", "S300", "S1200", "Snever")
FIXTURE_ONLY_STREAMS = ("Scorr",)                                           # labelled fixture
assert sorted(CAPTURE_STREAMS + FIXTURE_ONLY_STREAMS) == sorted(STREAM_BY_NAME)


def _as_replay(records: Sequence[InputRecord]) -> tuple:
    out = []
    for r in records:
        observed = r.observed_at if r.observed_at is not None else r.available_at
        out.append(R.Record(r.id, r.subject, r.kind, "input", observed, r.available_at, kind=r.kind,
                            corrects=r.corrects))
    return tuple(out)


def scorr_records(records: Sequence[InputRecord]) -> tuple[tuple[InputRecord, ...], dict]:
    """Scorr: a stale completion version (response time R, available with the patch receipt, SIMULATED) and the
    real wait receipt as its correction (``corrects`` = the stale ID)."""
    patches = [r for r in records if r.kind == CHANGE_PATCH]
    waits = [r for r in records if r.kind == CHANGE_WAIT]
    if len(patches) != 1 or len(waits) != 1:
        return tuple(records), {"perturbation": "scorr", "applicable": False,
                                "reason": f"{len(patches)} patch / {len(waits)} wait rows"}
    patch, wait = patches[0], waits[0]
    payload = wait.payload()
    response = patch.payload_view()["patch_receipt"]["response_received_at"]
    payload["wait_receipt"] = dict(payload["wait_receipt"], response_received_at=response)
    payload["SIMULATED"] = "Scorr stale version: completion recorded at the patch response"
    stale = InputRecord(wait.id + "#scorr-stale", CHANGE_WAIT, wait.subject, ts_us(response), patch.available_at,
                        canonical(payload), wait.source + " (Scorr stale version)", None, wait.deployment_uid,
                        wait.revision, simulated=True)
    corrected = replace(wait, corrects=stale.id)
    out = []
    for r in records:
        if r.id == wait.id:
            out.extend((stale, corrected))
        else:
            out.append(r)
    R.Stream(_as_replay(out))   # validates IDs and that the correction arrives after the stale version
    manifest = {"perturbation": "scorr", "applicable": True,
                "stale": {"record_id": stale.id, "observed_at": R.iso(stale.observed_at),
                          "available_at": R.iso(stale.available_at)},
                "corrected": {"record_id": corrected.id, "corrects": stale.id,
                              "available_at": R.iso(corrected.available_at)}}
    return tuple(out), manifest


def perturb(records: Sequence[InputRecord], spec: StreamSpec) -> tuple[tuple[InputRecord, ...], dict]:
    """Apply one stream to the change rows (``spec.kinds``) through replay.delay / replay.drop; pure."""
    records = tuple(records)
    R.Stream(_as_replay(records))                     # unique IDs, valid correction links
    if spec.scorr:
        out, manifest = scorr_records(records)
        return out, dict(manifest, stream=spec.name)
    replayed = _as_replay(records)
    if spec.drop:
        kept, manifest = R.drop(replayed, 1.0, 0, kinds=spec.kinds)
        keep = {r.record_id for r in kept}
        out = tuple(r for r in records if r.id in keep)
    else:
        shifted, manifest = R.delay(replayed, spec.shift_seconds, kinds=spec.kinds)
        availability = {r.record_id: r.available_at for r in shifted}
        out = tuple(r if availability[r.id] == r.available_at else replace(r, available_at=availability[r.id])
                    for r in records)
    return out, dict(manifest, stream=spec.name)


# ---------------------------------------------------------------------------------------------------------------
# A's binding and per-capture constants
# ---------------------------------------------------------------------------------------------------------------
def configuration_payload(records: Sequence[InputRecord]) -> dict:
    rows = [r for r in records if r.kind == CONFIGURATION]
    if len(rows) != 1:
        raise InputError(f"expected one configuration row, found {len(rows)}")
    return rows[0].payload()


def service_deployments(records: Sequence[InputRecord]) -> dict:
    """Immutable service -> Deployment map from the configuration row (the live audit's own function)."""
    from .mapping import live_module
    try:
        return live_module().deployments_from_configuration(configuration_payload(records))
    except SystemExit as exc:          # the live audit's check() aborts with SystemExit
        raise InputError(str(exc)) from None


def planned_service(records: Sequence[InputRecord]) -> str | None:
    change = (configuration_payload(records).get("incident") or {}).get("change") or {}
    return change.get("service")


def bind(records: Sequence[InputRecord], patch_request_at: int | None) -> Binding:
    """A's identity from the plan entry and the cluster sightings only (never from a change receipt).

    The Deployment is the plan's changed service mapped through the configuration row's manifests; u_C, r_C and g_C
    come from its earliest sighting; every sighting before the patch request must show u_C at r_C (and g_C)."""
    service = planned_service(records)
    if not service:
        raise InputError("the configuration row names no planned change")
    mapping = service_deployments(records)
    if service not in mapping:
        raise InputError(f"{service} has no Deployment in the configuration row")
    name = mapping[service]
    rows = []
    for r in records:
        if r.kind != API:
            continue
        resource = r.payload_view()["resource_data"]
        if resource["kind"] == "Deployment" and resource["metadata"]["name"] == name and r.corrects is None:
            rows.append(r)
    rows.sort(key=lambda r: (r.observed_at, r.id))
    if not rows:
        raise InputError(f"no sighting of Deployment {name}")
    earliest = rows[0]
    meta = earliest.payload_view()["resource_data"]["metadata"]
    revision = _revision_of(meta)
    generation = meta.get("generation")
    if revision is None or isinstance(generation, bool) or not isinstance(generation, int):
        raise InputError(f"{earliest.id}: earliest sighting lacks an integer revision or generation")
    uid = meta["uid"]
    if patch_request_at is not None:
        for r in rows:
            if r.observed_at >= patch_request_at:
                continue
            m = r.payload_view()["resource_data"]["metadata"]
            if m["uid"] != uid or _revision_of(m) != revision or m.get("generation") != generation:
                raise InputError(f"{r.id}: Deployment sighting before the patch request is not u_C at r_C/g_C")
    rs_uid = template_hash = None
    replicasets = []
    for r in records:
        if r.kind == API and r.deployment_uid == uid and r.subject.startswith("ReplicaSet/") and r.revision == revision:
            replicasets.append(r)
    if replicasets:
        first = min(replicasets, key=lambda r: (r.observed_at, r.id))
        rs_meta = first.payload_view()["resource_data"]["metadata"]
        rs_uid = rs_meta["uid"]
        template_hash = (rs_meta.get("labels") or {}).get("pod-template-hash")
    return Binding(service, name, uid, revision, generation, earliest.id, rs_uid, template_hash)


def bound_change_records(records: Sequence[InputRecord], binding: Binding | None) -> tuple[InputRecord, ...]:
    """Set the bound revision on change rows: receipts bind through deployment_uid, and to r_C + 1 as the plan's
    single change. Unbound rows keep ``revision`` None."""
    if binding is None:
        return tuple(records)
    out = []
    for r in records:
        if r.kind in CHANGE_KINDS and r.deployment_uid == binding.deployment_uid and r.revision is None:
            out.append(replace(r, revision=binding.changed_revision))
        else:
            out.append(r)
    return tuple(out)


def patch_request_at(records: Sequence[InputRecord]) -> int | None:
    """P: the patch request start of the (unperturbed) patch row; None for a capture without a change."""
    patches = [r for r in records if r.kind == CHANGE_PATCH and r.corrects is None]
    if not patches:
        return None
    if len(patches) > 1:
        raise InputError("more than one patch row")
    return change_record(patches[0]).request_started_at


def horizon(records: Sequence[InputRecord]) -> int:
    """H: the last availability of the capture's cluster records (never shifted, so equal in every stream)."""
    times = [r.available_at for r in records if r.kind == API]
    if not times:
        raise InputError("no cluster records")
    return max(times)


# ---------------------------------------------------------------------------------------------------------------
# Input coverage (the dry run): field presence only, no rule is evaluated
# ---------------------------------------------------------------------------------------------------------------
def input_coverage(ci: CaptureInputs) -> dict:
    records = ci.records
    kinds = ci.notes["rows_by_kind"]
    out = {"capture": ci.capture_id, "source": ci.source, "rows_by_kind": kinds,
           "requests_target_block": len(ci.requests),
           "request_indices": [ci.requests[0][0], ci.requests[-1][0]] if ci.requests else None,
           "request_indices_are_1_to_n": [k for k, _ in ci.requests] == list(range(1, len(ci.requests) + 1)),
           "api_available_ns_vs_payload_mismatch": ci.notes["api_available_ns_vs_payload_mismatch"],
           "change_available_vs_receipt_mismatch": ci.notes["change_available_vs_receipt_mismatch"]}
    config = [r for r in records if r.kind == CONFIGURATION]
    service = None
    mapping = {}
    if len(config) == 1:
        change = (config[0].payload_view().get("incident") or {}).get("change") or {}
        service = change.get("service")
        try:
            mapping = service_deployments(records)
        except InputError as exc:
            mapping = {"error": str(exc)}
    out["configuration"] = {"rows": len(config), "planned_change_service_present": bool(service),
                            "planned_change_service": service,
                            "service_mapped_to_deployment": bool(service) and service in mapping}
    deployment_name = mapping.get(service) if service and isinstance(mapping, dict) else None
    fields = ("observedGeneration", "replicas", "updatedReplicas", "readyReplicas", "availableReplicas",
              "unavailableReplicas")

    def tally(rows):
        result = {"rows": len(rows), "metadata.generation": 0, "revision_annotation": 0, "spec.replicas": 0,
                  "status.conditions": 0, **{f"status.{f}": 0 for f in fields}}
        for r in rows:
            res = r.payload_view()["resource_data"]
            meta, spec, status = res.get("metadata") or {}, res.get("spec") or {}, res.get("status") or {}
            result["metadata.generation"] += "generation" in meta
            result["revision_annotation"] += REVISION_ANNOTATION in (meta.get("annotations") or {})
            result["spec.replicas"] += spec.get("replicas") is not None
            result["status.conditions"] += "conditions" in status
            for f in fields:
                result[f"status.{f}"] += f in status
        return result

    deployments = [r for r in records if r.kind == API and r.subject.startswith("Deployment/")]
    planned = [r for r in deployments
               if deployment_name and r.payload_view()["resource_data"]["metadata"]["name"] == deployment_name]
    replicasets = [r for r in records if r.kind == API and r.subject.startswith("ReplicaSet/")]
    out["deployment_rows_all"] = tally(deployments)
    out["deployment_rows_planned_service"] = tally(planned)
    out["deployment_uids_planned_service"] = len({r.subject for r in planned})
    out["replicaset_rows"] = {"rows": len(replicasets),
                              "revision_annotation": sum(r.revision is not None for r in replicasets),
                              "pod_template_hash_label": sum(
                                  "pod-template-hash" in (r.payload_view()["resource_data"]["metadata"].get("labels")
                                                          or {}) for r in replicasets),
                              "deployment_owner": sum(r.deployment_uid is not None for r in replicasets)}
    change = {}
    for kind, key in ((CHANGE_PATCH, "patch_receipt"), (CHANGE_WAIT, "wait_receipt")):
        rows = [r for r in records if r.kind == kind]
        entry = {"rows": len(rows)}
        for r in rows:
            payload = r.payload_view()
            receipt = payload.get(key) or {}
            entry["fields_present"] = sorted(k for k in ("request_started_at", "response_received_at",
                                                         "collector_available_at", "exit_code", "args")
                                             if k in receipt)
            entry["deployment_uid_present"] = bool(r.deployment_uid)
            if kind == CHANGE_PATCH:
                entry["payload_deployment_uid_present"] = "deployment_uid" in payload
            else:
                entry["wait_exit_code_present"] = "wait_exit_code" in payload
                entry["timeout_arg_present"] = any(str(a).startswith("--timeout=") for a in receipt.get("args", []))
        change[kind] = entry
    out["change_records"] = change
    return out
