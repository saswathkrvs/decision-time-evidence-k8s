"""Append-only, knowledge-only evidence graph and independent SQLite selection.

No relationship-validity intervals or diagnostic scores are inferred here.
Integer UTC nanoseconds are acceptance-clock values, never source-event values.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def timestamp_ns(value: str) -> int:
    """Strict UTC ISO parser; preserves up to nine fractional digits exactly."""
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|\+00:00)", value)
    if not match:
        raise ValueError("Expected UTC ISO time with at most nanosecond precision")
    base = datetime.fromisoformat(match[1]).replace(tzinfo=timezone.utc)
    delta = base - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or "").ljust(9, "0"))


def _text(value):
    if not isinstance(value, str) or not value.strip() or value.strip() != value:
        raise ValueError("Expected nonempty text without outer whitespace")
    return value


def _ns(value):
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("Expected nonnegative signed-64-bit nanoseconds")
    return value


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    logical_id: str
    kind: str
    subject: str
    payload_json: str
    supports: tuple[str, ...]
    supersedes: tuple[str, ...]
    source_ref: str
    source_sha256: str
    acquired_at: str | None = None

    def __post_init__(self):
        for field in ("evidence_id", "logical_id", "kind", "subject", "source_ref"):
            _text(getattr(self, field))
        payload = json.loads(self.payload_json)
        if not isinstance(payload, dict) or canonical(payload) != self.payload_json:
            raise ValueError("Payload must be a canonical JSON object")
        if not re.fullmatch(r"[a-f0-9]{64}", self.source_sha256):
            raise ValueError("Source SHA-256 required")
        for values in (self.supports, self.supersedes):
            if not isinstance(values, tuple) or len(set(values)) != len(values):
                raise ValueError("Dependencies must be unique tuples")
            for value in values:
                _text(value)
                if value == self.evidence_id:
                    raise ValueError("Self dependency/correction")
        if self.acquired_at is not None:
            timestamp_ns(self.acquired_at)

    @property
    def payload(self):
        return json.loads(self.payload_json)

    @classmethod
    def from_dict(cls, value):
        value = dict(value)
        value["payload_json"] = canonical(value.pop("payload"))
        value["supports"] = tuple(value.get("supports", ()))
        value["supersedes"] = tuple(value.get("supersedes", ()))
        return cls(**value)

    def to_dict(self):
        value = asdict(self)
        value["payload"] = json.loads(value.pop("payload_json"))
        return value


@dataclass(frozen=True)
class Accepted:
    evidence: Evidence
    available_ns: int

    def __post_init__(self):
        if not isinstance(self.evidence, Evidence):
            raise ValueError("Expected Evidence")
        _ns(self.available_ns)
        if self.evidence.acquired_at is not None:
            if timestamp_ns(self.evidence.acquired_at) > self.available_ns:
                raise ValueError("Acceptance precedes recorded host acquisition")


def validate_history(rows: Iterable[Accepted]) -> tuple[Accepted, ...]:
    """Unordered input allowed; supports/corrections must already be accepted.

    Explicit supersession withdraws its target permanently from that cutoff.
    A later correction does not resurrect a withdrawn predecessor. A derived
    row whose support is withdrawn becomes unavailable until rematerialized.
    """
    rows = tuple(rows)
    if not all(isinstance(row, Accepted) for row in rows):
        raise ValueError("Expected Accepted records")
    by_id = {row.evidence.evidence_id: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("Duplicate evidence IDs are not idempotent imports")
    graph = {}
    for row in rows:
        record = row.evidence
        graph[record.evidence_id] = record.supports + record.supersedes
        for dependency in graph[record.evidence_id]:
            if dependency not in by_id:
                raise ValueError("Missing prerequisite")
            prior = by_id[dependency]
            if prior.available_ns > row.available_ns:
                raise ValueError("Derived availability precedes prerequisite")
        for target in record.supersedes:
            old = by_id[target]
            if old.available_ns >= row.available_ns:
                raise ValueError("Correction must follow its target")
            if (old.evidence.logical_id, old.evidence.kind) != (record.logical_id, record.kind):
                raise ValueError("Correction scope mismatch")
    visiting, done = set(), set()
    def visit(key):
        if key in visiting:
            raise ValueError("Cyclic evidence dependencies")
        if key in done:
            return
        visiting.add(key)
        for parent in graph[key]:
            visit(parent)
        visiting.remove(key)
        done.add(key)
    for key in graph:
        visit(key)
    # Each correction targets the current version, rather than branching.
    groups = {}
    for row in rows:
        groups.setdefault((row.evidence.kind, row.evidence.logical_id), []).append(row)
    for versions in groups.values():
        versions.sort(key=lambda row: (row.available_ns, row.evidence.evidence_id))
        for previous, current in zip(versions, versions[1:]):
            if current.evidence.supersedes != (previous.evidence.evidence_id,):
                raise ValueError("Duplicate logical key or correction branch")
    return rows


def _readiness(rows, readiness_ns=None):
    """Validate a persisted readiness gate for every stored logical record."""
    gates = ({row.evidence.evidence_id: row.available_ns for row in rows}
             if readiness_ns is None else dict(readiness_ns))
    if set(gates) != {row.evidence.evidence_id for row in rows}:
        raise ValueError("Readiness gates must cover exactly the evidence IDs")
    effective = []
    for row in rows:
        ready = _ns(gates[row.evidence.evidence_id])
        if ready < row.available_ns:
            raise ValueError("Readiness gate precedes logical acceptance")
        effective.append(Accepted(row.evidence, ready))
    validate_history(effective)
    return gates


class EvidenceGraph:
    """Evidence nodes, support edges and explicit withdrawal edges."""
    def __init__(self, rows=(), *, readiness_ns=None):
        self.rows = validate_history(rows)
        self._nodes = {row.evidence.evidence_id: row for row in self.rows}
        self.readiness_ns = _readiness(self.rows, readiness_ns)

    def visible(self, cutoff_ns: int, *, kind=None, subject=None) -> tuple[Accepted, ...]:
        _ns(cutoff_ns)
        candidates = {key: Accepted(row.evidence, self.readiness_ns[key])
                      for key, row in self._nodes.items() if self.readiness_ns[key] <= cutoff_ns}
        withdrawn = {target for row in candidates.values() for target in row.evidence.supersedes}
        cache = {}
        def eligible(key):
            if key not in cache:
                cache[key] = key in candidates and key not in withdrawn and all(
                    eligible(parent) for parent in candidates[key].evidence.supports)
            return cache[key]
        return tuple(candidates[key] for key in sorted(candidates) if eligible(key)
                     and (kind is None or candidates[key].evidence.kind == kind)
                     and (subject is None or candidates[key].evidence.subject == subject))


class EvidenceSqlite:
    """Relational cutoff/withdrawal/dependency filtering with a recursive CTE."""
    def __init__(self, rows=(), *, readiness_ns=None):
        self.rows = validate_history(rows)
        self.readiness_ns = _readiness(self.rows, readiness_ns)
        self.connection = sqlite3.connect(":memory:")
        self.connection.executescript("""
            CREATE TABLE evidence(id TEXT PRIMARY KEY, logical_id TEXT, kind TEXT,
                subject TEXT, available_ns INTEGER, record TEXT);
            CREATE TABLE support(child TEXT, parent TEXT, PRIMARY KEY(child,parent));
            CREATE TABLE withdrawal(correction TEXT, target TEXT, PRIMARY KEY(correction,target));
            CREATE INDEX lookup ON evidence(kind,subject,available_ns);
        """)
        self.connection.executemany("INSERT INTO evidence VALUES (?,?,?,?,?,?)", [
            (r.evidence.evidence_id, r.evidence.logical_id, r.evidence.kind, r.evidence.subject,
             r.available_ns, canonical(r.evidence.to_dict())) for r in self.rows])
        self.connection.executemany("INSERT INTO support VALUES (?,?)", [
            (r.evidence.evidence_id, p) for r in self.rows for p in r.evidence.supports])
        self.connection.executemany("INSERT INTO withdrawal VALUES (?,?)", [
            (r.evidence.evidence_id, p) for r in self.rows for p in r.evidence.supersedes])
        self.connection.commit()

    def visible(self, cutoff_ns: int, *, kind=None, subject=None) -> tuple[Accepted, ...]:
        _ns(cutoff_ns)
        rows = self.connection.execute("""
            WITH RECURSIVE
            gated AS (
                SELECT e.*, CAST(g.value AS INTEGER) AS ready_ns
                FROM evidence e JOIN json_each(:readiness) g ON g.key=e.id
            ),
            visible AS (SELECT * FROM gated WHERE ready_ns <= :cutoff),
            blocked(id) AS (
                SELECT e.id FROM gated e WHERE e.ready_ns > :cutoff
                UNION
                SELECT w.target FROM withdrawal w JOIN visible v ON v.id=w.correction
                UNION
                SELECT s.child FROM support s JOIN blocked b ON b.id=s.parent
            )
            SELECT v.record,v.ready_ns FROM visible v
            WHERE NOT EXISTS (SELECT 1 FROM blocked b WHERE b.id=v.id)
              AND (:kind IS NULL OR v.kind=:kind)
              AND (:subject IS NULL OR v.subject=:subject)
            ORDER BY v.id
        """, {"cutoff": cutoff_ns, "kind": kind, "subject": subject,
              "readiness": canonical(self.readiness_ns)}).fetchall()
        return tuple(Accepted(Evidence.from_dict(json.loads(record)), accepted) for record, accepted in rows)

    def close(self):
        self.connection.close()


class ImportSession:
    """Single-writer import with a fail-closed, post-readiness publication gate.

    Candidate graph and SQLite stores are built and read back before a measured
    confirmation, then the final stores are built and read back. A second
    measured boundary gates those prepared stores before publication under the
    session lock. It records conservative process readiness, not an exact
    durable-commit or concurrent-reader visibility instant. No data store is
    rebuilt after this gate. Persist logical_rows and readiness_ns together to
    reconstruct both timing meanings; rows contains effective ready times.
    """
    def __init__(self, wall_clock: Callable[[], int] = time.time_ns,
                 monotonic_clock: Callable[[], int] = time.monotonic_ns):
        self._wall, self._mono = wall_clock, monotonic_clock
        self.rows = ()
        self.logical_rows = ()
        self.readiness_ns = {}
        self.receipts = []
        self.graph = EvidenceGraph()
        self.sql = EvidenceSqlite()
        self._lock = threading.RLock()

    def ingest(self, records: Iterable[Evidence]):
        with self._lock:
            records = tuple(records)
            if not records:
                raise ValueError("Empty import batch")
            started, mono_start = self._wall(), self._mono()
            _ns(started)
            if self.receipts and started <= self.receipts[-1]["ready_ns"]:
                raise ValueError("Host wall-clock rollback/repeated boundary; fail closed")
            # Provisional values are never published as actual acceptance.
            draft_rows = self.logical_rows + tuple(Accepted(e, started) for e in records)
            draft_gates = self.readiness_ns | {e.evidence_id: started for e in records}
            candidate_graph = EvidenceGraph(draft_rows, readiness_ns=draft_gates)
            candidate_sql = EvidenceSqlite(draft_rows, readiness_ns=draft_gates)
            try:
                left, right = candidate_graph.visible(started), candidate_sql.visible(started)
                if left != right:
                    raise ValueError("Backend readiness mismatch")
            finally:
                candidate_sql.close()
            confirmed, mono_end = self._wall(), self._mono()
            if confirmed < started or mono_end < mono_start:
                raise ValueError("Clock rollback during ingestion; fail closed")
            _ns(confirmed)
            confirmed_rows = self.logical_rows + tuple(Accepted(e, confirmed) for e in records)
            confirmed_gates = self.readiness_ns | {e.evidence_id: confirmed for e in records}
            graph = EvidenceGraph(confirmed_rows, readiness_ns=confirmed_gates)
            sql = EvidenceSqlite(confirmed_rows, readiness_ns=confirmed_gates)
            try:
                if graph.visible(confirmed) != sql.visible(confirmed):
                    raise ValueError("Final backend readiness mismatch")
                ready, mono_ready = self._wall(), self._mono()
                _ns(ready)
                if ready < confirmed or mono_ready < mono_end:
                    raise ValueError("Clock rollback before publication; fail closed")
                gates = self.readiness_ns | {e.evidence_id: ready for e in records}
                # The prepared stores receive metadata only; no rebuild follows
                # this readiness boundary. All new members share one gate.
                graph.readiness_ns = dict(gates)
                sql.readiness_ns = dict(gates)
            except BaseException:
                sql.close()
                raise
            receipt = {"sequence": len(self.receipts) + 1, "started_ns": started,
                "confirmed_available_ns": confirmed, "ready_ns": ready, "available_ns": ready,
                "confirmation_elapsed_ns": mono_end - mono_start,
                "readiness_elapsed_ns": mono_ready - mono_start,
                "record_count": len(records), "record_ids": [e.evidence_id for e in records],
                "semantics": "logical confirmation plus final-store process-readiness gate; not exact durable commit or historical live ingestion"}
            self.sql.close()
            self.logical_rows = confirmed_rows
            self.rows = tuple(Accepted(row.evidence, gates[row.evidence.evidence_id]) for row in confirmed_rows)
            self.readiness_ns, self.graph, self.sql = gates, graph, sql
            self.receipts.append(receipt)
            return receipt

    def query(self, backend, cutoff_ns, **kwargs):
        with self._lock:
            if backend not in ("graph", "sqlite"):
                raise ValueError("Unknown backend")
            return (self.graph if backend == "graph" else self.sql).visible(cutoff_ns, **kwargs)

    def close(self):
        self.sql.close()


def derived_record(kind, logical_id, subject, payload, supports, supersedes=()):
    """A version's identity binds its full payload, supports and policy version."""
    body = {"kind": kind, "logical_id": logical_id, "subject": subject,
            "payload": payload, "supports": sorted(set(supports)), "supersedes": list(supersedes),
            "policy_version": "identity-observation-v1"}
    digest = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    return Evidence.from_dict({k: body[k] for k in ("kind", "logical_id", "subject", "payload", "supports", "supersedes")} | {
        "evidence_id": "derived:" + digest, "source_ref": "policy:identity-observation-v1",
        "source_sha256": digest, "acquired_at": None})
