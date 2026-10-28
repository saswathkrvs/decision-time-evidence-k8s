"""Declarative governance policy gate over a bitemporal operational view.

Research prototype; it never executes an action and makes no safety claim.

A proposed remediation action (restart_pod, delete_pod, scale_deployment,
rollback_deployment, drain_node) is evaluated against the operational view
assembled from the existing ``aiops_kg.temporal`` stores **as of a knowledge
cutoff** (availability time) for a given **observation time** (valid time).
Six named rules each return ALLOW / NEEDS_APPROVAL / ABSTAIN / DENY with a
reason code, a human-readable detail and the record (fact) IDs they used. The
combined verdict is the most severe: DENY > ABSTAIN > NEEDS_APPROVAL > ALLOW.

Unknown is an explicit answer: a rule that cannot establish what it needs from
the view returns ABSTAIN instead of guessing. No function reads the wall clock
or uses randomness, so evaluation is deterministic.

The module also provides ``materialize_facts``: a deterministic mapping from
timestamped observations (snapshot sightings, command receipts) to immutable
``Fact`` versions under the explicitly labelled carry-forward assumption A1.
A1 is a modelling assumption, not proven Kubernetes validity.
"""
from __future__ import annotations

import math
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Mapping

from aiops_kg.temporal import Fact, GraphStore, Resolution, SqliteStore

UTC = timezone.utc

# --------------------------------------------------------------------------
# Verdicts and vocabulary
# --------------------------------------------------------------------------
ALLOW = "ALLOW"
NEEDS_APPROVAL = "NEEDS_APPROVAL"
ABSTAIN = "ABSTAIN"
DENY = "DENY"
SEVERITY = {ALLOW: 0, NEEDS_APPROVAL: 1, ABSTAIN: 2, DENY: 3}
VERDICTS = tuple(sorted(SEVERITY, key=SEVERITY.__getitem__))
BLOCKING = frozenset({NEEDS_APPROVAL, ABSTAIN, DENY})

ACTION_TARGET_KIND = {
    "restart_pod": "Pod",
    "delete_pod": "Pod",
    "scale_deployment": "Deployment",
    "rollback_deployment": "Deployment",
    "drain_node": "Node",
}
ACTION_KINDS = tuple(ACTION_TARGET_KIND)
# Every supported action mutates cluster state, so all are subject to R4.
MUTATING_ACTIONS = frozenset(ACTION_KINDS)
OBJECT_KINDS = frozenset({"Pod", "ReplicaSet", "Deployment", "Node"})

# Predicates used by the operational view. All except NAME are single-valued
# at a given valid time and are read through the temporal resolver.
STATE = "STATE"            # Pod: ready|not_ready|terminating|failed|succeeded|absent; others: present|absent
CONTROLLER = "CONTROLLER"  # Pod -> "ReplicaSet/<uid>", ReplicaSet -> "Deployment/<uid>"
GENERATION = "GENERATION"  # Deployment/ReplicaSet metadata.generation (spec-change counter)
NODE = "NODE"              # Pod -> "NodeName/<spec.nodeName>" (name-valued binding, no Node UID)
NAME = "NAME"              # identity property; knowledge-only lookup; valid_from = creation time

POD_CURRENT_STATES = frozenset({"ready", "not_ready"})
POD_GONE_STATES = frozenset({"absent", "failed", "succeeded"})

# Documented Online Boutique call graph (caller, callee), using the Online
# Boutique Deployment names; "cart -> redis" is cartservice -> redis-cart.
ONLINE_BOUTIQUE_CALL_GRAPH = (
    ("frontend", "adservice"),
    ("frontend", "cartservice"),
    ("frontend", "checkoutservice"),
    ("frontend", "currencyservice"),
    ("frontend", "productcatalogservice"),
    ("frontend", "recommendationservice"),
    ("frontend", "shippingservice"),
    ("checkoutservice", "cartservice"),
    ("checkoutservice", "currencyservice"),
    ("checkoutservice", "emailservice"),
    ("checkoutservice", "paymentservice"),
    ("checkoutservice", "productcatalogservice"),
    ("checkoutservice", "shippingservice"),
    ("recommendationservice", "productcatalogservice"),
    ("cartservice", "redis-cart"),
)


def _text(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a nonempty string without outer whitespace")
    return value


def _utc(value, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(UTC)


def _seconds(value, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite nonnegative number")
    if not math.isfinite(float(value)) or value < 0:
        raise ValueError(f"{name} must be a finite nonnegative number")
    return float(value)


def iso(value: datetime | None) -> str | None:
    """Stable UTC ISO-8601 text with microseconds and a Z suffix."""
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def combine(verdicts: Iterable[str]) -> str:
    """Most severe verdict wins: DENY > ABSTAIN > NEEDS_APPROVAL > ALLOW."""
    items = tuple(verdicts)
    if not items:
        raise ValueError("combine() needs at least one verdict")
    for verdict in items:
        if verdict not in SEVERITY:
            raise ValueError(f"unknown verdict: {verdict!r}")
    return max(items, key=SEVERITY.__getitem__)


def dependents(service: str, edges: Iterable[tuple[str, str]], *,
               direction: str = "downstream", transitive: bool = True) -> tuple[str, ...]:
    """Services reachable from ``service`` in the call graph.

    ``downstream`` follows caller -> callee edges (the services whose request
    paths pass through ``service``); ``upstream`` follows callee -> caller.
    """
    if direction not in ("downstream", "upstream"):
        raise ValueError("direction must be 'downstream' or 'upstream'")
    adjacency: dict[str, set[str]] = defaultdict(set)
    for caller, callee in edges:
        start, end = (caller, callee) if direction == "downstream" else (callee, caller)
        adjacency[start].add(end)
    seen: set[str] = set()
    frontier = [service]
    while frontier:
        node = frontier.pop()
        for nxt in sorted(adjacency.get(node, ())):
            if nxt != service and nxt not in seen:
                seen.add(nxt)
                if transitive:
                    frontier.append(nxt)
    return tuple(sorted(seen))


# --------------------------------------------------------------------------
# Actions, configuration and results
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ObjectRef:
    """Reference to the object an action targets.

    Resolution order: ``uid`` (canonical), then ``name`` (unique name match at
    the cutoff), then ``service`` (the service's Deployment, or its single
    current Pod). With none of these the target is unspecified.
    """
    kind: str
    uid: str | None = None
    name: str | None = None
    service: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in OBJECT_KINDS:
            raise ValueError(f"unsupported object kind: {self.kind!r}")
        for attr in ("uid", "name", "service"):
            value = getattr(self, attr)
            if value is not None:
                _text(value, attr)


@dataclass(frozen=True, slots=True)
class Action:
    """A proposed (never executed) remediation action."""
    action_id: str
    kind: str
    target: ObjectRef
    service: str | None = None
    replicas: int | None = None

    def __post_init__(self) -> None:
        _text(self.action_id, "action_id")
        if self.kind not in ACTION_TARGET_KIND:
            raise ValueError(f"unsupported action kind: {self.kind!r}")
        if self.target.kind != ACTION_TARGET_KIND[self.kind]:
            raise ValueError(f"{self.kind} requires a {ACTION_TARGET_KIND[self.kind]} target")
        if self.kind != "drain_node":
            _text(self.service, "service")
        elif self.service is not None:
            raise ValueError("drain_node is node-scoped; service must be None")
        if self.kind == "scale_deployment":
            if type(self.replicas) is not int or self.replicas < 0:
                raise ValueError("scale_deployment requires a nonnegative integer replicas")
        elif self.replicas is not None:
            raise ValueError("replicas is only valid for scale_deployment")


@dataclass(frozen=True, slots=True)
class FreezeWindow:
    """Change freeze over valid time [start, end).

    ``declared_at`` is the knowledge time at which the freeze became known; a
    view whose cutoff precedes it does not see the freeze. ``None`` means it
    was configured before any decision considered here.
    """
    label: str
    start: datetime
    end: datetime
    declared_at: datetime | None = None

    def __post_init__(self) -> None:
        _text(self.label, "label")
        object.__setattr__(self, "start", _utc(self.start, "start"))
        object.__setattr__(self, "end", _utc(self.end, "end"))
        if self.end <= self.start:
            raise ValueError("freeze end must be after start")
        if self.declared_at is not None:
            object.__setattr__(self, "declared_at", _utc(self.declared_at, "declared_at"))


def _pairs(value, name: str, value_check) -> tuple:
    items = value.items() if isinstance(value, Mapping) else value
    result = tuple(sorted((_text(k, name), value_check(v)) for k, v in items))
    if len({k for k, _ in result}) != len(result):
        raise ValueError(f"duplicate keys in {name}")
    return result


def _floor_value(value) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("replica floors must be nonnegative integers")
    return value


@dataclass(frozen=True)
class GateConfig:
    """Thresholds and policy inputs. Defaults follow the v1 specification."""
    change_window_seconds: float = 600.0          # R2: N (default 10 minutes)
    replica_floor: int = 1                        # R3 default floor
    replica_floor_by_service: tuple = ()          # R3 per-service floors
    freeze_windows: tuple = ()                    # R4
    call_graph: tuple = ONLINE_BOUTIQUE_CALL_GRAPH  # R5 edge list
    blast_radius_k: int = 3                       # R5: k
    blast_radius_direction: str = "downstream"    # R5 reading of "dependents"
    blast_radius_transitive: bool = True
    stale_view_seconds: float = 300.0             # R6: S
    carry_forward_seconds: float = 600.0          # A1 freshness for known-open facts
    service_deployments: tuple = ()               # service -> Deployment name map

    def __post_init__(self) -> None:
        for name in ("change_window_seconds", "stale_view_seconds", "carry_forward_seconds"):
            object.__setattr__(self, name, _seconds(getattr(self, name), name))
        _floor_value(self.replica_floor)
        if type(self.blast_radius_k) is not int or self.blast_radius_k < 0:
            raise ValueError("blast_radius_k must be a nonnegative integer")
        if self.blast_radius_direction not in ("downstream", "upstream"):
            raise ValueError("blast_radius_direction must be 'downstream' or 'upstream'")
        if not isinstance(self.blast_radius_transitive, bool):
            raise ValueError("blast_radius_transitive must be a bool")
        object.__setattr__(self, "replica_floor_by_service",
                           _pairs(self.replica_floor_by_service, "replica_floor_by_service", _floor_value))
        object.__setattr__(self, "service_deployments",
                           _pairs(self.service_deployments, "service_deployments",
                                  lambda v: _text(v, "deployment name")))
        windows = tuple(self.freeze_windows)
        if not all(isinstance(w, FreezeWindow) for w in windows):
            raise ValueError("freeze_windows must contain FreezeWindow instances")
        object.__setattr__(self, "freeze_windows", tuple(sorted(windows, key=lambda w: (w.start, w.label))))
        edges = tuple((_text(a, "caller"), _text(b, "callee")) for a, b in self.call_graph)
        object.__setattr__(self, "call_graph", edges)

    def floor_for(self, service: str) -> int:
        return dict(self.replica_floor_by_service).get(service, self.replica_floor)

    def deployment_for(self, service: str) -> str | None:
        return dict(self.service_deployments).get(service)

    def service_for_deployment(self, deployment_name: str) -> str | None:
        for service, name in self.service_deployments:
            if name == deployment_name:
                return service
        return None


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule: str
    name: str
    verdict: str
    reason: str
    detail: str
    record_ids: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"rule": self.rule, "name": self.name, "verdict": self.verdict,
                "reason": self.reason, "detail": self.detail, "record_ids": list(self.record_ids)}


@dataclass(frozen=True, slots=True)
class Decision:
    action_id: str
    verdict: str
    observed_at: datetime
    knowledge_cutoff: datetime
    rules: tuple[RuleResult, ...]
    record_ids: tuple[str, ...]
    newest_record_available_at: datetime | None

    @property
    def blocked(self) -> bool:
        return self.verdict in BLOCKING

    @property
    def deciding_rules(self) -> tuple[str, ...]:
        if self.verdict == ALLOW:
            return ()
        return tuple(r.rule for r in self.rules if r.verdict == self.verdict)

    def rule(self, rule_id: str) -> RuleResult:
        for result in self.rules:
            if result.rule == rule_id:
                return result
        raise KeyError(rule_id)

    def explain(self) -> str:
        lines = [f"{self.action_id}: {self.verdict} (observed {iso(self.observed_at)}, "
                 f"knowledge cutoff {iso(self.knowledge_cutoff)})"]
        for r in self.rules:
            lines.append(f"  {r.rule} {r.name}: {r.verdict} [{r.reason}] {r.detail}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"action_id": self.action_id, "verdict": self.verdict,
                "observed_at": iso(self.observed_at), "knowledge_cutoff": iso(self.knowledge_cutoff),
                "deciding_rules": list(self.deciding_rules),
                "rules": [r.to_dict() for r in self.rules], "record_ids": list(self.record_ids),
                "newest_record_available_at": iso(self.newest_record_available_at)}


# --------------------------------------------------------------------------
# Evidence -> bitemporal facts (mapping assumption A1)
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Observation:
    """One timestamped observation of a single-valued (subject, predicate).

    ``observed_at`` is the valid-time instant at which ``value`` was observed to
    hold; ``available_at`` is when the pipeline could use the record.
    ``starts_at`` optionally carries a recorded source transition time at which
    this value began (e.g. object creation), used only when it opens a run.
    """
    record_id: str
    subject: str
    predicate: str
    value: str
    observed_at: datetime
    available_at: datetime
    starts_at: datetime | None = None

    def __post_init__(self) -> None:
        for name in ("record_id", "subject", "predicate", "value"):
            _text(getattr(self, name), name)
        if self.predicate == NAME:
            raise ValueError("NAME is an identity property; use identity_fact()")
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        object.__setattr__(self, "available_at", _utc(self.available_at, "available_at"))
        if self.available_at < self.observed_at:
            raise ValueError("an observation cannot be available before it was observed")
        if self.starts_at is not None:
            object.__setattr__(self, "starts_at", _utc(self.starts_at, "starts_at"))
            if self.starts_at > self.observed_at:
                raise ValueError("starts_at cannot be later than observed_at")


def _derive_runs(known: list[Observation]) -> list[tuple[tuple, tuple[str, ...]]]:
    """Facts implied by the observations known so far (assumption A1).

    Consecutive observations (in valid-time order) with equal values form a run.
    A run is valid from its first observation (or an earlier recorded
    ``starts_at``). A closed run ends at its last observation; the interval up
    to the next run's first observation is left uncovered (explicit
    uncertainty). The final run is known-open, confirmed at its last
    observation. A single-point closed run yields no fact: point observations
    are not intervals.
    """
    ordered = sorted(known, key=lambda o: (o.observed_at, o.record_id))
    runs: list[tuple[str, list[Observation]]] = []
    for obs in ordered:
        if runs and runs[-1][0] == obs.value:
            runs[-1][1].append(obs)
        else:
            if runs and runs[-1][1][-1].observed_at == obs.observed_at:
                raise ValueError(
                    f"conflicting values at one instant for {obs.subject} {obs.predicate}: "
                    f"{runs[-1][1][-1].record_id} vs {obs.record_id}")
            runs.append((obs.value, [obs]))
    derived = []
    for index, (value, items) in enumerate(runs):
        first, last = items[0], items[-1]
        starts = [o.starts_at for o in items if o.starts_at is not None]
        valid_from = min([first.observed_at] + starts)
        support = tuple(sorted(o.record_id for o in items))
        if index + 1 < len(runs):
            following = runs[index + 1][1][0]
            if last.observed_at > valid_from:
                derived.append(((value, valid_from, last.observed_at, False, None),
                                support + (following.record_id,)))
        else:
            derived.append(((value, valid_from, None, True, last.observed_at), support))
    return derived


def materialize_facts(observations: Iterable[Observation]) -> tuple[tuple[Fact, ...], dict[str, tuple[str, ...]]]:
    """Replay observations in availability order into immutable Fact versions.

    At each distinct availability instant the facts implied by everything known
    so far are re-derived. A previously published fact that is no longer
    implied is superseded at that instant; a newly implied fact becomes
    available at that instant. Old versions are never rewritten, so every
    earlier knowledge cutoff remains reproducible. Returns the facts and a map
    from fact ID to the observation record IDs supporting it.
    """
    groups: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    for obs in observations:
        if not isinstance(obs, Observation):
            raise ValueError("materialize_facts accepts Observation instances only")
        # One record may describe several predicates of a subject, but never
        # two values of the same (subject, predicate).
        if any(o.record_id == obs.record_id for o in groups[(obs.subject, obs.predicate)]):
            raise ValueError(f"duplicate record {obs.record_id} for {obs.subject} {obs.predicate}")
        groups[(obs.subject, obs.predicate)].append(obs)
    facts: list[Fact] = []
    support_map: dict[str, tuple[str, ...]] = {}
    for key in sorted(groups):
        items = groups[key]
        by_instant: dict[datetime, list[Observation]] = defaultdict(list)
        for obs in items:
            by_instant[obs.available_at].append(obs)
        availability = {o.record_id: o.available_at for o in items}
        known: list[Observation] = []
        active: dict[tuple, int] = {}
        drafts: list[dict] = []
        for instant in sorted(by_instant):
            known.extend(sorted(by_instant[instant], key=lambda o: o.record_id))
            derived = _derive_runs(known)
            contents = {content for content, _ in derived}
            for content in [c for c in active if c not in contents]:
                drafts[active.pop(content)]["superseded_at"] = instant
            for content, support in derived:
                if content in active:
                    continue
                arrived = [rid for rid in support if availability[rid] == instant]
                trigger = max(arrived) if arrived else max(support, key=lambda r: (availability[r], r))
                drafts.append({"content": content, "available_at": instant, "superseded_at": None,
                               "support": support, "trigger": trigger})
                active[content] = len(drafts) - 1
        subject, predicate = key
        for number, draft in enumerate(drafts, start=1):
            value, valid_from, valid_to, known_open, confirmed_at = draft["content"]
            fact_id = f"{subject}|{predicate}|{value}|{'open' if known_open else 'closed'}|v{number}"
            facts.append(Fact(fact_id=fact_id, subject=subject, predicate=predicate, object=value,
                              valid_from=valid_from, valid_to=valid_to,
                              available_at=draft["available_at"], superseded_at=draft["superseded_at"],
                              source_id=draft["trigger"], known_open=known_open,
                              confirmed_at=confirmed_at))
            support_map[fact_id] = draft["support"]
    return tuple(facts), support_map


def identity_fact(subject: str, name: str, created_at: datetime, available_at: datetime,
                  source_id: str) -> Fact:
    """Knowledge-only identity record: the object's name and creation time.

    Read by ``OperationalView.identity``/``lookup`` only (never ``resolve``).
    ``valid_from`` carries the recorded creation time so that an object created
    after an observation time can be excluded from that time's view.
    """
    return Fact(fact_id=f"{subject}|{NAME}|{name}", subject=subject, predicate=NAME, object=name,
                valid_from=created_at, valid_to=None, available_at=available_at,
                superseded_at=None, source_id=source_id)


# --------------------------------------------------------------------------
# Bitemporal store wrapper and the operational view
# --------------------------------------------------------------------------
class BitemporalStore:
    """Facts plus the existing graph (and optionally SQLite) resolvers."""

    def __init__(self, facts: Iterable[Fact], *, engines: tuple[str, ...] = ("graph",)):
        self.facts = tuple(facts)
        self._by_id = {f.fact_id: f for f in self.facts}
        if len(self._by_id) != len(self.facts):
            raise ValueError("duplicate fact IDs")
        self._by_predicate: dict[str, tuple[Fact, ...]] = {}
        grouped: dict[str, list[Fact]] = defaultdict(list)
        for f in self.facts:
            grouped[f.predicate].append(f)
        self._by_predicate = {p: tuple(sorted(v, key=lambda f: f.fact_id)) for p, v in grouped.items()}
        self._engines: dict[str, object] = {}
        for engine in engines:
            if engine == "graph":
                self._engines[engine] = GraphStore(self.facts)
            elif engine == "sqlite":
                self._engines[engine] = SqliteStore(self.facts)
            else:
                raise ValueError(f"unknown engine {engine!r}")
        self.horizon = max((f.available_at for f in self.facts), default=None)

    def fact(self, fact_id: str) -> Fact:
        return self._by_id[fact_id]

    def facts_for(self, predicate: str) -> tuple[Fact, ...]:
        return self._by_predicate.get(predicate, ())

    def engine(self, name: str):
        return self._engines[name]

    def view(self, observed_at: datetime, knowledge_cutoff: datetime, *,
             carry_forward_seconds: float, engine: str = "graph") -> "OperationalView":
        return OperationalView(self, observed_at, knowledge_cutoff,
                               carry_forward_seconds=carry_forward_seconds, engine=engine)

    def as_known(self, decision_time: datetime, *, carry_forward_seconds: float,
                 engine: str = "graph") -> "OperationalView":
        """Records available at the decision cutoff only."""
        return self.view(decision_time, decision_time,
                         carry_forward_seconds=carry_forward_seconds, engine=engine)

    def corrected(self, decision_time: datetime, *, carry_forward_seconds: float,
                  engine: str = "graph", horizon: datetime | None = None) -> "OperationalView":
        """Hindsight: every record in the store, at the same observation time."""
        cutoff = max(t for t in (decision_time, self.horizon, horizon) if t is not None)
        return self.view(decision_time, cutoff,
                         carry_forward_seconds=carry_forward_seconds, engine=engine)

    def close(self) -> None:
        for engine in self._engines.values():
            if isinstance(engine, SqliteStore):
                engine.close()


class OperationalView:
    """The store as seen at ``knowledge_cutoff`` for ``observed_at``.

    Single-valued relations go through the temporal resolver (graph or SQLite
    engine). Candidate enumeration and name/identity lookups are knowledge-only
    (``available_at <= cutoff < superseded_at``) and never assert validity.
    """

    def __init__(self, store: BitemporalStore, observed_at: datetime, knowledge_cutoff: datetime,
                 *, carry_forward_seconds: float, engine: str = "graph"):
        self.store = store
        self.observed_at = _utc(observed_at, "observed_at")
        self.knowledge_cutoff = _utc(knowledge_cutoff, "knowledge_cutoff")
        if self.observed_at > self.knowledge_cutoff:
            raise ValueError("observed_at cannot be later than knowledge_cutoff")
        self.carry_forward_seconds = _seconds(carry_forward_seconds, "carry_forward_seconds")
        self.engine_name = engine
        self._engine = store.engine(engine)
        self._recorders: list[set[str]] = []
        self._cache: dict[tuple[str, str], Resolution] = {}

    # -- record accounting ---------------------------------------------------
    @contextmanager
    def recording(self) -> Iterator[set[str]]:
        used: set[str] = set()
        self._recorders.append(used)
        try:
            yield used
        finally:
            # Stack discipline with an identity check: equal (e.g. empty) sets
            # must never be confused with one another.
            popped = self._recorders.pop()
            if popped is not used:
                raise RuntimeError("recording scopes exited out of order")

    def _note(self, fact_ids: Iterable[str]) -> None:
        ids = tuple(fact_ids)
        for recorder in self._recorders:
            recorder.update(ids)

    # -- temporal and knowledge-only queries --------------------------------
    def fact(self, fact_id: str) -> Fact:
        return self.store.fact(fact_id)

    def resolve(self, subject: str, predicate: str) -> Resolution:
        key = (subject, predicate)
        if key not in self._cache:
            self._cache[key] = self._engine.resolve(subject, predicate, self.observed_at,
                                                    self.knowledge_cutoff, self.carry_forward_seconds)
        result = self._cache[key]
        self._note(result.fact_ids)
        return result

    def _visible(self, fact: Fact) -> bool:
        return fact.available_at <= self.knowledge_cutoff and (
            fact.superseded_at is None or self.knowledge_cutoff < fact.superseded_at)

    def subjects_with(self, predicate: str, obj: str) -> tuple[str, ...]:
        """Knowledge-only candidate enumeration; validity is checked separately."""
        return tuple(sorted({f.subject for f in self.store.facts_for(predicate)
                             if f.object == obj and self._visible(f)}))

    def identity(self, subject: str) -> tuple[str, str | None, datetime | None, tuple[str, ...]]:
        """(status, name, created_at, fact_ids) from visible NAME records."""
        rows = [f for f in self.store.facts_for(NAME) if f.subject == subject and self._visible(f)]
        ids = tuple(sorted(f.fact_id for f in rows))
        self._note(ids)
        names = {f.object for f in rows}
        if not rows:
            return "unknown", None, None, ids
        if len(names) > 1:
            return "conflict", None, None, ids
        created = max((f.valid_from for f in rows if f.valid_from is not None), default=None)
        return "known", next(iter(names)), created, ids

    def existed_by_observation(self, subject: str) -> bool | None:
        """False if the recorded creation is after the observation time."""
        status, _, created, _ = self.identity(subject)
        if status != "known" or created is None:
            return None
        return created <= self.observed_at

    def lookup(self, kind: str, name: str) -> tuple[str, ...]:
        rows = [f for f in self.store.facts_for(NAME)
                if f.object == name and f.subject.startswith(kind + "/") and self._visible(f)]
        self._note(f.fact_id for f in rows)
        return tuple(sorted({f.subject for f in rows}))


# --------------------------------------------------------------------------
# Shared view analysis used by the rules
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PodInfo:
    key: str
    member: bool | None      # controlled (via its ReplicaSet) by the service Deployment?
    state: str | None        # resolved STATE, None when unknown at this view
    node: str | None         # resolved NODE value, None when unknown
    record_ids: tuple[str, ...]

    @property
    def possibly_member(self) -> bool:
        return self.member is not False

    @property
    def certainly_ready(self) -> bool:
        return self.member is True and self.state == "ready"

    @property
    def possibly_ready(self) -> bool:
        return self.possibly_member and self.state in (None, "ready")

    @property
    def certainly_current(self) -> bool:
        return self.member is True and self.state in POD_CURRENT_STATES

    @property
    def possibly_current(self) -> bool:
        return self.possibly_member and (self.state is None or self.state in POD_CURRENT_STATES)


def _resolved(res: Resolution) -> str | None:
    return res.value if res.status == "resolved" else None


def pod_chain(view: OperationalView, pod_key: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    """(ReplicaSet key, Deployment key, fact_ids); None where unknown."""
    with view.recording() as used:
        rs = _resolved(view.resolve(pod_key, CONTROLLER))
        deployment = _resolved(view.resolve(rs, CONTROLLER)) if rs else None
    return rs, deployment, tuple(sorted(used))


def service_pods(view: OperationalView, deployment_key: str) -> tuple[PodInfo, ...]:
    """Pods that are, or may be, controlled by ``deployment_key`` at this view."""
    pods: list[PodInfo] = []
    seen: set[str] = set()
    for rs in view.subjects_with(CONTROLLER, deployment_key):
        if not rs.startswith("ReplicaSet/") or view.existed_by_observation(rs) is False:
            continue
        for pod in view.subjects_with(CONTROLLER, rs):
            if pod in seen or not pod.startswith("Pod/"):
                continue
            seen.add(pod)
            if view.existed_by_observation(pod) is False:
                continue
            with view.recording() as used:
                pod_rs, pod_deployment, _ = pod_chain(view, pod)
                if pod_rs is None or pod_deployment is None:
                    rs_value = _resolved(view.resolve(pod, CONTROLLER))
                    member = False if rs_value and not rs_value.startswith("ReplicaSet/") else None
                else:
                    member = pod_deployment == deployment_key
                state = _resolved(view.resolve(pod, STATE))
                node = _resolved(view.resolve(pod, NODE))
            pods.append(PodInfo(pod, member, state, node, tuple(sorted(used))))
    return tuple(sorted(pods, key=lambda p: p.key))


def healthy_bounds(pods: Iterable[PodInfo]) -> tuple[int, int]:
    pods = tuple(pods)
    return sum(p.certainly_ready for p in pods), sum(p.possibly_ready for p in pods)


@dataclass(frozen=True, slots=True)
class TargetInfo:
    status: str                    # resolved | not_found | ambiguous | uncertain | unspecified | conflict
    key: str | None
    reason: str
    detail: str
    record_ids: tuple[str, ...]
    deployment_key: str | None     # the stated service's Deployment, if resolvable
    deployment_status: str


def service_deployment(view: OperationalView, config: GateConfig,
                       service: str | None) -> tuple[str, str | None, str]:
    """(status, Deployment key, detail) for a stated service."""
    if service is None:
        return "unspecified", None, "no service stated"
    name = config.deployment_for(service)
    if name is None:
        return "not_found", None, f"service {service!r} has no Deployment mapping"
    matches = view.lookup("Deployment", name)
    if not matches:
        return "not_found", None, f"no Deployment named {name!r} is known at the cutoff"
    if len(matches) > 1:
        return "ambiguous", None, f"{len(matches)} Deployments named {name!r}"
    return "resolved", matches[0], f"service {service!r} -> {matches[0]}"


def resolve_target(action: Action, view: OperationalView, config: GateConfig) -> TargetInfo:
    ref = action.target
    with view.recording() as used:
        d_status, d_key, d_detail = service_deployment(view, config, action.service)
        status, key, reason, detail = "unspecified", None, "no_target_reference", \
            "request names no UID, name or service for the target"
        if ref.uid is not None:
            key = f"{ref.kind}/{ref.uid}"
            ident = view.identity(key)[0]
            if ident == "known":
                status, reason, detail = "resolved", "uid", f"UID reference {key}"
            elif ident == "conflict":
                status, key, reason, detail = "conflict", None, "identity_conflict", \
                    f"conflicting identity records for {key}"
            else:
                status, key, reason, detail = "not_found", None, "unknown_uid", \
                    f"no identity record for {ref.kind}/{ref.uid} is visible at the cutoff"
        elif ref.name is not None:
            matches = view.lookup(ref.kind, ref.name)
            if len(matches) == 1:
                status, key, reason, detail = "resolved", matches[0], "unique_name", \
                    f"name {ref.name!r} -> {matches[0]}"
            elif matches:
                status, reason, detail = "ambiguous", "ambiguous_name", \
                    f"{len(matches)} {ref.kind} objects named {ref.name!r}"
            else:
                status, reason, detail = "not_found", "unknown_name", \
                    f"no {ref.kind} named {ref.name!r} is visible at the cutoff"
        elif ref.service is not None:
            if ref.service != action.service:
                raise ValueError("service-level target must match the action's service")
            if d_status != "resolved":
                status, reason, detail = d_status, "service_" + d_status, d_detail
            elif ref.kind == "Deployment":
                status, key, reason, detail = "resolved", d_key, "service_deployment", d_detail
            elif ref.kind == "Pod":
                pods = service_pods(view, d_key)
                certain = [p for p in pods if p.certainly_current]
                possible = [p for p in pods if p.possibly_current]
                if not possible:
                    status, reason, detail = "not_found", "no_current_instance", \
                        f"no current Pod of {ref.service!r} is known at this view"
                elif len(certain) > 1:
                    status, reason, detail = "ambiguous", "multiple_current_instances", \
                        f"{len(certain)} current Pods of {ref.service!r}; request must name a UID"
                elif len(possible) == 1 and len(certain) == 1:
                    status, key, reason, detail = "resolved", certain[0].key, "single_current_instance", \
                        f"single current Pod of {ref.service!r}: {certain[0].key}"
                else:
                    status, reason, detail = "uncertain", "instance_set_uncertain", \
                        f"{len(certain)} certain / {len(possible)} possible current Pods of {ref.service!r}"
            else:
                status, reason, detail = "unspecified", "unsupported_service_reference", \
                    f"service-level reference is not supported for {ref.kind}"
    return TargetInfo(status, key, reason, detail, tuple(sorted(used)), d_key, d_status)


# --------------------------------------------------------------------------
# Rules. Each takes the evaluation context and returns one RuleResult.
# --------------------------------------------------------------------------
@dataclass(slots=True)
class GateContext:
    action: Action
    view: OperationalView
    config: GateConfig
    target: TargetInfo
    prior_record_ids: tuple[str, ...] = ()


def _result(rule, name, verdict, reason, detail, used) -> RuleResult:
    return RuleResult(rule, name, verdict, reason, detail, tuple(sorted(set(used))))


def _unresolved_target(ctx: GateContext, rule: str, name: str, used) -> RuleResult:
    t = ctx.target
    return _result(rule, name, ABSTAIN, "target_" + t.status, t.detail, tuple(used) + t.record_ids)


def _node_name(ctx: GateContext) -> str | None:
    if ctx.target.key is None:
        return None
    status, name, _, _ = ctx.view.identity(ctx.target.key)
    return name if status == "known" else None


def _node_pods(ctx: GateContext) -> dict[str, tuple[str | None, tuple[PodInfo, ...]]]:
    """Per configured service: (Deployment key, pods possibly bound to the node)."""
    node_name = _node_name(ctx)
    result = {}
    for service, _ in ctx.config.service_deployments:
        _, d_key, _ = service_deployment(ctx.view, ctx.config, service)
        if d_key is None:
            continue
        pods = service_pods(ctx.view, d_key)
        on_node = tuple(p for p in pods if p.node in (None, f"NodeName/{node_name}"))
        if on_node:
            result[service] = (d_key, pods)
    return result


def rule_r1_target_identity(ctx: GateContext) -> RuleResult:
    """R1 target-identity-valid.

    The target must be known to exist and be the currently valid instance at
    the decision cutoff. Unknown -> ABSTAIN; known retired/absent -> DENY.
    For a Pod: STATE ready|not_ready and a resolved controller chain to the
    stated service's Deployment. A terminating, failed or absent Pod is not a
    valid target even while a controller link is still recorded.
    """
    rule, name = "R1", "target-identity-valid"
    view, target = ctx.view, ctx.target
    with view.recording() as used:
        used.update(target.record_ids)
        if target.status != "resolved":
            return _unresolved_target(ctx, rule, name, used)
        key = target.key
        if view.existed_by_observation(key) is False:
            return _result(rule, name, DENY, "not_yet_created",
                           f"{key} was created after the observation time", used)
        state = view.resolve(key, STATE)
        if state.status != "resolved":
            return _result(rule, name, ABSTAIN, "state_" + state.reason,
                           f"{key} STATE is {state.status} ({state.reason}) at this view", used)
        if key.startswith("Pod/"):
            if state.value in POD_GONE_STATES:
                return _result(rule, name, DENY, "target_gone",
                               f"{key} is {state.value}; it is no longer a live instance", used)
            if state.value == "terminating":
                return _result(rule, name, DENY, "target_retiring",
                               f"{key} is terminating; acting on it targets a retiring instance", used)
            rs, deployment, _ = pod_chain(view, key)
            if rs is None or deployment is None:
                return _result(rule, name, ABSTAIN, "controller_chain_unknown",
                               f"{key} controller chain is not resolvable at this view", used)
            if target.deployment_key is not None and deployment != target.deployment_key:
                return _result(rule, name, DENY, "identity_mismatch",
                               f"{key} is controlled by {deployment}, not {target.deployment_key}", used)
            if target.deployment_key is None:
                return _result(rule, name, ABSTAIN, "service_" + target.deployment_status,
                               f"cannot confirm {key} belongs to service {ctx.action.service!r}", used)
            return _result(rule, name, ALLOW, "current_instance",
                           f"{key} is {state.value} and controlled by {rs} -> {deployment}", used)
        if state.value != "present":
            return _result(rule, name, DENY, "target_gone", f"{key} is {state.value}", used)
        if key.startswith("Deployment/") and ctx.action.service is not None:
            if target.deployment_key != key:
                return _result(rule, name, DENY if target.deployment_key else ABSTAIN,
                               "identity_mismatch" if target.deployment_key else "service_unresolved",
                               f"{key} is not the Deployment of service {ctx.action.service!r}", used)
        return _result(rule, name, ALLOW, "present", f"{key} is present at this view", used)


def rule_r2_target_changed_recently(ctx: GateContext) -> RuleResult:
    """R2 target-changed-recently.

    If the target's Deployment or ReplicaSet (for a node drain: the
    Deployments of Pods bound to the node) began its current generation less
    than N seconds before the observation time -> NEEDS_APPROVAL. Generation
    (metadata.generation) counts spec changes and starts at 1 on creation.
    An unknown current generation -> ABSTAIN.
    """
    rule, name = "R2", "target-changed-recently"
    view, config, action = ctx.view, ctx.config, ctx.action
    with view.recording() as used:
        if ctx.target.status != "resolved":
            return _unresolved_target(ctx, rule, name, used)
        subjects: list[str] = []
        if action.kind in ("restart_pod", "delete_pod"):
            rs, deployment, _ = pod_chain(view, ctx.target.key)
            if rs is None or deployment is None:
                return _result(rule, name, ABSTAIN, "controller_chain_unknown",
                               f"cannot identify the Deployment/ReplicaSet of {ctx.target.key}", used)
            subjects = [rs, deployment]
        elif action.kind in ("scale_deployment", "rollback_deployment"):
            subjects = [ctx.target.key]
        else:
            subjects = sorted({d for d, _ in _node_pods(ctx).values()})
            if not subjects:
                return _result(rule, name, ALLOW, "no_workloads_on_node",
                               "no configured workload has Pods bound to the node", used)
        changes = []
        for subject in subjects:
            res = view.resolve(subject, GENERATION)
            if res.status != "resolved":
                return _result(rule, name, ABSTAIN, "change_history_" + res.reason,
                               f"current generation of {subject} is {res.status} ({res.reason})", used)
            began = max(view.fact(fid).valid_from for fid in res.fact_ids)
            changes.append((began, subject, res.value))
        began, subject, generation = max(changes)
        age = (view.observed_at - began).total_seconds()
        window = config.change_window_seconds
        if age < window:
            return _result(rule, name, NEEDS_APPROVAL, "changed_recently",
                           f"{subject} generation {generation} began {age:.3f}s before the "
                           f"observation time (< N={window:g}s)", used)
        return _result(rule, name, ALLOW, "no_recent_change",
                       f"latest change: {subject} generation {generation}, {age:.3f}s earlier "
                       f"(>= N={window:g}s)", used)


def _floor_decision(service: str, floor: int, before: tuple[int, int],
                    after: tuple[int, int]) -> tuple[str, str, str]:
    removed_hi = before[1] - after[1]
    text = (f"{service}: healthy replicas before [{before[0]},{before[1]}] -> "
            f"after [{after[0]},{after[1]}], floor {floor}")
    if after[0] >= floor:
        return ALLOW, "floor_satisfied", text
    if removed_hi <= 0 and before[0] - after[0] <= 0:
        return ALLOW, "no_healthy_replica_removed", text
    if after[1] < floor:
        return DENY, "below_replica_floor", text
    return ABSTAIN, "healthy_count_uncertain", text


def rule_r3_replica_floor(ctx: GateContext) -> RuleResult:
    """R3 replica-floor.

    Restart/delete/scale (and drain, which evicts every Pod on the node) may
    not drop a service's healthy (ready, non-terminating) replicas below its
    floor. Counts are intervals [certain, possible] over the view: DENY if even
    the optimistic count falls below the floor, ALLOW if the pessimistic count
    stays at or above it (or no possibly-healthy replica is removed), otherwise
    ABSTAIN. Rollback is modelled as a surge rollout (maxUnavailable=0 in the
    manifest) that removes no healthy replica.
    """
    rule, name = "R3", "replica-floor"
    view, config, action = ctx.view, ctx.config, ctx.action
    with view.recording() as used:
        if action.kind == "drain_node":
            if ctx.target.status != "resolved":
                return _unresolved_target(ctx, rule, name, used)
            node_name = _node_name(ctx)
            outcomes = []
            for service, (_, pods) in sorted(_node_pods(ctx).items()):
                before = healthy_bounds(pods)
                on = lambda p: p.node == f"NodeName/{node_name}"
                maybe_on = lambda p: p.node in (None, f"NodeName/{node_name}")
                after = (sum(p.certainly_ready and not maybe_on(p) for p in pods),
                         sum(p.possibly_ready and not on(p) for p in pods))
                outcomes.append(_floor_decision(service, config.floor_for(service), before, after))
            if not outcomes:
                return _result(rule, name, ALLOW, "no_workloads_on_node",
                               "no configured workload has Pods bound to the node", used)
            verdict = combine(o[0] for o in outcomes)
            reasons = sorted({o[1] for o in outcomes if o[0] == verdict})
            return _result(rule, name, verdict, "+".join(reasons), "; ".join(o[2] for o in outcomes), used)
        service = action.service
        if ctx.target.deployment_key is None:
            return _result(rule, name, ABSTAIN, "service_" + ctx.target.deployment_status,
                           f"healthy replicas of {service!r} cannot be counted at this view",
                           tuple(used) + ctx.target.record_ids)
        pods = service_pods(view, ctx.target.deployment_key)
        before = healthy_bounds(pods)
        if action.kind in ("restart_pod", "delete_pod"):
            if ctx.target.status != "resolved":
                return _unresolved_target(ctx, rule, name, used)
            after = healthy_bounds(p for p in pods if p.key != ctx.target.key)
        elif action.kind == "scale_deployment":
            n = action.replicas
            after = (min(before[0], n), min(before[1], n))
        else:  # rollback_deployment
            after = before
        verdict, reason, text = _floor_decision(service, config.floor_for(service), before, after)
        return _result(rule, name, verdict, reason, text, used)


def rule_r4_freeze_window(ctx: GateContext) -> RuleResult:
    """R4 freeze-window: mutating actions inside a known freeze -> DENY.

    A freeze applies when start <= observation time < end and it was declared
    at or before the knowledge cutoff (a late declaration is a late record).
    """
    rule, name = "R4", "freeze-window"
    view = ctx.view
    if ctx.action.kind not in MUTATING_ACTIONS:
        return _result(rule, name, ALLOW, "not_mutating", "action does not mutate state", ())
    active = [w for w in ctx.config.freeze_windows
              if w.start <= view.observed_at < w.end
              and (w.declared_at is None or w.declared_at <= view.knowledge_cutoff)]
    pending = [w for w in ctx.config.freeze_windows
               if w.start <= view.observed_at < w.end and w not in active]
    if active:
        labels = ", ".join(f"{w.label} [{iso(w.start)}, {iso(w.end)})" for w in active)
        return _result(rule, name, DENY, "freeze_window_active", f"inside freeze {labels}",
                       tuple(f"freeze:{w.label}" for w in active))
    detail = "no known freeze covers the observation time"
    if pending:
        detail += f" ({len(pending)} covering freeze(s) not yet declared at this cutoff)"
    return _result(rule, name, ALLOW, "no_active_freeze", detail, ())


def rule_r5_blast_radius(ctx: GateContext) -> RuleResult:
    """R5 blast-radius: more than k dependents in the call graph -> NEEDS_APPROVAL.

    Dependents are the services reachable from the affected service(s) in the
    supplied edge list (direction/transitivity configurable). For a node drain
    the affected services are those with Pods possibly bound to the node.
    """
    rule, name = "R5", "blast-radius"
    config = ctx.config
    with ctx.view.recording() as used:
        if ctx.action.kind == "drain_node":
            if ctx.target.status != "resolved":
                return _unresolved_target(ctx, rule, name, used)
            affected = sorted(_node_pods(ctx))
        else:
            affected = [ctx.action.service]
        blast: set[str] = set()
        for service in affected:
            blast.update(dependents(service, config.call_graph, direction=config.blast_radius_direction,
                                    transitive=config.blast_radius_transitive))
        members = ", ".join(sorted(blast)) or "none"
        text = (f"affected {affected}; {len(blast)} {config.blast_radius_direction} dependents "
                f"({members}); k={config.blast_radius_k}")
        if len(blast) > config.blast_radius_k:
            return _result(rule, name, NEEDS_APPROVAL, "blast_radius_exceeds_k", text, used)
        return _result(rule, name, ALLOW, "blast_radius_within_k", text, used)


def rule_r6_stale_view(ctx: GateContext) -> RuleResult:
    """R6 stale-view guard.

    If the newest availability time among the records the decision relied on
    (R1-R5) is older than the decision (observation) time by more than S
    seconds -> NEEDS_APPROVAL. No relied-on record -> ABSTAIN. In the
    as-known view the decision time is the knowledge cutoff; in hindsight
    views relied-on records may postdate the decision (negative staleness).
    """
    rule, name = "R6", "stale-view-guard"
    view = ctx.view
    fact_ids = [fid for fid in ctx.prior_record_ids if not fid.startswith("freeze:")]
    if not fact_ids:
        return _result(rule, name, ABSTAIN, "no_supporting_records",
                       "the decision relied on no store record", ())
    newest_id = max(fact_ids, key=lambda fid: (view.fact(fid).available_at, fid))
    newest = view.fact(newest_id).available_at
    staleness = (view.observed_at - newest).total_seconds()
    limit = ctx.config.stale_view_seconds
    text = f"newest relied-on record available {iso(newest)}; staleness {staleness:.3f}s (S={limit:g}s)"
    if staleness > limit:
        return _result(rule, name, NEEDS_APPROVAL, "view_may_be_stale", text, (newest_id,))
    return _result(rule, name, ALLOW, "view_fresh", text, (newest_id,))


RULES = (
    ("R1", rule_r1_target_identity),
    ("R2", rule_r2_target_changed_recently),
    ("R3", rule_r3_replica_floor),
    ("R4", rule_r4_freeze_window),
    ("R5", rule_r5_blast_radius),
)


def evaluate(action: Action, view: OperationalView, config: GateConfig) -> Decision:
    """Evaluate one proposed action against one operational view."""
    if not isinstance(action, Action) or not isinstance(view, OperationalView):
        raise ValueError("evaluate() needs an Action and an OperationalView")
    target = resolve_target(action, view, config)
    ctx = GateContext(action, view, config, target)
    results = [fn(ctx) for _, fn in RULES]
    relied = tuple(sorted({rid for r in results for rid in r.record_ids}))
    ctx.prior_record_ids = relied
    results.append(rule_r6_stale_view(ctx))
    fact_ids = tuple(rid for rid in relied if not rid.startswith("freeze:"))
    newest = max((view.fact(fid).available_at for fid in fact_ids), default=None)
    return Decision(action.action_id, combine(r.verdict for r in results), view.observed_at,
                    view.knowledge_cutoff, tuple(results), relied, newest)
