"""Records -> gate observations and fact stores for each knowledge rule.

Observations. Cluster sightings go through policy-gate v1's own mapping (``build_observations`` of
experiments/policy-gate-v1/run_policy_gate_audit.py, imported read-only through the live audit script, with
``include_receipts=False``): Pod/ReplicaSet/Deployment/Node STATE, CONTROLLER, NODE, GENERATION, derived absences and
identity (NAME) facts, exactly as gate v1 maps them. The adapter adds, explicitly:

- ROLLOUT_STATUS of the plan's Deployment (subject ``DeploymentName/<name>``) from every Deployment sighting;
- GENERATION(u_C) from the accepted patch ``change_receipt`` row: g_C at ``request_started_at`` and g_C + 1 at
  ``response_received_at``, both available at the row's (per-stream) availability, IDs ``<evidence_id>#...``.

No observation is built from a later sighting, and nothing is read from evidence/capture.json.

Fact stores (all append-only: a record never changes; a correction withdraws its predecessor from the correction's
availability; old fact versions are never rewritten):

- ``a1_facts``: assumption A1 as ``policy_gate.materialize_facts`` implements it. Groups without corrections and
  without same-instant conflicts are passed to ``materialize_facts`` unchanged; only groups with a withdrawal or a
  conflict use a generalisation that re-derives runs at every availability *and withdrawal* instant and treats a
  same-instant conflict as a run boundary (the conflicting values are published as competing known-open facts while
  the conflict is the newest observation, so the resolver answers ``conflict``).
- ``latest_facts``: the latest-snapshot rule of view (L): at every knowledge instant the usable record with the
  greatest ``observed_at`` (then ``available_at``, ID) is published as one known-open fact confirmed at its own
  ``observed_at`` (so the resolver applies "unknown if c - observed_at >= F"); several values at the greatest
  ``observed_at`` are published as competing facts (conflict -> unknown). Its ``valid_from`` is the start of the
  trailing run of equal values among usable records, so that R2 can ask when the current generation began.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping, Sequence

from aiops_kg.policy_gate import (GENERATION, NAME, BitemporalStore, Observation, OperationalView, _derive_runs,
                                  identity_fact, materialize_facts)
from aiops_kg.temporal import Fact

from .common import LIVE_AUDIT_SCRIPT, R, InputError, dt, ts_us
from .inputs import API, CHANGE_PATCH, CHANGE_WAIT, FREEZE, InputRecord, change_record
from .rollout import ROLLOUT_STATUS, Binding, status_value

_LIVE = None


def live_module():
    """experiments/policy-gate-live-v1/run_policy_gate_live.py, imported read-only (never run)."""
    global _LIVE
    if _LIVE is None:
        _LIVE = R.import_script(LIVE_AUDIT_SCRIPT, "policy_gate_live_readonly_for_govpilot")
    return _LIVE


def pga():
    """Policy-gate v1's audit module (loaders, mapping, make_config), as the live audit imported it."""
    return live_module().pga


# ---------------------------------------------------------------------------------------------------------------
# Records -> observations
# ---------------------------------------------------------------------------------------------------------------
def sighting_row(rec: InputRecord) -> dict:
    """The dict ``load_sightings`` builds for one api_observation row (same fields, same parsing)."""
    payload = rec.payload()
    resource = payload["resource_data"]
    meta = resource["metadata"]
    return {"record_id": rec.id, "collection_id": payload.get("collection_id"),
            "snapshot_id": payload.get("snapshot_id"), "resource": payload.get("resource"),
            "kind": resource["kind"], "uid": meta["uid"], "name": meta["name"],
            "subject": f"{resource['kind']}/{meta['uid']}", "created_at": dt(ts_us(meta["creationTimestamp"])),
            "observed_at": dt(rec.observed_at), "available_at": dt(rec.available_at),
            "index_available_at": dt(rec.available_at), "clock_adjusted": payload.get("clock_adjusted"),
            "source_sha256": payload.get("_source_record_sha256"), "resource_data": resource}


def _gate_v1_observations(rows: list[dict]):
    """policy-gate v1's build_observations without receipts. A ReplicaSet/Deployment row without
    metadata.generation (fixture only) would crash v1's mapping; it is mapped with a sentinel whose GENERATION
    observation is then removed (R7 reads the absence from ROLLOUT_STATUS)."""
    patched, sentinel = [], set()
    for row in rows:
        meta = row["resource_data"]["metadata"]
        if row["kind"] in ("ReplicaSet", "Deployment") and "generation" not in meta:
            row = dict(row, resource_data=dict(row["resource_data"], metadata=dict(meta, generation=-1)))
            sentinel.add(row["record_id"])
        patched.append(row)
    try:
        observations, identities, info = pga().build_observations(patched, None, {}, include_receipts=False)
    except SystemExit as exc:
        raise InputError(str(exc)) from None
    observations = [o for o in observations if not (o.predicate == GENERATION and o.record_id in sentinel)]
    return observations, identities, info


@dataclass(frozen=True)
class ModelInputs:
    """What the views read in one stream, derived from that stream's records only."""
    observations: tuple[Observation, ...]
    identity_facts: tuple[Fact, ...]
    withdrawals: Mapping[str, int]                  # observation record_id -> withdrawal instant (us)
    provenance: Mapping[str, tuple[str, ...]]       # observation record_id -> input record IDs
    receipt_observations: frozenset                 # observation record_ids derived from change rows
    cluster_observations: frozenset                 # observation record_ids derived from api sightings (+ absences)
    completion_receipts: tuple                      # ChangeRecord (wait), every version
    completion_withdrawals: Mapping[str, int]       # wait record id -> withdrawal instant
    freezes: tuple[InputRecord, ...]
    freeze_withdrawals: Mapping[str, int]
    availability: Mapping[str, int]                 # observation record_id -> available_at (us); also inputs

    def gate_v1_observations(self) -> tuple[Observation, ...]:
        return tuple(o for o in self.observations if o.predicate != ROLLOUT_STATUS)

    def serialize(self) -> list:
        """Canonical, order-independent description (side-channel comparisons)."""
        obs = sorted((o.record_id, o.subject, o.predicate, o.value, R.to_us(o.observed_at), R.to_us(o.available_at),
                      R.to_us(o.starts_at) if o.starts_at else None) for o in self.observations)
        ident = sorted((f.fact_id, R.to_us(f.valid_from), R.to_us(f.available_at), f.source_id)
                       for f in self.identity_facts)
        receipts = sorted(sorted(c.to_dict().items()) for c in self.completion_receipts)
        freezes = sorted((f.id, f.observed_at, f.available_at, f.payload_json) for f in self.freezes)
        return [obs, ident, sorted(self.withdrawals.items()), receipts,
                sorted(self.completion_withdrawals.items()), freezes]


def _withdrawals(records: Sequence[InputRecord]) -> dict:
    out = {}
    for r in records:
        if r.corrects is not None:
            out[r.corrects] = min(out.get(r.corrects, r.available_at), r.available_at)
    return out


def build_model_inputs(records: Sequence[InputRecord], binding: Binding | None) -> ModelInputs:
    withdrawn_inputs = _withdrawals(records)
    api = [r for r in records if r.kind == API]
    base = sorted((r for r in api if r.corrects is None), key=lambda r: (r.observed_at, r.id))
    corrections = sorted((r for r in api if r.corrects is not None), key=lambda r: (r.observed_at, r.id))
    observations, identities, _ = _gate_v1_observations([sighting_row(r) for r in base])
    observations = list(observations)
    for rec in corrections:        # mapped alone: a correction fixes a value, never a list's membership
        extra, _, _ = _gate_v1_observations([sighting_row(rec)])
        observations.extend(extra)
    provenance: dict[str, tuple[str, ...]] = {}
    by_snapshot: dict[str, list[str]] = defaultdict(list)
    first_sighting: dict[str, str] = {}
    for rec in base:        # sorted by (observed_at, id): the first row of a subject is the one v1's "seen" uses
        by_snapshot[rec.payload_view().get("snapshot_id")].append(rec.id)
        first_sighting.setdefault(rec.subject, rec.id)
    cluster = set()
    for o in observations:
        if o.record_id.startswith("absence:"):
            # an absence is derived from the complete list without the object *and* the earlier sighting that
            # made the object known; both are its provenance
            snapshot = o.record_id.split(":")[1]
            sources = set(by_snapshot.get(snapshot, ()))
            if o.subject in first_sighting:
                sources.add(first_sighting[o.subject])
            provenance[o.record_id] = tuple(sorted(sources))
        else:
            provenance[o.record_id] = (o.record_id,)
        cluster.add(o.record_id)
    for rec in base + corrections:
        resource = rec.payload_view()["resource_data"]
        if resource["kind"] != "Deployment":
            continue
        observations.append(Observation(rec.id, f"DeploymentName/{resource['metadata']['name']}", ROLLOUT_STATUS,
                                        status_value(resource), dt(rec.observed_at), dt(rec.available_at)))
        provenance[rec.id] = (rec.id,)
        cluster.add(rec.id)
    receipts = set()
    for rec in records:
        if rec.kind != CHANGE_PATCH or binding is None:
            continue
        change = change_record(rec)
        if change.deployment_uid != binding.deployment_uid or change.exit_code != 0:
            continue
        for suffix, value, when in (("request_started_at", binding.generation, change.request_started_at),
                                    ("response_received_at", binding.generation + 1, change.response_received_at)):
            rid = f"{rec.id}#{suffix}"
            observations.append(Observation(rid, binding.deployment_key, GENERATION, str(value), dt(when),
                                            dt(rec.available_at)))
            provenance[rid] = (rec.id,)
            receipts.add(rid)
            if rec.id in withdrawn_inputs:
                withdrawn_inputs.setdefault(rid, withdrawn_inputs[rec.id])
    withdrawals = {}
    for o in observations:
        if o.record_id.startswith("absence:"):
            continue                # a correction fixes a value, never a list's membership
        times = [withdrawn_inputs[s] for s in provenance[o.record_id] if s in withdrawn_inputs]
        if o.record_id in withdrawn_inputs:
            times.append(withdrawn_inputs[o.record_id])
        if times:
            withdrawals[o.record_id] = min(times)
    waits = tuple(change_record(r) for r in records if r.kind == CHANGE_WAIT)
    completion_withdrawals = {c.record_id: withdrawn_inputs[c.record_id] for c in waits
                              if c.record_id in withdrawn_inputs}
    freezes = tuple(sorted((r for r in records if r.kind == FREEZE), key=lambda r: r.id))
    freeze_withdrawals = {f.id: withdrawn_inputs[f.id] for f in freezes if f.id in withdrawn_inputs}
    availability = {o.record_id: R.to_us(o.available_at) for o in observations}
    for rec in records:
        availability.setdefault(rec.id, rec.available_at)
    return ModelInputs(tuple(observations), tuple(identities), withdrawals, provenance, frozenset(receipts),
                       frozenset(cluster), waits, completion_withdrawals, freezes, freeze_withdrawals, availability)


# ---------------------------------------------------------------------------------------------------------------
# Fact builders
# ---------------------------------------------------------------------------------------------------------------
def _groups(observations: Iterable[Observation]) -> dict:
    groups: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    for o in observations:
        groups[(o.subject, o.predicate)].append(o)
    return groups


def _has_conflict(items: Sequence[Observation]) -> bool:
    values: dict[datetime, set] = defaultdict(set)
    for o in items:
        values[o.observed_at].add(o.value)
    return any(len(v) > 1 for v in values.values())


def _usable(items, instant, withdrawals) -> list[Observation]:
    return [o for o in items if o.available_at <= instant
            and not (o.record_id in withdrawals and dt(withdrawals[o.record_id]) <= instant)]


def _runs_with_conflicts(usable: list[Observation]) -> list:
    """A1 runs over usable observations, with a same-instant conflict as a run boundary.

    A run closed by a conflict ends at its last observation (support includes the conflicting records). If the
    conflict is the newest observation instant, each conflicting value is published as a known-open fact confirmed
    at that instant, so the resolver reports a conflict until a later observation or until F expires."""
    by_instant: dict[datetime, list[Observation]] = defaultdict(list)
    for o in usable:
        by_instant[o.observed_at].append(o)
    conflicts = sorted(x for x, obs in by_instant.items() if len({o.value for o in obs}) > 1)
    if not conflicts:
        return _derive_runs(usable)
    ordered = sorted(usable, key=lambda o: (o.observed_at, o.record_id))
    segments, current, index = [], [], 0
    for o in ordered:
        while index < len(conflicts) and o.observed_at >= conflicts[index]:
            segments.append((current, conflicts[index]))
            current = []
            index += 1
        if o.observed_at in conflicts:
            continue
        current.append(o)
    while index < len(conflicts):
        segments.append((current, conflicts[index]))
        current, index = [], index + 1
    result = []
    for seg, boundary in segments:
        if not seg:
            continue
        runs = _derive_runs(seg)
        *head, (content, support) = runs
        result.extend(head)
        value, valid_from, _, _, confirmed = content
        if confirmed > valid_from:
            following = tuple(sorted(o.record_id for o in by_instant[boundary]))
            result.append(((value, valid_from, confirmed, False, None), support + following))
    if current:
        result.extend(_derive_runs(current))
    else:
        last = conflicts[-1]
        for value in sorted({o.value for o in by_instant[last]}):
            ids = tuple(sorted(o.record_id for o in by_instant[last] if o.value == value))
            result.append(((value, last, None, True, last), ids))
    return result


def _replay_group(key, items, withdrawals, derive, prefix: str):
    """Publish/supersede loop of materialize_facts, over availability and withdrawal instants.

    A version is identified by its content *and* its supporting records: when a correction withdraws a record, a
    fact with the same content but different support is a new version (the old one, whose evidence was withdrawn,
    is superseded at the withdrawal instant), so no usable version ever cites a withdrawn record."""
    instants = sorted({o.available_at for o in items}
                      | {dt(withdrawals[o.record_id]) for o in items if o.record_id in withdrawals})
    availability = {o.record_id: o.available_at for o in items}
    active: dict[tuple, int] = {}
    drafts: list[dict] = []
    for instant in instants:
        derived = [(content, tuple(support)) for content, support in derive(_usable(items, instant, withdrawals))]
        versions = set(derived)
        for version in [v for v in active if v not in versions]:
            drafts[active.pop(version)]["superseded_at"] = instant
        for content, support in derived:
            if (content, support) in active:
                continue
            arrived = [rid for rid in support if availability.get(rid) == instant]
            trigger = max(arrived) if arrived else max(support, key=lambda r: (availability.get(r), r))
            drafts.append({"content": content, "available_at": instant, "superseded_at": None,
                           "support": support, "trigger": trigger})
            active[(content, support)] = len(drafts) - 1
    subject, predicate = key
    facts, support_map = [], {}
    for number, draft in enumerate(drafts, start=1):
        value, valid_from, valid_to, known_open, confirmed_at = draft["content"][:5]
        fact_id = f"{prefix}{subject}|{predicate}|{value}|{'open' if known_open else 'closed'}|v{number}"
        facts.append(Fact(fact_id=fact_id, subject=subject, predicate=predicate, object=value,
                          valid_from=valid_from, valid_to=valid_to, available_at=draft["available_at"],
                          superseded_at=draft["superseded_at"], source_id=draft["trigger"],
                          known_open=known_open, confirmed_at=confirmed_at))
        support_map[fact_id] = draft["support"]
    return facts, support_map


def _group_key(key, items, withdrawals) -> tuple:
    return (key, tuple(sorted((o.record_id, R.to_us(o.available_at)) for o in items)),
            tuple(sorted((o.record_id, withdrawals[o.record_id]) for o in items if o.record_id in withdrawals)))


def a1_facts(observations: Sequence[Observation], withdrawals: Mapping[str, int], *,
             cache: dict | None = None) -> tuple[tuple[Fact, ...], dict]:
    """Assumption A1 facts; clean groups go to ``policy_gate.materialize_facts`` unchanged.

    ``materialize_facts`` treats every (subject, predicate) group independently (its fact IDs are numbered per
    group), so a group's facts depend only on that group's observations; ``cache`` (optional) reuses them across
    calls with the same group content (the earlier-cutoff check rebuilds many truncated stores)."""
    groups = _groups(observations)
    facts, support = [], {}
    for key in sorted(groups):
        items = groups[key]
        cache_key = ("a1",) + _group_key(key, items, withdrawals) if cache is not None else None
        if cache_key is not None and cache_key in cache:
            more, more_support = cache[cache_key]
        elif any(o.record_id in withdrawals for o in items) or _has_conflict(items):
            more, more_support = _replay_group(key, items, withdrawals, _runs_with_conflicts, "")
        else:
            more, more_support = materialize_facts(items)
        if cache_key is not None:
            cache[cache_key] = (more, more_support)
        facts.extend(more)
        support.update(more_support)
    return tuple(facts), support


def _latest_contents(usable: list[Observation]) -> list:
    if not usable:
        return []
    newest = max(o.observed_at for o in usable)
    top = [o for o in usable if o.observed_at == newest]
    values = sorted({o.value for o in top})
    if len(values) > 1:
        return [((v, newest, None, True, newest, "conflict"),
                 tuple(sorted(o.record_id for o in top if o.value == v))) for v in values]
    value = values[0]
    chosen = max(top, key=lambda o: (o.available_at, o.record_id))
    by_instant: dict[datetime, list[Observation]] = defaultdict(list)
    for o in usable:
        by_instant[o.observed_at].append(o)
    run: list[Observation] = []
    for instant in sorted(by_instant, reverse=True):
        group = by_instant[instant]
        if any(o.value != value for o in group):
            break
        run.extend(group)
    start = min((o.starts_at or o.observed_at) for o in run)
    return [((value, start, None, True, newest, chosen.record_id), tuple(sorted(o.record_id for o in run)))]


def latest_facts(observations: Sequence[Observation], withdrawals: Mapping[str, int], *,
                 cache: dict | None = None) -> tuple[tuple[Fact, ...], dict]:
    """View (L)'s latest-snapshot facts (see the module docstring); ``cache`` as in ``a1_facts``."""
    groups = _groups(observations)
    facts, support = [], {}
    for key in sorted(groups):
        items = groups[key]
        cache_key = ("latest",) + _group_key(key, items, withdrawals) if cache is not None else None
        if cache_key is not None and cache_key in cache:
            more, more_support = cache[cache_key]
        else:
            more, more_support = _replay_group(key, items, withdrawals, _latest_contents, "L|")
            if cache_key is not None:
                cache[cache_key] = (more, more_support)
        facts.extend(more)
        support.update(more_support)
    return tuple(facts), support


def hindsight_observations(model: ModelInputs, tau: int) -> tuple[list[Observation], dict, dict]:
    """(c-hind) at cutoff tau: the causal usable observations, plus per cluster (subject, predicate) the first
    sighting with observed_at >= tau in the full stream (final versions), re-stamped at tau (``#hind``).

    Returns (observations, provenance additions, hindsight distances in us per projected record)."""
    cutoff = dt(tau)
    final = [o for o in model.observations if o.record_id not in model.withdrawals]
    causal = _usable(model.observations, cutoff, model.withdrawals)
    groups = _groups(o for o in final if o.record_id in model.cluster_observations and o.observed_at >= cutoff)
    projected, provenance, distance = [], {}, {}
    for key in sorted(groups):
        first = min(groups[key], key=lambda o: (o.observed_at, o.available_at, o.record_id))
        rid = f"{first.record_id}#hind"
        projected.append(Observation(rid, first.subject, first.predicate, first.value, cutoff, cutoff))
        provenance[rid] = model.provenance.get(first.record_id, (first.record_id,))
        distance[rid] = R.to_us(first.observed_at) - tau
    return causal + projected, provenance, distance


def hindsight_identities(model: ModelInputs, tau: int) -> tuple[Fact, ...]:
    """Identity facts of objects created by tau, projected to be known at tau (hindsight)."""
    out = []
    for f in model.identity_facts:
        if f.valid_from is not None and R.to_us(f.valid_from) > tau:
            continue
        if R.to_us(f.available_at) <= tau:
            out.append(f)
        else:
            out.append(identity_fact(f.subject, f.object, f.valid_from, dt(tau), f.source_id))
    return tuple(out)


# ---------------------------------------------------------------------------------------------------------------
# Stores, the dual engine and the traced view
# ---------------------------------------------------------------------------------------------------------------
class EngineDisagreement(RuntimeError):
    pass


class DualEngine:
    """Answers every resolver query with the graph and the SQLite engine and compares them."""

    def __init__(self, graph, sqlite, *, strict: bool = True):
        self.graph, self.sqlite, self.strict = graph, sqlite, strict
        self.queries = 0
        self.disagreements: list[tuple] = []

    def resolve(self, subject, predicate, observed_at, decision_at, freshness_seconds):
        a = self.graph.resolve(subject, predicate, observed_at, decision_at, freshness_seconds)
        b = self.sqlite.resolve(subject, predicate, observed_at, decision_at, freshness_seconds)
        self.queries += 1
        if a != b:
            self.disagreements.append((subject, predicate, R.iso(R.to_us(observed_at)), a, b))
            if self.strict:
                raise EngineDisagreement(f"graph/SQLite disagree on {subject} {predicate}")
        return a


class PilotStore(BitemporalStore):
    """A BitemporalStore with both engines, the fact -> observation support map and a dual engine."""

    def __init__(self, facts: Iterable[Fact], support: Mapping[str, tuple[str, ...]], *, label: str):
        super().__init__(facts, engines=("graph", "sqlite"))
        self.label = label
        self.support = dict(support)
        for f in self.facts:
            if f.predicate == NAME:
                self.support.setdefault(f.fact_id, (f.source_id,))
        self.dual = DualEngine(super().engine("graph"), super().engine("sqlite"))

    def engine(self, name: str):
        if name == "dual":
            return self.dual
        return super().engine(name)


class TracedView(OperationalView):
    """OperationalView that records every fact it handed out (resolver and knowledge-only lookups) and every fact a
    candidate enumeration touched, independently of the gate's own ``recording()`` scopes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.noted: set[str] = set()
        self.enumerated: set[str] = set()

    def _note(self, fact_ids):
        ids = tuple(fact_ids)
        self.noted.update(ids)
        super()._note(ids)

    def subjects_with(self, predicate: str, obj: str):
        self.enumerated.update(f.fact_id for f in self.store.facts_for(predicate)
                               if f.object == obj and self._visible(f))
        return super().subjects_with(predicate, obj)


def build_store(facts_and_support, identities, *, label: str) -> PilotStore:
    facts, support = facts_and_support
    return PilotStore(tuple(facts) + tuple(identities), support, label=label)
