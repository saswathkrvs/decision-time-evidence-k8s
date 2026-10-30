"""Execution model of the follow-up gate analysis and the per-capture-and-observer decision logs.

Posing. Target-block requests k = 1..K, t_k = the client root span's start. A is posed at kappa = t_k + Delta if
kappa >= P (the unperturbed patch row's request start, a design constant); B at kappa_B = max(t_k + Delta, a_k),
a_k = the acquisition of request k's server span of the changed service (its target). The dispatch instant is
x = kappa + delta.

Waiting. The first evaluation uses the records available at kappa and asks whether the action is safe at x; after an
ABSTAIN the request is re-evaluated at each later instant tau of the shared schedule, each time with cutoff tau and
observation tau + delta; a terminal ALLOW at tau executes at tau + delta. The request is open while tau < kappa + E
(E = 120 s); a request still abstaining is EXPIRED at kappa + E if kappa + E <= H, else CENSORED at H; a request
posed after H is CENSORED without an evaluation. H = the earliest of the capture's observers' last availabilities,
so that every condition is censored at the same instant. (L-kappa): evaluations at observation = cutoff = tau, a
terminal ALLOW at tau executes at tau + delta. (R): the first answered response whose request started at or after x
(and before x + E); its verdict; an ALLOW executes at its receipt x_R; an ABSTAIN waits for the next answered
response; responses received after H are not used.

The shared schedule. One schedule per observer, stream and delta (the views reading one store share it, so (T) and
(L) see identical instants). It holds every instant at which a verdict on the changed service can change: the
availability of every observation, identity fact, completion receipt, freeze record and withdrawal; and, shifted by
-delta because the view looks at tau + delta, every freshness boundary (observed_at + F, F in {30, 600} s; dropped only
where a strictly newer observation of the same subject and predicate is usable by then), R2's window ends, R6's limits
(knowledge instant + S + 1 us), recorded validity starts and identity creation times, freeze starts and ends; and H.
Only subjects that a decision on the changed service can read contribute, so an arrival of another subject cannot
change a verdict. (c-hind)'s schedule adds every cluster sighting's observed_at - delta.

Decision logs. One gzipped JSON-lines log per capture and observer, streamed line by line as the evaluations are
computed: a meta line, the K1 and clamp tables, then schedule, fact, evaluation and request lines in computation
order (deterministic). Evaluations are memoised per (observer, stream, knowledge rule and F, action, cutoff,
dispatch); a fact line is written the first time an evaluation cites the fact. ``LogIndex`` lists every log with the
SHA-256 of its uncompressed text; it is closed after the capture's last log and its reconstruction checks, and request
rows are read back only through it, which re-checks each file's digest before yielding a row.
"""
from __future__ import annotations

import bisect
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from aiops_kg.policy_gate import ABSTAIN, ALLOW, GENERATION, NAME, Observation
from aiops_kg.temporal import Fact

from .common import (AdapterError, GzipJsonlWriter, R, canonical, gzip_digest, iso, iter_gzip_records, s_to_us,
                     seconds, sha256_text)
from .conditions import (APPROVE_THEN_EXECUTE, FORWARD, FUTURE, HINDSIGHT, LATEST, N_SECONDS, RECHECK_POSING,
                         S_SECONDS, TWO_CLOCK, ActionSpec, Condition, decide, entry_fact_ids, first_rules, is_fact,
                         r7_reason)
from .forward import build_forward_store
from .mapping2 import ClampLog, build_model_inputs_clamped, gate_records, merge_k1, recheck_model, tick_records
from govpilot import mapping as GM  # noqa: E402  (read-only)
from govpilot.engine import request_instants  # noqa: E402
from govpilot.inputs import CHANGE_KINDS, bound_change_records, perturb  # noqa: E402
from govpilot.views import CausalityViolation, check_causal  # noqa: E402

NOT_POSED, EXPIRED, CENSORED = "NOT_POSED", "EXPIRED", "CENSORED"
F_SCHEDULE = (30.0, 600.0)


class SealedLogError(RuntimeError):
    pass


class UnsealedLogError(PermissionError):
    pass


# ---------------------------------------------------------------------------------------------------------------
# The capture as the decision side sees it
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class Stage2Capture:
    capture_id: str
    plan: object                  # capture.ArmPlan
    binding: object | None        # govpilot rollout.Binding (A's identity)
    P: int | None
    H: int
    H_by_observer: dict
    service_deployments: dict
    changed_service: str | None
    floors: dict
    requests: tuple               # (k, t_us)
    b_targets: dict               # k -> {"uid", "a_us", "span": evidence id, "server_spans": n} or {"why": ...}
    observers: tuple
    condition_names: tuple
    stream_names: tuple
    deltas: tuple                 # Delta (s)
    dispatch: tuple               # delta (s)
    actions: tuple                # "A", "B"
    notes: dict = field(default_factory=dict)

    def action_a(self):
        from .conditions import action_a
        return action_a(self.capture_id, self.binding)

    def action_b(self, uid: str):
        from .conditions import action_b
        return action_b(self.capture_id, self.changed_service, uid)

    def summary(self) -> dict:
        return {"capture": self.capture_id, "binding": self.binding.to_dict() if self.binding else None,
                "P": iso(self.P), "H": iso(self.H), "H_by_observer": {k: iso(v) for k, v in
                                                                       sorted(self.H_by_observer.items())},
                "changed_service": self.changed_service, "service_deployments": self.service_deployments,
                "replica_floor_by_service": dict(sorted(self.floors.items())), "requests": len(self.requests),
                "b_targets_posable": sum(1 for v in self.b_targets.values() if "uid" in v),
                "b_targets_not_posable": {str(k): v["why"] for k, v in sorted(self.b_targets.items())
                                          if "uid" not in v},
                "observers": list(self.observers), "conditions": list(self.condition_names),
                "streams": list(self.stream_names), "Delta_s": list(self.deltas), "delta_s": list(self.dispatch),
                "actions": list(self.actions)}


# ---------------------------------------------------------------------------------------------------------------
# Relevant subjects and the schedule
# ---------------------------------------------------------------------------------------------------------------
def relevant_subjects(model, deployment_name: str | None) -> frozenset | None:
    """Subjects a decision on the changed service can read (see the module docstring); None = every subject."""
    if deployment_name is None:
        return None
    deployments = {f.subject for f in model.identity_facts if f.predicate == NAME and f.object == deployment_name
                   and f.subject.startswith("Deployment/")}
    controllers = defaultdict(set)
    for o in model.observations:
        if o.predicate == "CONTROLLER":
            controllers[o.value].add(o.subject)
    replicasets = {s for d in deployments for s in controllers.get(d, ()) if s.startswith("ReplicaSet/")}
    pods = {s for rs in replicasets for s in controllers.get(rs, ()) if s.startswith("Pod/")}
    return frozenset(deployments | replicasets | pods | {f"DeploymentName/{deployment_name}"})


def _freshness_boundaries(items, keep_all: bool, f_us, delta_us: int) -> list[int]:
    """observed + F - delta for every observation that can still be the newest usable one of its group at that
    cutoff (dropped when a strictly newer observation is available by then)."""
    by_observed = defaultdict(list)
    for observed, available in items:
        by_observed[observed].append(available)
    instants = sorted(by_observed)
    newer_min = {}
    running = None
    for observed in reversed(instants):
        newer_min[observed] = running
        here = min(by_observed[observed])
        running = here if running is None else min(running, here)
    out = []
    for observed in instants:
        for f in f_us:
            boundary = observed + f - delta_us
            later = newer_min[observed]
            if keep_all or later is None or later > boundary:
                out.append(boundary)
    return out


def schedule_instants(model, H: int, delta_us: int, *, relevant=None, hindsight: bool = False,
                      F_values=F_SCHEDULE, N_values=(N_SECONDS,)) -> tuple[int, ...]:
    n_list, s_us = [s_to_us(n) for n in N_values], s_to_us(S_SECONDS) + 1
    f_us = [s_to_us(f) for f in F_values]
    instants = {H}
    groups = defaultdict(list)
    for o in model.observations:
        if relevant is not None and o.subject not in relevant:
            continue
        observed, available = R.to_us(o.observed_at), R.to_us(o.available_at)
        instants.update((available, available + s_us - delta_us))
        groups[(o.subject, o.predicate)].append((observed, available, o.record_id))
        starts = R.to_us(o.starts_at) if o.starts_at is not None else None
        if starts is not None:
            instants.add(starts - delta_us)
        if o.predicate == GENERATION:
            for n_us in n_list:
                instants.add(observed + n_us - delta_us)
                if starts is not None:
                    instants.add(starts + n_us - delta_us)
        if hindsight and o.record_id in model.cluster_observations:
            instants.add(observed - delta_us)
    for items in groups.values():
        keep_all = any(rid in model.withdrawals for _, _, rid in items)
        instants.update(_freshness_boundaries([(o, a) for o, a, _ in items], keep_all, f_us, delta_us))
    for f in model.identity_facts:
        if relevant is not None and f.subject not in relevant:
            continue
        available = R.to_us(f.available_at)
        instants.update((available, available + s_us - delta_us))
        if f.valid_from is not None:
            instants.add(R.to_us(f.valid_from) - delta_us)
    for when in list(model.withdrawals.values()) + list(model.completion_withdrawals.values()) \
            + list(model.freeze_withdrawals.values()):
        instants.update((when, when + s_us - delta_us))
    for c in model.completion_receipts:
        instants.add(c.available_at)
    for f in model.freezes:
        from .common import ts_us
        payload = f.payload_view()
        instants.update((f.available_at, ts_us(payload["start"]) - delta_us, ts_us(payload["end"]) - delta_us))
    return tuple(sorted(x for x in instants if x <= H))


# ---------------------------------------------------------------------------------------------------------------
# The decision log of one capture and observer
# ---------------------------------------------------------------------------------------------------------------
class DecisionLogWriter:
    """Streams one capture-and-observer log; keeps only the keys of what it already wrote."""

    def __init__(self, path: Path, meta: dict):
        self.writer = GzipJsonlWriter(path)
        self.writer.write("meta", meta)
        self.facts_written: set = set()
        self.schedules_written: set = set()
        self.evaluations = 0
        self.requests = 0

    def schedule(self, observer: str, stream: str, kind: str, delta_s, instants) -> str:
        key = f"{observer}|{stream}|{kind}|delta={delta_s:g}"
        if key not in self.schedules_written:
            self.schedules_written.add(key)
            self.writer.write("schedule", {"key": key, "observer": observer, "stream": stream, "kind": kind,
                                           "dispatch_delay_s": delta_s, "instants_us": list(instants)})
        return key

    def facts(self, capture: str, observer: str, stream: str, store, fact_ids) -> None:
        for fid in fact_ids:
            key = (stream, store.label, fid)
            if key in self.facts_written:
                continue
            self.facts_written.add(key)
            f = store.fact(fid)
            self.writer.write("fact", {"capture": capture, "observer": observer, "stream": stream,
                                       "store": store.label, "fact_id": fid, "subject": f.subject,
                                       "predicate": f.predicate, "object": f.object,
                                       "valid_from": iso(R.to_us(f.valid_from)) if f.valid_from else None,
                                       "valid_to": iso(R.to_us(f.valid_to)) if f.valid_to else None,
                                       "available_at": iso(R.to_us(f.available_at)),
                                       "superseded_at": iso(R.to_us(f.superseded_at)) if f.superseded_at else None,
                                       "known_open": f.known_open,
                                       "confirmed_at": iso(R.to_us(f.confirmed_at)) if f.confirmed_at else None,
                                       "support": list(store.support.get(fid, ()))})

    def evaluation(self, entry: dict) -> None:
        self.evaluations += 1
        self.writer.write("evaluation", entry)

    def request(self, row: dict) -> None:
        self.requests += 1
        self.writer.write("request", row)

    def table(self, kind: str, rows) -> None:
        for row in rows:
            self.writer.write(kind, row)

    def close(self) -> dict:
        return self.writer.close()


# ---------------------------------------------------------------------------------------------------------------
# One observer's store under one stream
# ---------------------------------------------------------------------------------------------------------------
class ObserverContext:
    """Records of one observer under one change-record stream: the clamped model with K1, lazily built forward
    stores, the schedules and the evaluation memo. Reconstruction check 3 (exact provenance) and the causality guard run on every
    evaluation as it is computed; check 4 counts the dual engine's queries."""

    def __init__(self, capture: Stage2Capture, observer: str, stream, records, k1_observations, clamps: ClampLog,
                 log: DecisionLogWriter | None, *, model=None, fact_cache: dict | None = None, prepared=None):
        """``prepared`` = (stream records, manifest) of an earlier context on the same records and stream (the
        reconstruction checks reuse them instead of perturbing again; the perturbation is deterministic)."""
        self.capture, self.observer, self.stream_spec = capture, observer, stream
        self.stream = stream.name
        if prepared is None:
            perturbed, manifest = perturb(records, stream)
            prepared = (bound_change_records(perturbed, capture.binding), manifest)
        self.records, self.manifest = prepared
        if model is None:
            base = build_model_inputs_clamped(self.records, capture.binding, clamps)
            model = merge_k1(base, k1_observations)
        self.model = model
        self.k1_ids = frozenset(o.record_id for o in k1_observations)
        self.log = log
        self._stores: dict = {}
        self.memo: dict = {}
        self._schedules: dict = {}
        self.relevant = relevant_subjects(self.model, capture.binding.deployment_name if capture.binding else None)
        self.provenance = {"n": 0, "x": 0, "failures": []}
        self.fact_cache = fact_cache
        self._hind_index = None
        # Off unless an analysis sets them (sweeps.decision_log_pass): evaluation key -> input records behind it, and
        # the evaluation keys requested since ``trace`` was last set to a list. Neither changes any evaluation.
        self.input_log: dict | None = None
        self.trace: list | None = None

    @property
    def _hind(self) -> "_HindsightIndex":
        if self._hind_index is None:
            self._hind_index = _HindsightIndex(self.model)
        return self._hind_index

    # -- stores ---------------------------------------------------------------------------------------------------
    def store(self, knowledge: str):
        if knowledge not in self._stores:
            m = self.model
            if knowledge == TWO_CLOCK:
                built = build_forward_store(GM.a1_facts(m.observations, m.withdrawals, cache=self.fact_cache),
                                            m.identity_facts, label=TWO_CLOCK)
            elif knowledge == LATEST:
                built = build_forward_store(GM.latest_facts(m.observations, m.withdrawals, cache=self.fact_cache),
                                            m.identity_facts, label=LATEST)
            else:
                raise KeyError(knowledge)
            self._stores[knowledge] = built
        return self._stores[knowledge]

    def close(self) -> None:
        for store in self._stores.values():
            store.close()
        self._stores.clear()
        if self._hind_index is not None:
            self._hind_index.close()

    def withdrawn_by(self, tau: int) -> set:
        m = self.model
        out = set()
        for table in (m.withdrawals, m.completion_withdrawals, m.freeze_withdrawals):
            out.update(rid for rid, when in table.items() if when <= tau)
        return out

    def usable_freezes(self, tau: int):
        m = self.model
        return [f for f in m.freezes if f.available_at <= tau
                and not (f.id in m.freeze_withdrawals and m.freeze_withdrawals[f.id] <= tau)]

    def schedule(self, delta_us: int, *, hindsight: bool = False, F: float | None = None,
                 N: float | None = None) -> tuple[int, ...]:
        """Retry instants: every record arrival and every instant at which a rule's time limit passes, for the
        freshness limits F_SCHEDULE (plus ``F``) and R2's window N_SECONDS (plus ``N``)."""
        F_values = F_SCHEDULE if F is None or F in F_SCHEDULE else tuple(sorted(set(F_SCHEDULE) | {F}))
        N_values = (N_SECONDS,) if N is None or N == N_SECONDS else (N_SECONDS, N)
        key = (delta_us, hindsight, F_values, N_values)
        if key not in self._schedules:
            self._schedules[key] = schedule_instants(self.model, self.capture.H, delta_us, relevant=self.relevant,
                                                     hindsight=hindsight, F_values=F_values, N_values=N_values)
        return self._schedules[key]

    def engine_counts(self) -> dict:
        queries = disagreements = 0
        for store in self._stores.values():
            queries += store.dual.queries
            disagreements += len(store.dual.disagreements)
        q, d = self._hind_index.engine_counts() if self._hind_index is not None else (0, 0)
        return {"n": queries + q, "x": queries + q - disagreements - d, "disagreements": disagreements + d}

    # -- evaluation -----------------------------------------------------------------------------------------------
    def eval_id(self, view: str, act: ActionSpec, cutoff: int, observation: int) -> str:
        return f"{self.capture.capture_id}|{self.observer}|{self.stream}|{view}|{act.key}|{cutoff}|{observation}"

    def compute(self, knowledge: str, F: float, act: ActionSpec, cutoff: int, observation: int, *,
                hindsight: bool = False, condition_config: dict | None = None,
                N: float = N_SECONDS) -> tuple[dict, object, tuple]:
        """One evaluation without the memo or the log: (entry, store, record IDs behind it)."""
        cap = self.capture
        view_name = f"{knowledge}@F{F:g}"
        if hindsight:
            store, extra = self._hind.store(cutoff, observation, self.usable_freezes(cutoff))
            entry, records = decide(view_name=view_name, knowledge=knowledge, F=F, store=store, act=act,
                                    binding=cap.binding, service_deployments=cap.service_deployments,
                                    floors=cap.floors, cutoff_us=observation, observation_us=observation,
                                    freezes=self.usable_freezes(cutoff), view_config=condition_config or {}, N=N)
            entry["hindsight"] = dict(extra, kind="future-snapshot sensitivity (hindsight, not a live read)",
                                      knowledge_cutoff_for_change_records_us=cutoff)
            return entry, store, records
        store = self.store(knowledge)
        view_config = {"view": view_name, "knowledge": knowledge, "F_seconds": F, "N_seconds": N,
                       "S_seconds": S_SECONDS, "r7": "state", "observer": self.observer}
        entry, records = decide(view_name=view_name, knowledge=knowledge, F=F, store=store, act=act,
                                binding=cap.binding, service_deployments=cap.service_deployments, floors=cap.floors,
                                cutoff_us=cutoff, observation_us=observation, freezes=self.usable_freezes(cutoff),
                                view_config=view_config, N=N)
        return entry, store, records

    def evaluate(self, cond: Condition, act: ActionSpec, cutoff: int, observation: int) -> dict:
        key = (cond.eval_view, act.key, cutoff, observation)
        if self.trace is not None:
            self.trace.append(key)
        if key in self.memo:
            return self.memo[key]
        cap = self.capture
        hind = cond.posing == HINDSIGHT
        entry, store, records = self.compute(cond.knowledge, cond.F, act, cutoff, observation, hindsight=hind,
                                             condition_config=cond.config(), N=cond.N)
        if not hind:
            check_causal(dict(entry, view=cond.eval_view), records, self, cutoff)
            self._provenance(entry, store, cutoff)
            if self.input_log is not None:
                self.input_log[key] = frozenset(self.records_behind(entry, store))
        entry = dict(entry, eval_id=self.eval_id(cond.eval_view, act, cutoff, observation), capture=cap.capture_id,
                     observer=self.observer, stream=self.stream)
        if self.log is not None:
            self.log.evaluation(entry)
            self.log.facts(cap.capture_id, self.observer, self.stream, store, entry_fact_ids(entry))
        compact = {"eval_id": entry["eval_id"], "verdict": entry["verdict"], "deciding": entry["deciding"],
                   "first_rules": first_rules(entry), "r7_reason": r7_reason(entry),
                   **relied_bounds(entry, store, cond.F, cond.N)}
        self.memo[key] = compact
        return compact

    def records_behind(self, entry: dict, store) -> set:
        """The input records behind one evaluation: every record a rule cites, the records behind every cited fact,
        and the input records behind those (the set that reconstruction check 3 verifies in ``_provenance``)."""
        m = self.model
        records = set()
        for r in entry["rules"]:
            for identifier in r["ids"]:
                if not is_fact(identifier):
                    records.add(identifier.split(":", 1)[1])
                else:
                    records.update(store.support.get(identifier, ()))
        behind = set(records)
        for rid in records:
            behind.update(m.provenance.get(rid, (rid,)))
        return behind

    def _provenance(self, entry: dict, store, tau: int) -> None:
        """Reconstruction check 3 on one evaluation (govpilot.checks.check_provenance's conditions, from the facts the entry
        cites): per-rule IDs and the configuration hash present; every cited fact available and not superseded at
        tau; every record behind it (and every input record behind those) available and not withdrawn at tau; no
        fact handed out but unlisted."""
        m = self.model
        withdrawn_at = {}
        for table in (m.withdrawals, m.completion_withdrawals, m.freeze_withdrawals):
            withdrawn_at.update(table)
        ok = bool(entry.get("config_sha256")) and all("ids" in r for r in entry["rules"])
        records = set()
        for r in entry["rules"]:
            for identifier in r["ids"]:
                if not is_fact(identifier):
                    records.add(identifier.split(":", 1)[1])
                    continue
                f = store.fact(identifier)
                if R.to_us(f.available_at) > tau or (f.superseded_at is not None and R.to_us(f.superseded_at) <= tau):
                    ok = False
                records.update(store.support.get(identifier, ()))
        behind = set(records)
        for rid in records:
            behind.update(m.provenance.get(rid, (rid,)))
        for rid in behind:
            available = m.availability.get(rid)
            if available is None or available > tau or (rid in withdrawn_at and withdrawn_at[rid] <= tau):
                ok = False
        if entry["provenance_unlisted_fact_ids"]:
            ok = False
        self.provenance["n"] += 1
        if ok:
            self.provenance["x"] += 1
        elif len(self.provenance["failures"]) < 20:
            self.provenance["failures"].append(entry.get("eval_id") or f"{entry['view']}|{entry['cutoff_us']}")


def relied_bounds(entry: dict, store, F: float, N: float = N_SECONDS) -> dict:
    """For the H-G2 design check, from the facts this evaluation relied on: the instants at which a relied-on
    known-open fact's freshness ends (confirmed_at + F) and R2's window end (the newest GENERATION start R2 resolved
    + N)."""
    f_us, n_us = s_to_us(F), s_to_us(N)
    ends = set()
    for fid in entry_fact_ids(entry):
        f = store.fact(fid)
        if f.known_open and f.confirmed_at is not None and f.predicate != NAME:
            ends.add(R.to_us(f.confirmed_at) + f_us)
    r2_end = None
    for rule in entry["rules"]:
        if rule["rule"] != "R2" or rule["verdict"] == ABSTAIN:
            continue
        starts = [store.fact(fid).valid_from for fid in rule["ids"] if is_fact(fid)
                  and store.fact(fid).predicate == GENERATION]
        if starts and all(s is not None for s in starts):
            r2_end = max(R.to_us(s) for s in starts) + n_us
    return {"freshness_ends_us": sorted(ends), "r2_window_end_us": r2_end}


# ---------------------------------------------------------------------------------------------------------------
# (c-hind): single-cutoff hindsight stores
# ---------------------------------------------------------------------------------------------------------------
class _HindsightIndex:
    """(c-hind) at (tau, x): the causal observations usable at tau plus, per cluster (subject, predicate), the first
    sighting with observed_at >= x in the full stream (final versions), re-stamped at x (``#hind``); the facts are
    (L)'s latest-snapshot contents (govpilot.mapping._latest_contents, the function L's store replays) computed at
    the single knowledge instant x; identities of objects created by x are known (Stage 1's D12). The store is
    evaluated at observation = cutoff = x; change records enter only if available by tau."""

    def __init__(self, model):
        self.model = model
        self._by_avail = sorted(model.observations, key=lambda o: (R.to_us(o.available_at), o.record_id))
        self._avail = [R.to_us(o.available_at) for o in self._by_avail]
        final = [o for o in model.observations if o.record_id not in model.withdrawals
                 and o.record_id in model.cluster_observations]
        groups = defaultdict(list)
        for o in final:
            groups[(o.subject, o.predicate)].append(o)
        self._future = {}
        for key, items in groups.items():
            items.sort(key=lambda o: (R.to_us(o.observed_at), R.to_us(o.available_at), o.record_id))
            self._future[key] = (items, [R.to_us(o.observed_at) for o in items])
        self._cache: dict = {}
        self._closed_counts = [0, 0]

    def store(self, cutoff: int, x: int, freezes):
        prefix = bisect.bisect_right(self._avail, cutoff)
        projection = []
        for key in sorted(self._future):
            items, times = self._future[key]
            index = bisect.bisect_left(times, x)
            if index < len(items):
                projection.append(items[index].record_id)
        cache_key = (prefix, tuple(projection), x)
        if cache_key in self._cache:
            return self._cache[cache_key]
        for old in list(self._cache):
            self._close(self._cache.pop(old)[0])
        m = self.model
        withdrawn = {rid for rid, when in m.withdrawals.items() if when <= cutoff}
        causal = [o for o in self._by_avail[:prefix] if o.record_id not in withdrawn]
        projected, provenance, distance = [], {}, {}
        by_id = {o.record_id: o for o in m.observations}
        for rid in projection:
            first = by_id[rid]
            new_id = f"{rid}#hind"
            projected.append(Observation(new_id, first.subject, first.predicate, first.value, R.from_us(x),
                                         R.from_us(x)))
            provenance[new_id] = m.provenance.get(rid, (rid,))
            distance[new_id] = R.to_us(first.observed_at) - x
        groups = defaultdict(list)
        for o in causal + projected:
            groups[(o.subject, o.predicate)].append(o)
        facts, support = [], {}
        for key in sorted(groups):
            for content, ids in GM._latest_contents(groups[key]):
                value, valid_from, valid_to, known_open, confirmed_at = content[:5]
                members = [o for o in groups[key] if o.record_id in ids]
                available = max(o.available_at for o in members)
                fact_id = f"H|{key[0]}|{key[1]}|{value}|{'open' if known_open else 'closed'}"
                facts.append(Fact(fact_id=fact_id, subject=key[0], predicate=key[1], object=value,
                                  valid_from=valid_from, valid_to=valid_to, available_at=available,
                                  superseded_at=None, source_id=max(ids), known_open=known_open,
                                  confirmed_at=confirmed_at))
                support[fact_id] = tuple(sorted({src for rid in ids for src in provenance.get(rid, (rid,))}))
        store = build_forward_store((facts, support), GM.hindsight_identities(m, x), label=FUTURE)
        relied_projected = sorted(provenance)
        extra = {"projected_records": len(relied_projected),
                 "max_distance_seconds": max((distance[r] for r in relied_projected), default=0) / 1e6}
        self._cache[cache_key] = (store, extra)
        return store, extra

    def _close(self, store):
        self._closed_counts[0] += store.dual.queries
        self._closed_counts[1] += len(store.dual.disagreements)
        store.close()

    def engine_counts(self):
        queries = self._closed_counts[0] + sum(s.dual.queries for s, _ in self._cache.values())
        bad = self._closed_counts[1] + sum(len(s.dual.disagreements) for s, _ in self._cache.values())
        return queries, bad

    def close(self):
        for key in list(self._cache):
            self._close(self._cache.pop(key)[0])


# ---------------------------------------------------------------------------------------------------------------
# The recheck observer: one store per answered tick
# ---------------------------------------------------------------------------------------------------------------
class RecheckContext:
    """Condition (R): every answered tick is one snapshot, observed and available at its receipt x_R."""

    def __init__(self, capture: Stage2Capture, ticks, clamps: ClampLog, log: DecisionLogWriter | None):
        self.capture, self.log, self.clamps = capture, log, clamps
        self.ticks = []
        from .common import ts_us
        for evidence_id, payload in ticks:
            self.ticks.append({"evidence_id": evidence_id, "tick": payload["tick"],
                               "request_started_us": ts_us(payload["request_started_at"]),
                               "x_r_us": ts_us(payload["response_received_at"]),
                               "available_us": ts_us(payload["available_at"]), "payload": payload})
        self.ticks.sort(key=lambda t: (t["request_started_us"], t["tick"]))
        self._starts = [t["request_started_us"] for t in self.ticks]
        self._stores: dict = {}
        self.memo: dict = {}
        self.r2_starts: list = []
        self.provenance = {"n": 0, "x": 0, "failures": []}
        self.stream = "*"
        self.observer = "recheck"

    def _store(self, index: int):
        if index not in self._stores:
            tick = self.ticks[index]
            records = tick_records(tick["payload"], tick["evidence_id"])
            model, starts = recheck_model(records, self.clamps)
            for s in starts:
                self.r2_starts.append(dict(s, tick=tick["tick"], evidence_id=tick["evidence_id"]))
            store = build_forward_store(GM.a1_facts(model.observations, model.withdrawals), model.identity_facts,
                                        label=f"recheck_tick_{tick['tick']}")
            self._stores[index] = (store, model)
        return self._stores[index]

    def window(self, x: int, end: int, H: int) -> list[int]:
        """Indices of answered ticks whose request started in [x, end) and that were received by H."""
        start = bisect.bisect_left(self._starts, x)
        out = []
        for index in range(start, len(self.ticks)):
            tick = self.ticks[index]
            if tick["request_started_us"] >= end:
                break
            if tick["x_r_us"] <= H:
                out.append(index)
        return out

    def evaluate(self, cond: Condition, act: ActionSpec, index: int) -> dict:
        key = (act.key, index)
        if key in self.memo:
            return self.memo[key]
        cap = self.capture
        tick = self.ticks[index]
        store, model = self._store(index)
        x_r = tick["x_r_us"]
        view_config = {"view": "recheck_response", "knowledge": "recheck_response", "F_seconds": cond.F,
                       "N_seconds": N_SECONDS, "S_seconds": S_SECONDS, "r7": "state", "observer": "recheck",
                       "r2_start": "current ReplicaSet creationTimestamp + 1 s, clamped to x_R"}
        entry, records = decide(view_name="recheck_response", knowledge="recheck_response", F=cond.F, store=store,
                                act=act, binding=cap.binding, service_deployments=cap.service_deployments,
                                floors=cap.floors, cutoff_us=x_r, observation_us=x_r, view_config=view_config)
        shim = _ModelShim(model)
        check_causal(dict(entry, view="R"), records, shim, x_r)
        ok = all(model.availability.get(rid, x_r + 1) <= x_r for rid in records) and \
            not entry["provenance_unlisted_fact_ids"] and bool(entry["config_sha256"])
        self.provenance["n"] += 1
        self.provenance["x"] += int(ok)
        entry = dict(entry, eval_id=f"{cap.capture_id}|recheck|*|recheck_response|{act.key}|{tick['tick']}",
                     capture=cap.capture_id, observer="recheck", stream="*", tick=tick["tick"],
                     tick_evidence_id=tick["evidence_id"], request_started_us=tick["request_started_us"],
                     x_r_us=x_r)
        if self.log is not None:
            self.log.evaluation(entry)
            self.log.facts(cap.capture_id, "recheck", "*", store, entry_fact_ids(entry))
        compact = {"eval_id": entry["eval_id"], "verdict": entry["verdict"], "deciding": entry["deciding"],
                   "first_rules": first_rules(entry), "r7_reason": r7_reason(entry), "x_r_us": x_r,
                   "tick": tick["tick"], "request_started_us": tick["request_started_us"]}
        self.memo[key] = compact
        return compact

    def engine_counts(self) -> dict:
        queries = sum(s.dual.queries for s, _ in self._stores.values())
        bad = sum(len(s.dual.disagreements) for s, _ in self._stores.values())
        return {"n": queries, "x": queries - bad, "disagreements": bad}

    def close(self):
        for store, _ in self._stores.values():
            store.close()
        self._stores.clear()


class _ModelShim:
    def __init__(self, model):
        self.model = model

    def withdrawn_by(self, tau):
        return set()


# ---------------------------------------------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------------------------------------------
def pose(capture: Stage2Capture, family: str, k: int, t_us: int, delta_cap_s: float):
    """(posed, kappa, action spec, reason). A: kappa = t_k + Delta, posed iff kappa >= P. B: kappa_B = max(t_k +
    Delta, a_k), posed iff request k has a server span of the changed service."""
    kappa = t_us + s_to_us(delta_cap_s)
    if family == "A":
        if capture.binding is None or capture.P is None:
            return False, kappa, None, "no planned change (A never posed)"
        if kappa < capture.P:
            return False, kappa, capture.action_a(), "before the patch request P"
        return True, kappa, capture.action_a(), None
    target = capture.b_targets.get(k) or {"why": "request without spans"}
    if "uid" not in target:
        return False, kappa, None, target["why"]
    return True, max(kappa, target["a_us"]), capture.action_b(target["uid"]), None


def late_k1(k1_index, kappa: int, x: int) -> int:
    """Number of K1 records (of the changed service's Pods, this observer) with stamp <= x available after
    kappa."""
    if not k1_index:
        return 0
    return sum(1 for stamp, available in k1_index if stamp <= x and available > kappa)


def base_row(capture: Stage2Capture, cond: Condition, stream: str, family: str, k: int, t_us: int, delta_cap_s,
             delta_s, kappa: int, act: ActionSpec | None) -> dict:
    row = {"capture": capture.capture_id, "observer": cond.observer, "condition": cond.name, "stream": stream,
           "action": family, "action_key": act.key if act else None, "k": k, "t_k": iso(t_us), "t_k_us": t_us,
           "Delta_s": delta_cap_s, "delta_s": delta_s, "kappa_us": kappa, "kappa": iso(kappa),
           "x_us": kappa + s_to_us(delta_s), "x": iso(kappa + s_to_us(delta_s)), "hindsight": not cond.causal}
    if family == "B":
        target = capture.b_targets.get(k) or {}
        row.update(target_uid=target.get("uid"), a_k_us=target.get("a_us"), server_span=target.get("span"),
                   server_spans_in_trace=target.get("server_spans"))
    return row


def run_request(cond: Condition, ctx, capture: Stage2Capture, family: str, k: int, t_us: int, delta_cap_s: float,
                delta_s: float, log: DecisionLogWriter | None, *, k1_index=None) -> dict:
    posed, kappa, act, reason = pose(capture, family, k, t_us, delta_cap_s)
    row = base_row(capture, cond, ctx.stream, family, k, t_us, delta_cap_s, delta_s, kappa, act)
    if not posed:
        row.update(posed=False, disposition=NOT_POSED, not_posed_reason=reason, evaluations={"count": 0})
        if log is not None:
            log.request(row)
        return row
    H, delta = capture.H, s_to_us(delta_s)
    x = kappa + delta
    row["posed"] = True
    row["late_k1_records"] = late_k1(k1_index, kappa, x)
    if cond.posing == RECHECK_POSING:
        return _run_recheck(cond, ctx, capture, act, row, x, log)
    if cond.posing != RECHECK_POSING and hasattr(ctx, "records"):
        receipts = {}
        end = kappa + s_to_us(cond.E)
        for rec in ctx.records:
            if rec.kind in CHANGE_KINDS:
                receipts[rec.id] = {"available_at": iso(rec.available_at), "before_expiry": rec.available_at < end,
                                    "by_horizon": rec.available_at <= H}
        row["receipts"] = receipts
    if kappa > H:
        row.update(first_verdict=None, disposition=CENSORED, disposition_at=iso(H), waiting_s=0.0, censored=True,
                   expired=False, posed_after_horizon=True, evaluations={"count": 0}, dispatch_us=None)
        if log is not None:
            log.request(row)
        return row
    if cond.posing == FORWARD:
        sched_delta, observe = delta, (lambda tau: tau + delta)
    elif cond.posing == APPROVE_THEN_EXECUTE:
        sched_delta, observe = 0, (lambda tau: tau)
    elif cond.posing == HINDSIGHT:
        sched_delta, observe = delta, (lambda tau: tau + delta)
    else:
        raise AdapterError(f"unknown posing {cond.posing}")
    hind = cond.posing == HINDSIGHT
    schedule = ctx.schedule(sched_delta, hindsight=hind, F=cond.F, N=cond.N)
    key = None
    if log is not None:
        key = log.schedule(ctx.observer, ctx.stream, "hindsight" if hind else "causal", sched_delta / 1e6, schedule)
    instants = request_instants(schedule, kappa, H, cond.E)
    first, outcome, count = None, None, 0
    for tau in instants:
        result = ctx.evaluate(cond, act, tau, observe(tau))
        count += 1
        if first is None:
            first = result
        if result["verdict"] != ABSTAIN:
            outcome = (result, tau)
            break
    row.update(first_verdict=first["verdict"], first_eval=first["eval_id"], first_deciding=first["deciding"],
               first_rules=first["first_rules"], first_freshness_ends_us=first["freshness_ends_us"],
               first_r2_window_end_us=first["r2_window_end_us"],
               evaluations={"count": count, "first_cutoff_us": instants[0], "last_cutoff_us": instants[count - 1],
                            "schedule": key}, posed_after_horizon=False)
    if outcome is not None:
        result, tau = outcome
        verdict = result["verdict"]
        dispatch = tau + delta if verdict == ALLOW else None
        row.update(disposition=verdict, disposition_at=iso(tau), disposition_cutoff_us=tau,
                   disposition_source=result["deciding"] if verdict != ALLOW else [],
                   disposition_eval=result["eval_id"], disposition_r7_reason=result["r7_reason"],
                   waiting_s=seconds(tau - kappa), censored=False, expired=False, dispatch_us=dispatch,
                   dispatch_at=iso(dispatch) if dispatch is not None else None)
    elif kappa + s_to_us(cond.E) <= H:
        row.update(disposition=EXPIRED, disposition_at=iso(kappa + s_to_us(cond.E)), disposition_source=["expiry"],
                   waiting_s=float(cond.E), censored=False, expired=True, dispatch_us=None)
    else:
        row.update(disposition=CENSORED, disposition_at=iso(H), disposition_source=["horizon"],
                   waiting_s=seconds(H - kappa), censored=True, expired=False, dispatch_us=None)
    if log is not None:
        log.request(row)
    return row


def _run_recheck(cond: Condition, ctx: RecheckContext, capture: Stage2Capture, act: ActionSpec, row: dict, x: int,
                 log) -> dict:
    H, end = capture.H, x + s_to_us(cond.E)
    if x > H:
        row.update(first_verdict=None, disposition=CENSORED, disposition_at=iso(H), waiting_s=0.0, censored=True,
                   expired=False, posed_after_horizon=True, evaluations={"count": 0, "ticks": []},
                   dispatch_us=None)
        if log is not None:
            log.request(row)
        return row
    indices = ctx.window(x, end, H)
    first, outcome, used = None, None, []
    for index in indices:
        result = ctx.evaluate(cond, act, index)
        used.append(result["tick"])
        if first is None:
            first = result
        if result["verdict"] != ABSTAIN:
            outcome = result
            break
    row.update(first_verdict=first["verdict"] if first else None, first_eval=first["eval_id"] if first else None,
               first_deciding=first["deciding"] if first else None,
               first_rules=first["first_rules"] if first else None,
               first_response_request_started_us=first["request_started_us"] if first else None,
               evaluations={"count": len(used), "ticks": used}, posed_after_horizon=False)
    if outcome is not None:
        verdict = outcome["verdict"]
        dispatch = outcome["x_r_us"] if verdict == ALLOW else None
        row.update(disposition=verdict, disposition_at=iso(outcome["x_r_us"]), disposition_cutoff_us=outcome["x_r_us"],
                   disposition_source=outcome["deciding"] if verdict != ALLOW else [],
                   disposition_eval=outcome["eval_id"], disposition_r7_reason=outcome["r7_reason"],
                   waiting_s=seconds(outcome["x_r_us"] - x), censored=False, expired=False, dispatch_us=dispatch,
                   dispatch_at=iso(dispatch) if dispatch is not None else None)
    elif end <= H:
        row.update(disposition=EXPIRED, disposition_at=iso(end), disposition_source=["expiry"],
                   waiting_s=float(cond.E), censored=False, expired=True, dispatch_us=None,
                   no_response=not used)
    else:
        row.update(disposition=CENSORED, disposition_at=iso(H), disposition_source=["horizon"],
                   waiting_s=seconds(H - x), censored=True, expired=False, dispatch_us=None, no_response=not used)
    if log is not None:
        log.request(row)
    return row


# ---------------------------------------------------------------------------------------------------------------
# The sealed index of one capture's logs
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class LogIndex:
    directory: Path
    meta: dict = field(default_factory=dict)
    entries: dict = field(default_factory=dict)
    sealed: bool = False

    def add(self, observer: str, entry: dict, counts: dict) -> None:
        if self.sealed:
            raise SealedLogError("the decision-log index is sealed")
        if observer in self.entries:
            raise SealedLogError(f"{observer} already has a decision log")
        self.entries[observer] = dict(entry, observer=observer, **counts)

    def text(self) -> str:
        return canonical({"meta": self.meta, "logs": [self.entries[o] for o in sorted(self.entries)]}) + "\n"

    def seal(self) -> str:
        self.sealed = True
        return sha256_text(self.text())

    def write(self, path) -> str:
        if not self.sealed:
            raise UnsealedLogError("seal the decision-log index before writing it")
        text = self.text()
        Path(path).write_text(text, encoding="utf-8", newline="\n")
        return sha256_text(text)

    def path_of(self, observer: str) -> Path:
        return Path(self.directory) / self.entries[observer]["file"]

    def verify(self, observer: str) -> None:
        if not self.sealed:
            raise UnsealedLogError("the evaluator reads decision logs only through a decision-log index")
        entry = self.entries[observer]
        if gzip_digest(self.path_of(observer)) != entry["sha256_of_uncompressed_text"]:
            raise SealedLogError(f"{entry['file']} differs from the log written for {observer}")

    def iter_records(self, observer: str, kinds=("request",)):
        """Rows of one log after its digest was re-checked (two passes: verify, then read). The evaluator's only
        way in."""
        self.verify(observer)
        yield from iter_gzip_records(self.path_of(observer), kinds)

    def iter_unverified(self, observer: str, kinds=("request",)):
        """Rows of a closed log before the seal, for the decision-side phases only (the design check and the
        reconstruction checks, which never read a label); the evaluator uses ``iter_records``."""
        if observer not in self.entries:
            return
        yield from iter_gzip_records(self.path_of(observer), kinds)

    @classmethod
    def load(cls, path) -> "LogIndex":
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        index = cls(Path(path).parent / "decision_logs", meta=doc["meta"],
                    entries={e["observer"]: e for e in doc["logs"]})
        index.sealed = True
        return index
