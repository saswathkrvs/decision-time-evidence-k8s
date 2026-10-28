"""The knowledge views of the development rollback pilot and their evaluation at one instant.

Every evaluation decides at observation time = knowledge cutoff = tau with the gate's rules R1-R6 at the live-audit
configuration (N = 30 s, floor 1, k = 3 downstream, S = 300 s; built with policy-gate v1's own ``make_config``), plus
R7 where the view has it. The combined verdict is the most severe (DENY > ABSTAIN > NEEDS_APPROVAL > ALLOW). R6 is
gate v1's rule over R1-R5's records; R7 does not feed it.

Causal views:

======  ===========================================================  =================  ======================
view    knowledge rule for each predicate at cutoff tau             R7                 after a first ABSTAIN
======  ===========================================================  =================  ======================
T       two-clock A1 facts through the gate resolver, F = 30 s      state              waits
L       latest usable record (observed_at, available_at, ID), F 30  state              waits
T+p     as T                                                        state+procedural   waits
L+p     as L                                                        state+procedural   waits
d       as T                                                        state              terminal escalation
a       gate v1 as-known: A1 facts, F = 600 s                        none               waits
======  ===========================================================  =================  ======================

Hindsight views (``evaluate_hindsight(..., hindsight=True)`` only; never a live read, never a baseline):

- ``c-hind``: as L, except each cluster predicate comes from the first sighting with observed_at >= tau in the full
  stream (distance logged); change records stay causal; reported only as a sensitivity (T4);
- ``CV``: the corrected view: A1 facts with the cutoff after every record, all final-version freezes, R7 state clause
  only; used only for the X1 fixtures' corrected verdicts; never a policy and never run on a capture.

A causal evaluation consumes only records with available_at <= tau: its store answers only with fact versions
available at tau, and ``evaluate_causal`` re-checks that every record it cites was available and not withdrawn at tau.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping

from aiops_kg.policy_gate import ALLOW, Action, FreezeWindow, ObjectRef, combine, evaluate

from . import rollout
from .common import InputError, R, canonical, dt, sha256_text, ts_us
from .inputs import (InputRecord, bind, bound_change_records, horizon, patch_request_at, planned_service,
                     service_deployments)
from .mapping import (ModelInputs, TracedView, a1_facts, build_model_inputs, build_store, hindsight_identities,
                      hindsight_observations, latest_facts, pga)

TWO_CLOCK, LATEST, GATE_V1, FUTURE, CORRECTED = "two_clock", "latest", "gate_v1", "future_snapshot", "corrected"
F_PRIMARY = 30.0
F_GATE_V1 = 600.0
E_PRIMARY = 120.0
N_SECONDS = 30.0                      # R2 change window (live-audit configuration)
S_SECONDS = 300.0                     # R6 stale-view limit
FREEZE_PREFIX = "freeze:"


class HindsightRequired(PermissionError):
    """A hindsight view was requested through the causal (decision) path, or without ``hindsight=True``."""


class CausalityViolation(AssertionError):
    """A causal evaluation cited a record that was not available (or was withdrawn) at its cutoff."""


@dataclass(frozen=True)
class ViewSpec:
    name: str
    knowledge: str
    F: float
    r7: str | None                    # None | "state" | "state+procedural"
    after_abstain: str                # "wait" | "escalate"
    causal: bool
    role: str
    E: float | None = E_PRIMARY       # None: open until H (sensitivity)

    def config(self) -> dict:
        return {"view": self.name, "knowledge": self.knowledge, "F_seconds": self.F, "r7": self.r7,
                "after_abstain": self.after_abstain, "E_seconds": self.E, "N_seconds": N_SECONDS,
                "S_seconds": S_SECONDS, "causal": self.causal, "role": self.role}


CAUSAL_VIEWS = {
    "T": ViewSpec("T", TWO_CLOCK, F_PRIMARY, "state", "wait", True, "treatment"),
    "L": ViewSpec("L", LATEST, F_PRIMARY, "state", "wait", True, "matched practical comparator"),
    "T+p": ViewSpec("T+p", TWO_CLOCK, F_PRIMARY, "state+procedural", "wait", True, "procedural rule (treatment)"),
    "L+p": ViewSpec("L+p", LATEST, F_PRIMARY, "state+procedural", "wait", True, "procedural rule (comparator)"),
    "d": ViewSpec("d", TWO_CLOCK, F_PRIMARY, "state", "escalate", True, "operational comparison: escalation"),
    "a": ViewSpec("a", GATE_V1, F_GATE_V1, None, "wait", True, "operational comparison: gate v1 as-known"),
}
HINDSIGHT_VIEWS = {
    "c-hind": ViewSpec("c-hind", FUTURE, F_PRIMARY, "state", "wait", False,
                       "future-snapshot sensitivity (hindsight, not a live read)"),
    "CV": ViewSpec("CV", CORRECTED, F_PRIMARY, "state", "wait", False,
                   "corrected view (X1 fixtures' corrected verdicts only; never a policy)"),
}
MATCHED_PAIRS = (("T", "L"), ("T+p", "L+p"))
OPERATIONAL_PAIRS = (("T", "d"), ("T", "a"))


def causal_view(name: str) -> ViewSpec:
    """A causal view (or one of its F600 / Eopen sensitivities) by name; hindsight names are refused."""
    base, _, variant = name.partition("@")
    if base in HINDSIGHT_VIEWS:
        raise HindsightRequired(f"{name} is a hindsight view and cannot be used on the decision path")
    if base not in CAUSAL_VIEWS:
        raise KeyError(name)
    spec = CAUSAL_VIEWS[base]
    return sensitivity(spec, variant) if variant else spec


def sensitivity(spec: ViewSpec, variant: str) -> ViewSpec:
    """Sections 4.5 / 6.4 T4 sensitivities: ``F600`` (F = 600 s) and ``Eopen`` (open until H)."""
    if variant == "F600":
        return dataclasses.replace(spec, name=f"{spec.name}@F600", F=600.0)
    if variant == "Eopen":
        return dataclasses.replace(spec, name=f"{spec.name}@Eopen", E=None)
    raise KeyError(f"unknown sensitivity {variant!r}")


def hindsight_view(name: str, *, hindsight: bool) -> ViewSpec:
    if hindsight is not True:
        raise HindsightRequired(f"{name}: hindsight views need hindsight=True")
    return HINDSIGHT_VIEWS[name]


# ---------------------------------------------------------------------------------------------------------------
# Per-capture and per-stream context
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class CaptureModel:
    """One capture (or fixture) as the decision side sees it: S0 records, requests, A and its constants."""
    capture_id: str
    records: tuple[InputRecord, ...]
    requests: tuple[tuple[int, int], ...]
    binding: rollout.Binding | None
    P: int | None
    H: int
    service_deployments: dict
    action: Action | None

    def gate_config(self, F: float, freezes=()):
        base = pga().make_config({"service_deployments": self.service_deployments}, tuple(freezes), N_SECONDS)
        return dataclasses.replace(base, carry_forward_seconds=F)

    def config_hash(self, spec: ViewSpec) -> str:
        return _config_hash(canonical(self.service_deployments), canonical(
            self.binding.to_dict() if self.binding else None), canonical(spec.config()))


@lru_cache(maxsize=None)
def _config_hash(service_map: str, binding: str, view: str) -> str:
    cfg = pga().make_config({"service_deployments": json.loads(service_map)}, (), N_SECONDS)
    return sha256_text(canonical({
        "view": json.loads(view),
        "kubectl": rollout.KUBECTL_REFERENCE, "binding": json.loads(binding),
        "gate": {"change_window_seconds": cfg.change_window_seconds, "replica_floor": cfg.replica_floor,
                 "blast_radius_k": cfg.blast_radius_k, "blast_radius_direction": cfg.blast_radius_direction,
                 "blast_radius_transitive": cfg.blast_radius_transitive, "stale_view_seconds": cfg.stale_view_seconds,
                 "call_graph": [list(e) for e in cfg.call_graph],
                 "service_deployments": [list(p) for p in cfg.service_deployments]}}))


def capture_model(capture_id: str, records, requests) -> CaptureModel:
    """Binding and constants from the unperturbed (S0) records; fixed before any verdict."""
    records = tuple(records)
    P = patch_request_at(records)
    binding = bind(records, P) if planned_service(records) else None
    if binding is not None and P is None:
        raise InputError(f"{capture_id}: a planned change without a patch row")
    action = None
    if binding is not None:
        action = Action(f"{capture_id}/A", "rollback_deployment", ObjectRef("Deployment", uid=binding.deployment_uid),
                        service=binding.service)
    return CaptureModel(capture_id, bound_change_records(records, binding), tuple(requests), binding, P,
                        horizon(records), dict(service_deployments(records)), action)


class StreamContext:
    """One stream of one capture: its records, derived model inputs, lazily built stores and an evaluation memo."""

    def __init__(self, capture: CaptureModel, stream: str, records, manifest: Mapping | None = None):
        self.capture = capture
        self.stream = stream
        self.records = bound_change_records(tuple(records), capture.binding)
        self.manifest = dict(manifest or {})
        self.model: ModelInputs = build_model_inputs(self.records, capture.binding)
        self._stores: dict = {}
        self.memo: dict = {}
        self.fact_cache: dict | None = None      # optional per-group fact cache (checks only)

    def store(self, knowledge: str):
        if knowledge == CORRECTED:
            knowledge = TWO_CLOCK
        if knowledge not in self._stores:
            m = self.model
            cache = self.fact_cache
            if knowledge == TWO_CLOCK:
                built = build_store(a1_facts(m.observations, m.withdrawals, cache=cache), m.identity_facts,
                                    label=TWO_CLOCK)
            elif knowledge == LATEST:
                built = build_store(latest_facts(m.observations, m.withdrawals, cache=cache), m.identity_facts,
                                    label=LATEST)
            elif knowledge == GATE_V1:
                built = build_store(a1_facts(m.gate_v1_observations(), m.withdrawals, cache=cache),
                                    m.identity_facts, label=GATE_V1)
            else:
                raise KeyError(knowledge)
            self._stores[knowledge] = built
        return self._stores[knowledge]

    def close(self) -> None:
        for store in self._stores.values():
            store.close()
        self._stores.clear()

    def usable_completion(self, tau: int):
        m = self.model
        return [c for c in m.completion_receipts if c.available_at <= tau
                and not (c.record_id in m.completion_withdrawals and m.completion_withdrawals[c.record_id] <= tau)]

    def usable_freezes(self, tau: int):
        m = self.model
        return [f for f in m.freezes if f.available_at <= tau
                and not (f.id in m.freeze_withdrawals and m.freeze_withdrawals[f.id] <= tau)]

    def final_freezes(self):
        return [f for f in self.model.freezes if f.id not in self.model.freeze_withdrawals]

    def final_completion(self):
        return [c for c in self.model.completion_receipts if c.record_id not in self.model.completion_withdrawals]

    def last_knowledge_instant(self) -> int:
        """A cutoff at or after every availability and withdrawal of this stream (hindsight views)."""
        m = self.model
        instants = list(m.availability.values())
        for table in (m.withdrawals, m.completion_withdrawals, m.freeze_withdrawals):
            instants.extend(table.values())
        return max(instants)

    def withdrawn_by(self, tau: int) -> set:
        m = self.model
        out = set()
        for table in (m.withdrawals, m.completion_withdrawals, m.freeze_withdrawals):
            out.update(rid for rid, when in table.items() if when <= tau)
        return out


def freeze_windows(records) -> tuple[FreezeWindow, ...]:
    """FreezeWindow per usable freeze record: label = record ID, declared_at = the record's availability (gate v1's
    R4 compares declared_at with the knowledge cutoff)."""
    out = []
    for f in records:
        payload = f.payload_view()
        out.append(FreezeWindow(f.id, dt(ts_us(payload["start"])), dt(ts_us(payload["end"])), dt(f.available_at)))
    return tuple(out)


# ---------------------------------------------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------------------------------------------
def records_behind(store, ids) -> tuple[str, ...]:
    """Record IDs behind rule IDs: fact -> supporting observations; freeze:/input: name a record directly."""
    out = set()
    for identifier in ids:
        if identifier.startswith(FREEZE_PREFIX):
            out.add(identifier[len(FREEZE_PREFIX):])
        elif identifier.startswith(rollout.INPUT_PREFIX):
            out.add(identifier[len(rollout.INPUT_PREFIX):])
        else:
            out.update(store.support.get(identifier, ()))
    return tuple(sorted(out))


def inputs_behind(model: ModelInputs, records) -> tuple[str, ...]:
    """Input record IDs behind model record IDs (a derived absence -> its list rows and the object's first
    sighting; a receipt-derived observation -> its change row; a sighting, receipt or freeze -> itself)."""
    out = set()
    for rid in records:
        out.update(model.provenance.get(rid, (rid,)))
    return tuple(sorted(out))


def _is_fact(identifier: str) -> bool:
    return not identifier.startswith((FREEZE_PREFIX, rollout.INPUT_PREFIX))


def _decide(spec: ViewSpec, sctx: StreamContext, store, tau: int, cutoff: int, freezes, receipts) -> tuple:
    """Run R1-R6 (+R7) once; returns (entry, record IDs behind the entry). The entry lists per-rule IDs (store fact
    IDs, ``freeze:``/``input:`` record IDs); record IDs are derived through the store's support map."""
    capture = sctx.capture
    before = store.dual.queries
    view = TracedView(store, dt(tau), dt(cutoff), carry_forward_seconds=spec.F, engine="dual")
    decision = evaluate(capture.action, view, capture.gate_config(spec.F, freeze_windows(freezes)))
    rules = list(decision.rules)
    state = None
    if spec.r7 is not None:
        state, ids = rollout.resolve_state(view, capture.binding)
        procedural = rollout.procedural_clause(receipts, capture.binding) if "procedural" in spec.r7 else None
        rules.append(rollout.r7_rule(state, ids, capture.binding, procedural))
    verdict = combine(r.verdict for r in rules)
    listed = {x for r in rules for x in r.record_ids if _is_fact(x)}
    entry = {"view": spec.name, "stream": sctx.stream, "instant": R.iso(tau), "instant_us": tau,
             "verdict": verdict,
             "deciding": [] if verdict == ALLOW else [f"{r.rule}:{r.reason}" for r in rules if r.verdict == verdict],
             "rules": [{"rule": r.rule, "verdict": r.verdict, "reason": r.reason, "detail": r.detail,
                        "ids": list(r.record_ids)} for r in rules],
             "config_sha256": capture.config_hash(spec),
             "r7": None if state is None else state.to_dict(),
             "store": store.label, "store_queries": store.dual.queries - before,
             "provenance_unlisted_fact_ids": sorted(view.noted - listed)}
    return entry, records_behind(store, (x for r in rules for x in r.record_ids))


def entry_fact_ids(entry: dict) -> list[str]:
    return sorted({x for r in entry["rules"] for x in r["ids"] if _is_fact(x)})


def check_causal(entry: dict, records, sctx: StreamContext, tau: int) -> None:
    """Every record an evaluation relies on (model records and the input records behind them) must have been
    available, and not withdrawn, at its cutoff."""
    availability = sctx.model.availability
    withdrawn = sctx.withdrawn_by(tau)
    for rid in sorted(set(records) | set(inputs_behind(sctx.model, records))):
        available = availability.get(rid)
        if available is None or available > tau:
            raise CausalityViolation(f"{entry['view']} at {R.iso(tau)} relies on {rid}, available "
                                     f"{R.iso(available) if available is not None else 'never'}")
        if rid in withdrawn:
            raise CausalityViolation(f"{entry['view']} at {R.iso(tau)} relies on withdrawn {rid}")


def evaluate_causal(spec: ViewSpec, sctx: StreamContext, tau: int) -> dict:
    """One evaluation of a causal view at tau (observation time = cutoff = tau); memoised per stream."""
    if not spec.causal or spec.knowledge in (FUTURE, CORRECTED):
        raise HindsightRequired(f"{spec.name} is not a causal view")
    if sctx.capture.action is None:
        raise InputError(f"{sctx.capture.capture_id}: A is never posed (no planned change)")
    key = (spec.name, tau)
    if key not in sctx.memo:
        entry, records = _decide(spec, sctx, sctx.store(spec.knowledge), tau, tau, sctx.usable_freezes(tau),
                                 sctx.usable_completion(tau))
        check_causal(entry, records, sctx, tau)
        sctx.memo[key] = entry
    return sctx.memo[key]


def evaluate_hindsight(spec: ViewSpec, sctx: StreamContext, tau: int, *, hindsight: bool) -> dict:
    """(c-hind) or CV at tau. Requires ``hindsight=True``; never reachable from the decision path. CV serves only the X1
    fixtures' corrected verdicts."""
    if hindsight is not True:
        raise HindsightRequired("hindsight evaluations need hindsight=True")
    if spec.causal:
        raise HindsightRequired(f"{spec.name} is causal; use evaluate_causal")
    if sctx.capture.action is None:
        raise InputError(f"{sctx.capture.capture_id}: A is never posed (no planned change)")
    key = ("hindsight", spec.name, tau)
    if key in sctx.memo:
        return sctx.memo[key]
    if spec.knowledge == CORRECTED:
        cutoff = max(tau, sctx.last_knowledge_instant())
        entry, _ = _decide(spec, sctx, sctx.store(CORRECTED), tau, cutoff, sctx.final_freezes(),
                           sctx.final_completion())
        entry["hindsight"] = {"kind": "corrected view: all records, final versions"}
    elif spec.knowledge == FUTURE:
        observations, provenance, distance = hindsight_observations(sctx.model, tau)
        facts, raw_support = latest_facts(observations, {})
        support = {fid: tuple(sorted({src for obs in ids for src in provenance.get(obs, (obs,))}))
                   for fid, ids in raw_support.items()}
        store = build_store((facts, support), hindsight_identities(sctx.model, tau), label=FUTURE)
        try:
            entry, records = _decide(spec, sctx, store, tau, tau, sctx.usable_freezes(tau),
                                     sctx.usable_completion(tau))
        finally:
            store.close()
        relied = {obs for fid in entry_fact_ids(entry) for obs in raw_support.get(fid, ())}
        projected = sorted(rid for rid in relied if rid in distance)
        entry["hindsight"] = {"kind": "future-snapshot sensitivity (hindsight, not a live read)",
                              "records_relied_on": list(records),
                              "projected_records_relied_on": projected,
                              "max_distance_seconds": max((distance[r] for r in projected), default=0) / 1e6}
    else:
        raise KeyError(spec.knowledge)
    sctx.memo[key] = entry
    return entry
