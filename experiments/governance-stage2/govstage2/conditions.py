"""The gate conditions, actions A and B, the gate configuration, and one evaluation.

Every condition runs R1-R6 of gate v1 (src/aiops_kg/policy_gate.py ``evaluate``) at the development configuration
(N = 30 s, k = 3 downstream, S = 300 s; experiments/policy-gate-v1's own ``make_config``) with the plan's R3 floors
(``replica_floor_by_service``), plus R7's state clause (govpilot/rollout.py, kubectl's DeploymentStatusViewer order,
A's binding). The combined verdict is the most severe (DENY > ABSTAIN > NEEDS_APPROVAL > ALLOW). R7's records do not
feed R6.

==========  =========  ======================  ===================================================================
condition   observer   knowledge rule          evaluation (cutoff kappa or tau, dispatch x)
==========  =========  ======================  ===================================================================
T_p         poller     two-clock A1, F = 30 s   at (tau, tau + delta): records available at tau, safe at x
L_p         poller     latest record, F = 30 s  as T_p
T_w, L_w    watch      as T_p, L_p              as T_p (watch cache-snapshot store)
L-kappa     poller     latest record, F = 30 s  at (tau, tau) -- approved at the cutoff -- executed at tau + delta
R           recheck    one response             at (x_R, x_R) on the first response whose request started at or
                                                after x; ALLOW executes at x_R; ABSTAIN waits for the next response
c-hind      poller     as L, cluster predicates  hindsight (never a live read): the first sighting at or after x,
                       from the future           re-stamped at x; change records causal at tau (sensitivity only)
T@F600      poller     as T_p, F = 600 s        as T_p (stream S0 only)
L@F600      poller     as L_p, F = 600 s        as L_p (stream S0 only)
==========  =========  ======================  ===================================================================

Actions. A: roll back the newest change (gate v1 ``rollback_deployment`` on u_C; the development binding). B: restart
the changed service's Pod that served request k (gate v1 ``restart_pod``, target UID from the span). R1 (target
identity), R3 (floor) and R7 decide B; R2, R4, R5 and R6 run too, as everywhere.

An evaluation is identified by (observer, stream, knowledge rule and F, action, cutoff, dispatch); L-kappa's
evaluations at (tau, tau) are therefore the same evaluations as L_p's at delta = 0.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from functools import lru_cache

from aiops_kg.policy_gate import ALLOW, Action, FreezeWindow, ObjectRef, combine, evaluate

from .common import R, canonical, dt, iso, sha256_text, ts_us
from .forward import ForwardTracedView
from govpilot import rollout  # noqa: E402  (read-only: R7)
from govpilot.mapping import pga  # noqa: E402
from govpilot.views import FREEZE_PREFIX  # noqa: E402

TWO_CLOCK, LATEST, FUTURE, RECHECK = "two_clock", "latest", "future_snapshot", "recheck_response"
N_SECONDS = 30.0
S_SECONDS = 300.0
F_PRIMARY = 30.0
F_SENSITIVITY = 600.0
E_SECONDS = 120.0
FORWARD, APPROVE_THEN_EXECUTE, RECHECK_POSING, HINDSIGHT = "forward", "approve_then_execute", "recheck", "hindsight"


@dataclass(frozen=True)
class Condition:
    name: str
    observer: str
    knowledge: str
    F: float
    posing: str
    role: str
    streams_only: tuple | None = None
    E: float = E_SECONDS
    N: float = N_SECONDS          # R2's recent-change window (the parameter sweep varies it)

    @property
    def causal(self) -> bool:
        return self.posing != HINDSIGHT

    @property
    def eval_view(self) -> str:
        view = f"{self.knowledge}@F{self.F:g}"
        return view if self.N == N_SECONDS else f"{view}@N{self.N:g}"

    def config(self) -> dict:
        return {"condition": self.name, "observer": self.observer, "knowledge": self.knowledge, "F_seconds": self.F,
                "posing": self.posing, "role": self.role, "E_seconds": self.E, "N_seconds": self.N,
                "S_seconds": S_SECONDS, "streams_only": list(self.streams_only) if self.streams_only else None,
                "r7": "state"}


CONDITIONS = {
    "T_p": Condition("T_p", "poller", TWO_CLOCK, F_PRIMARY, FORWARD, "treatment (two-clock gate, poller store)"),
    "L_p": Condition("L_p", "poller", LATEST, F_PRIMARY, FORWARD, "matched latest-snapshot comparator (H-G1)"),
    "T_w": Condition("T_w", "watch", TWO_CLOCK, F_PRIMARY, FORWARD, "collector control (H-G4): two-clock, watch"),
    "L_w": Condition("L_w", "watch", LATEST, F_PRIMARY, FORWARD, "collector control: latest snapshot, watch"),
    "L-kappa": Condition("L-kappa", "poller", LATEST, F_PRIMARY, APPROVE_THEN_EXECUTE,
                         "check-to-use comparator (H-G2): judged at the cutoff, executed later without a re-check"),
    "R": Condition("R", "recheck", RECHECK, F_PRIMARY, RECHECK_POSING,
                   "fresh-state recheck at dispatch (H-G3)"),
    "c-hind": Condition("c-hind", "poller", FUTURE, F_PRIMARY, HINDSIGHT,
                        "future-snapshot sensitivity (hindsight, not a live read); never a baseline"),
    "T@F600": Condition("T@F600", "poller", TWO_CLOCK, F_SENSITIVITY, FORWARD, "freshness sensitivity",
                        streams_only=("S0",)),
    "L@F600": Condition("L@F600", "poller", LATEST, F_SENSITIVITY, FORWARD, "freshness sensitivity",
                        streams_only=("S0",)),
}
OBSERVER_ORDER = ("poller", "watch", "recheck")


def conditions_for(names) -> list[Condition]:
    out = []
    for name in names:
        if name not in CONDITIONS:
            raise KeyError(f"unknown condition {name!r} (known: {', '.join(CONDITIONS)})")
        out.append(CONDITIONS[name])
    return out


# ---------------------------------------------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ActionSpec:
    key: str           # "A" or "B:<pod uid>"
    family: str        # "A" or "B"
    action: Action

    @property
    def target_uid(self) -> str | None:
        return self.key.split(":", 1)[1] if self.family == "B" else None


def action_a(capture_id: str, binding) -> ActionSpec:
    return ActionSpec("A", "A", Action(f"{capture_id}/A", "rollback_deployment",
                                       ObjectRef("Deployment", uid=binding.deployment_uid), service=binding.service))


def action_b(capture_id: str, service: str, pod_uid: str) -> ActionSpec:
    return ActionSpec(f"B:{pod_uid}", "B", Action(f"{capture_id}/B/{pod_uid}", "restart_pod",
                                                  ObjectRef("Pod", uid=pod_uid), service=service))


# ---------------------------------------------------------------------------------------------------------------
# Gate configuration and its hash
# ---------------------------------------------------------------------------------------------------------------
def gate_config(service_deployments: dict, floors: dict, F: float, freezes=(), N: float = N_SECONDS):
    base = pga().make_config({"service_deployments": service_deployments}, tuple(freezes), N)
    return dataclasses.replace(base, carry_forward_seconds=F, replica_floor_by_service=tuple(sorted(floors.items())))


def freeze_windows(records) -> tuple[FreezeWindow, ...]:
    out = []
    for f in records:
        payload = f.payload_view()
        out.append(FreezeWindow(f.id, dt(ts_us(payload["start"])), dt(ts_us(payload["end"])), dt(f.available_at)))
    return tuple(out)


@lru_cache(maxsize=None)
def _config_hash(view_config: str, binding: str, services: str, floors: str) -> str:
    cfg = gate_config(json.loads(services), json.loads(floors), F_PRIMARY)
    return sha256_text(canonical({
        "view": json.loads(view_config), "kubectl": rollout.KUBECTL_REFERENCE,
        "binding": json.loads(binding),
        "gate": {"change_window_seconds": cfg.change_window_seconds, "replica_floor": cfg.replica_floor,
                 "replica_floor_by_service": [list(p) for p in cfg.replica_floor_by_service],
                 "blast_radius_k": cfg.blast_radius_k, "blast_radius_direction": cfg.blast_radius_direction,
                 "blast_radius_transitive": cfg.blast_radius_transitive, "stale_view_seconds": cfg.stale_view_seconds,
                 "call_graph": [list(e) for e in cfg.call_graph],
                 "service_deployments": [list(p) for p in cfg.service_deployments]}}))


def config_hash(view_config: dict, binding, service_deployments: dict, floors: dict) -> str:
    return _config_hash(canonical(view_config), canonical(binding.to_dict() if binding else None),
                        canonical(service_deployments), canonical(floors))


# ---------------------------------------------------------------------------------------------------------------
# One evaluation
# ---------------------------------------------------------------------------------------------------------------
def records_behind(store, ids) -> tuple[str, ...]:
    out = set()
    for identifier in ids:
        if identifier.startswith(FREEZE_PREFIX):
            out.add(identifier[len(FREEZE_PREFIX):])
        elif identifier.startswith(rollout.INPUT_PREFIX):
            out.add(identifier[len(rollout.INPUT_PREFIX):])
        else:
            out.update(store.support.get(identifier, ()))
    return tuple(sorted(out))


def is_fact(identifier: str) -> bool:
    return not identifier.startswith((FREEZE_PREFIX, rollout.INPUT_PREFIX))


def decide(*, view_name: str, knowledge: str, F: float, store, act: ActionSpec, binding, service_deployments: dict,
           floors: dict, cutoff_us: int, observation_us: int, freezes=(), view_config: dict,
           N: float = N_SECONDS) -> tuple[dict, tuple]:
    """R1-R6 (+ R7 state clause) once, at knowledge cutoff ``cutoff_us`` and observation (dispatch) time
    ``observation_us`` (>= the cutoff; through the forward view), with R2's window ``N``. Returns (entry, record IDs
    behind the entry)."""
    before = store.dual.queries
    view = ForwardTracedView(store, dt(observation_us), dt(cutoff_us), carry_forward_seconds=F, engine="dual")
    decision = evaluate(act.action, view, gate_config(service_deployments, floors, F, freeze_windows(freezes), N=N))
    rules = list(decision.rules)
    state = None
    if binding is not None:
        state, ids = rollout.resolve_state(view, binding)
        rules.append(rollout.r7_rule(state, ids, binding, None))
    verdict = combine(r.verdict for r in rules)
    listed = {x for r in rules for x in r.record_ids if is_fact(x)}
    entry = {"view": view_name, "knowledge": knowledge, "F_s": F, "action": act.key,
             "cutoff": iso(cutoff_us), "cutoff_us": cutoff_us, "observation": iso(observation_us),
             "observation_us": observation_us, "dispatch_after_cutoff_s": round((observation_us - cutoff_us) / 1e6, 6),
             "verdict": verdict,
             "deciding": [] if verdict == ALLOW else [f"{r.rule}:{r.reason}" for r in rules if r.verdict == verdict],
             "rules": [{"rule": r.rule, "verdict": r.verdict, "reason": r.reason, "detail": r.detail,
                        "ids": list(r.record_ids)} for r in rules],
             "config_sha256": config_hash(view_config, binding, service_deployments, floors),
             "r7": None if state is None else state.to_dict(),
             "store": store.label, "store_queries": store.dual.queries - before,
             "provenance_unlisted_fact_ids": sorted(view.noted - listed)}
    if binding is None:
        entry["r7_note"] = "no planned change: R7 has no binding and is not evaluated"
    return entry, records_behind(store, (x for r in rules for x in r.record_ids))


def entry_fact_ids(entry: dict) -> list[str]:
    return sorted({x for r in entry["rules"] for x in r["ids"] if is_fact(x)})


def trace(entry: dict, store) -> str:
    """Verdict, per-rule trace and the record IDs behind it (reconstruction checks 1 and 2 compare these)."""
    ids = [x for r in entry["rules"] for x in r["ids"]]
    return canonical({"verdict": entry["verdict"], "rules": entry["rules"], "records": records_behind(store, ids)})


def r7_reason(entry: dict) -> str | None:
    return next((r["reason"] for r in entry["rules"] if r["rule"] == "R7"), None)


def first_rules(entry: dict) -> list[str]:
    return [f"{r['rule']}:{r['verdict']}:{r['reason']}" for r in entry["rules"]]


def us_iso(us):
    return R.iso(us)
