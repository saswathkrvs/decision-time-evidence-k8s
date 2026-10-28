"""R7 change-in-progress: kubectl's rollout-status logic with UID/revision binding.

State clause (every view except (a)). The view resolves, with its own knowledge rule,

- GENERATION of Deployment u_C (Deployment sightings plus the patch receipt: g_C at the request start, g_C + 1 at
  the response), and
- ROLLOUT_STATUS of the plan's Deployment, a canonical JSON value taken from one Deployment sighting
  (``status_value``): uid, revision annotation, the sighting's own metadata.generation, spec.replicas, the status
  counters the collector keeps, and the Progressing condition's reason when conditions were recorded,

and then applies ``deployment_state`` in kubectl's order (``DeploymentStatusViewer.Status``,
k8s.io/kubectl pkg/polymorphichelpers/rollout_status.go, read at ``master`` and at tag ``kubernetes-1.34.1`` on
2026-10-06; no difference in the function's logic was seen between the two). The pin: kubectl v1.34.1 (client) and
Kubernetes v1.34.11 (server), as every capture's ``raw/kubectl-version.stdout`` records (``environment.py``):

1. generation > observedGeneration                      -> IN_PROGRESS
2. Progressing reason ProgressDeadlineExceeded           -> FAILED
3. updatedReplicas < spec.replicas                       -> IN_PROGRESS
4. status.replicas > updatedReplicas                     -> IN_PROGRESS (old replicas not yet terminated)
5. availableReplicas < updatedReplicas                   -> IN_PROGRESS
6. otherwise                                             -> COMPLETE (at the sighting's revision)

Binding first: the status sighting must carry metadata.uid == u_C and an integer revision in {r_C, r_C + 1};
anything else is UNKNOWN. Absent status counters read as 0 (as in kubectl; the collector copies only keys present);
an absent metadata.generation, spec.replicas or revision, a non-integer or negative value, or no usable sighting is
UNKNOWN. Without recorded conditions step 2 cannot fire: the result carries the note
``progress_condition_not_recorded`` and a failed rollout shows as IN_PROGRESS.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from aiops_kg.policy_gate import ABSTAIN, ALLOW, NEEDS_APPROVAL, RuleResult, combine

from .common import canonical

IN_PROGRESS = "IN_PROGRESS"
COMPLETE = "COMPLETE"
FAILED = "FAILED"
UNKNOWN = "UNKNOWN"
STATES = (IN_PROGRESS, COMPLETE, FAILED, UNKNOWN)

ROLLOUT_STATUS = "ROLLOUT_STATUS"
REVISION_ANNOTATION = "deployment.kubernetes.io/revision"
TIMED_OUT_REASON = "ProgressDeadlineExceeded"   # deploymentutil.TimedOutReason
STATUS_COUNTERS = ("observedGeneration", "replicas", "updatedReplicas", "readyReplicas", "availableReplicas",
                   "unavailableReplicas")
KUBECTL_CLIENT_PIN = "v1.34.1"           # clientVersion.gitVersion in every capture's raw/kubectl-version.stdout
KUBERNETES_SERVER_PIN = "v1.34.11"       # serverVersion.gitVersion in the same files
KUBECTL_REFERENCE = {
    "function": "DeploymentStatusViewer.Status",
    "file": "k8s.io/kubectl pkg/polymorphichelpers/rollout_status.go",
    "read_at": ["master", "kubernetes-1.34.1"],
    "pin": "kubectl v1.34.1 (client) / Kubernetes v1.34.11 (server), recorded in "
           "phase3/captures/<C>/raw/kubectl-version.stdout for all nine captures; rollout_status.go read at tag "
           "kubernetes-1.34.1",
    "client_gitVersion": KUBECTL_CLIENT_PIN,
    "server_gitVersion": KUBERNETES_SERVER_PIN,
}
R7_NAME = "change-in-progress"


@dataclass(frozen=True, slots=True)
class Binding:
    """A's identity, fixed before any verdict; see ``inputs.bind``."""
    service: str
    deployment_name: str
    deployment_uid: str        # u_C
    revision: int              # r_C (revision at the earliest sighting; the rollback target)
    generation: int            # g_C (metadata.generation at the earliest sighting)
    source_record: str         # evidence ID of the earliest Deployment sighting
    replicaset_uid: str | None = None
    pod_template_hash: str | None = None

    @property
    def changed_revision(self) -> int:
        return self.revision + 1

    @property
    def deployment_key(self) -> str:
        return f"Deployment/{self.deployment_uid}"

    @property
    def status_subject(self) -> str:
        return f"DeploymentName/{self.deployment_name}"

    def to_dict(self) -> dict:
        return {"service": self.service, "deployment_name": self.deployment_name,
                "deployment_uid": self.deployment_uid, "revision": self.revision,
                "changed_revision": self.changed_revision, "generation": self.generation,
                "rollback": f"revision {self.changed_revision} -> {self.revision}",
                "source_record": self.source_record, "replicaset_uid": self.replicaset_uid,
                "pod_template_hash": self.pod_template_hash}


def status_value(resource) -> str:
    """ROLLOUT_STATUS value of one Deployment sighting (canonical JSON; only fields present are copied)."""
    meta = resource.get("metadata") or {}
    spec = resource.get("spec") or {}
    status = resource.get("status") or {}
    conditions = status.get("conditions")
    conditions = conditions if isinstance(conditions, list) else None
    reason = None
    for cond in conditions or ():
        if isinstance(cond, dict) and cond.get("type") == "Progressing":
            reason = cond.get("reason")
    annotations = meta.get("annotations") or {}
    value = {
        "uid": meta.get("uid"),
        "name": meta.get("name"),
        "revision": annotations.get(REVISION_ANNOTATION),
        "generation": meta.get("generation") if "generation" in meta else None,
        "has_generation": "generation" in meta,
        "spec_replicas": spec.get("replicas"),
        "status": {k: status[k] for k in STATUS_COUNTERS if k in status},
        "conditions_recorded": conditions is not None,
        "progressing_reason": reason,
    }
    return canonical(value)


def _nonneg_int(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _revision(text) -> int | None:
    if isinstance(text, bool):
        return None
    if isinstance(text, int):
        return text if text >= 0 else None
    if isinstance(text, str) and text.isdigit():
        return int(text)
    return None


@dataclass(frozen=True, slots=True)
class StateResult:
    state: str
    reason: str
    detail: str
    revision: int | None = None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"state": self.state, "reason": self.reason, "detail": self.detail, "revision": self.revision,
                "notes": list(self.notes)}


def deployment_state(generation, status: dict, binding: Binding) -> StateResult:
    """kubectl's rollout-status order on (resolved generation, one bound status sighting).

    ``generation`` is the view's resolved GENERATION value (string or int); ``status`` the parsed ROLLOUT_STATUS.
    """
    uid = status.get("uid")
    if uid != binding.deployment_uid:
        return StateResult(UNKNOWN, "uid_not_bound", f"status sighting uid {uid!r} is not u_C {binding.deployment_uid}")
    if status.get("revision") is None:
        return StateResult(UNKNOWN, "revision_absent", "no deployment.kubernetes.io/revision annotation")
    revision = _revision(status.get("revision"))
    if revision is None:
        return StateResult(UNKNOWN, "revision_invalid", f"revision {status.get('revision')!r} is not an integer")
    if revision not in (binding.revision, binding.changed_revision):
        return StateResult(UNKNOWN, "revision_not_bound",
                           f"revision {revision} outside {{{binding.revision}, {binding.changed_revision}}}")
    if not status.get("has_generation", status.get("generation") is not None):
        return StateResult(UNKNOWN, "generation_absent", "status sighting has no metadata.generation", revision)
    if _nonneg_int(status.get("generation")) is None:
        return StateResult(UNKNOWN, "generation_invalid", f"metadata.generation {status.get('generation')!r}", revision)
    resolved = _nonneg_int(generation) if isinstance(generation, int) else _revision(generation)
    if resolved is None:
        return StateResult(UNKNOWN, "generation_invalid", f"resolved GENERATION {generation!r}", revision)
    if status.get("spec_replicas") is None:
        return StateResult(UNKNOWN, "spec_replicas_absent", "spec.replicas absent", revision)
    spec_replicas = _nonneg_int(status.get("spec_replicas"))
    if spec_replicas is None:
        return StateResult(UNKNOWN, "spec_replicas_invalid", f"spec.replicas {status.get('spec_replicas')!r}", revision)
    counters = {}
    raw = status.get("status") or {}
    for key in ("observedGeneration", "updatedReplicas", "replicas", "availableReplicas"):
        if key not in raw:
            counters[key] = 0
            continue
        number = _nonneg_int(raw[key])
        if number is None:
            return StateResult(UNKNOWN, "status_counter_invalid", f"status.{key} {raw[key]!r}", revision)
        counters[key] = number
    notes = () if status.get("conditions_recorded") else ("progress_condition_not_recorded",)
    observed, updated = counters["observedGeneration"], counters["updatedReplicas"]
    total, available = counters["replicas"], counters["availableReplicas"]
    if resolved > observed:
        return StateResult(IN_PROGRESS, "spec_update_not_observed",
                           f"generation {resolved} > observedGeneration {observed}", revision, notes)
    if status.get("conditions_recorded") and status.get("progressing_reason") == TIMED_OUT_REASON:
        return StateResult(FAILED, "progress_deadline_exceeded", "Progressing reason ProgressDeadlineExceeded",
                           revision, notes)
    if updated < spec_replicas:
        return StateResult(IN_PROGRESS, "updated_below_spec", f"updatedReplicas {updated} < spec.replicas "
                           f"{spec_replicas}", revision, notes)
    if total > updated:
        return StateResult(IN_PROGRESS, "old_replicas_pending_termination",
                           f"status.replicas {total} > updatedReplicas {updated}", revision, notes)
    if available < updated:
        return StateResult(IN_PROGRESS, "updated_not_available",
                           f"availableReplicas {available} < updatedReplicas {updated}", revision, notes)
    return StateResult(COMPLETE, "complete", f"revision {revision} complete (spec {spec_replicas}, updated {updated}, "
                       f"total {total}, available {available})", revision, notes)


def sighting_state(value: str, binding: Binding) -> StateResult:
    """The state function applied to one sighting with its own generation (the evaluator's GT-1s input)."""
    status = json.loads(value)
    return deployment_state(status.get("generation"), status, binding)


def state_clause_verdict(result: StateResult, binding: Binding) -> tuple[str, str]:
    if result.state == FAILED:
        return NEEDS_APPROVAL, "rollout_failed"
    if result.state == COMPLETE:
        if result.revision == binding.changed_revision:
            return ALLOW, "rollout_complete"
        return ALLOW, "no_visible_change"
    if result.state == IN_PROGRESS:
        return ABSTAIN, "rollout_in_progress:" + result.reason
    return ABSTAIN, "rollout_state_unknown:" + result.reason


def resolve_state(view, binding: Binding) -> tuple[StateResult, tuple[str, ...]]:
    """Resolve GENERATION and ROLLOUT_STATUS through the view's own resolver and apply ``deployment_state``.

    Returns the state and the fact IDs the two resolutions used (recorded through the view's provenance)."""
    with view.recording() as used:
        status_res = view.resolve(binding.status_subject, ROLLOUT_STATUS)
        gen_res = view.resolve(binding.deployment_key, "GENERATION")
    used = tuple(sorted(used))
    if status_res.status != "resolved":
        kind = "conflict" if status_res.status == "conflict" else status_res.reason
        return StateResult(UNKNOWN, "status_" + kind, f"ROLLOUT_STATUS {status_res.status} ({status_res.reason})"), used
    if gen_res.status != "resolved":
        kind = "conflict" if gen_res.status == "conflict" else gen_res.reason
        return StateResult(UNKNOWN, "generation_" + kind, f"GENERATION {gen_res.status} ({gen_res.reason})"), used
    return deployment_state(gen_res.value, json.loads(status_res.value), binding), used


INPUT_PREFIX = "input:"   # rule record IDs that name an input record directly (not a store fact)


def procedural_clause(receipts, binding: Binding) -> tuple[str, str, tuple[str, ...]]:
    """(verdict, reason, IDs) from the completion receipts usable at the cutoff (already filtered by the caller).

    IDs are ``input:<record id>``: receipts are read directly, never through the resolver (a receipt does not go
    stale)."""
    bound = [r for r in receipts if r.deployment_uid == binding.deployment_uid]
    failed = sorted(INPUT_PREFIX + r.record_id for r in bound if r.exit_code != 0)
    if failed:
        return NEEDS_APPROVAL, "rollout_wait_failed", tuple(failed)
    ok = sorted(INPUT_PREFIX + r.record_id for r in bound if r.exit_code == 0)
    if ok:
        return ALLOW, "completion_receipt_usable", tuple(ok)
    return ABSTAIN, "completion_receipt_not_usable", ()


def r7_rule(state: StateResult, state_ids: tuple[str, ...], binding: Binding,
            procedural: tuple[str, str, tuple[str, ...]] | None) -> RuleResult:
    """One RuleResult for R7: the state clause, and the procedural clause when the view adopts it."""
    verdict, reason = state_clause_verdict(state, binding)
    detail = f"state {state.state} ({state.detail})"
    if state.notes:
        detail += f"; notes: {', '.join(state.notes)}"
    ids = tuple(state_ids)
    if procedural is not None:
        p_verdict, p_reason, p_ids = procedural
        detail += f"; procedural {p_verdict} ({p_reason})"
        verdict = combine((verdict, p_verdict))
        reason = f"{reason}+procedural:{p_reason}"
        ids = ids + tuple(p_ids)
    return RuleResult("R7", R7_NAME, verdict, reason, detail, tuple(sorted(set(ids))))
