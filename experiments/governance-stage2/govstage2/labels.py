"""Outcome labels, computed after the decision logs are written, never from the gate rules R1-R7.

Sources (final record versions, spans and fault records; no store and no view's knowledge rule):

- the kubelet Ready history of every Pod: every stamped transition any observer recorded (Ready condition
  lastTransitionTime, lastState.terminated.finishedAt with an incremented restartCount, state.running.startedAt after
  a restart), found by fault_control_kill.k1_extract over the union of the three observers' K1-ready rows; the
  source's own stamp is used (``stamp_us``), never the clamped placement;
- deletion stamps: a Pod is terminating from its deletion request = deletionTimestamp - the grace period of its
  Deployment's manifest; when that instant is not inside [last record without deletionTimestamp - b_c, first record
  with it + b_c] the bracket itself is used and every instant inside it is U (recorded);
- spans: the server spans of the changed service (Pod UID x the Pod's pod-template-hash) for the physical rollout
  interval, gRPC health checks (the kubelet's probes) excluded; the patch response R (the patch row);
- EndpointSlice readiness from the watch's events and list objects, as received (the cross-check of action B);
- the fault records: the F1 worker window and target (ground_truth/ground_truth.json: timeline_host active_start /
  active_end, observed.fault_target, evaluation_summary.latency_effect_established), the F2 kill receipt
  (evaluation_only/stage2/host_command.jsonl);
- the clock band b_c.

Labels at an instant x (host clock). Kubelet and span stamps are on the node clock: any label boundary within b_c of a
decision instant makes that decision's label U. Host-clock boundaries (R, the worker window) are compared exactly.

Action A: [P, R) U; [R, end] V1, where end = the later of (i) the end of the last workload request (not a health
check) served by a Pod of the old revision and (ii) the last new Pod's Ready stamp, read as the first instant after R at which the Deployment's desired
number of new-revision Pods are Ready at once by the kubelet history (so a new Pod killed mid-rollout counts with its
return to Ready); after end: GT-2-A (complete, inside the worker window, the fault on a new-revision Pod of the
changed service, effect established), U (the same without an established effect), late ALLOW (at or after
active_end, posed before it), V2 (GT-3) otherwise.

Action B, in this order: U if x is beyond the label evidence; the target's status at x (not Ready, terminating or
gone = violation; a boundary within b_c = U); the EndpointSlice cross-check of every Pod the label depends on (the
target for V-target, every Pod of the service otherwise): a disagreement beyond the band makes the label U and is
counted; V-target; V-floor (the service's Ready Pods other than the target fewer than its floor; counted as an
interval [certain, possible], uncertain = U); GT-2-B (the target is the F1 worker's Pod, the worker active at x, the
effect established; without an established effect U); neutral otherwise.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field

from aiops_kg import fault_control_kill as K

from .common import iso, ts_us
from govpilot.inputs import CHANGE_PATCH, change_record  # noqa: E402  (read-only)

GT0, U, V1, GT2A, LATE, GT3 = "GT-0", "U", "V1", "GT-2-A", "LATE_ALLOW", "V2 (GT-3)"
VTARGET, VFLOOR, GT2B, NEUTRAL = "V-target", "V-floor", "GT-2-B", "neutral"
UNSAFE = {"A": (V1,), "B": (VTARGET, VFLOOR)}
OPPORTUNITY = {"A": GT2A, "B": GT2B}


@dataclass
class PodHistory:
    uid: str
    name: str | None = None
    service: str | None = None
    template_hash: str | None = None
    created_us: int | None = None
    transitions: list = field(default_factory=list)       # (stamp_us, state) sorted
    deletion_request_us: int | None = None                 # deletionTimestamp - grace
    deletion_bracket: tuple | None = None                  # (last record without, first record with) observation us
    deletion_note: str | None = None
    gone_after_us: int | None = None                       # first evidence of removal (DELETED event / absence)
    last_record_us: int | None = None

    def state_at(self, x: int):
        """(state, last transition stamp <= x, next transition stamp > x): the kubelet Ready state at x."""
        stamps = [s for s, _ in self.transitions]
        index = bisect.bisect_right(stamps, x)
        before = self.transitions[index - 1] if index else None
        after = self.transitions[index][0] if index < len(self.transitions) else None
        return (before[1] if before else None), (before[0] if before else None), after


class Labeller:
    """Every label input of one capture, built once after the seal."""

    def __init__(self):
        self.band_us = None
        self.pods: dict[str, PodHistory] = {}
        self.slices: dict[str, list] = {}
        self.notes: dict = {}

    # -- construction -----------------------------------------------------------------------------------------------
    @classmethod
    def build(cls, capture, inputs, label_inputs, grace_by_service: dict) -> "Labeller":
        self = cls()
        self.capture = capture
        self.band_us = inputs.band_us
        self.floors = dict(capture.floors) or {}
        self.service = capture.changed_service
        self.binding = capture.binding
        self.P = capture.P
        self.grace = dict(grace_by_service)
        rows = [r for observer in ("poller", "watch", "recheck") for r in label_inputs.k1_rows.get(observer) or []]
        self._pods_from_rows(rows)
        self._ready_history(rows)
        self._slices(label_inputs.endpoint_slices)
        self.label_horizon = max((p.last_record_us for p in self.pods.values() if p.last_record_us is not None),
                                 default=None)
        self.R = None
        for rec in inputs.base_records:
            if rec.kind == CHANGE_PATCH and rec.corrects is None:
                self.R = change_record(rec).response_received_at
        self._fault(label_inputs)
        self._rollout(inputs)
        return self

    def _pods_from_rows(self, rows):
        by_uid = defaultdict(list)
        for row in rows:
            observed = K._time_field(row, "observed_at")
            by_uid[row["pod_uid"]].append((observed, row))
        for uid, items in by_uid.items():
            items.sort(key=lambda item: (item[0], item[1]["record_id"]))
            first = items[0][1]["pod"]
            meta = first["metadata"]
            labels = meta.get("labels") or {}
            p = PodHistory(uid, meta.get("name"), labels.get("app"), labels.get("pod-template-hash"),
                           ts_us(meta["creationTimestamp"]) if meta.get("creationTimestamp") else None)
            p.last_record_us = items[-1][0]
            without = [o for o, row in items if not row["pod"]["metadata"].get("deletionTimestamp")]
            with_deletion = [(o, row) for o, row in items if row["pod"]["metadata"].get("deletionTimestamp")]
            if with_deletion:
                first_with, row = with_deletion[0]
                deletion = ts_us(row["pod"]["metadata"]["deletionTimestamp"])
                grace = self.grace.get(p.service, 30)
                request = deletion - grace * 1_000_000
                last_without = max((o for o in without if o < first_with), default=None)
                band = self.band_us or 0
                low = (last_without - band) if last_without is not None else None
                if (low is None or request >= low) and request <= first_with + band:
                    p.deletion_request_us = request
                    p.deletion_note = "deletionTimestamp - grace"
                else:
                    p.deletion_bracket = (last_without, first_with)
                    p.deletion_note = ("deletionTimestamp - grace lies outside the records' bracket; the bracket "
                                       "[last record without, first record with deletionTimestamp] is used (U inside)")
            deleted = [o for o, row in items if row.get("event_type") == "DELETED"]
            if deleted:
                p.gone_after_us = min(deleted)
            self.pods[uid] = p

    def _ready_history(self, rows):
        extraction = K.k1_extract(rows, band_us=self.band_us, allow_mixed_observers=True)
        seen = set()
        for o in extraction["observations"]:
            key = (o["pod_uid"], o["stamp_us"], o["state"], o["source_field"])
            seen.add(key)
            self.pods[o["pod_uid"]].transitions.append((o["stamp_us"], o["state"]))
        for d in extraction["dropped"]:
            key = (d["pod_uid"], d["stamp_us"], d["state"], d["source_field"])
            if key not in seen:
                self.pods[d["pod_uid"]].transitions.append((d["stamp_us"], d["state"]))
        rank = {"not_ready": 0, "ready": 1}
        for p in self.pods.values():
            p.transitions = sorted(set(p.transitions), key=lambda t: (t[0], rank[t[1]]))
        self.notes["k1_union_counts"] = extraction["counts"]

    def _slices(self, slices):
        by_service = defaultdict(list)
        for receipt, evidence_id, obj in slices:
            service = (obj["metadata"].get("labels") or {}).get("kubernetes.io/service-name")
            if service:
                ready = {}
                for endpoint in obj.get("endpoints") or []:
                    ref = (endpoint.get("targetRef") or {}).get("uid")
                    cond = endpoint.get("conditions") or {}
                    if ref:
                        ready[ref] = bool(cond.get("ready")) and not cond.get("terminating")
                by_service[service].append((receipt, evidence_id, ready))
        self.slices = {s: sorted(v, key=lambda item: (item[0], item[1])) for s, v in by_service.items()}

    def _fault(self, label_inputs):
        doc = label_inputs.ground_truth or {}
        observed = doc.get("observed") or {}
        target = observed.get("fault_target") or {}
        timeline = doc.get("timeline_host") or {}

        def mark(name):
            value = (timeline.get(name) or {}).get("host_utc")
            return ts_us(value) if value else None
        self.fault_present = bool(((doc.get("planned") or {}).get("labels") or {}).get("fault_present"))
        self.fault_service = target.get("service")
        self.fault_pod = target.get("pod_uid")
        self.fault_selected_by = target.get("selected_by")
        self.active_start, self.active_end = mark("active_start"), mark("active_end")
        self.effect = (doc.get("evaluation_summary") or {}).get("latency_effect_established")
        self.kills = [{"id": k.get("id"), "start": ts_us(k["request_started_at"]),
                       "end": ts_us(k["response_received_at"])} for k in label_inputs.kill_receipts]
        fault = ((doc.get("planned") or {}).get("fault") or {})
        self.fault_type = fault.get("type") if isinstance(fault, dict) else None
        if self.fault_type is None and self.kills:
            self.fault_type = "F2"

    def _rollout(self, inputs):
        """The physical rollout interval of section 7.1."""
        self.old_hash = self.binding.pod_template_hash if self.binding else None
        self.new_hash, self.desired = None, None
        if self.binding is None:
            self.rollout = None
            return
        for rec in list(inputs.poller_api) + list(inputs.watch_api):
            resource = rec.payload_view()["resource_data"]
            meta = resource["metadata"]
            if resource["kind"] == "ReplicaSet" and rec.deployment_uid == self.binding.deployment_uid \
                    and rec.revision == self.binding.changed_revision:
                self.new_hash = (meta.get("labels") or {}).get("pod-template-hash")
            if resource["kind"] == "Deployment" and meta.get("uid") == self.binding.deployment_uid:
                self.desired = (resource.get("spec") or {}).get("replicas", self.desired)
        old_served = [s.end_us for s in inputs.spans.all_servers(self.service)
                      if s.pod_uid in self.pods and self.pods[s.pod_uid].template_hash == self.old_hash
                      and self.old_hash is not None and not s.health_check]
        last_old = max(old_served) if old_served else None
        new_pods = [p for p in self.pods.values() if p.service == self.service and p.template_hash == self.new_hash
                    and self.new_hash is not None]
        complete = None
        if self.R is not None and self.desired:
            stamps = sorted({s for p in new_pods for s, _ in p.transitions if s >= self.R} | {self.R})
            for s in stamps:
                ready = sum(1 for p in new_pods if p.state_at(s)[0] == "ready" and not self._terminating(p, s))
                if ready >= self.desired:
                    complete = s
                    break
        end = None
        if complete is not None:
            end = max(x for x in (last_old, complete) if x is not None)
        self.rollout = {"R_us": self.R, "old_hash": self.old_hash, "new_hash": self.new_hash,
                        "desired_new_replicas": self.desired, "last_old_served_end_us": last_old,
                        "new_ready_complete_us": complete, "end_us": end,
                        "end_basis": None if end is None else ("old-revision request end" if end == last_old else
                                                                "last new Pod Ready stamp")}

    # -- Pod states at x ------------------------------------------------------------------------------------------
    def _terminating(self, p: PodHistory, x: int) -> bool:
        return (p.deletion_request_us is not None and x >= p.deletion_request_us) or \
            (p.deletion_bracket is not None and x >= p.deletion_bracket[1])

    def pod_status(self, uid: str, x: int) -> tuple[str, str]:
        """('ready' | 'down' | 'uncertain', reason) of one Pod at x by the kubelet history and deletion stamps."""
        p = self.pods.get(uid)
        if p is None:
            return "uncertain", "pod_without_records"
        band = self.band_us
        if band is None:
            return "uncertain", "clock_band_unavailable"
        if p.gone_after_us is not None and x >= p.gone_after_us:
            return "down", "gone"
        if p.deletion_request_us is not None:
            if abs(x - p.deletion_request_us) <= band:
                return "uncertain", "deletion_request_within_band"
            if x > p.deletion_request_us:
                return "down", "terminating"
        if p.deletion_bracket is not None:
            low, high = p.deletion_bracket
            if x >= high:
                return "down", "terminating"
            if low is None or x > low:
                return "uncertain", "deletion_between_records"
        if p.created_us is not None and x < p.created_us - band:
            return "down", "not_yet_created"
        state, last, following = p.state_at(x)
        if (last is not None and x - last <= band) or (following is not None and following - x <= band):
            return "uncertain", "ready_transition_within_band"
        if state is None:
            return "uncertain", "no_ready_history_before_x"
        return ("ready", "ready") if state == "ready" else ("down", "not_ready")

    def slice_ready(self, uid: str, service: str, x: int):
        items = self.slices.get(service) or []
        index = bisect.bisect_right([t for t, _, _ in items], x)
        if index == 0:
            return None
        return items[index - 1][2].get(uid, False)

    def kubelet_ready(self, uid: str, x: int):
        p = self.pods.get(uid)
        if p is None:
            return None
        if (p.gone_after_us is not None and x >= p.gone_after_us) or self._terminating(p, x):
            return False
        state = p.state_at(x)[0]
        return None if state is None else state == "ready"

    def cross_check(self, uid: str, service: str, x: int) -> str | None:
        """'agree', 'disagree_within_band', 'disagree_beyond_band', or None (no slice before x)."""
        sliced = self.slice_ready(uid, service, x)
        if sliced is None:
            return None
        kubelet = self.kubelet_ready(uid, x)
        if kubelet is None or kubelet == sliced:
            return "agree"
        band = self.band_us or 0
        for t in (x - band, x + band):
            if self.kubelet_ready(uid, t) == sliced:
                return "disagree_within_band"
        p = self.pods.get(uid)
        if p is not None and any(x - band <= s <= x + band for s, _ in p.transitions):
            return "disagree_within_band"
        return "disagree_beyond_band"

    # -- labels ---------------------------------------------------------------------------------------------------
    def label_a(self, x: int, kappa: int | None = None) -> tuple[str, str]:
        if self.binding is None or self.P is None:
            return GT3, "no_change"
        if x < self.P:
            return GT0, "before_patch_request"
        if self.R is None or x < self.R:
            return U, "U_pre"
        if self.label_horizon is not None and x > self.label_horizon:
            return U, "beyond_label_evidence"
        end = (self.rollout or {}).get("end_us")
        if end is None:
            return V1, "rollout_not_complete_in_records"
        band = self.band_us
        if band is None:
            return U, "clock_band_unavailable"
        if abs(x - end) <= band:
            return U, "rollout_end_within_band"
        if x < end:
            return V1, "inside_physical_rollout_interval"
        return self._gt2a(x, kappa)

    def _gt2a(self, x: int, kappa: int | None) -> tuple[str, str]:
        inside = self.active_start is not None and self.active_start <= x < self.active_end
        fault_on_new = (self.fault_present and self.fault_service == self.service and self.fault_pod is not None
                        and self.fault_pod in self.pods and self.pods[self.fault_pod].template_hash == self.new_hash
                        and self.fault_type != "F2")
        if fault_on_new:
            if self.effect:
                if inside:
                    return GT2A, "constructed mitigation opportunity"
                if self.active_end is not None and x >= self.active_end and kappa is not None and \
                        kappa < self.active_end:
                    return LATE, "executed at or after active_end; posed before it"
                return GT3, "outside the fault window"
            if inside:
                return U, "GT-2-A conditions without an established effect"
            return GT3, "outside the fault window"
        if not self.fault_present:
            return GT3, "no fault"
        return GT3, "fault not on a new-revision Pod of the changed service" if self.fault_type != "F2" \
            else "F2 kill: rollback is not its mitigation"

    def label_b(self, x: int, target: str) -> tuple[str, str, dict]:
        """(label, reason, detail) of restarting ``target`` at x."""
        detail = {}
        if self.label_horizon is not None and x > self.label_horizon:
            return U, "beyond_label_evidence", detail
        status, reason = self.pod_status(target, x)
        detail["target"] = reason
        if status == "uncertain":
            return U, "target_" + reason, detail
        if status == "down":
            check = self.cross_check(target, self.service, x)
            detail["cross_check"] = {target: check}
            if check == "disagree_beyond_band":
                return U, "endpointslice_disagreement", detail
            return VTARGET, reason, detail
        others = [p for p in self.pods.values() if p.service == self.service and p.uid != target]
        certain = possible = 0
        uncertain_pods = []
        for p in others:
            s, _ = self.pod_status(p.uid, x)
            if s == "ready":
                certain += 1
                possible += 1
            elif s == "uncertain":
                possible += 1
                uncertain_pods.append(p.uid)
        floor = self.floors.get(self.service, 1)
        detail["floor"] = {"floor": floor, "ready_others_certain": certain, "ready_others_possible": possible}
        checks = {uid: self.cross_check(uid, self.service, x) for uid in sorted([target] + [p.uid for p in others])}
        detail["cross_check"] = checks
        if any(v == "disagree_beyond_band" for v in checks.values()):
            return U, "endpointslice_disagreement", detail
        if possible < floor:
            return VFLOOR, "below_floor", detail
        if certain < floor:
            return U, "floor_count_within_band", detail
        return self._gt2b(x, target, detail)

    def _gt2b(self, x: int, target: str, detail: dict) -> tuple[str, str, dict]:
        worker = self.fault_present and self.fault_type != "F2" and self.fault_pod == target
        inside = self.active_start is not None and self.active_start <= x < self.active_end
        if worker and inside:
            if self.effect:
                return GT2B, "worker Pod restarted while the worker was active", detail
            return U, "GT-2-B conditions without an established effect", detail
        return NEUTRAL, "healthy replica restarted with the floor kept", detail

    def opportunity_at(self, family: str, kappa: int, target: str | None) -> bool:
        """Whether the request is labelled GT-2 at its posing instant (missed-opportunity denominator)."""
        if family == "A":
            return self.label_a(kappa, kappa)[0] == GT2A
        return self.label_b(kappa, target)[0] == GT2B

    def in_window(self, x: int) -> bool:
        return self.active_start is not None and self.active_start <= x < self.active_end

    # -- reporting ------------------------------------------------------------------------------------------------
    def summary(self) -> dict:
        rollout = None
        if self.rollout:
            rollout = {k: (iso(v) if k.endswith("_us") and v is not None else v) for k, v in self.rollout.items()}
        return {
            "rule": "labels never use R1-R7, a store or a view's knowledge rule",
            "clock_band_us": self.band_us, "label_horizon": iso(self.label_horizon) if self.label_horizon else None,
            "physical_rollout_interval": rollout,
            "fault": {"present": self.fault_present, "type": self.fault_type, "service": self.fault_service,
                      "pod_uid": self.fault_pod, "selected_by": self.fault_selected_by,
                      "active_start": iso(self.active_start) if self.active_start else None,
                      "active_end": iso(self.active_end) if self.active_end else None,
                      "latency_effect_established": self.effect,
                      "kill_receipts": [{"id": k["id"], "start": iso(k["start"]), "end": iso(k["end"])}
                                        for k in self.kills]},
            "pods": [{"uid": p.uid, "name": p.name, "service": p.service, "template_hash": p.template_hash,
                      "ready_transitions": [[iso(s), st] for s, st in p.transitions],
                      "deletion_request": iso(p.deletion_request_us) if p.deletion_request_us else None,
                      "deletion_bracket": [iso(v) if v else None for v in p.deletion_bracket]
                      if p.deletion_bracket else None, "deletion_note": p.deletion_note,
                      "gone_after": iso(p.gone_after_us) if p.gone_after_us else None}
                     for p in sorted(self.pods.values(), key=lambda p: (p.service or "", p.name or "", p.uid))],
            "floors": dict(sorted(self.floors.items())), "notes": self.notes}
