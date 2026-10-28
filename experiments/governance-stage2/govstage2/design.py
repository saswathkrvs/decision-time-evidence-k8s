"""Record timing: transitions of the counted objects, contested decisions, decisions reached by a late correction
(counted per request row by the engine) and the measured lags. Computed from record timing and the decision logs
alone, before any label is read.

Counted objects: the changed service's Pods (the target Pod and its siblings) and the bound Deployment.

Transitions with a kubelet- or API-stamped valid time (the source's own field, never the clamped placement):

- Pod: every K1 transition (Ready condition lastTransitionTime; lastState.terminated.finishedAt with an incremented
  restartCount; state.running.startedAt after a restart), from fault_control_kill.k1_extract per observer; creation
  (creationTimestamp); deletion request (deletionTimestamp - the manifest's grace period);
- bound Deployment: every distinct Progressing condition (reason, lastUpdateTime), stamped lastUpdateTime; every
  ReplicaSet it owns that was created during the capture (creationTimestamp), the rollout's start.

First availability per observer: the acceptance of the observer's first record that reflects the object's state at
or after the transition (or, for a Pod, the first complete Pod list that lacks a Pod listed before). A transition the
observer never recorded itself is therefore available when the observer first shows a later state, and "never" only
if it never shows the object again.

Contested decisions, per posed decision (stream, action, k, Delta, delta) with cutoff kappa and dispatch x: decisions
at which the compared views could have differed in knowledge.

- H-G4 and H-G3: some transition with stamp <= x whose first availability in the poller store is after kappa (or
  never); the secondary pair ((T_w), (R)) uses the watch store's availability;
- H-G2: some transition with stamp in (kappa, x], or R2's window or a relied-on record's freshness ending in (kappa, x]
  in the first evaluation of (T_p) or (L-kappa) (the request rows carry both).

The design check passes for a comparison if its primary cells hold at least 30 contested decisions over the included
captures of the arm and at least one in at least half of them; the per-capture counts are computed here and the
thresholds are applied across captures by the analysis (analysis/stats.py).
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field

from aiops_kg import fault_control_kill as K

from .capture import manifest_grace_seconds
from .common import iso, s_to_us, ts_us
from .mapping2 import snapshot_pod_rows

PRIMARY = {
    "G": {"H-G2": {"action": "B", "stream": "S0", "delta_s": (10, 30, 80), "pair": ("T_p", "L-kappa")},
          "H-G3": {"action": "B", "stream": "S0", "delta_s": (0, 10, 30, 80), "pair": ("T_p", "R")},
          "H-G3 (T_w, R) secondary": {"action": "B", "stream": "S0", "delta_s": (0, 10, 30, 80), "pair": ("T_w", "R")},
          "H-G4": {"action": "B", "stream": "S0", "delta_s": (0, 10, 30, 80), "pair": ("T_p", "T_w")},
          "action A secondary (H-G4)": {"action": "A", "stream": "S0", "delta_s": (0, 10, 30, 80),
                                        "pair": ("T_p", "T_w")}},
    "D": {"H-G4": {"action": "A", "streams": ("S30", "Snever"), "delta_s": (0,), "pair": ("T_p", "T_w")}},
}
THRESHOLD_TOTAL, THRESHOLD_SHARE = 30, 0.5


@dataclass
class Transitions:
    items: list = field(default_factory=list)   # dicts: object, kind, stamp_us, source_field, avail{observer: us}
    not_counted: list = field(default_factory=list)   # deletion stamps inconsistent with the records (see below)

    def summary(self) -> dict:
        by_kind = defaultdict(int)
        for t in self.items:
            by_kind[t["kind"]] += 1
        return {"counted_transitions": len(self.items), "by_kind": dict(sorted(by_kind.items())),
                "deletion_stamps_not_counted": self.not_counted,
                "rule": "counted objects = the changed service's Pods and the bound Deployment"
                        "; stamps are the sources' own fields; a deletion request (deletionTimestamp - grace) "
                        "earlier than the last record without deletionTimestamp by more than the clock band is "
                        "inconsistent with the records and not counted (listed)"}


def pod_row_stamp(pod: dict, grace_us: int) -> int | None:
    """The latest transition stamp a Pod version carries (creation, deletion request = deletionTimestamp - grace,
    Ready lastTransitionTime, lastState.terminated.finishedAt, state.running.startedAt)."""
    meta, status = pod["metadata"], pod.get("status") or {}
    stamps = []
    if meta.get("creationTimestamp"):
        stamps.append(ts_us(meta["creationTimestamp"]))
    if meta.get("deletionTimestamp"):
        stamps.append(ts_us(meta["deletionTimestamp"]) - grace_us)
    for cond in status.get("conditions") or []:
        if cond.get("type") == "Ready" and cond.get("lastTransitionTime"):
            stamps.append(ts_us(cond["lastTransitionTime"]))
    for c in status.get("containerStatuses") or []:
        finished = ((c.get("lastState") or {}).get("terminated") or {}).get("finishedAt")
        started = ((c.get("state") or {}).get("running") or {}).get("startedAt")
        stamps += [ts_us(v) for v in (finished, started) if v]
    return max(stamps) if stamps else None


def deployment_row_stamp(resource: dict) -> int:
    stamps = [ts_us(resource["metadata"]["creationTimestamp"])]
    for cond in (resource.get("status") or {}).get("conditions") or []:
        stamps += [ts_us(cond[f]) for f in ("lastUpdateTime", "lastTransitionTime") if cond.get(f)]
    return max(stamps)


class _Reflection:
    """One observer's records per counted object, for "first availability of a record reflecting the object's state
    at or after a stamp" (module docstring)."""

    def __init__(self):
        self.rows: dict = defaultdict(list)          # object -> [(available, stamp)]
        self.lists: list = []                        # complete Pod lists: (observed, available, present uids)

    def add(self, obj: str, available: int, stamp: int | None) -> None:
        if stamp is not None:
            self.rows[obj].append((available, stamp))

    def seal(self) -> None:
        self._prefix = {}
        for obj, items in self.rows.items():
            items.sort()
            best, prefix = None, []
            for _, stamp in items:
                best = stamp if best is None else max(best, stamp)
                prefix.append(best)
            self._prefix[obj] = prefix
        self.lists.sort(key=lambda item: (item[0], item[1]))
        self._first_seen = {}
        for observed, _, present in self.lists:
            for uid in present:
                self._first_seen.setdefault(uid, observed)

    def available(self, obj: str, stamp: int) -> int | None:
        found = None
        prefix = self._prefix.get(obj)
        if prefix:
            index = bisect.bisect_left(prefix, stamp)
            if index < len(prefix):
                found = self.rows[obj][index][0]
        if obj.startswith("Pod/"):
            uid = obj[4:]
            first = self._first_seen.get(uid)
            if first is not None:
                for observed, available, present in self.lists:
                    if observed > first and observed >= stamp and uid not in present:
                        if found is None or available < found:
                            found = available
                        break
        return found


def _reflections(inputs, capture, grace_us: int) -> dict:
    service, binding = capture.changed_service, capture.binding
    out = {name: _Reflection() for name in ("poller", "watch", "recheck")}
    for observer in out:
        for row in inputs.k1_rows.get(observer) or []:
            pod = row["pod"]
            if (pod["metadata"].get("labels") or {}).get("app") == service:
                out[observer].add("Pod/" + row["pod_uid"], K._time_field(row, "available_at"),
                                  pod_row_stamp(pod, grace_us))
    for observer, records in (("poller", inputs.poller_api), ("watch", inputs.watch_api)):
        lists = defaultdict(lambda: [None, None, set()])
        for rec in records:
            resource = rec.payload_view()["resource_data"]
            meta = resource["metadata"]
            kind = resource["kind"]
            if kind == "Pod":
                entry = lists[rec.payload_view().get("snapshot_id") or rec.id]
                entry[0] = rec.observed_at if entry[0] is None else min(entry[0], rec.observed_at)
                entry[1] = rec.available_at if entry[1] is None else max(entry[1], rec.available_at)
                entry[2].add(meta["uid"])
                if (meta.get("labels") or {}).get("app") == service:
                    out[observer].add("Pod/" + meta["uid"], rec.available_at, pod_row_stamp(resource, grace_us))
            elif binding is not None and kind == "Deployment" and meta.get("uid") == binding.deployment_uid:
                out[observer].add("Deployment/" + binding.deployment_uid, rec.available_at,
                                  deployment_row_stamp(resource))
            elif binding is not None and kind == "ReplicaSet" and rec.deployment_uid == binding.deployment_uid:
                out[observer].add("Deployment/" + binding.deployment_uid, rec.available_at,
                                  ts_us(meta["creationTimestamp"]))
        out[observer].lists = [tuple(v) for v in lists.values() if v[0] is not None]
    for _, payload in inputs.recheck_ticks:
        available, observed = ts_us(payload["available_at"]), ts_us(payload["response_received_at"])
        present = set()
        for obj in payload.get("objects") or []:
            meta = obj["metadata"]
            if obj["kind"] == "Pod":
                present.add(meta["uid"])
                if (meta.get("labels") or {}).get("app") == service:
                    out["recheck"].add("Pod/" + meta["uid"], available, pod_row_stamp(obj, grace_us))
            elif binding is not None and obj["kind"] == "Deployment" and meta.get("uid") == binding.deployment_uid:
                out["recheck"].add("Deployment/" + binding.deployment_uid, available, deployment_row_stamp(obj))
            elif binding is not None and obj["kind"] == "ReplicaSet":
                owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
                if owners and owners[0].get("uid") == binding.deployment_uid:
                    out["recheck"].add("Deployment/" + binding.deployment_uid, available,
                                       ts_us(meta["creationTimestamp"]))
        out["recheck"].lists.append((observed, available, present))
    for reflection in out.values():
        reflection.seal()
    return out


def transitions(inputs, capture) -> Transitions:
    """Every transition of a counted object any observer recorded (with the source's own stamp), and per observer
    its first availability (module docstring)."""
    service = capture.changed_service
    grace_us = manifest_grace_seconds(inputs.configuration).get(service, 30) * 1_000_000
    table: dict = {}

    def add(obj, kind, stamp, field_name):
        table.setdefault((obj, kind, stamp, field_name), {"object": obj, "kind": kind, "stamp_us": stamp,
                                                          "source_field": field_name, "avail": {},
                                                          "recorded_by": set()})
        return table[(obj, kind, stamp, field_name)]

    rows_by_observer = {}
    for observer in ("poller", "watch", "recheck"):
        rows = [r for r in inputs.k1_rows.get(observer) or []
                if (r["pod"]["metadata"].get("labels") or {}).get("app") == service]
        if rows and observer == "watch":   # the store's own snapshot sightings, as the decision phase's K1 extraction
            seen = {r["record_id"] for r in rows}
            rows += [r for r in snapshot_pod_rows(inputs.watch_api, "watch")
                     if (r["pod"]["metadata"].get("labels") or {}).get("app") == service
                     and r["record_id"] not in seen]
        rows_by_observer[observer] = rows
    # a deletion request is placed at deletionTimestamp - grace (the API adds the grace period); a placement earlier
    # than the last record (any observer) without deletionTimestamp by more than b_c contradicts the records
    band = inputs.band_us or 0
    last_without, not_counted = {}, {}
    for rows in rows_by_observer.values():
        for row in rows:
            if not row["pod"]["metadata"].get("deletionTimestamp"):
                observed = K._time_field(row, "observed_at")
                last_without[row["pod_uid"]] = max(last_without.get(row["pod_uid"], observed), observed)
    for observer, rows in rows_by_observer.items():
        if not rows:
            continue
        extraction = K.k1_extract(rows, band_us=inputs.band_us)
        for o in extraction["observations"]:
            add("Pod/" + o["pod_uid"], "pod_" + o["source_field"].split(".")[-1].split("[")[0], o["stamp_us"],
                o["source_field"])["recorded_by"].add(observer)
        for row in rows:
            meta = row["pod"]["metadata"]
            if meta.get("creationTimestamp"):
                add("Pod/" + row["pod_uid"], "pod_created", ts_us(meta["creationTimestamp"]),
                    "metadata.creationTimestamp")["recorded_by"].add(observer)
            if meta.get("deletionTimestamp"):
                stamp = ts_us(meta["deletionTimestamp"]) - grace_us
                previous = last_without.get(row["pod_uid"])
                if previous is not None and stamp < previous - band:
                    not_counted.setdefault(row["pod_uid"], {"pod": "Pod/" + row["pod_uid"], "stamp": iso(stamp),
                                                            "last_record_without_deletion": iso(previous)})
                    continue
                add("Pod/" + row["pod_uid"], "pod_deletion_requested", stamp,
                    "metadata.deletionTimestamp - grace")["recorded_by"].add(observer)
    binding = capture.binding
    if binding is not None:
        objects = [("poller", r.payload_view()["resource_data"], r.deployment_uid) for r in inputs.poller_api] + \
                  [("watch", r.payload_view()["resource_data"], r.deployment_uid) for r in inputs.watch_api]
        for _, payload in inputs.recheck_ticks:
            for obj in payload.get("objects") or []:
                owners = [o for o in obj["metadata"].get("ownerReferences", []) if o.get("controller") is True]
                objects.append(("recheck", obj, owners[0].get("uid") if owners else None))
        for observer, resource, owner in objects:
            meta = resource["metadata"]
            if resource["kind"] == "Deployment" and meta.get("uid") == binding.deployment_uid:
                for cond in (resource.get("status") or {}).get("conditions") or []:
                    if cond.get("type") == "Progressing" and cond.get("lastUpdateTime"):
                        add("Deployment/" + binding.deployment_uid, "deployment_progressing",
                            ts_us(cond["lastUpdateTime"]),
                            f"status.conditions[Progressing:{cond.get('reason')}].lastUpdateTime"
                            )["recorded_by"].add(observer)
            elif resource["kind"] == "ReplicaSet" and owner == binding.deployment_uid:
                add("Deployment/" + binding.deployment_uid, "replicaset_created", ts_us(meta["creationTimestamp"]),
                    f"ReplicaSet/{meta['uid']} metadata.creationTimestamp")["recorded_by"].add(observer)
    reflections = _reflections(inputs, capture, grace_us)
    items = []
    for item in sorted(table.values(), key=lambda t: (t["stamp_us"], t["object"], t["kind"], t["source_field"])):
        for observer, reflection in reflections.items():
            available = reflection.available(item["object"], item["stamp_us"])
            if available is not None:
                item["avail"][observer] = available
        item["recorded_by"] = sorted(item["recorded_by"])
        items.append(item)
    return Transitions(items, [not_counted[uid] for uid in sorted(not_counted)])


# ---------------------------------------------------------------------------------------------------------------
# Contested decisions
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class Contested:
    arm: str
    flags: dict = field(default_factory=dict)        # decision key -> {comparison: bool}
    counts: dict = field(default_factory=dict)       # comparison -> {"contested", "posed"}

    def summary(self) -> dict:
        return {"rule": "record timing only, before any label", "arm": self.arm,
                "primary_cells": {name: {k: (list(v) if isinstance(v, tuple) else v) for k, v in spec.items()}
                                  for name, spec in PRIMARY.get(self.arm, {}).items()},
                "per_comparison": self.counts,
                "thresholds": {"total_at_least": THRESHOLD_TOTAL, "share_of_captures_with_one_at_least":
                               THRESHOLD_SHARE, "applied_by": "design_check_verdict over the arm's included captures"}}

    def is_contested(self, comparison: str, key) -> bool:
        return bool(self.flags.get(key, {}).get(comparison))


def decision_key(row: dict):
    return (row["stream"], row["action"], row["k"], row["Delta_s"], row["delta_s"])


def contested(index, capture, timing: Transitions) -> Contested:
    """Flags per posed decision (the decision keys of the poller's (T_p) and (L-kappa) rows and the watch's (T_w)
    rows: a decision's kappa and x do not depend on the condition) for the comparisons whose two conditions ran;
    H-G2's relied-on bounds come from (T_p)'s and (L-kappa)'s first evaluations. Reads the closed logs (decision
    side, before the seal)."""
    result = Contested(capture.plan.arm)
    items = timing.items
    active = {name for name, spec in PRIMARY.get(capture.plan.arm, {}).items()
              if all(c in capture.condition_names for c in spec["pair"])}
    first_rows = {}
    for observer, names in (("poller", ("T_p", "L-kappa")), ("watch", ("T_w",))):
        for kind, row in index.iter_unverified(observer, ("request",)):
            if row["condition"] in names and row.get("posed"):
                first_rows.setdefault(decision_key(row), {})[row["condition"]] = row
    for key, rows in sorted(first_rows.items(), key=lambda item: str(item[0])):
        row = next(iter(rows.values()))
        kappa, x = row["kappa_us"], row["x_us"]       # kappa and x depend on the decision, not on the condition
        flags = {}
        late_poller = any(t["stamp_us"] <= x and (t["avail"].get("poller") is None or t["avail"]["poller"] > kappa)
                          for t in items)
        late_watch = any(t["stamp_us"] <= x and (t["avail"].get("watch") is None or t["avail"]["watch"] > kappa)
                         for t in items)
        flags["H-G4"] = flags["H-G3"] = late_poller
        flags["H-G3 (T_w, R) secondary"] = late_watch
        flags["action A secondary (H-G4)"] = late_poller
        inside = any(kappa < t["stamp_us"] <= x for t in items)
        bounds = []
        for name in ("T_p", "L-kappa"):
            r = rows.get(name) or {}
            bounds += list(r.get("first_freshness_ends_us") or [])
            if r.get("first_r2_window_end_us") is not None:
                bounds.append(r["first_r2_window_end_us"])
        flags["H-G2"] = inside or any(kappa < b <= x for b in bounds)
        result.flags[key] = {name: flag for name, flag in flags.items() if name in active}
    for name, spec in PRIMARY.get(capture.plan.arm, {}).items():
        streams = spec.get("streams") or (spec.get("stream"),)
        missing = [c for c in spec["pair"] if c not in capture.condition_names]
        if missing:
            result.counts[name] = {"contested": None, "posed": None, "pair": list(spec["pair"]),
                                   "not_computed": f"{', '.join(missing)} not run in this invocation"}
            continue
        posed = hits = 0
        for (stream, action, k, delta_cap, delta), flags in result.flags.items():
            if stream not in streams or action != spec["action"] or delta not in spec["delta_s"]:
                continue
            posed += 1
            hits += bool(flags.get(name))
        result.counts[name] = {"contested": hits, "posed": posed, "pair": list(spec["pair"])}
    return result


def design_check_verdict(per_capture_counts: list[int]) -> dict:
    """The design-check rule over the included captures of an arm: pass iff at least 30 contested decisions in all
    and at least one in at least half of the captures."""
    total = sum(per_capture_counts)
    with_one = sum(1 for c in per_capture_counts if c >= 1)
    captures = len(per_capture_counts)
    passed = total >= THRESHOLD_TOTAL and captures > 0 and with_one >= THRESHOLD_SHARE * captures
    return {"passes": passed, "contested": total, "captures_with_one": with_one, "captures": captures,
            "label_if_failed": None if passed else
            f"uninformative: design check failed ({total} contested decisions in {with_one} of {captures} captures)"}


# ---------------------------------------------------------------------------------------------------------------
# Measured lags
# ---------------------------------------------------------------------------------------------------------------
def _stats(values):
    values = sorted(values)
    if not values:
        return {"n": 0, "min_s": None, "median_s": None, "max_s": None}
    n = len(values)
    median = values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2
    return {"n": n, "min_s": round(values[0] / 1e6, 6), "median_s": round(median / 1e6, 6),
            "max_s": round(values[-1] / 1e6, 6)}


def measured_lags(inputs, capture, timing: Transitions, label_inputs) -> dict:
    """Per observer: stamp -> first availability lags of the counted transitions that happened inside the capture
    (stamp after the observer's first record), the poller's Pod-list intervals, the recheck's read latency, and the
    kubelet's delay from the kill command's receipt to the target's not-Ready stamp; the clock band beside them."""
    out = {"clock_band_us": inputs.band_us, "rule": "no timestamp corrected"}
    starts = {}
    for observer, rows in inputs.k1_rows.items():
        if rows:
            starts[observer] = min(K._time_field(r, "observed_at") for r in rows)
    per = {}
    for observer in ("poller", "watch", "recheck"):
        lags = [t["avail"][observer] - t["stamp_us"] for t in timing.items if observer in t["avail"]
                and observer in starts and t["stamp_us"] >= starts[observer]]
        per[observer] = _stats(lags)
    out["transition_to_first_availability"] = per
    lists = sorted({r.observed_at for r in inputs.poller_api
                    if r.payload_view().get("resource") == "pods"})
    out["poller_pod_list_intervals"] = _stats([b - a for a, b in zip(lists, lists[1:])])
    latencies = [round(float(p["read_latency_ms"]) * 1000) for _, p in inputs.recheck_ticks
                 if p.get("read_latency_ms") is not None]
    out["recheck_read_latency"] = _stats(latencies)
    kill_delays = []
    if label_inputs.kill_receipts and label_inputs.ground_truth:
        target = ((label_inputs.ground_truth.get("observed") or {}).get("fault_target") or {}).get("pod_uid")
        for receipt in label_inputs.kill_receipts:
            end = ts_us(receipt["response_received_at"])
            stamps = [t["stamp_us"] for t in timing.items if t["object"] == f"Pod/{target}"
                      and t["kind"].startswith("pod_") and "Ready" in t["source_field"] and t["stamp_us"] >= end
                      - (inputs.band_us or 0)]
            if stamps:
                kill_delays.append(min(stamps) - end)
    out["kill_to_not_ready_stamp"] = _stats(kill_delays)
    return out


def iso_or_none(us):
    return iso(us) if us is not None else None


def seconds_to_us(value):
    return s_to_us(value)
