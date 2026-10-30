"""Snapshot-based state histories of the arm-G captures: what periodic snapshots of the cluster record, what the gate
decides from them, and how far each history reproduces the gate's decisions.

A snapshot history keeps the poller's lists at a longer interval: every k-th poll from phase j (polls j + 1,
j + 1 + k, ...; the Pod, ReplicaSet and Deployment lists of one poll are kept or dropped together and the poller's K1
rows with them, as ``replays.thinned``, which is phase 0), for k = 6, 12 and 24 polls (``INTERVALS``; median
intervals of about 15, 30 and 60 s at the captured poll of 2.4-2.5 s) and k = 1 (the captured stream). Two readings
of the same kept lists are compared:

S, one clock   every object holds its listed state from the list's receipt: a change is placed at the first kept list
               that shows it, and a state that begins and ends between two kept lists is not recorded. A store of
               timestamped snapshots whose consecutive duplicates are merged into one validity range (from the first
               to the last list showing them) holds exactly this information.
T, two clocks  the same lists with the objects' own stamps (kubelet Ready and container stamps, creation and deletion
               timestamps): the gate's poller store, thinned.
W              the watch's records (every event and list object, with the same stamps): the event-driven history.

Reference. The labeller's Pod status (``labels.Labeller.pod_status``: the kubelet Ready history and the deletion stamps
from the union of the three observers' records, with the clock band b_c), never a store or a gate rule. The Pods are
those of the changed service; the window runs from the first to the last Pod list of the poller.

Measures (``snapshot_pass``; per capture; every phase of every interval for 1-3 and 6, the phases ``DECISION_PHASES``
for 4 and 5):

1. Episodes. Each Pod's reference timeline is split into episodes: starting (creation to the first Ready stamp),
   ready, not ready (a not-ready stamp after Ready and before the deletion request) and terminating (deletion request
   to removal); the episodes that begin inside the window and last longer than zero at the stamps' one-second
   resolution are counted (the reference reads every observer's records, so a termination no list showed still
   counts). S records an episode when a kept list shows the Pod in the episode's state within it (b_c added at both
   ends); T also when the kept records' own stamps place the episode's start (a labeller built from the kept records
   alone); W likewise from the watch's records. With the instant at which each history places the start (S: the
   first kept list showing the episode).
2. Object states. Every Pod, ReplicaSet and Deployment state the watch's cache held (consecutive distinct projected
   states per object, the resourceVersion ignored; an object's last state holds to the end of the window unless the
   object left the cache, i.e. was deleted): how many of them a kept list shows while it held (1 s added at both
   ends).
3. Status over time. Every second of each Pod's lifetime within the window: the status (ready or not) each history
   reports, against the reference. S reports the state of the latest kept list (carried forward; absent from it = not
   ready; before the first kept list = unknown); T and W apply the labeller's rule to their own records (a status
   within b_c of one of their stamps, or not covered by them, is unknown), a Pod that leaves the kept lists being
   gone from the first kept list without it and a Pod they never recorded being absent. Seconds whose reference status
   is uncertain are left out.
4. Decisions. Restart decisions (action B, stream S0, the replay cells) of the two-clock gate on T with freshness
   limits of 30 and 600 s, and of the same gate on S (``sweeps.receipt_time_model`` of the thinned stream), counted
   and labelled as the sweeps (``sweeps.tally``).
5. Audit. The gate's own decisions (T_p on the captured stream) against the same gate replayed from T and from S
   (``replays.verdict_agreement``).
6. Volume. Pod, ReplicaSet and Deployment records per poll and their projected bytes; per interval, the records kept
   and those left after merging consecutive duplicates per object; the watch's events and list objects of the same
   kinds, with their projected bytes and the received bytes of the events.

The phases average out where the kept lists fall relative to the incident: a count per interval is the mean over
its phases.
"""
from __future__ import annotations

import bisect
import json
import statistics
import time
from collections import OrderedDict, defaultdict
from pathlib import Path

from .capture import manifest_grace_seconds, raw_capture_of, read_decision_inputs, read_label_inputs
from .common import canonical, iso, ts_us
from .conditions import CONDITIONS as ADAPTER_CONDITIONS
from .engine2 import run_request
from .labels import Labeller
from .pipeline import build_capture
from .replays import ACTION, BASE, pod_list_intervals, poll_number, poller_context, requests_of, verdict_agreement
from .sweeps import tally, to_receipt_time

INTERVALS = (1, 6, 12, 24)                       # polls per kept list (1 = the captured stream)
DECISION_PHASES = {1: (0,), 6: (0, 2, 4), 12: (0, 4, 8), 24: (0, 8, 16)}
GRID_US = 1_000_000                              # status sampling step (measure 3)
STATE_TOLERANCE_US = 1_000_000                   # measure 2: a kept list within 1 s of an object state's lifetime
CACHE_PRESENT_US = 1_500_000                     # measure 2: an object in the cache's records of the last 1.5 s
KINDS = ("Pod", "ReplicaSet", "Deployment")
TYPES = ("starting", "ready", "not_ready", "terminating")
CONTENT = {"starting": "not_ready", "ready": "ready", "not_ready": "not_ready", "terminating": "terminating"}
HISTORIES = ("S", "T", "W")


# ---------------------------------------------------------------------------------------------------------------
# Kept lists
# ---------------------------------------------------------------------------------------------------------------
def poll_lists(inputs) -> list:
    """[(poll number, Pod list receipt us)] of the poller, in poll order."""
    first = {}
    for r in inputs.poller_api:
        n = poll_number(r)
        snap = r.payload_view().get("snapshot_id") or ""
        if n is not None and snap.endswith("-pods"):
            first[n] = min(first.get(n, r.observed_at), r.observed_at)
    return sorted(first.items())


def kept(n: int, k: int, j: int) -> bool:
    return (n - 1 - j) % k == 0


def thinned_phase(inputs, k: int, j: int):
    """(poller API records, poller K1 rows) of polls j + 1, j + 1 + k, ... (``replays.thinned`` is phase 0)."""
    api = [r for r in inputs.poller_api if poll_number(r) is None or kept(poll_number(r), k, j)]
    ids = {r.id for r in api}
    return tuple(api), [row for row in inputs.k1_rows["poller"] if row["record_id"] in ids]


def pod_content(pod: dict) -> str:
    """'terminating' (deletionTimestamp set), 'ready' (Ready condition True) or 'not_ready' of one Pod record."""
    if (pod.get("metadata") or {}).get("deletionTimestamp"):
        return "terminating"
    for c in (pod.get("status") or {}).get("conditions") or []:
        if c.get("type") == "Ready":
            return "ready" if c.get("status") == "True" else "not_ready"
    return "not_ready"


def row_us(row: dict, name: str) -> int:
    value = row.get(name + "_ns")
    return int(value) // 1000 if value is not None else ts_us(row[name])


class Lists:
    """The poller's Pod rows by poll: receipt instants and, per poll, the rows of the Pods it listed."""

    def __init__(self, inputs, uids):
        self.order = poll_lists(inputs)
        number = {r.id: poll_number(r) for r in inputs.poller_api}
        self.rows = defaultdict(dict)                   # poll number -> uid -> row
        for row in inputs.k1_rows["poller"]:
            n = number.get(row["record_id"])
            if n is not None and row["pod_uid"] in uids:
                self.rows[n][row["pod_uid"]] = row

    def phase(self, k: int, j: int) -> list:
        """[(receipt us, {uid: row})] of the kept lists."""
        return [(t, self.rows.get(n, {})) for n, t in self.order if kept(n, k, j)]


def absences(lists: list) -> dict:
    """uid -> receipt of the first kept list after the Pod's last appearance that does not show it."""
    last_seen = {}
    for index, (_, pods) in enumerate(lists):
        for uid in pods:
            last_seen[uid] = index
    out = {}
    for uid, index in last_seen.items():
        if index + 1 < len(lists):
            out[uid] = lists[index + 1][0]
    return out


def history_of(rows, *, band_us: int, grace: dict, gone=None) -> Labeller:
    """Pod histories built by the labeller's rules from ``rows`` alone (kubelet stamps, deletion stamps, DELETED
    events); ``gone`` (uid -> instant) marks a Pod removed at that instant unless the rows say earlier."""
    lab = Labeller()
    lab.band_us = band_us
    lab.grace = dict(grace)
    if rows:
        lab._pods_from_rows(rows)
        lab._ready_history(rows)
    for uid, when in (gone or {}).items():
        p = lab.pods.get(uid)
        if p is not None and (p.gone_after_us is None or when < p.gone_after_us):
            p.gone_after_us = when
    return lab


# ---------------------------------------------------------------------------------------------------------------
# 1. Episodes
# ---------------------------------------------------------------------------------------------------------------
def episodes(lab: Labeller, uids, start_us: int, end_us: int) -> list:
    """Reference episodes (uid, type, begin us, end us or None) of the Pods ``uids`` that begin in
    [start_us, end_us]."""
    out = []
    for uid in sorted(uids):
        p = lab.pods.get(uid)
        if p is None:
            continue
        deletion = p.deletion_request_us
        if deletion is None and p.deletion_bracket is not None:
            deletion = p.deletion_bracket[1]
        stop = deletion if deletion is not None else p.gone_after_us
        segments, current, ever_ready = [], None, False
        if p.created_us is not None:
            current = ["starting", p.created_us]
        for stamp, state in p.transitions:
            if stop is not None and stamp >= stop:
                continue
            if state == "ready":
                if current is None or current[0] != "ready":
                    if current is not None:
                        segments.append((current[0], current[1], stamp))
                    current = ["ready", stamp]
                ever_ready = True
            elif current is None:
                current = ["not_ready" if ever_ready else "starting", stamp]
            elif current[0] == "ready":
                segments.append(("ready", current[1], stamp))
                current = ["not_ready", stamp]
        if deletion is not None:
            if current is not None:
                segments.append((current[0], current[1], deletion))
            current = ["terminating", deletion]
        if current is not None:
            segments.append((current[0], current[1], p.gone_after_us if current[0] == "terminating" else None))
        for kind, begin, end in segments:
            if start_us <= begin <= end_us and (end is None or end > begin):
                out.append((uid, kind, begin, end))
    return out


def first_shown(lists: list, times: list, uid: str, kind: str, begin: int, end: int, band: int):
    """Receipt of the first kept list within [begin - band, end + band] that shows the Pod in the episode's state."""
    lo = bisect.bisect_left(times, begin - band)
    hi = bisect.bisect_right(times, end + band)
    for index in range(lo, hi):
        row = lists[index][1].get(uid)
        if row is not None and pod_content(row["pod"]) == CONTENT[kind]:
            return lists[index][0]
    return None


def stamped(lab: Labeller, uid: str, kind: str, begin: int, end, band: int):
    """The start a history's own stamps give the episode (within ``band`` of the reference), or None."""
    p = lab.pods.get(uid)
    if p is None:
        return None
    if kind == "starting":
        if p.created_us is None or abs(p.created_us - begin) > band:
            return None
        if end is not None and not any(state == "ready" and abs(s - end) <= band for s, state in p.transitions):
            return None
        return p.created_us
    if kind == "terminating":
        if p.deletion_request_us is not None and abs(p.deletion_request_us - begin) <= band:
            return p.deletion_request_us
        return None
    hits = [s for s, state in p.transitions if state == kind and abs(s - begin) <= band]
    return min(hits, key=lambda s: abs(s - begin)) if hits else None


def watch_lists(rows: list, uids) -> list:
    """The watch's Pod records as one list per record: [(receipt us, {uid: row})], the Pod gone after a DELETED
    event (its record still shows the final state)."""
    out = []
    for row in sorted(rows, key=lambda r: (row_us(r, "observed_at"), r["record_id"])):
        if row["pod_uid"] in uids:
            out.append((row_us(row, "observed_at"), {row["pod_uid"]: row}))
    return out


# ---------------------------------------------------------------------------------------------------------------
# 2. Object states
# ---------------------------------------------------------------------------------------------------------------
def projected(record) -> tuple:
    """(kind, uid, content) of an API record, the resourceVersion left out of the content."""
    data = record.payload_view()["resource_data"]
    meta = dict(data.get("metadata") or {})
    meta.pop("resourceVersion", None)
    return data.get("kind"), meta.get("uid"), canonical(dict(data, metadata=meta))


def watch_states(watch_api, end_us: int) -> list:
    """Consecutive distinct states per object in the watch's cache records: (kind, uid, content, from us, to us). A
    state holds until the next one; an object's last state until the end of the window if the object is still in the
    cache's last records (within ``CACHE_PRESENT_US``), otherwise until its last record (the object was deleted)."""
    by_object = defaultdict(list)
    cache_end = None
    for r in watch_api:
        cache_end = r.observed_at if cache_end is None else max(cache_end, r.observed_at)
        kind, uid, content = projected(r)
        if kind in KINDS and uid:
            by_object[kind, uid].append((r.observed_at, content))
    out = []
    for (kind, uid), items in by_object.items():
        items.sort()
        runs = []
        for at, content in items:
            if runs and runs[-1][1] == content:
                runs[-1][3] = at
            else:
                runs.append([at, content, at, at])
        for index, (start, content, _, last) in enumerate(runs):
            if index + 1 < len(runs):
                to = runs[index + 1][0]
            else:
                to = max(last, end_us) if last >= cache_end - CACHE_PRESENT_US else last
            out.append((kind, uid, content, start, to))
    return out


def poll_states(poller_api) -> dict:
    """(kind, uid) -> [(receipt us, content)] of every listed object, by poll number."""
    out = defaultdict(list)
    for r in poller_api:
        n = poll_number(r)
        kind, uid, content = projected(r)
        if n is not None and kind in KINDS and uid:
            out[kind, uid].append((n, r.observed_at, content))
    for items in out.values():
        items.sort()
    return out


def states_recorded(states: list, polled: dict, k: int, j: int) -> OrderedDict:
    """How many of the watch's object states a kept list shows while the state held (measure 2), by kind."""
    out = OrderedDict((kind, 0) for kind in KINDS)
    for kind, uid, content, start, to in states:
        for n, at, listed in polled.get((kind, uid), ()):
            if kept(n, k, j) and start - STATE_TOLERANCE_US <= at <= to + STATE_TOLERANCE_US and listed == content:
                out[kind] += 1
                break
    return out


# ---------------------------------------------------------------------------------------------------------------
# 3. Status over time
# ---------------------------------------------------------------------------------------------------------------
def status_of(lab: Labeller, uid: str, x: int) -> str:
    """'ready', 'down' or 'unknown' of one Pod at x by the labeller's rule on a history's own records."""
    if uid not in lab.pods:
        return "down"
    status, _ = lab.pod_status(uid, x)
    return "unknown" if status == "uncertain" else status


def carried(lists: list, times: list, uid: str, x: int) -> str:
    """The state of the latest kept list at or before x (absent = 'down'; no list yet = 'unknown')."""
    index = bisect.bisect_right(times, x) - 1
    if index < 0:
        return "unknown"
    row = lists[index][1].get(uid)
    return "ready" if row is not None and pod_content(row["pod"]) == "ready" else "down"


def tally_status(answers: list) -> OrderedDict:
    out = OrderedDict([("seconds", 0), ("wrong", 0), ("unknown", 0)])
    for truth, answer in answers:
        out["seconds"] += 1
        if answer == "unknown":
            out["unknown"] += 1
        elif answer != truth:
            out["wrong"] += 1
    return out


# ---------------------------------------------------------------------------------------------------------------
# 6. Volume
# ---------------------------------------------------------------------------------------------------------------
def watch_volume(converted: Path) -> OrderedDict:
    """Events and list objects of the watched kinds in the watch's records: counts, projected and received bytes."""
    out = OrderedDict([("events", 0), ("list_objects", 0), ("projected_bytes", 0), ("event_line_bytes", 0)])
    for name, key in (("api_watch_event.jsonl", "events"), ("api_watch_list_object.jsonl", "list_objects")):
        path = Path(converted) / "stage2" / name
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                p = (json.loads(line).get("record") or {}).get("payload") or {}
                if p.get("kind") not in KINDS:
                    continue
                out[key] += 1
                out["projected_bytes"] += len(canonical(p["resource_data"]).encode("utf-8"))
                out["event_line_bytes"] += int(p.get("line_bytes") or 0)
    return out


def poll_volume(poller_api, lists_order: list) -> OrderedDict:
    """Records of the watched kinds per poll and their projected bytes; per interval and phase, the records kept and
    those left after merging consecutive duplicates per object (with their bytes)."""
    per_poll = defaultdict(lambda: [0, 0])
    objects = defaultdict(list)
    for r in poller_api:
        n = poll_number(r)
        kind, uid, content = projected(r)
        if n is None or kind not in KINDS:
            continue
        size = len(canonical(r.payload_view()["resource_data"]).encode("utf-8"))
        per_poll[n][0] += 1
        per_poll[n][1] += size
        objects[uid].append((n, content, size))
    for items in objects.values():
        items.sort()
    out = OrderedDict([("polls", len(lists_order)),
                       ("records_per_poll", statistics.median(v[0] for v in per_poll.values()) if per_poll else None),
                       ("records", sum(v[0] for v in per_poll.values())),
                       ("projected_bytes", sum(v[1] for v in per_poll.values())),
                       ("intervals", OrderedDict())])
    for k in INTERVALS:
        phases = OrderedDict()
        for j in range(k):
            records = size = merged = merged_size = 0
            for n, v in per_poll.items():
                if kept(n, k, j):
                    records += v[0]
                    size += v[1]
            for items in objects.values():
                previous = None
                for n, content, s in items:
                    if not kept(n, k, j):
                        continue
                    if content != previous:
                        merged += 1
                        merged_size += s
                    previous = content
            phases[str(j)] = [records, size, merged, merged_size]
        out["intervals"][str(k)] = OrderedDict([
            ("records", mean(v[0] for v in phases.values())), ("projected_bytes", mean(v[1] for v in phases.values())),
            ("merged_records", mean(v[2] for v in phases.values())),
            ("merged_projected_bytes", mean(v[3] for v in phases.values()))])
    return out


def mean(values) -> float:
    values = list(values)
    return round(sum(values) / len(values), 4) if values else None


# ---------------------------------------------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------------------------------------------
def state_measures(inputs, capture, labeller, converted: Path) -> OrderedDict:
    """Measures 1-3 and 6 (no gate evaluation)."""
    band = labeller.band_us
    service = labeller.service
    uids = frozenset(p.uid for p in labeller.pods.values() if p.service == service)
    lists = Lists(inputs, uids)
    start_us, end_us = lists.order[0][1], lists.order[-1][1]
    reference = episodes(labeller, uids, start_us, end_us)
    watch_rows = [r for r in inputs.k1_rows.get("watch") or [] if r["pod_uid"] in uids]
    W = history_of(watch_rows, band_us=band, grace=labeller.grace)
    wl = watch_lists(watch_rows, uids)
    wt = [t for t, _ in wl]
    grid = list(range(start_us - start_us % GRID_US + GRID_US, end_us, GRID_US))
    truth = {}
    for uid in sorted(uids):
        p = labeller.pods[uid]
        alive = [x for x in grid if (p.created_us is None or x >= p.created_us)
                 and (p.gone_after_us is None or x < p.gone_after_us)]
        truth[uid] = [(x, s) for x, s in ((x, labeller.pod_status(uid, x)[0]) for x in alive) if s != "uncertain"]

    recorded = OrderedDict((h, OrderedDict()) for h in HISTORIES)
    lags = OrderedDict((h, OrderedDict()) for h in ("S", "T"))
    status = OrderedDict((h, OrderedDict()) for h in HISTORIES)
    states = watch_states(inputs.watch_api, end_us)
    polled = poll_states(inputs.poller_api)
    state_counts = OrderedDict((kind, sum(1 for s in states if s[0] == kind)) for kind in KINDS)
    recorded_states = OrderedDict()
    intervals = OrderedDict()
    for k in INTERVALS:
        per_type = {h: defaultdict(float) for h in ("S", "T")}
        lag_s = {h: [] for h in ("S", "T")}
        answers = {h: [] for h in ("S", "T")}
        state_sum = defaultdict(float)
        medians = []
        for j in range(k):
            kept_lists = lists.phase(k, j)
            times = [t for t, _ in kept_lists]
            api, rows = thinned_phase(inputs, k, j)
            medians.append(pod_list_intervals(api)["median_s"])
            T = history_of([r for r in rows if r["pod_uid"] in uids], band_us=band, grace=labeller.grace,
                           gone=absences(kept_lists))
            for uid, kind, begin, end in reference:
                stop = end if end is not None else end_us
                shown = first_shown(kept_lists, times, uid, kind, begin, stop, band)
                own = stamped(T, uid, kind, begin, end, band)
                if shown is not None:
                    per_type["S"][kind] += 1 / k
                    lag_s["S"].append(round((shown - begin) / 1e6, 3))
                if shown is not None or own is not None:
                    per_type["T"][kind] += 1 / k
                    lag_s["T"].append(round(((own if own is not None else shown) - begin) / 1e6, 3))
            for uid, samples in truth.items():
                for x, s in samples:
                    answers["S"].append((s, carried(kept_lists, times, uid, x)))
                    answers["T"].append((s, status_of(T, uid, x)))
            for kind, n in states_recorded(states, polled, k, j).items():
                state_sum[kind] += n / k
        intervals[str(k)] = OrderedDict([("phases", k), ("median_interval_s_by_phase", medians),
                                         ("median_interval_s", statistics.median(m for m in medians if m is not None)
                                          if any(m is not None for m in medians) else None)])
        for h in ("S", "T"):
            recorded[h][str(k)] = OrderedDict((t, round(per_type[h][t], 4)) for t in TYPES)
            lags[h][str(k)] = sorted(lag_s[h])
            st = tally_status(answers[h])
            st["wrong"] = round(st["wrong"] / k, 4)
            st["unknown"] = round(st["unknown"] / k, 4)
            st["seconds"] = round(st["seconds"] / k, 4)
            status[h][str(k)] = st
        recorded_states[str(k)] = OrderedDict((kind, round(state_sum[kind], 4)) for kind in KINDS)
    w_types = defaultdict(int)
    for uid, kind, begin, end in reference:
        stop = end if end is not None else end_us
        if first_shown(wl, wt, uid, kind, begin, stop, band) is not None or \
                stamped(W, uid, kind, begin, end, band) is not None:
            w_types[kind] += 1
    recorded["W"]["events"] = OrderedDict((t, w_types[t]) for t in TYPES)
    status["W"]["events"] = tally_status([(s, status_of(W, uid, x)) for uid, v in truth.items() for x, s in v])
    return OrderedDict([
        ("window", OrderedDict([("first_list", iso(start_us)), ("last_list", iso(end_us)),
                                ("seconds", round((end_us - start_us) / 1e6, 3)), ("pods", len(uids)),
                                ("clock_band_s", round(band / 1e6, 6))])),
        ("intervals", intervals),
        ("episodes", OrderedDict([
            ("reference", [OrderedDict([("pod", uid), ("type", kind), ("begin", iso(begin)),
                                        ("end", iso(end) if end is not None else None),
                                        ("seconds", round(((end if end is not None else end_us) - begin) / 1e6, 3)),
                                        ("open_at_end", end is None)])
                           for uid, kind, begin, end in reference]),
            ("by_type", OrderedDict((t, sum(1 for e in reference if e[1] == t)) for t in TYPES)),
            ("recorded", recorded), ("start_lag_s", lags)])),
        ("object_states", OrderedDict([("watch", state_counts), ("recorded", recorded_states)])),
        ("status", status),
        ("volume", OrderedDict([("poller", poll_volume(inputs.poller_api, lists.order)),
                                ("watch", watch_volume(converted))]))])


def decision_measures(inputs, capture, labeller, progress=None) -> tuple:
    """Measures 4 and 5: per interval and decision phase, the gate on T (F = 30 and 600 s) and on S."""
    Tp, T600 = ADAPTER_CONDITIONS["T_p"], ADAPTER_CONDITIONS["T@F600"]
    timing = OrderedDict()

    def rows_of(cond, ctx, name, k1_index=None):
        return [dict(run_request(cond, ctx, capture, ACTION, k, t_us, dc, d, None, k1_index=k1_index),
                     condition=name) for dc, d, k, t_us in requests_of(capture)]

    started = time.perf_counter()
    ctx, k1_index = poller_context(capture, inputs)
    gate = rows_of(Tp, ctx, "T_p", k1_index)
    gate600 = rows_of(T600, ctx, "T@F600", k1_index)
    ctx.close()
    timing["captured"] = round(time.perf_counter() - started, 1)
    decisions, audit = OrderedDict(), OrderedDict()
    for k in INTERVALS:
        for j in DECISION_PHASES[k]:
            started = time.perf_counter()
            key = "%d/%d" % (k, j)
            if k == 1:
                t30, t600 = gate, gate600
            else:
                api, rows = thinned_phase(inputs, k, j)
                tctx, index = poller_context(capture, inputs, api=api, k1_rows=rows)
                t30 = rows_of(Tp, tctx, "T_p[snapshot %s]" % key, index)
                t600 = rows_of(T600, tctx, "T@F600[snapshot %s]" % key, index)
                tctx.close()
            api, rows = thinned_phase(inputs, k, j)
            sctx = to_receipt_time(poller_context(capture, inputs, api=api, k1_rows=rows)[0])
            s30 = rows_of(Tp, sctx, "T_p[one clock %s]" % key)
            sctx.close()
            decisions[key] = OrderedDict([("T F30", tally(t30, labeller, ACTION)),
                                          ("T F600", tally(t600, labeller, ACTION)),
                                          ("S F30", tally(s30, labeller, ACTION))])
            audit[key] = OrderedDict([("T", verdict_agreement(gate, t30)), ("S", verdict_agreement(gate, s30))])
            timing[key] = round(time.perf_counter() - started, 1)
            if progress:
                progress("%s snapshot %s %.1f s" % (capture.capture_id, key, timing[key]))
    return decisions, audit, timing


def snapshot_pass(converted, plan_path, out_path, *, raw=None, progress=None) -> dict:
    """See the module docstring."""
    converted = Path(converted).resolve()
    inputs = read_decision_inputs(converted, raw=raw)
    plan_doc = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    capture = build_capture(inputs, plan_doc, conditions=list(BASE))
    if capture.plan.arm != "G":
        raise ValueError("arm-G captures only")
    raw_dir = Path(raw).resolve() if raw else raw_capture_of(converted)
    labeller = Labeller.build(capture, inputs, read_label_inputs(converted, raw_dir),
                              manifest_grace_seconds(inputs.configuration))
    started = time.perf_counter()
    doc = OrderedDict([("capture", capture.capture_id), ("scenario", capture.plan.scenario),
                       ("service", labeller.service), ("H", iso(capture.H))])
    doc.update(state_measures(inputs, capture, labeller, converted))
    seconds = OrderedDict([("state measures", round(time.perf_counter() - started, 1))])
    if progress:
        progress("%s state measures %.1f s" % (capture.capture_id, seconds["state measures"]))
    decisions, audit, timing = decision_measures(inputs, capture, labeller, progress=progress)
    doc["cells"] = {"action": ACTION, "stream": "S0", "Delta_s": sorted({dc for dc, _, _, _ in requests_of(capture)}),
                    "delta_s": sorted({d for _, d, _, _ in requests_of(capture)})}
    doc["decisions"] = decisions
    doc["audit"] = audit
    seconds.update(timing)
    doc["seconds"] = seconds
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    return doc
