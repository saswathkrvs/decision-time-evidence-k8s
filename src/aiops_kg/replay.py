"""Availability replay engine v1: perturb a record stream, replay context policies, score a decision.

Research prototype; no accuracy, safety or RCA claim. It asks how much DELAYED, MISSING and CORRECTED
deployment/topology records change what a diagnostic pipeline can decide, and whether an availability-aware
(two-clock) policy with an explicit use / fall-back / abstain rule does better than latest-state and plain
temporal-join alternatives that receive identical evidence at the same cutoff.

Three parts:

1. **Record-stream perturbations** (``delay``, ``drop``, ``drop_transition``, ``correct_late``,
   ``jitter_clock``): pure functions over records that return a new tuple plus a manifest of what changed.
2. **Context policies** (``latest_state``, ``temporal_join``, ``bitemporal_abstain``): each answers "what
   was the value of (subject, predicate) at valid time t, using only records usable at cutoff c" and returns
   an ``Answer`` (value, status CONFIRMED / FALLBACK / ABSTAIN, reason, record IDs used).
3. **A decision-task adapter**: ``attribute_instance`` (which candidate instance served an event at t,
   decided at c), scoring helpers, and the loaders of the 22 Sep 2026 rollout task and of a converted capture.

Conventions. Every time is an integer number of microseconds since the Unix epoch (UTC). Nothing reads the
wall clock; randomness comes only from explicit seeds (``random.Random(seed)``). Inputs are never mutated:
records are immutable and every function returns new tuples. A record is usable at cutoff c when
``available_at <= c`` and no correction of it is available by c (append-only versions: a correction withdraws
its predecessor from the correction's availability time on; nothing is overwritten or deleted).
"""
from __future__ import annotations

import importlib.util
import json
import math
import random
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
US = 1_000_000
HINDSIGHT = 2**62  # a cutoff after every record

CONFIRMED = "CONFIRMED"
FALLBACK = "FALLBACK"
ABSTAIN = "ABSTAIN"
STATUSES = (CONFIRMED, FALLBACK, ABSTAIN)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def to_us(value: datetime) -> int:
    """Timezone-aware datetime -> integer microseconds since the epoch (exact)."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("expected a timezone-aware datetime")
    delta = value.astimezone(UTC) - EPOCH
    return (delta.days * 86400 + delta.seconds) * US + delta.microseconds


def from_us(value: int) -> datetime:
    return EPOCH + timedelta(microseconds=value)


def iso(value: int | None) -> str | None:
    return None if value is None else from_us(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def seconds_to_us(seconds: float, *, name: str = "seconds", allow_negative: bool = False) -> int:
    """Finite seconds -> integer microseconds (round half away from zero, exact for decimal inputs)."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds):
        raise ValueError(f"{name} must be a finite number")
    if seconds < 0 and not allow_negative:
        raise ValueError(f"{name} must be nonnegative")
    scaled = abs(seconds) * US
    magnitude = math.floor(scaled + 0.5)
    return -magnitude if seconds < 0 else magnitude


def _text(value, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a nonempty string without outer whitespace")
    return value


def _int(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer number of microseconds")
    return value


# ---------------------------------------------------------------------------
# Records and the replayable stream
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Record:
    """One immutable record version.

    ``observed_at`` is the valid-time instant at which the source saw ``value`` (a snapshot sighting);
    ``available_at`` is when the pipeline could first use the record. Optional ``valid_from`` is a recorded
    start of the value (<= observed_at, e.g. a transition time the source states) and optional ``valid_to``
    a recorded exclusive end; without ``valid_to`` the record is a sighting. ``corrects`` names the record
    version this one corrects: once this record is available, that version is withdrawn (never deleted).
    ``kind`` is the record class used by perturbation selectors (e.g. api, absence, request).
    """
    record_id: str
    subject: str
    predicate: str
    value: str
    observed_at: int
    available_at: int
    kind: str = "record"
    valid_from: int | None = None
    valid_to: int | None = None
    corrects: str | None = None
    group: str | None = None

    def __post_init__(self) -> None:
        for name in ("record_id", "subject", "predicate", "value", "kind"):
            _text(getattr(self, name), name)
        _int(self.observed_at, "observed_at")
        _int(self.available_at, "available_at")
        if self.available_at < self.observed_at:
            raise ValueError(f"{self.record_id}: a record cannot be available before it was observed")
        if self.valid_from is not None and _int(self.valid_from, "valid_from") > self.observed_at:
            raise ValueError(f"{self.record_id}: valid_from cannot be later than observed_at")
        if self.valid_to is not None and _int(self.valid_to, "valid_to") <= self.start:
            raise ValueError(f"{self.record_id}: valid_to must be after the interval start")
        if self.corrects is not None and _text(self.corrects, "corrects") == self.record_id:
            raise ValueError(f"{self.record_id}: a record cannot correct itself")
        if self.group is not None:
            _text(self.group, "group")

    @property
    def start(self) -> int:
        return self.observed_at if self.valid_from is None else self.valid_from

    @property
    def is_sighting(self) -> bool:
        return self.valid_to is None

    def to_dict(self) -> dict:
        return {"record_id": self.record_id, "subject": self.subject, "predicate": self.predicate,
                "value": self.value, "observed_at": iso(self.observed_at), "available_at": iso(self.available_at),
                "kind": self.kind, "valid_from": iso(self.valid_from), "valid_to": iso(self.valid_to),
                "corrects": self.corrects, "group": self.group}


def _order(record: Record) -> tuple:
    return (record.observed_at, record.record_id)


class Stream:
    """A validated, indexed record stream; answers "which versions are usable at cutoff c"."""

    __slots__ = ("records", "_index", "_corrections", "_by_id")

    def __init__(self, records: Iterable[Record]):
        items = tuple(records)
        by_id: dict[str, Record] = {}
        for record in items:
            if not isinstance(record, Record):
                raise ValueError("a stream holds Record instances only")
            if record.record_id in by_id:
                raise ValueError(f"duplicate record_id: {record.record_id}")
            by_id[record.record_id] = record
        for record in items:
            if record.corrects is not None:
                target = by_id.get(record.corrects)
                if target is None:
                    raise ValueError(f"{record.record_id} corrects unknown record {record.corrects}")
                if record.available_at <= target.available_at:
                    raise ValueError(f"{record.record_id} must become available after the version it corrects")
        index: dict[tuple[str, str], list[Record]] = {}
        for record in items:
            index.setdefault((record.subject, record.predicate), []).append(record)
        self.records = tuple(sorted(items, key=lambda r: (r.subject, r.predicate) + _order(r)))
        self._index = {key: tuple(sorted(rows, key=_order)) for key, rows in index.items()}
        self._corrections = tuple(sorted((r.available_at, r.corrects) for r in items if r.corrects is not None))
        self._by_id = by_id

    def __len__(self) -> int:
        return len(self.records)

    def record(self, record_id: str) -> Record:
        return self._by_id[record_id]

    def withdrawn(self, cutoff: int) -> frozenset[str]:
        """IDs of versions withdrawn by a correction available by ``cutoff``."""
        return frozenset(target for available, target in self._corrections if available <= cutoff)

    @property
    def ever_withdrawn(self) -> frozenset[str]:
        return self.withdrawn(HINDSIGHT)

    def versions(self, subject: str, predicate: str) -> tuple[Record, ...]:
        """Every version of (subject, predicate), usable or not, in valid-time order."""
        return self._index.get((subject, predicate), ())

    def visible(self, subject: str, predicate: str, cutoff: int) -> tuple[Record, ...]:
        """Versions of (subject, predicate) usable at ``cutoff``, in valid-time order."""
        withdrawn = self.withdrawn(cutoff)
        return tuple(r for r in self._index.get((subject, predicate), ())
                     if r.available_at <= cutoff and r.record_id not in withdrawn)

    def subjects(self, predicate: str | None = None) -> tuple[str, ...]:
        return tuple(sorted({s for s, p in self._index if predicate is None or p == predicate}))


def as_stream(records) -> Stream:
    return records if isinstance(records, Stream) else Stream(records)


# ---------------------------------------------------------------------------
# Part 1: record-stream perturbations (pure; each returns (records, manifest))
# ---------------------------------------------------------------------------
Selector = Callable[[Record], bool]


def _selected(record: Record, kinds, where: Selector | None) -> bool:
    return (kinds is None or record.kind in kinds) and (where is None or bool(where(record)))


def _kinds(kinds) -> frozenset[str] | None:
    return None if kinds is None else frozenset(_text(k, "kind") for k in kinds)


def _records(records) -> tuple[Record, ...]:
    """Validated records in their input order (a Stream yields its own canonical order)."""
    if isinstance(records, Stream):
        return records.records
    items = tuple(records)
    Stream(items)  # validates types, unique IDs and correction links
    return items


def delay(records, seconds: float, *, kinds: Iterable[str] | None = None,
          where: Selector | None = None) -> tuple[tuple[Record, ...], dict]:
    """Shift ``available_at`` of the selected records by ``seconds`` (valid time and IDs unchanged)."""
    shift = seconds_to_us(seconds, name="delay seconds")
    kinds = _kinds(kinds)
    out, changed = [], []
    for r in _records(records):
        if _selected(r, kinds, where):
            out.append(replace(r, available_at=r.available_at + shift))
            changed.append({"record_id": r.record_id, "available_at_before": iso(r.available_at),
                            "available_at_after": iso(r.available_at + shift)})
        else:
            out.append(r)
    manifest = {"perturbation": "delay", "seconds": seconds, "kinds": sorted(kinds) if kinds else None,
                "changed": len(changed), "records": changed}
    return tuple(out), manifest


def drop(records, fraction: float, seed: int, *, kinds: Iterable[str] | None = None,
         where: Selector | None = None) -> tuple[tuple[Record, ...], dict]:
    """Remove round-half-up(fraction x n) of the n selected records, chosen by ``random.Random(seed)``
    from the selected IDs in sorted order (deterministic for a given seed)."""
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not 0 <= fraction <= 1:
        raise ValueError("fraction must be a number in [0, 1]")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    kinds = _kinds(kinds)
    items = _records(records)
    eligible = sorted(r.record_id for r in items if _selected(r, kinds, where))
    count = math.floor(fraction * len(eligible) + 0.5)
    chosen = frozenset(random.Random(seed).sample(eligible, count))
    manifest = {"perturbation": "drop", "fraction": fraction, "seed": seed,
                "kinds": sorted(kinds) if kinds else None, "eligible": len(eligible),
                "dropped": len(chosen), "record_ids": sorted(chosen)}
    return tuple(r for r in items if r.record_id not in chosen), manifest


def revealing_records(records, *, mode: str = "change") -> tuple[tuple[Record, str | None], ...]:
    """Records that first reveal a transition, on the final (hindsight) versions of the stream.

    Per (subject, predicate), sightings are ordered by (observed_at, record_id). mode='change': a sighting
    whose value differs from the preceding sighting's value (the first sighting of the new value);
    mode='first': the first sighting (reveals that the subject exists); mode='both': either. Returns
    (record, previous value or None) pairs.
    """
    if mode not in ("change", "first", "both"):
        raise ValueError("mode must be 'change', 'first' or 'both'")
    stream = as_stream(records)
    withdrawn = stream.ever_withdrawn
    groups: dict[tuple[str, str], list[Record]] = {}
    for r in stream.records:
        if r.is_sighting and r.record_id not in withdrawn:
            groups.setdefault((r.subject, r.predicate), []).append(r)
    found = []
    for key in sorted(groups):
        rows = sorted(groups[key], key=_order)
        for index, r in enumerate(rows):
            previous = rows[index - 1].value if index else None
            if index == 0 and mode in ("first", "both"):
                found.append((r, None))
            elif index and previous != r.value and mode in ("change", "both"):
                found.append((r, previous))
    return tuple(found)


def drop_transition(records, *, mode: str = "change", where: Selector | None = None,
                    kinds: Iterable[str] | None = None) -> tuple[tuple[Record, ...], dict]:
    """Remove the records that first reveal a transition (the "missing record" case).

    The revealing records are found by ``revealing_records(mode=...)`` on the input; ``where``/``kinds``
    narrow them. Only those records are removed; the transition is then revealed, if at all, by a later one.
    """
    kinds = _kinds(kinds)
    items = _records(records)
    targets = [(r, prev) for r, prev in revealing_records(items, mode=mode) if _selected(r, kinds, where)]
    ids = frozenset(r.record_id for r, _ in targets)
    manifest = {"perturbation": "drop_transition", "mode": mode, "dropped": len(ids),
                "records": [{"record_id": r.record_id, "subject": r.subject, "predicate": r.predicate,
                             "from": prev, "to": r.value, "observed_at": iso(r.observed_at),
                             "available_at": iso(r.available_at)} for r, prev in targets]}
    return tuple(r for r in items if r.record_id not in ids), manifest


def correct_late(records, seconds: float, *, where: Selector,
                 wrong_value: str | Mapping[str, str] | None = None) -> tuple[tuple[Record, ...], dict]:
    """Emit a wrong version first and the corrected version ``seconds`` later (never overwrite).

    Each selected record r is replaced by two versions: ``r.record_id + '#stale'`` with the wrong value at
    r's own observed/available times, and ``r.record_id + '#corrected'`` with r's value, available
    ``seconds`` later and ``corrects`` = the stale version. The wrong value defaults to the preceding
    sighting's value for the same (subject, predicate) (the pre-transition state carried in a stale
    re-sighting); it may be given as one string or per record ID.
    """
    shift = seconds_to_us(seconds, name="correction delay seconds")
    if shift <= 0:
        raise ValueError("a late correction needs a positive delay")
    if where is None:
        raise ValueError("correct_late needs an explicit selector")
    items = _records(records)
    stream = Stream(items)
    out, entries = [], []
    for r in items:
        if not _selected(r, None, where):
            out.append(r)
            continue
        if isinstance(wrong_value, Mapping):
            wrong = wrong_value[r.record_id]
        elif wrong_value is not None:
            wrong = wrong_value
        else:
            earlier = [x for x in stream.visible(r.subject, r.predicate, HINDSIGHT)
                       if x.is_sighting and _order(x) < _order(r)]
            if not earlier:
                raise ValueError(f"{r.record_id}: no preceding sighting to supply the stale value")
            wrong = earlier[-1].value
        _text(wrong, "wrong value")
        if wrong == r.value:
            raise ValueError(f"{r.record_id}: the wrong value equals the record's value")
        stale = replace(r, record_id=r.record_id + "#stale", value=wrong)
        corrected = replace(r, record_id=r.record_id + "#corrected", available_at=r.available_at + shift,
                            corrects=stale.record_id)
        out.extend((stale, corrected))
        entries.append({"original": r.record_id, "subject": r.subject, "observed_at": iso(r.observed_at),
                        "stale": {"record_id": stale.record_id, "value": wrong, "available_at": iso(stale.available_at)},
                        "corrected": {"record_id": corrected.record_id, "value": r.value,
                                      "available_at": iso(corrected.available_at), "corrects": stale.record_id}})
    Stream(out)  # validates the new version chain
    manifest = {"perturbation": "correct_late", "seconds": seconds, "corrected": len(entries), "records": entries}
    return tuple(out), manifest


def jitter_clock(records, seconds: float, *, seed: int | None = None, kinds: Iterable[str] | None = None,
                 where: Selector | None = None) -> tuple[tuple[Record, ...], dict]:
    """Shift the clock of the selected records.

    seed=None: a constant offset of ``seconds`` (may be negative). Otherwise each selected record, in
    record_id order, gets an independent offset drawn uniformly from [-|seconds|, +|seconds|] with
    ``random.Random(seed)``, quantised to the microsecond. One clock stamps a record, so observed_at,
    available_at and any recorded valid_from / valid_to all move by the same offset.
    """
    kinds = _kinds(kinds)
    items = _records(records)
    if seed is None:
        offsets = {r.record_id: seconds_to_us(seconds, allow_negative=True)
                   for r in items if _selected(r, kinds, where)}
    else:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer or None")
        bound = abs(seconds)
        seconds_to_us(bound)  # validates
        rng = random.Random(seed)
        offsets = {rid: seconds_to_us(rng.uniform(-bound, bound), allow_negative=True)
                   for rid in sorted(r.record_id for r in items if _selected(r, kinds, where))}
    out = []
    for r in items:
        shift = offsets.get(r.record_id)
        if shift is None:
            out.append(r)
            continue
        move = lambda value: None if value is None else value + shift
        out.append(replace(r, observed_at=r.observed_at + shift, available_at=r.available_at + shift,
                           valid_from=move(r.valid_from), valid_to=move(r.valid_to)))
    manifest = {"perturbation": "jitter_clock", "seconds": seconds, "seed": seed,
                "kinds": sorted(kinds) if kinds else None, "shifted": len(offsets),
                "offsets_us": dict(sorted(offsets.items()))}
    return tuple(out), manifest


# ---------------------------------------------------------------------------
# Part 2: context policies
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Answer:
    value: str | None
    status: str
    reason: str
    record_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown status {self.status!r}")
        if (self.value is None) != (self.status == ABSTAIN):
            raise ValueError("an ABSTAIN answer has no value and every other answer has one")


def latest_state(stream, subject: str, predicate: str, t: int, c: int) -> Answer:
    """Baseline 1: the latest picture at the cutoff, whatever t is.

    The usable record with the greatest observed_at (then available_at, record_id) wins; validity and the
    observation time t are ignored and no unknowns are produced (ABSTAIN only when no record exists).
    """
    rows = as_stream(stream).visible(subject, predicate, c)
    if not rows:
        return Answer(None, ABSTAIN, "no_record_available", ())
    r = max(rows, key=lambda x: (x.observed_at, x.available_at, x.record_id))
    return Answer(r.value, CONFIRMED, "latest_record_at_cutoff", (r.record_id,))


def join_intervals(rows: Sequence[Record]) -> tuple[tuple[int, int | None, Record], ...]:
    """Valid intervals for the plain temporal join: a record's recorded [start, valid_to) if it states an end,
    else [start, start of the next record with a later start) - the standard as-of / SCD-2 reading."""
    ordered = sorted(rows, key=lambda r: (r.start, r.observed_at, r.record_id))
    starts = sorted({r.start for r in ordered})
    out = []
    for r in ordered:
        if r.valid_to is not None:
            end = r.valid_to
        else:
            later = [s for s in starts if s > r.start]
            end = later[0] if later else None
        out.append((r.start, end, r))
    return tuple(out)


def temporal_join(stream, subject: str, predicate: str, t: int, c: int) -> Answer:
    """Baseline 2: valid time only, no abstention.

    Among records usable at c, use the one whose valid interval (``join_intervals``) covers t (the latest
    start wins if several do) -> CONFIRMED; if none covers t, take the nearest earlier record (latest end,
    then start) -> FALLBACK. ABSTAIN only when no record starts at or before t (no row to join).
    """
    rows = as_stream(stream).visible(subject, predicate, c)
    if not rows:
        return Answer(None, ABSTAIN, "no_record_available", ())
    intervals = join_intervals(rows)
    covering = [(start, r) for start, end, r in intervals if start <= t and (end is None or t < end)]
    if covering:
        _, r = max(covering, key=lambda x: (x[0], x[1].available_at, x[1].record_id))
        return Answer(r.value, CONFIRMED, "valid_interval_covers_t", (r.record_id,))
    earlier = [(end, start, r) for start, end, r in intervals if start <= t]
    if earlier:
        _, _, r = max(earlier, key=lambda x: (x[0], x[1], x[2].record_id))
        return Answer(r.value, FALLBACK, "nearest_earlier_record", (r.record_id,))
    return Answer(None, ABSTAIN, "no_record_at_or_before_t", ())


def bitemporal_abstain(stream, subject: str, predicate: str, t: int, c: int, *,
                       freshness_seconds: float = 600.0) -> Answer:
    """The project's two-clock rule: use / fall back / abstain.

    Records usable at c only. (1) USE: values valid at t by evidence - a recorded interval covering t, or
    snapshot sightings p (last at or before t) and n (first after t) with the same value (assumption A1), or
    a sighting exactly at t with no later sighting. One value -> CONFIRMED; several -> ABSTAIN
    (conflicting_values_at_t). (2) If nothing is valid at t: p and n differ -> ABSTAIN
    (transition_between_records: the change happened somewhere between them); nothing known at or before t
    -> ABSTAIN (no_record_at_or_before_t; a snapshot is not extended backwards); a recorded end of a value
    at or before t and after p -> ABSTAIN (value_ended_no_successor); a record starting after t with a
    different value than p -> ABSTAIN (transition_between_records); otherwise FALL BACK to p's value if
    t - p.observed_at < F -> FALLBACK, else ABSTAIN (stale_beyond_freshness). With snapshot sightings only,
    the value/unknown answer equals the project's temporal resolver over policy_gate.materialize_facts
    (checked in experiments/replay-policy-v1).
    """
    freshness = seconds_to_us(freshness_seconds, name="freshness_seconds")
    rows = as_stream(stream).visible(subject, predicate, c)
    if not rows:
        return Answer(None, ABSTAIN, "no_record_available", ())
    evidence: dict[str, list[str]] = {}
    for r in rows:
        if r.valid_to is not None:
            covered = r.start <= t < r.valid_to
        else:
            covered = r.start < r.observed_at and r.start <= t < r.observed_at
        if covered:
            evidence.setdefault(r.value, []).append(r.record_id)
    sightings = [r for r in rows if r.is_sighting]
    before = [r for r in sightings if r.observed_at <= t]
    after = [r for r in sightings if r.observed_at > t]
    p = before[-1] if before else None
    n = after[0] if after else None
    if p is not None and n is not None and p.value == n.value:
        evidence.setdefault(p.value, []).extend((p.record_id, n.record_id))
    elif p is not None and n is None and p.observed_at == t:
        evidence.setdefault(p.value, []).append(p.record_id)
    if len(evidence) > 1:
        ids = tuple(sorted({rid for group in evidence.values() for rid in group}))
        return Answer(None, ABSTAIN, "conflicting_values_at_t", ids)
    if evidence:
        (value, ids), = evidence.items()
        return Answer(value, CONFIRMED, "valid_at_t", tuple(sorted(set(ids))))
    if p is not None and n is not None:
        return Answer(None, ABSTAIN, "transition_between_records", (p.record_id, n.record_id))
    later = [r for r in rows if r.start > t]
    first_later = min(later, key=lambda r: (r.start, r.record_id)) if later else None
    ended = [r for r in rows if r.valid_to is not None and r.valid_to <= t]
    last_end = max(ended, key=lambda r: (r.valid_to, r.record_id)) if ended else None
    if p is None and last_end is None:
        return Answer(None, ABSTAIN, "no_record_at_or_before_t",
                      (first_later.record_id,) if first_later is not None else ())
    if last_end is not None and (p is None or last_end.valid_to > p.observed_at):
        ids = (last_end.record_id,) if p is None else (p.record_id, last_end.record_id)
        return Answer(None, ABSTAIN, "value_ended_no_successor", ids)
    if first_later is not None and first_later.value != p.value:
        return Answer(None, ABSTAIN, "transition_between_records", (p.record_id, first_later.record_id))
    if t - p.observed_at >= freshness:
        return Answer(None, ABSTAIN, "stale_beyond_freshness", (p.record_id,))
    return Answer(p.value, FALLBACK, "carried_forward_within_freshness", (p.record_id,))


@dataclass(frozen=True)
class Policy:
    """A named context policy. ``abstains``: may abstain by design; ``valid_time``: uses t."""
    name: str
    resolve: Callable[..., Answer]
    abstains: bool
    valid_time: bool
    params: tuple = ()

    def __call__(self, stream, subject: str, predicate: str, t: int, c: int) -> Answer:
        return self.resolve(stream, subject, predicate, t, c)


def make_policy(name: str, *, freshness_seconds: float = 600.0) -> Policy:
    if name == "latest_state":
        return Policy("latest_state", latest_state, abstains=False, valid_time=False)
    if name == "temporal_join":
        return Policy("temporal_join", temporal_join, abstains=False, valid_time=True)
    if name == "bitemporal_abstain":
        seconds_to_us(freshness_seconds, name="freshness_seconds")
        return Policy(f"bitemporal_abstain_F{freshness_seconds:g}",
                      partial(bitemporal_abstain, freshness_seconds=freshness_seconds),
                      abstains=True, valid_time=True, params=(("freshness_seconds", freshness_seconds),))
    raise ValueError(f"unknown policy {name!r}")


# ---------------------------------------------------------------------------
# Part 3: instance-attribution task adapter and scoring
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Candidate:
    """A candidate instance: its subject key, the short label used as the answer, and its recorded creation
    floor (known to the view once any record of the candidate is usable)."""
    key: str
    label: str
    created_floor: int | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    answer: str | None
    status: str
    reason: str
    record_ids: tuple[str, ...]
    classes: tuple[tuple[str, str, str, str], ...]  # (label, class, rule, status) per candidate

    def to_dict(self) -> dict:
        return {"answer": self.answer, "status": self.status, "reason": self.reason,
                "record_ids": list(self.record_ids),
                "classes": {label: {"class": cls, "rule": rule, "status": status}
                            for label, cls, rule, status in self.classes}}


def attribute_instance(stream, candidates: Sequence[Candidate], t: int, c: int, policy: Policy, *,
                       predicate: str = "STATE", serving_value: str = "ready",
                       retired_values: Iterable[str] = (), lifecycle_rules: bool | None = None) -> Decision:
    """Which candidate served an event at valid time t, decided with records usable at cutoff c.

    Per candidate, first matching rule: not_in_view (no usable record) -> not a candidate; for valid-time
    policies (lifecycle_rules defaults to policy.valid_time): K2 created_floor > t -> not_serving; K1 the
    last usable sighting at or before t has a retired value -> not_serving (irreversible); then the policy's
    answer: value == serving_value -> serving, other value -> not_serving, ABSTAIN -> possibly_serving for a
    policy that abstains by design, and not_serving (no row to join) for one that does not. Combination:
    exactly one serving and nothing else possible -> that label (CONFIRMED if every in-view candidate's
    status is CONFIRMED, else FALLBACK); none possible -> ABSTAIN no_serving_pod_confirmed; one possible but
    unconfirmed -> ABSTAIN serving_pod_unconfirmed; two or more possible -> ABSTAIN two_pods_possible for an
    abstaining policy, else a forced tie-break to the newest created candidate (reason tie_break_newest).
    """
    stream = as_stream(stream)
    lifecycle = policy.valid_time if lifecycle_rules is None else lifecycle_rules
    retired = frozenset(retired_values)
    classes, used, statuses = [], set(), []
    serving, possible = [], []
    for cand in candidates:
        rows = stream.visible(cand.key, predicate, c)
        if not rows:
            classes.append((cand.label, "not_in_view", "no_record_available", ABSTAIN))
            continue
        sightings_before = [r for r in rows if r.is_sighting and r.observed_at <= t]
        if lifecycle and cand.created_floor is not None and t < cand.created_floor:
            cls, rule, status, ids = "not_serving", "K2_created_after_t", CONFIRMED, (rows[0].record_id,)
        elif lifecycle and sightings_before and sightings_before[-1].value in retired:
            last = sightings_before[-1]
            cls, rule, status, ids = "not_serving", "K1_retired_before_t:" + last.value, CONFIRMED, (last.record_id,)
        else:
            answer = policy(stream, cand.key, predicate, t, c)
            ids, status = answer.record_ids, answer.status
            if answer.status == ABSTAIN:
                cls = "possibly_serving" if policy.abstains else "not_serving"
                rule = answer.reason if policy.abstains else "no_row_at_t:" + answer.reason
                if not policy.abstains:
                    status = CONFIRMED
            else:
                cls = "serving" if answer.value == serving_value else "not_serving"
                rule = f"{answer.reason}:{answer.value}"
        classes.append((cand.label, cls, rule, status))
        statuses.append(status)
        used.update(ids)
        if cls == "serving":
            serving.append(cand)
        if cls in ("serving", "possibly_serving"):
            possible.append(cand)
    record_ids = tuple(sorted(used))
    classes_t = tuple(classes)
    if len(possible) == 1 and len(serving) == 1:
        status = CONFIRMED if all(s == CONFIRMED for s in statuses) else FALLBACK
        return Decision(serving[0].label, status, "single_confirmed_serving_pod", record_ids, classes_t)
    if not possible:
        return Decision(None, ABSTAIN, "no_serving_pod_confirmed", record_ids, classes_t)
    if len(possible) == 1:
        return Decision(None, ABSTAIN, "serving_pod_unconfirmed", record_ids, classes_t)
    if policy.abstains or not serving:
        return Decision(None, ABSTAIN, "two_pods_possible", record_ids, classes_t)
    chosen = max(serving, key=lambda x: (x.created_floor if x.created_floor is not None else -1, x.key))
    status = CONFIRMED if all(s == CONFIRMED for s in statuses) else FALLBACK
    return Decision(chosen.label, status, "tie_break_newest", record_ids, classes_t)


def outcome(answer: str | None, truth: str) -> str:
    """correct / wrong against the truth label; an abstention (no answer) is neither."""
    if answer is None:
        return "abstain"
    return "correct" if answer == truth else "wrong"


def score(rows: Sequence[Mapping], *, withdrawn: Iterable[str] = ()) -> dict:
    """Counts for one (policy x stream x cutoff) cell. rows need answer, status, outcome, reason, record_ids,
    event. harmful = wrong answers (a wrong instance is harmful; an abstention is not)."""
    withdrawn = frozenset(withdrawn)
    n = len(rows)
    count = lambda pred: sum(1 for r in rows if pred(r))
    correct = count(lambda r: r["outcome"] == "correct")
    wrong = count(lambda r: r["outcome"] == "wrong")
    abstain = count(lambda r: r["outcome"] == "abstain")
    reasons: dict[str, int] = {}
    for r in rows:
        if r["outcome"] == "abstain":
            reasons[r["reason"]] = reasons.get(r["reason"], 0) + 1
    return {
        "n": n, "correct": correct, "wrong": wrong, "abstain": abstain, "harmful": wrong,
        "coverage": round((correct + wrong) / n, 4) if n else None,
        "confirmed": count(lambda r: r["status"] == CONFIRMED),
        "fallback": count(lambda r: r["status"] == FALLBACK),
        "wrong_confirmed": count(lambda r: r["outcome"] == "wrong" and r["status"] == CONFIRMED),
        "wrong_fallback": count(lambda r: r["outcome"] == "wrong" and r["status"] == FALLBACK),
        "tie_breaks": count(lambda r: r["reason"] == "tie_break_newest"),
        "answers_using_withdrawn_version": count(
            lambda r: r["answer"] is not None and bool(withdrawn.intersection(r["record_ids"]))),
        "abstain_reasons": dict(sorted(reasons.items())),
        "wrong_events": [r["event"] for r in rows if r["outcome"] == "wrong"],
        "abstain_events": [r["event"] for r in rows if r["outcome"] == "abstain"],
    }


def flips(rows_at_cutoff: Sequence[Mapping], rows_later: Sequence[Mapping]) -> dict:
    """Saved answers that change when the same policy re-decides the same events with later records.

    flip_to_other: answered X, later Y != X. flip_to_abstain: answered, later abstains. resolved_later:
    abstained, later answers (not a flip of an answer).
    """
    later = {r["event"]: r["answer"] for r in rows_later}
    to_other = [r["event"] for r in rows_at_cutoff if r["answer"] is not None
                and later[r["event"]] is not None and later[r["event"]] != r["answer"]]
    to_abstain = [r["event"] for r in rows_at_cutoff if r["answer"] is not None and later[r["event"]] is None]
    resolved = [r["event"] for r in rows_at_cutoff if r["answer"] is None and later[r["event"]] is not None]
    return {"flips": len(to_other) + len(to_abstain), "flip_to_other": len(to_other),
            "flip_to_abstain": len(to_abstain), "resolved_later": len(resolved),
            "flip_to_other_events": to_other, "flip_to_abstain_events": to_abstain,
            "resolved_later_events": resolved}


# ---------------------------------------------------------------------------
# The real rollout task (experiments/attribution-lag-v1), loaded read-only
# ---------------------------------------------------------------------------
ATTRIBUTION_LAG_SCRIPT = "experiments/attribution-lag-v1/run_attribution_lag.py"


def import_script(path: Path, module_name: str):
    """Import an experiment script by path without writing bytecode (the file is only read)."""
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot import {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


@dataclass(frozen=True)
class RolloutTask:
    """Instance attribution on the 22 Sep 2026 rollout: which recommendationservice Pod served request i."""
    module: object                       # the attribution-lag script, imported read-only
    records: tuple[Record, ...]          # Pod STATE records (kinds api, absence)
    events: tuple[Record, ...]           # one record per request: observed_at = available_at = t_req
    truth: Mapping[str, str]             # event record_id -> span-verified Pod label (old / new)
    candidates: tuple[Candidate, ...]
    predicate: str
    serving_value: str
    retired_values: frozenset
    default_freshness_seconds: float
    deltas: tuple                        # ((label, seconds or None), ...)
    request_index: Mapping[str, int]
    context: Mapping[str, object]        # protocol, capture, sightings, patch, pods for cross-checks

    def decide(self, stream, event: Record, delta_seconds, policy: Policy, **kwargs) -> Decision:
        t = event.observed_at
        c = HINDSIGHT if delta_seconds is None else t + seconds_to_us(delta_seconds)
        return attribute_instance(stream, self.candidates, t, c, policy, predicate=self.predicate,
                                  serving_value=self.serving_value, retired_values=self.retired_values, **kwargs)


def records_from_pods(pods: Mapping[str, Mapping], snapshot_of: Mapping[str, str], predicate: str) -> tuple[Record, ...]:
    """attribution-lag per-Pod observation tuples (observed_us, available_us, value, record_id) -> Records."""
    out = []
    for subject, pod in sorted(pods.items()):
        for observed, available, value, record_id in pod["observations"]:
            kind = "absence" if record_id.startswith("absence:") else "api"
            out.append(Record(record_id, subject, predicate, value, observed, available, kind=kind,
                              group=snapshot_of.get(record_id)))
    return tuple(out)


def load_attribution_lag_task(root: Path | str) -> RolloutTask:
    """Build the recommendationservice instance-attribution task from the real rollout evidence.

    Reuses the attribution-lag script's loader and constants (imported read-only): requests and span-verified
    truth (load_requests), Pod STATE observations derived by the policy-gate audit's load_sightings /
    build_observations (pod_observations), candidate labels, creation floors, RETIRED, DELTAS and the
    carry-forward F. Nothing is written.
    """
    root = Path(root).resolve()
    module = import_script(root / ATTRIBUTION_LAG_SCRIPT, "attribution_lag_v1_readonly_for_replay")
    pga = module.pga
    protocol = json.loads(pga.INPUTS["protocol"].read_text(encoding="utf-8"))
    capture = json.loads(pga.INPUTS["capture"].read_text(encoding="utf-8"))
    sightings = pga.load_sightings(protocol)
    patch = pga.patch_receipt(capture)
    pods, _ = module.pod_observations(sightings, patch, protocol)
    snapshot_of = {row["record_id"]: row["snapshot_id"] for row in sightings}
    for pod in pods.values():
        for _, _, _, record_id in pod["observations"]:
            if record_id.startswith("absence:"):
                snapshot_of[record_id] = record_id.split(":")[1]
    predicate = module.STATE
    records = records_from_pods(pods, snapshot_of, predicate)
    requests = module.load_requests()
    events, truth, index = [], {}, {}
    for r in requests:
        event_id = f"request/{r['request_index']}"
        events.append(Record(event_id, event_id, "T_REQ", str(r["request_index"]), r["t_req_us"], r["t_req_us"],
                             kind="request"))
        truth[event_id] = r["truth"]
        index[event_id] = r["request_index"]
    candidates = tuple(Candidate(subject, module.LABEL[pod["uid"]], pod["created_floor_us"])
                       for subject, pod in sorted(pods.items()))
    return RolloutTask(module=module, records=records, events=tuple(events), truth=truth, candidates=candidates,
                       predicate=predicate, serving_value="ready", retired_values=frozenset(module.RETIRED),
                       default_freshness_seconds=module.CARRY_FORWARD_US / US, deltas=tuple(module.DELTAS),
                       request_index=index,
                       context={"protocol": protocol, "capture": capture, "sightings": sightings, "patch": patch,
                                "pods": pods, "requests": requests})


# ---------------------------------------------------------------------------
# A Phase 3 capture (phase3/CAPTURE_FORMAT.md): the same task, derived from <capture>/evidence/ rows
# ---------------------------------------------------------------------------
def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def capture_service(capture: Path, protocol: Mapping, service: str | None) -> tuple[str, str]:
    """(target service, where it came from): --service, else the planned CHANGE in incident.json (the plan
    entry may be nested under "incident" or be the whole file), else evidence/protocol.json replacement_service.

    Evaluator-only fields are never consulted: the injected fault service (incident.json fault.service) and
    ground_truth are not legitimate operator knowledge at decision time, so a capture without a planned change
    (e.g. plan entry I3, fault only) must be given the service explicitly with --service. (Corrected 30 Sep 2026;
    the earlier version fell back to fault.service.)"""
    if service:
        return _text(service, "service"), "--service"
    path = Path(capture) / "incident.json"
    if path.exists():
        doc = _json(path)
        entry = doc.get("incident", doc) if isinstance(doc, Mapping) else {}
        part = entry.get("change") if isinstance(entry, Mapping) else None
        if isinstance(part, Mapping) and part.get("service"):
            return part["service"], "incident.json change.service"
    for key in ("replacement_service", "change_service"):
        if protocol.get(key):
            return protocol[key], f"evidence/protocol.json {key}"
    raise ValueError("no target service: pass --service (the fault service in incident.json is evaluator-only and is "
                     "deliberately not used) or provide incident.json with a planned change.service")


def load_capture_task(capture: Path | str, service: str | None = None, *, root: Path | str | None = None) -> RolloutTask:
    """Build the instance-attribution task from a converted Phase 3 capture, deriving everything from rows.

    Model input: evidence/accepted_evidence.jsonl api_observation rows, mapped to Pod STATE records by the
    policy-gate audit's own load_sightings()/build_observations() (imported read-only; the evidence path is
    redirected in memory only), keeping the Pods whose label app == service (checked against the
    Pod -> ReplicaSet -> Deployment owner chain). Scoring only: span_claim rows give each ordinary request's
    root span (no parent, attribute aiops.request.index), t_req = its startTimeUnixNano floored to the
    microsecond, and the span-verified truth = the k8s.pod.uid shared by every span of the target service in
    that trace; client_request rows give the block (client-reference / client-target) by trace_id. Nothing in
    the capture is written. No 22 Sep fact is hard-coded: counts, UIDs, labels and the split come from rows.
    """
    capture = Path(capture).resolve()
    root = Path(root).resolve() if root is not None else Path(__file__).resolve().parents[2]
    evidence_dir = capture / "evidence"
    evidence_file = evidence_dir / "accepted_evidence.jsonl"
    if not evidence_file.exists():
        raise FileNotFoundError(f"{evidence_file} not found: run phase3/convert_capture.py --capture {capture} first")
    protocol = _json(evidence_dir / "protocol.json")
    capture_doc = _json(evidence_dir / "capture.json") if (evidence_dir / "capture.json").exists() else {}
    service, service_source = capture_service(capture, protocol, service)
    module = import_script(root / ATTRIBUTION_LAG_SCRIPT, "attribution_lag_v1_readonly_for_capture")
    pga = module.pga
    notes: list[str] = []

    rows = [json.loads(line) for line in evidence_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    kinds: dict[str, int] = {}
    for row in rows:
        kinds[row["record"]["kind"]] = kinds.get(row["record"]["kind"], 0) + 1

    previous = pga.INPUTS["api_sightings"]
    pga.INPUTS["api_sightings"] = evidence_file  # in memory only; restored below
    try:
        sightings = pga.load_sightings(protocol)
        observations, _, info = pga.build_observations(sightings, None, protocol, include_receipts=False)
    finally:
        pga.INPUTS["api_sightings"] = previous
    # available_ns (row) and payload available_at must agree to the microsecond (CAPTURE_FORMAT.md).
    by_id = {row["record"]["evidence_id"]: row for row in rows if row["record"]["kind"] == "api_observation"}
    lag_mismatch = [s["record_id"] for s in sightings
                    if by_id[s["record_id"]]["available_ns"] // 1000 != to_us(s["available_at"])]
    if lag_mismatch:
        notes.append(f"{len(lag_mismatch)} api rows: available_ns // 1000 != payload available_at; payload used")

    labels, owners, rs_owner, deployment_name = {}, {}, {}, {}
    for s in sightings:
        meta = s["resource_data"]["metadata"]
        controller = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
        if s["kind"] == "Pod":
            app = meta.get("labels", {}).get("app")
            if labels.setdefault(s["subject"], app) != app:
                raise ValueError(f"label changed for {s['subject']}")
            if controller:
                owners[s["subject"]] = controller[0]["uid"]
        elif s["kind"] == "ReplicaSet" and controller:
            rs_owner[meta["uid"]] = controller[0]["uid"]
        elif s["kind"] == "Deployment":
            deployment_name[meta["uid"]] = meta["name"]
    by_label = sorted(k for k, app in labels.items() if app == service)
    by_chain = sorted(k for k, rs in owners.items() if deployment_name.get(rs_owner.get(rs)) == service)
    if by_label != by_chain:
        raise ValueError(f"{service}: Pods by label {by_label} and by owner chain {by_chain} disagree")
    if not by_label:
        raise ValueError(f"no Pod of service {service!r} in the capture's API sightings")

    snapshot_of = {s["record_id"]: s["snapshot_id"] for s in sightings}
    records = []
    for o in observations:
        if o.subject in by_label and o.predicate == "STATE":
            kind = "absence" if o.record_id.startswith("absence:") else "api"
            group = o.record_id.split(":")[1] if kind == "absence" else snapshot_of.get(o.record_id)
            records.append(Record(o.record_id, o.subject, "STATE", o.value, to_us(o.observed_at),
                                  to_us(o.available_at), kind=kind, group=group))
    records.sort(key=lambda r: (r.subject, r.observed_at, r.record_id))
    created = {k: to_us(info["identities"][k]["created_at"]) for k in by_label}
    order = sorted(by_label, key=lambda k: (created[k], k))
    names = ["old", "new"] if len(order) == 2 else [f"p{i}" for i in range(1, len(order) + 1)]
    if len(order) > 9:
        raise ValueError("more than 9 candidate Pods; widen the answer codes first")
    candidates = tuple(Candidate(k, names[i], created[k]) for i, k in enumerate(order))
    label_of_uid = {c.key.split("/", 1)[1]: c.label for c in candidates}

    spans_by_trace: dict[str, list[dict]] = {}
    block_of_trace: dict[str, str] = {}
    for row in rows:
        record = row["record"]
        if record["kind"] == "span_claim":
            spans_by_trace.setdefault(record["payload"]["trace_id"], []).append(record["payload"])
        elif record["kind"] == "client_request":
            payload = record["payload"]
            if payload.get("trace_id"):
                block_of_trace[payload["trace_id"]] = payload.get("block") or payload.get("source") or "client"
    requests, unverified = [], []
    for trace_id, spans in spans_by_trace.items():
        for p in spans:
            span = p["span"]
            if span.get("parentSpanId") or "aiops.request.index" not in (p.get("span_attributes") or {}):
                continue
            mine = [q for q in spans if (q.get("resource_attributes") or {}).get("service.name") == service]
            servers = [q for q in mine if q["span"].get("kind") == 2]
            uids = {(q.get("resource_attributes") or {}).get("k8s.pod.uid") for q in mine}
            item = {"trace_id": trace_id, "block": block_of_trace.get(trace_id),
                    "index": int(p["span_attributes"]["aiops.request.index"]),
                    "root_service": (p.get("resource_attributes") or {}).get("service.name"),
                    "t_req_us": int(span["startTimeUnixNano"]) // 1000}
            if len(servers) == 1 and len(uids) == 1 and next(iter(uids)) in label_of_uid:
                item["truth_uid"] = next(iter(uids))
                requests.append(item)
            else:
                item["why"] = (f"{len(servers)} server spans of {service}, Pod UIDs {sorted(u or '-' for u in uids)}"
                               + ("" if uids <= set(label_of_uid) else " (not a sighted candidate)"))
                unverified.append(item)
    requests.sort(key=lambda r: (r["t_req_us"], r["block"] or "", r["index"]))
    events, truth, index = [], {}, {}
    for number, r in enumerate(requests, start=1):
        event_id = f"request/{number}"
        r["event"] = number
        r["label"] = f"{r['block']}:{r['index']}" if r["block"] else str(r["index"])
        events.append(Record(event_id, event_id, "T_REQ", r["label"], r["t_req_us"], r["t_req_us"], kind="request"))
        truth[event_id] = label_of_uid[r["truth_uid"]]
        index[event_id] = number
    if unverified:
        notes.append(f"{len(unverified)} requests without a span-verified {service} Pod are not scored")
    ground_truth = capture / "ground_truth" / "ground_truth.json"
    return RolloutTask(module=module, records=tuple(records), events=tuple(events), truth=truth,
                       candidates=candidates, predicate="STATE", serving_value="ready",
                       retired_values=frozenset(module.RETIRED), default_freshness_seconds=module.CARRY_FORWARD_US / US,
                       deltas=tuple(module.DELTAS), request_index=index,
                       context={"capture_dir": capture, "evidence_file": evidence_file, "protocol": protocol,
                                "capture": capture_doc, "service": service, "service_source": service_source,
                                "sightings": sightings, "rows_by_kind": dict(sorted(kinds.items())),
                                "requests": requests, "unverified_requests": unverified,
                                "owner_chain_agrees": True, "api_rows_available_mismatch": len(lag_mismatch),
                                "ground_truth": _json(ground_truth) if ground_truth.exists() else None,
                                "notes": notes})
