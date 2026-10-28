"""Synthetic temporal-context correctness prototype; no RCA performance claim.

GraphStore and SqliteStore independently select assertions using validity and
knowledge intervals. resolve() is for single-valued relationships, e.g. RUNS_ON.
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Literal


_UTC = timezone.utc
_EPOCH = datetime(1970, 1, 1, tzinfo=_UTC)
_UNDETERMINED = {"unknown_start", "unknown_end", "missing_confirmation"}


def _identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a nonempty string without outer whitespace")
    return value


def _utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    if value.utcoffset() is None:
        raise ValueError(f"{name} must have a defined UTC offset")
    try:
        return value.astimezone(_UTC)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{name} is outside the supported UTC datetime range") from exc


def _micros(value: datetime) -> int:
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


_MAX_FRESHNESS_US = _micros(datetime.max.replace(tzinfo=_UTC)) - _micros(
    datetime.min.replace(tzinfo=_UTC)
)


def _freshness_micros(value: float) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("freshness_seconds must be a finite nonnegative number")
    try:
        seconds = float(value)
    except OverflowError as exc:
        raise ValueError("freshness_seconds exceeds the supported range") from exc
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("freshness_seconds must be a finite nonnegative number")
    if seconds > _MAX_FRESHNESS_US / 1_000_000:
        raise ValueError("freshness_seconds exceeds the supported datetime span")
    return min(round(seconds * 1_000_000), _MAX_FRESHNESS_US)


@dataclass(frozen=True, slots=True)
class Fact:
    fact_id: str
    subject: str
    predicate: str
    object: str
    valid_from: datetime | None
    valid_to: datetime | None
    available_at: datetime
    superseded_at: datetime | None
    source_id: str
    known_open: bool = False
    confirmed_at: datetime | None = None

    def __post_init__(self) -> None:
        for name in ("fact_id", "subject", "predicate", "object", "source_id"):
            _identifier(getattr(self, name), name)
        if not isinstance(self.known_open, bool):
            raise ValueError("known_open must be a bool")
        for name in (
            "valid_from", "valid_to", "available_at", "superseded_at", "confirmed_at"
        ):
            value = getattr(self, name)
            if value is None:
                if name == "available_at":
                    raise ValueError("available_at is required")
            else:
                object.__setattr__(self, name, _utc(value, name))
        if self.valid_from is not None and self.valid_to is not None:
            if self.valid_to <= self.valid_from:
                raise ValueError("valid_to must be strictly after valid_from")
        if self.superseded_at is not None and self.superseded_at <= self.available_at:
            raise ValueError("superseded_at must be strictly after available_at")
        if self.known_open and self.valid_to is not None:
            raise ValueError("known_open and a finite valid_to are inconsistent")
        if self.confirmed_at is not None:
            if self.confirmed_at > self.available_at:
                raise ValueError("confirmed_at cannot be later than available_at")
            if self.known_open and self.valid_from is not None:
                if self.confirmed_at < self.valid_from:
                    raise ValueError("known-open confirmation cannot precede valid_from")


@dataclass(frozen=True, slots=True)
class Resolution:
    status: Literal["resolved", "unknown", "conflict"]
    value: str | None
    fact_ids: tuple[str, ...]
    reason: str


def _facts(facts: Iterable[Fact]) -> tuple[Fact, ...]:
    result = tuple(facts)
    seen: set[str] = set()
    for fact in result:
        if not isinstance(fact, Fact):
            raise ValueError("stores accept Fact instances only")
        if fact.fact_id in seen:
            raise ValueError(f"duplicate fact_id: {fact.fact_id}")
        seen.add(fact.fact_id)
    return result


def _query(subject, predicate, observed_at, decision_at, freshness_seconds):
    _identifier(subject, "subject")
    _identifier(predicate, "predicate")
    observed = _utc(observed_at, "observed_at")
    decision = _utc(decision_at, "decision_at")
    if observed > decision:
        raise ValueError("observed_at cannot be later than decision_at")
    return _micros(observed), _micros(decision), _freshness_micros(freshness_seconds)


def _summarize(rows: Iterable[tuple[str, str, str]]) -> Resolution:
    """Format already classified rows; this helper performs no temporal query."""
    rows = tuple(rows)
    if not rows:
        return Resolution("unknown", None, (), "no_available_facts")
    eligible = [row for row in rows if row[2] == "eligible"]
    values = {row[1] for row in eligible}
    ids = lambda records: tuple(sorted(row[0] for row in records))
    if len(values) > 1:
        return Resolution("conflict", None, ids(eligible), "conflicting_eligible_values")
    uncertain = [row for row in rows if row[2] in _UNDETERMINED]
    if values:
        value = next(iter(values))
        competing = [row for row in uncertain if row[1] != value]
        if competing:
            return Resolution(
                "unknown", None, ids(eligible + competing), "unresolved_validity"
            )
        return Resolution("resolved", value, ids(eligible), "unique_eligible_value")
    if uncertain:
        return Resolution("unknown", None, ids(uncertain), "unknown_validity")
    expired = [row for row in rows if row[2] == "expired"]
    if expired:
        return Resolution("unknown", None, ids(expired), "stale_confirmation")
    return Resolution("unknown", None, ids(rows), "outside_validity")


class GraphStore:
    """Typed adjacency lists keyed by subject, then relationship type."""

    def __init__(self, facts: Iterable[Fact]):
        adjacency: dict[str, dict[str, list[Fact]]] = {}
        for fact in _facts(facts):
            adjacency.setdefault(fact.subject, {}).setdefault(fact.predicate, []).append(fact)
        self._adjacency = {
            subject: {predicate: tuple(items) for predicate, items in relations.items()}
            for subject, relations in adjacency.items()
        }

    def resolve(
        self, subject: str, predicate: str, observed_at: datetime,
        decision_at: datetime, freshness_seconds: float,
    ) -> Resolution:
        observed, decision, freshness = _query(
            subject, predicate, observed_at, decision_at, freshness_seconds
        )
        rows = []
        for fact in self._adjacency.get(subject, {}).get(predicate, ()):
            if _micros(fact.available_at) > decision:
                continue
            if fact.superseded_at is not None and decision >= _micros(fact.superseded_at):
                continue
            start = None if fact.valid_from is None else _micros(fact.valid_from)
            end = None if fact.valid_to is None else _micros(fact.valid_to)
            if end is not None and observed >= end:
                state = "outside_validity"
            elif start is not None and observed < start:
                state = "outside_validity"
            elif start is None:
                state = "unknown_start"
            elif end is not None:
                state = "eligible"
            elif not fact.known_open:
                state = "unknown_end"
            elif fact.confirmed_at is None:
                state = "missing_confirmation"
            elif observed >= _micros(fact.confirmed_at) + freshness:
                state = "expired"
            else:
                state = "eligible"
            rows.append((fact.fact_id, fact.object, state))
        return _summarize(rows)


class SqliteStore:
    """Independent in-memory relational selection, with integer UTC microseconds."""

    _SELECT = """
        SELECT fact_id, object,
            CASE
                WHEN valid_to IS NOT NULL AND :observed >= valid_to THEN 'outside_validity'
                WHEN valid_from IS NOT NULL AND :observed < valid_from THEN 'outside_validity'
                WHEN valid_from IS NULL THEN 'unknown_start'
                WHEN valid_to IS NOT NULL THEN 'eligible'
                WHEN known_open = 0 THEN 'unknown_end'
                WHEN confirmed_at IS NULL THEN 'missing_confirmation'
                WHEN :observed >= confirmed_at + :freshness THEN 'expired'
                ELSE 'eligible'
            END AS validity_state
        FROM facts
        WHERE subject = :subject AND predicate = :predicate
            AND available_at <= :decision
            AND (superseded_at IS NULL OR :decision < superseded_at)
    """

    def __init__(self, facts: Iterable[Fact]):
        facts = _facts(facts)
        self._connection = sqlite3.connect(":memory:")
        self._connection.execute("""
            CREATE TABLE facts (
                fact_id TEXT PRIMARY KEY, subject TEXT NOT NULL, predicate TEXT NOT NULL,
                object TEXT NOT NULL, valid_from INTEGER, valid_to INTEGER,
                available_at INTEGER NOT NULL, superseded_at INTEGER,
                source_id TEXT NOT NULL, known_open INTEGER NOT NULL, confirmed_at INTEGER
            )
        """)
        self._connection.execute(
            "CREATE INDEX context_lookup ON facts(subject, predicate, available_at)"
        )
        optional = lambda value: None if value is None else _micros(value)
        self._connection.executemany(
            "INSERT INTO facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (fact.fact_id, fact.subject, fact.predicate, fact.object,
                 optional(fact.valid_from), optional(fact.valid_to),
                 _micros(fact.available_at), optional(fact.superseded_at), fact.source_id,
                 int(fact.known_open), optional(fact.confirmed_at))
                for fact in facts
            ],
        )
        self._connection.commit()

    def resolve(
        self, subject: str, predicate: str, observed_at: datetime,
        decision_at: datetime, freshness_seconds: float,
    ) -> Resolution:
        observed, decision, freshness = _query(
            subject, predicate, observed_at, decision_at, freshness_seconds
        )
        rows = self._connection.execute(self._SELECT, {
            "subject": subject, "predicate": predicate, "observed": observed,
            "decision": decision, "freshness": freshness,
        }).fetchall()
        return _summarize(rows)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SqliteStore:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
