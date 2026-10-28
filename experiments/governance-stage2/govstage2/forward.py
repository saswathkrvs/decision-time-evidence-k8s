"""Posing with delta: decide at observation (dispatch) time x later than the knowledge cutoff kappa.

The resolvers and the operational view refuse an observation time later than the cutoff (src/aiops_kg/temporal.py
``_query``; src/aiops_kg/policy_gate.py ``OperationalView``). The adapter evaluates x > kappa through subclasses that
lift only that guard, never by editing those modules, and a test shows that on fixtures without future-dated facts
this equals evaluating at kappa with F, N and S each shortened by delta.

What is lifted, and nothing else:

- ``temporal._query`` (called by GraphStore.resolve and SqliteStore.resolve) raises "observed_at cannot be later than
  decision_at". ``ForwardGraphStore.resolve`` and ``ForwardSqliteStore.resolve`` are the original methods' bodies,
  statement for statement, calling ``_forward_query``, which is ``temporal._query`` without that one ``if``.
- ``policy_gate.OperationalView.__init__`` raises "observed_at cannot be later than knowledge_cutoff".
  ``ForwardOperationalView.__init__`` is the original constructor without that one ``if``; every other method is
  inherited. ``ForwardTracedView`` is the development adapter's ``govpilot.mapping.TracedView`` (which records every
  fact it hands out) on top of it: the method resolution order is ForwardTracedView, TracedView,
  ForwardOperationalView, OperationalView, so TracedView's ``super().__init__`` reaches the guard-free constructor.
- ``ForwardPilotStore`` is ``govpilot.mapping.PilotStore`` (graph + SQLite + dual engine + support map) whose two
  engines are the forward resolvers (``ForwardBitemporalStore`` builds them; PilotStore's own constructor runs
  unchanged).

For x <= kappa every forward class answers exactly as the original class (tests/test_stage2_adapter.py checks it on
every query of a fixture); for x > kappa the original classes refuse, so the test checks the equivalence with
shortened F, N and S instead.
"""
from __future__ import annotations

from datetime import datetime

from aiops_kg import temporal as T
from aiops_kg.policy_gate import BitemporalStore, OperationalView, _seconds, _utc

from .common import GC  # noqa: F401  (ensures the read-only paths are set up)
from govpilot.mapping import PilotStore, TracedView  # noqa: E402  (read-only)


def _forward_query(subject, predicate, observed_at, decision_at, freshness_seconds):
    """``temporal._query`` without its guard ``if observed > decision: raise``; every other check is the one."""
    T._identifier(subject, "subject")
    T._identifier(predicate, "predicate")
    observed = T._utc(observed_at, "observed_at")
    decision = T._utc(decision_at, "decision_at")
    return T._micros(observed), T._micros(decision), T._freshness_micros(freshness_seconds)


class ForwardGraphStore(T.GraphStore):
    """``temporal.GraphStore`` whose ``resolve`` accepts observed_at > decision_at (body otherwise identical)."""

    def resolve(self, subject: str, predicate: str, observed_at: datetime, decision_at: datetime,
                freshness_seconds: float) -> T.Resolution:
        observed, decision, freshness = _forward_query(
            subject, predicate, observed_at, decision_at, freshness_seconds
        )
        rows = []
        for fact in self._adjacency.get(subject, {}).get(predicate, ()):
            if T._micros(fact.available_at) > decision:
                continue
            if fact.superseded_at is not None and decision >= T._micros(fact.superseded_at):
                continue
            start = None if fact.valid_from is None else T._micros(fact.valid_from)
            end = None if fact.valid_to is None else T._micros(fact.valid_to)
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
            elif observed >= T._micros(fact.confirmed_at) + freshness:
                state = "expired"
            else:
                state = "eligible"
            rows.append((fact.fact_id, fact.object, state))
        return T._summarize(rows)


class ForwardSqliteStore(T.SqliteStore):
    """``temporal.SqliteStore`` whose ``resolve`` accepts observed_at > decision_at (same SQL, same summary)."""

    def resolve(self, subject: str, predicate: str, observed_at: datetime, decision_at: datetime,
                freshness_seconds: float) -> T.Resolution:
        observed, decision, freshness = _forward_query(
            subject, predicate, observed_at, decision_at, freshness_seconds
        )
        rows = self._connection.execute(self._SELECT, {
            "subject": subject, "predicate": predicate, "observed": observed,
            "decision": decision, "freshness": freshness,
        }).fetchall()
        return T._summarize(rows)


class ForwardOperationalView(OperationalView):
    """``policy_gate.OperationalView`` whose constructor accepts observed_at > knowledge_cutoff."""

    def __init__(self, store: BitemporalStore, observed_at: datetime, knowledge_cutoff: datetime,
                 *, carry_forward_seconds: float, engine: str = "graph"):
        self.store = store
        self.observed_at = _utc(observed_at, "observed_at")
        self.knowledge_cutoff = _utc(knowledge_cutoff, "knowledge_cutoff")
        self.carry_forward_seconds = _seconds(carry_forward_seconds, "carry_forward_seconds")
        self.engine_name = engine
        self._engine = store.engine(engine)
        self._recorders: list[set[str]] = []
        self._cache: dict = {}


class ForwardTracedView(TracedView, ForwardOperationalView):
    """Stage 1's TracedView (records every fact it hands out) over the guard-free view."""


class ForwardBitemporalStore(BitemporalStore):
    """``policy_gate.BitemporalStore`` whose engines are the forward resolvers."""

    ENGINE_CLASSES = {"graph": ForwardGraphStore, "sqlite": ForwardSqliteStore}

    def __init__(self, facts, *, engines: tuple[str, ...] = ("graph",)):
        super().__init__(facts, engines=())
        for engine in engines:
            if engine not in self.ENGINE_CLASSES:
                raise ValueError(f"unknown engine {engine!r}")
            self._engines[engine] = self.ENGINE_CLASSES[engine](self.facts)


class ForwardPilotStore(PilotStore, ForwardBitemporalStore):
    """Stage 1's PilotStore with forward engines: method resolution order ForwardPilotStore, PilotStore,
    ForwardBitemporalStore, BitemporalStore, so PilotStore.__init__'s ``super().__init__(facts, engines=("graph",
    "sqlite"))`` builds the forward engines and its dual engine wraps them."""


def build_forward_store(facts_and_support, identities, *, label: str) -> ForwardPilotStore:
    """``govpilot.mapping.build_store`` with the forward store class."""
    facts, support = facts_and_support
    return ForwardPilotStore(tuple(facts) + tuple(identities), support, label=label)


def forward_view(store, observation_us: int, cutoff_us: int, *, carry_forward_seconds: float,
                 engine: str = "dual") -> ForwardTracedView:
    from .common import dt
    return ForwardTracedView(store, dt(observation_us), dt(cutoff_us), carry_forward_seconds=carry_forward_seconds,
                             engine=engine)
