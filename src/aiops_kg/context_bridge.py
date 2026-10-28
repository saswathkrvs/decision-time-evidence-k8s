"""Context-to-ranking bridge v1: how a context policy's as-known picture changes a ranker's input.

Research prototype; no accuracy, safety or RCA claim. The bridge makes the path explicit. Context changes WHICH
ENTITY a request is attributed to, therefore WHICH SAMPLES feed each entity's aggregate, WHICH ENTITIES are
candidates at all and WHICH ENTITY EDGES exist; the unchanged ranker then scores those aggregates. The telemetry
itself (request times, durations, error flags) is never changed.

Two clocks. Every context record has a valid time (``observed_at``: when the API poller saw the value) and an
availability time (``available_at``: when the pipeline could use it). Every request has a valid time t (its root
span start). The diagnosis is made once, at the decision time ``c = onset + Delta``; every policy receives exactly
the record versions usable at c (``replay.Stream.visible``: ``available_at <= c`` and not withdrawn by a correction
available by c).

The mechanism for one capture (one incident), fixed in ``PROTOCOL``:

1. **Observed requests.** A request is observed at c iff its root span has ENDED by c (its duration exists only
   then). This is an optimistic telemetry assumption: trace export and evidence-index ingestion are different
   availability boundaries and are not modelled. Only requests whose valid time t falls in the analysis window
   count: normal window [onset - W_before, onset), anomalous window [onset, onset + W_after).
2. **Entity attribution.** For every observed window request and every application service with a feature in that
   request, the serving Pod of that service at t is decided by ``replay.attribute_instance`` with the service's
   candidates, at cutoff c, under policy P (latest_state, temporal_join or bitemporal_abstain(F)). This is the
   replay-policy-v1 decision unchanged. An abstention leaves the request unattributed for that service: it is
   dropped from every entity's aggregate and counted.
3. **Candidate membership.** The candidates under P at c are the Pods that receive at least one attributed window
   request (the Pods the as-known context believes served the workload in the window). ``in_view`` (at least one
   usable record at c) is reported separately. Under hindsight (the span-verified serving Pods, evaluator only)
   the candidates are the true set.
4. **Feature aggregation.** Per candidate, per window, the per-request features of its service are collected into
   ``graph_rank``-compatible indicator records (node = entity key, feature name, normal sample, anomalous
   sample). Features: the frontend-observed request duration and error flag (root CLIENT span) go to the
   first-hop service; each downstream service gets its own SERVER span duration and error flag.
5. **Ranking.** Anomaly scores are ``graph_rank.node_anomaly_scores`` (robust one-sided n-sigma, p90 primary,
   unchanged); the primary order is ``graph_rank.anomaly_only_rank``. Secondary: ``graph_rank.graph_rank``
   (personalized PageRank) over the as-attributed caller -> callee entity edges. graph_rank is imported unchanged.
6. **Scoring (evaluator only).** The truth entity (the Pod that carried the fault) comes from
   ``ground_truth/ground_truth.json`` and is used only here: rank of the truth entity (pessimistic under ties),
   Top-1, "absent" when it is not a candidate, mis-attributed and abstained request counts, coverage.

**Unsighted Pods.** A Pod that the spans show serving a request of a service (its ``k8s.pod.uid``) but that is not
one of that service's candidates (the API poller never sighted it as a Pod of the service) is *unsighted*. No policy,
and not the hindsight reference either (it names only sighted candidates), can attribute a request to it: those
requests are counted per cell and service as ``unattributable_unsighted``, and the Pod is reported in the entity
table with label ``unsighted`` (a Pod that is a candidate of another service keeps that row) but never enters
attribution, candidates, indicators or edges for them. An unsighted truth entity is ``absent`` with reason
``unsighted`` in every cell.

Conventions follow ``replay.py``: integer microseconds since the epoch (UTC), no wall clock, no randomness, inputs
never mutated, deterministic iteration order.

**Exploratory v1.1 variants** (opt-in keyword arguments of ``evaluate_cell``, off by default, and then every output
is exactly v1's).
"""
from __future__ import annotations

import hashlib
import json
import re
import statistics
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from . import graph_rank as gr
from . import replay as R

NORMAL, ANOMALOUS = "normal", "anomalous"
WINDOWS = (NORMAL, ANOMALOUS)
HINDSIGHT = "hindsight"
ERROR_CODES = frozenset({2, "2", "STATUS_CODE_ERROR"})
SPAN_SERVER = 2
FRONTEND_FEATURES = ("frontend_request_duration_ms", "frontend_request_error")
DOWNSTREAM_FEATURES = ("downstream_server_duration_ms", "downstream_server_error")
DURATION_FEATURES = ("frontend_request_duration_ms", "downstream_server_duration_ms")
RETIRED = frozenset({"terminating", "failed", "succeeded", "absent"})

# The bridge's fixed parameters.
PROTOCOL = {
    "version": "context-bridge-v1",
    "deltas_seconds": (0, 5, 30, 60),
    "window_before_seconds": 20,
    "window_after_seconds": 20,
    "policies": (("latest_state", None), ("temporal_join", None), ("bitemporal_abstain", 600.0),
                 ("bitemporal_abstain", 30.0)),
    "streams": ("complete", "delayed_api_1s", "delayed_api_3s", "delayed_api_10s", "delayed_api_30s",
                "missing_switch_poll", "corrected_late_3s", "corrected_late_10s"),
    "statistic": gr.PRIMARY_STATISTIC,
    "sensitivity_statistic": "max",
    "request_observed_rule": "root span end <= c",
    "window_rule": "normal [onset - W_before, onset), anomalous [onset, onset + W_after), by request valid time t",
    "candidate_rule": "Pods receiving >= 1 attributed request of the observed analysis window",
    "truth_rank_rule": "pessimistic: 1 + #other candidates with score >= the truth's (12 decimals); Top-1 = rank 1 "
                       "and score > 0; truth not a candidate = absent (no rank)",
}

# Exploratory v1.1 variants, not used by the reported analyses: never part of PROTOCOL above; used only when
# evaluate_cell is called with the options on.
V1_1 = {
    "version": "context-bridge-v1.1-exploratory",
    "k_min": 3,
    "baseline_fallback": "service: a candidate with fewer than k_min own normal-window requests takes, per feature, "
                         "the normal-window values of every observed request of its own service (attributed to "
                         "any Pod or abstained) as its normal sample; its anomalous sample stays its own",
    "deferred_bucket": "the unattributed (request, service) pairs of a service form the candidate "
                       "'<service>/unresolved'; never a real Pod's aggregate, never an attribution",
    "deferred_outcome": "deferred_correct_service: the Top-1 decision is the truth service's bucket (not Top-1, "
                        "not a wrong decision); another service's bucket as Top-1 is a wrong decision",
}
K_MIN = V1_1["k_min"]
UNRESOLVED = "unresolved"
DEFERRED_CORRECT_SERVICE = "deferred_correct_service"


def bucket_key(service: str) -> str:
    """The M2 pseudo-entity of a service's unattributed requests (never a Pod key, which starts with 'Pod/')."""
    return f"{service}/{UNRESOLVED}"


def is_bucket(entity) -> bool:
    return isinstance(entity, str) and not entity.startswith("Pod/") and entity.endswith("/" + UNRESOLVED)


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ServiceContext:
    """One application service: its candidate Pods (from context records only) and the attribution constants."""
    service: str
    candidates: tuple[R.Candidate, ...]
    predicate: str = "STATE"
    serving_value: str = "ready"
    retired_values: frozenset = RETIRED

    def __post_init__(self) -> None:
        keys = [c.key for c in self.candidates]
        labels = [c.label for c in self.candidates]
        if len(set(keys)) != len(keys) or len(set(labels)) != len(labels):
            raise ValueError(f"{self.service}: candidate keys and labels must be unique")

    def key_of(self, label: str | None) -> str | None:
        if label is None:
            return None
        for cand in self.candidates:
            if cand.label == label:
                return cand.key
        raise ValueError(f"{self.service}: unknown candidate label {label!r}")

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(c.key for c in self.candidates)


@dataclass(frozen=True)
class RequestTelemetry:
    """One workload request: model input only (no Pod identity).

    ``t`` = valid time (root span start, us); ``end`` = root span end (us); ``features`` = service -> feature ->
    value; ``calls`` = (caller service, callee service) pairs derived from span parentage."""
    request_id: str
    t: int
    end: int
    features: Mapping[str, Mapping[str, float]]
    calls: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        R._text(self.request_id, "request_id")
        R._int(self.t, "t")
        R._int(self.end, "end")
        if self.end < self.t:
            raise ValueError(f"{self.request_id}: a request cannot end before it starts")


@dataclass(frozen=True)
class Windows:
    onset: int
    before_us: int
    after_us: int

    def __post_init__(self) -> None:
        R._int(self.onset, "onset")
        if R._int(self.before_us, "before_us") < 0 or R._int(self.after_us, "after_us") <= 0:
            raise ValueError("window lengths must be nonnegative (before) and positive (after)")

    def of(self, t: int) -> str | None:
        if self.onset - self.before_us <= t < self.onset:
            return NORMAL
        if self.onset <= t < self.onset + self.after_us:
            return ANOMALOUS
        return None

    @classmethod
    def seconds(cls, onset: int, before: float, after: float) -> "Windows":
        return cls(onset, R.seconds_to_us(before, name="W_before"), R.seconds_to_us(after, name="W_after"))


@dataclass(frozen=True)
class Attribution:
    """One (request, service) decision. ``entity`` is a candidate key, or None (abstained / unknown)."""
    request_id: str
    service: str
    window: str
    entity: str | None
    status: str
    reason: str
    record_ids: tuple[str, ...] = ()


def decision_cutoff(onset: int, delta_seconds: float) -> int:
    return onset + R.seconds_to_us(delta_seconds, name="Delta")


def observed_window_requests(requests: Iterable[RequestTelemetry], c: int, windows: Windows):
    """(request, window) for the requests whose valid time is in a window and whose root span ended by c,
    in (t, request_id) order; plus the per-window count of window requests not yet ended at c."""
    seen, pending = [], {NORMAL: 0, ANOMALOUS: 0}
    for req in sorted(requests, key=lambda r: (r.t, r.request_id)):
        w = windows.of(req.t)
        if w is None:
            continue
        if req.end <= c:
            seen.append((req, w))
        else:
            pending[w] += 1
    return seen, pending


# ---------------------------------------------------------------------------
# Steps 1-2: attribution (policy) and the hindsight reference (evaluator only)
# ---------------------------------------------------------------------------
def attribute_one(stream, service: ServiceContext, t: int, c: int, policy: R.Policy) -> R.Decision:
    """The replay-policy-v1 decision: ``replay.attribute_instance`` with the service's constants."""
    return R.attribute_instance(stream, service.candidates, t, c, policy, predicate=service.predicate,
                                serving_value=service.serving_value, retired_values=service.retired_values)


def attribute_requests(stream, services: Sequence[ServiceContext], requests: Iterable[RequestTelemetry], c: int,
                       windows: Windows, policy: R.Policy) -> tuple[list[Attribution], dict]:
    """Attribute every observed window request, per service that has a feature in it, at cutoff c under policy.

    Only record versions usable at c are consulted (``attribute_instance`` reads ``Stream.visible(..., c)``).
    Returns (attributions in (t, request_id, service) order, per-window count of requests not yet observed)."""
    stream = R.as_stream(stream)
    seen, pending = observed_window_requests(requests, c, windows)
    out = []
    for req, w in seen:
        for svc in services:
            if svc.service not in req.features:
                continue
            d = attribute_one(stream, svc, req.t, c, policy)
            out.append(Attribution(req.request_id, svc.service, w, svc.key_of(d.answer), d.status, d.reason,
                                   d.record_ids))
    return out, pending


def hindsight_attributions(services: Sequence[ServiceContext], requests: Iterable[RequestTelemetry], c: int,
                           windows: Windows, served_by: Mapping[str, Mapping[str, str | None]]
                           ) -> tuple[list[Attribution], dict]:
    """The labelled reference: each observed window request attributed to its span-verified serving Pod.

    EVALUATOR ONLY (the span Pod claims are never a policy input). Same observed requests as the policies at c.
    A serving Pod that is not a candidate of the service (unsighted) cannot be named from the API records either:
    the request stays unattributed for that service, reason ``unsighted``."""
    seen, pending = observed_window_requests(requests, c, windows)
    out = []
    for req, w in seen:
        truth = served_by.get(req.request_id, {})
        for svc in services:
            if svc.service not in req.features:
                continue
            key, reason = truth.get(svc.service), "span_verified"
            if key is None:
                reason = "truth_unknown"
            elif key not in svc.keys:
                key, reason = None, "unsighted"
            out.append(Attribution(req.request_id, svc.service, w, key, "TRUTH", reason))
    return out, pending


def unsighted_entities(services: Sequence[ServiceContext], requests: Iterable[RequestTelemetry],
                       served_by: Mapping[str, Mapping[str, str | None]], windows: Windows | None = None
                       ) -> list[dict]:
    """EVALUATOR ONLY (reporting): the span-verified serving Pods that are not a candidate of the service they
    served (never sighted by the API poller as a Pod of that service). Never a model input.

    One entry per (service, Pod) in (service, Pod) order: the number of workload requests it served and, when
    ``windows`` is given, how many of them lie in each analysis window (by valid time t). A service without any
    sighted Pod is not analysed (its features are not used) and is not listed."""
    keys_of = {svc.service: frozenset(svc.keys) for svc in services}
    found: dict[tuple[str, str], dict] = {}
    for req in sorted(requests, key=lambda r: (r.t, r.request_id)):
        for service, key in sorted(served_by.get(req.request_id, {}).items()):
            if key is None or service not in keys_of or key in keys_of[service]:
                continue
            entry = found.setdefault((service, key), {"entity": key, "service": service, "requests": 0})
            entry["requests"] += 1
            if windows is not None:
                slot = entry.setdefault("window_requests", {NORMAL: 0, ANOMALOUS: 0})
                w = windows.of(req.t)
                if w is not None:
                    slot[w] += 1
    return [found[k] for k in sorted(found)]


def in_view(stream, services: Sequence[ServiceContext], c: int) -> dict[str, bool]:
    """Candidate key -> has at least one usable record at c."""
    stream = R.as_stream(stream)
    return {cand.key: bool(stream.visible(cand.key, svc.predicate, c)) for svc in services for cand in svc.candidates}


# ---------------------------------------------------------------------------
# Steps 3-4: candidates and aggregates
# ---------------------------------------------------------------------------
def candidate_set(attributions: Iterable[Attribution]) -> list[str]:
    return sorted({a.entity for a in attributions if a.entity is not None})


def service_features(requests: Iterable[RequestTelemetry]) -> dict[str, tuple[str, ...]]:
    """Service -> the feature names it carries anywhere in the capture (fixed per capture, not per policy)."""
    out: dict[str, set] = {}
    for req in requests:
        for svc, feats in req.features.items():
            out.setdefault(svc, set()).update(feats)
    return {svc: tuple(sorted(names)) for svc, names in sorted(out.items())}


def aggregate(requests_by_id: Mapping[str, RequestTelemetry], attributions: Iterable[Attribution]
              ) -> dict[str, dict[str, dict[str, list[float]]]]:
    """entity -> window -> feature -> values, in attribution (t) order. Abstentions feed nothing."""
    out: dict[str, dict[str, dict[str, list[float]]]] = {}
    for a in attributions:
        if a.entity is None:
            continue
        feats = requests_by_id[a.request_id].features[a.service]
        slot = out.setdefault(a.entity, {NORMAL: {}, ANOMALOUS: {}})[a.window]
        for name, value in sorted(feats.items()):
            slot.setdefault(name, []).append(float(value))
    return out


def indicator_records(aggregates: Mapping[str, Mapping[str, Mapping[str, list[float]]]],
                      entity_service: Mapping[str, str], features: Mapping[str, Sequence[str]],
                      candidates: Iterable[str]) -> list[dict]:
    """graph_rank indicator records (the ``indicators_from_windows`` shape) for every candidate x feature of its
    service. Empty windows are kept: graph_rank excludes them (reason empty_window) and records that."""
    out = []
    for entity in sorted(candidates):
        service = entity_service[entity]
        slots = aggregates.get(entity, {NORMAL: {}, ANOMALOUS: {}})
        for name in features.get(service, ()):
            out.append({"indicator": f"{name}@{entity}", "node": entity, "source": "context_bridge",
                        "feature": name, "normal": list(slots[NORMAL].get(name, [])),
                        "anomalous": list(slots[ANOMALOUS].get(name, []))})
    return out


def entity_edges(requests_by_id: Mapping[str, RequestTelemetry], attributions: Iterable[Attribution]
                 ) -> list[tuple[str, str]]:
    """As-attributed caller -> callee entity edges: for each request's (caller service, callee service) span pair,
    the edge (entity of the caller, entity of the callee) when both are attributed (graph_rank walk-edge direction)."""
    per_request: dict[str, dict[str, str]] = {}
    for a in attributions:
        if a.entity is not None:
            per_request.setdefault(a.request_id, {})[a.service] = a.entity
    edges = set()
    for rid, entities in per_request.items():
        for caller, callee in requests_by_id[rid].calls:
            if caller in entities and callee in entities and entities[caller] != entities[callee]:
                edges.add((entities[caller], entities[callee]))
    return sorted(edges)


def service_normal_samples(requests_by_id: Mapping[str, RequestTelemetry], attributions: Iterable[Attribution]
                           ) -> tuple[dict[str, dict[str, list[float]]], dict[str, int]]:
    """M1's service-level normal-window sample: service -> feature -> the values of that service's own features in
    every observed normal-window (request, service) attribution, whatever its entity (a Pod of the service, or none),
    in attribution (t) order; plus service -> number of those requests. A request contributes only the features of
    the service the attribution is for, so services that share a feature name are never pooled."""
    samples: dict[str, dict[str, list[float]]] = {}
    counts: dict[str, int] = {}
    for a in attributions:
        if a.window != NORMAL:
            continue
        counts[a.service] = counts.get(a.service, 0) + 1
        slot = samples.setdefault(a.service, {})
        for name, value in sorted(requests_by_id[a.request_id].features[a.service].items()):
            slot.setdefault(name, []).append(float(value))
    return samples, counts


def variant_inputs(requests_by_id: Mapping[str, RequestTelemetry], attributions: Sequence[Attribution],
                   services: Sequence[ServiceContext], features: Mapping[str, Sequence[str]], *,
                   baseline_fallback: str | None = None, k_min: int = K_MIN, deferred_bucket: bool = False) -> dict:
    """The ranker's input under the exploratory v1.1 variants.

    The attributions are the policy's, unchanged. M2 (``deferred_bucket``): every unattributed (request, service)
    pair feeds the candidate ``bucket_key(service)`` instead of nothing; the real Pods' samples are untouched. M1
    (``baseline_fallback="service"``): every candidate (a bucket too) with fewer than ``k_min`` own normal-window
    requests takes ``service_normal_samples`` of its own service as the normal sample of each feature; its anomalous
    sample stays its own. Returns the ranked attributions (buckets filled in), the candidates (Pods, then buckets, in
    key order), the effective per-window samples, the graph_rank indicator records, the entity edges, the entity ->
    service map (buckets included) and, per candidate, ``baseline_source`` (own / service), ``baseline_n`` (requests
    in the normal sample used) and ``own_normal_n``."""
    if baseline_fallback not in (None, "service"):
        raise ValueError(f"baseline_fallback must be None or 'service', not {baseline_fallback!r}")
    if isinstance(k_min, bool) or not isinstance(k_min, int) or k_min < 1:
        raise ValueError("k_min must be a positive integer")
    entity_service = {cand.key: svc.service for svc in services for cand in svc.candidates}
    ranked = list(attributions)
    if deferred_bucket:
        ranked = [a if a.entity is not None else replace(a, entity=bucket_key(a.service)) for a in attributions]
        entity_service.update({bucket_key(svc.service): svc.service for svc in services})
    candidates = candidate_set(ranked)
    own = aggregate(requests_by_id, ranked)
    service_samples, service_counts = service_normal_samples(requests_by_id, attributions)
    effective, baseline = {}, {}
    for entity in candidates:
        slots = own.get(entity, {NORMAL: {}, ANOMALOUS: {}})
        own_n = sum(1 for a in ranked if a.entity == entity and a.window == NORMAL)
        service = entity_service[entity]
        if baseline_fallback == "service" and own_n < k_min:
            normal = {name: list(values) for name, values in service_samples.get(service, {}).items()}
            source, n = "service", service_counts.get(service, 0)
        else:
            normal, source, n = slots[NORMAL], "own", own_n
        effective[entity] = {NORMAL: normal, ANOMALOUS: slots[ANOMALOUS]}
        baseline[entity] = {"baseline_source": source, "baseline_n": n, "own_normal_n": own_n}
    return {"attributions": ranked, "candidates": candidates, "aggregates": effective,
            "indicators": indicator_records(effective, entity_service, features, candidates),
            "edges": entity_edges(requests_by_id, ranked), "entity_service": entity_service, "baseline": baseline}


# ---------------------------------------------------------------------------
# Steps 5-6: ranking (graph_rank, unchanged) and scoring against the evaluator-only truth
# ---------------------------------------------------------------------------
def rank_entities(indicators: Sequence[dict], candidates: Sequence[str], edges: Sequence[tuple[str, str]] = (),
                  statistic: str = PROTOCOL["statistic"], with_graph: bool = True) -> dict:
    """graph_rank's node anomaly scores, anomaly-only order (primary) and personalized PageRank (secondary)."""
    anomaly = gr.node_anomaly_scores(indicators, nodes=candidates, statistic=statistic)
    stray = sorted(set(anomaly) - set(candidates))
    if stray:
        raise ValueError(f"indicator nodes outside the candidates: {stray}")
    only = gr.anomaly_only_rank(anomaly)
    out = {"statistic": statistic, "anomaly": anomaly,
           "anomaly_only": [(row["node"], row["anomaly"]) for row in only["node_ranking"]]}
    if with_graph:
        g = gr.graph_rank(anomaly, edges)
        out["ppr"] = [(row["node"], row["ppr"], row["anomaly"]) for row in g["node_ranking"]]
        out["graph"] = g["graph"]
    return out


def truth_rank(scores: Mapping[str, float], truth: str | None, *, secondary: Mapping[str, float] | None = None,
               evidence: Mapping[str, float] | None = None, unsighted: bool = False) -> dict:
    """Rank of the truth entity among the candidates, pessimistic under ties (12 decimals, graph_rank's rounding).

    ``secondary`` breaks ties on the primary score (used for PPR: PPR, then anomaly, as graph_rank.rank_nodes).
    Top-1 = the truth is strictly first and its anomaly evidence (``evidence``, default ``scores``) is positive.
    Not a candidate -> absent (rank None), reason ``unsighted`` when the truth Pod is no candidate of any service
    (``unsighted=True``: no policy and not the hindsight reference can name it), else ``not_a_candidate``."""
    if truth is None:
        return {"entity": None, "present": None, "rank_pessimistic": None, "rank_optimistic": None, "top1": None,
                "candidates": len(scores), "outcome": "no_truth_entity"}
    if truth not in scores:
        return {"entity": truth, "present": False, "rank_pessimistic": None, "rank_optimistic": None, "top1": False,
                "candidates": len(scores), "outcome": "absent",
                "reason": "unsighted" if unsighted else "not_a_candidate"}
    if unsighted:
        raise ValueError(f"{truth}: an unsighted entity cannot be a candidate")
    rnd = lambda v: round(float(v), gr.RANK_DECIMALS)
    key = lambda e: (rnd(scores[e]), rnd(secondary[e]) if secondary is not None else 0.0)
    mine = key(truth)
    higher = sum(1 for e in scores if e != truth and key(e) > mine)
    ties = sum(1 for e in scores if e != truth and key(e) == mine)
    pessimistic, optimistic = 1 + higher + ties, 1 + higher
    positive = rnd((evidence if evidence is not None else scores)[truth]) > 0
    top1 = pessimistic == 1 and positive
    return {"entity": truth, "present": True, "rank_pessimistic": pessimistic, "rank_optimistic": optimistic,
            "top1": top1, "candidates": len(scores), "outcome": "top1" if top1 else "not_top1"}


def top1_decision(order: Sequence[tuple]) -> str | None:
    """The entity the ranking would name: first place with a positive score, strictly above the second (else None)."""
    if not order:
        return None
    first = order[0]
    if round(float(first[-1] if len(first) == 2 else first[2]), gr.RANK_DECIMALS) <= 0:
        return None
    if len(order) > 1:
        a = tuple(round(float(x), gr.RANK_DECIMALS) for x in first[1:])
        b = tuple(round(float(x), gr.RANK_DECIMALS) for x in order[1][1:])
        if a == b:
            return None
    return first[0]


# ---------------------------------------------------------------------------
# One cell: policy (or hindsight) x stream x Delta
# ---------------------------------------------------------------------------
def _median(values: Sequence[float]):
    return round(statistics.median(values), 6) if values else None


def _window_summary(entity: str, window: str, attributions: Sequence[Attribution],
                    requests_by_id: Mapping[str, RequestTelemetry], truth_of) -> dict:
    fed = [a for a in attributions if a.entity == entity and a.window == window]
    truly = [a for a in attributions if a.window == window and truth_of(a) == entity]
    feats: dict[str, list[float]] = {}
    for a in fed:
        for name, value in sorted(requests_by_id[a.request_id].features[a.service].items()):
            feats.setdefault(name, []).append(float(value))
    return {"n": len(fed),
            "mis_attributed": sum(1 for a in fed if truth_of(a) is not None and truth_of(a) != entity),
            "truth_unknown": sum(1 for a in fed if truth_of(a) is None),
            "lost_to_other": sum(1 for a in truly if a.entity is not None and a.entity != entity),
            "lost_to_abstain": sum(1 for a in truly if a.entity is None),
            "request_ids": [a.request_id for a in fed],
            "median": {name: _median(vals) for name, vals in sorted(feats.items())}}


def _bucket_summary(bucket: str, window: str, ranked: Sequence[Attribution],
                    requests_by_id: Mapping[str, RequestTelemetry], truth_of) -> dict:
    """M2 bucket row per window: the deferred requests it holds (never counted as mis-attributed: the bucket names no
    Pod) and, evaluator only, which span-verified Pods served them."""
    fed = [a for a in ranked if a.entity == bucket and a.window == window]
    feats: dict[str, list[float]] = {}
    served: dict[str, int] = {}
    for a in fed:
        for name, value in sorted(requests_by_id[a.request_id].features[a.service].items()):
            feats.setdefault(name, []).append(float(value))
        key = truth_of(a) or "truth_unknown"
        served[key] = served.get(key, 0) + 1
    return {"n": len(fed), "mis_attributed": 0, "truth_unknown": sum(1 for a in fed if truth_of(a) is None),
            "lost_to_other": 0, "lost_to_abstain": 0, "request_ids": [a.request_id for a in fed],
            "median": {name: _median(vals) for name, vals in sorted(feats.items())},
            "served_by_truth": dict(sorted(served.items()))}


def _anomaly_summary(anom) -> dict | None:
    return None if anom is None else {
        "score": round(anom["score"], 6), "usable_indicators": anom["usable_count"],
        "indicators": anom["indicator_count"],
        "excluded": [x.split("@", 1)[0] for x in anom["excluded_constant"]],
        "excluded_constant_changed": [x.split("@", 1)[0] for x in anom["excluded_constant_changed"]],
        "top_indicator": None if not anom["evidence"] else {
            "feature": anom["evidence"][0]["indicator"].split("@", 1)[0],
            "statistic_value": round(anom["evidence"][0]["statistic_value"], 6),
            "normal_median": round(anom["evidence"][0]["normal_median"], 6),
            "normal_scale": round(anom["evidence"][0]["normal_scale"], 6),
            "anomalous_median": round(anom["evidence"][0]["anomalous_median"], 6)}}


def _defer(row: dict, top1_entity: str | None, own_bucket: str | None) -> None:
    """M2 scoring: a ranking whose Top-1 decision is the truth service's bucket is ``deferred_correct_service``."""
    if own_bucket is not None and top1_entity == own_bucket and row.get("outcome") in ("not_top1", "absent"):
        row["outcome"] = DEFERRED_CORRECT_SERVICE


def _code(label: str | None) -> str:
    if label is None:
        return "?"
    if label in ("old", "new"):
        return label[0].upper()
    return label[1:] if label[:1] == "p" and label[1:].isdigit() and len(label) == 2 else "*"


def evaluate_cell(stream, services: Sequence[ServiceContext], requests: Sequence[RequestTelemetry], c: int,
                  windows: Windows, policy: R.Policy | None, served_by: Mapping[str, Mapping[str, str | None]],
                  truth_entity: str | None = None, *, statistic: str = PROTOCOL["statistic"],
                  sensitivity_statistic: str | None = PROTOCOL["sensitivity_statistic"],
                  baseline_fallback: str | None = None, k_min: int = K_MIN, deferred_bucket: bool = False) -> dict:
    """Steps 1-6 for one policy (``policy=None``: the hindsight reference) at decision time c.

    ``served_by`` and ``truth_entity`` are evaluator-only: they are used for the hindsight row and for scoring,
    never to attribute a request under a policy. A (request, service) whose span-verified Pod is not a candidate
    of the service is unsighted: counted per service as ``unattributable_unsighted`` (still mis-attributed when a
    policy feeds it to a sighted Pod), its Pod shown in ``entities`` with label ``unsighted`` (unless it is a
    candidate of another service, which keeps that row), and never added to the attributions, candidates,
    indicators or edges.

    Exploratory v1.1 options, off by default; with both off the output is
    exactly v1's. ``baseline_fallback="service"`` (M1, with ``k_min``) and ``deferred_bucket=True`` (M2) change only
    the ranker's input samples (``variant_inputs``), never an attribution, the Pod candidate set or a v1 count. They
    add ``baseline_source`` / ``baseline_n`` / ``own_normal_n`` to the entity rows, the bucket rows (label
    ``unresolved``), per-service ``deferred`` / ``evidence_coverage``, ``candidates.deferred_buckets``, the truth
    fields ``rank_among_pods`` / ``deferred_bucket``, the outcome ``deferred_correct_service`` (M2) and a ``variant``
    block. With M2 a Top-1 decision equal to the truth service's bucket is not a wrong decision; another service's
    bucket is."""
    variant = baseline_fallback is not None or bool(deferred_bucket)
    stream = R.as_stream(stream)
    by_id = {r.request_id: r for r in requests}
    if len(by_id) != len(requests):
        raise ValueError("duplicate request_id")
    if policy is None:
        attrs, pending = hindsight_attributions(services, requests, c, windows, served_by)
    else:
        attrs, pending = attribute_requests(stream, services, requests, c, windows, policy)
    seen, _ = observed_window_requests(requests, c, windows)
    observed = {w: sum(1 for _, ww in seen if ww == w) for w in WINDOWS}
    truth_map = {(rid, svc): key for rid, per in served_by.items() for svc, key in per.items()}
    truth_of = lambda a: truth_map.get((a.request_id, a.service))
    entity_service = {cand.key: svc.service for svc in services for cand in svc.candidates}
    label_of = {cand.key: cand.label for svc in services for cand in svc.candidates}
    keys_of = {svc.service: frozenset(svc.keys) for svc in services}
    # Unsighted: the span-verified Pod is not a candidate of the request's service. Reported, never a model input.
    unsighted = lambda a: truth_of(a) is not None and truth_of(a) not in keys_of[a.service]
    truth_unsighted = truth_entity is not None and truth_entity not in entity_service
    view = in_view(stream, services, c)
    candidates = candidate_set(attrs)
    feats = service_features(requests)
    aggs = aggregate(by_id, attrs)
    if variant:
        # v1.1: the same attributions; only the ranker's samples change (buckets; service baselines).
        vin = variant_inputs(by_id, attrs, services, feats, baseline_fallback=baseline_fallback, k_min=k_min,
                             deferred_bucket=deferred_bucket)
        ranked_candidates, indicators, edges, effective = (vin["candidates"], vin["indicators"], vin["edges"],
                                                           vin["aggregates"])
    else:
        vin, ranked_candidates, effective = None, candidates, aggs
        indicators = indicator_records(aggs, entity_service, feats, candidates)
        edges = entity_edges(by_id, attrs)
    ranked = rank_entities(indicators, ranked_candidates, edges, statistic)
    scores = {e: float(ranked["anomaly"][e]["score"]) for e in ranked_candidates}
    ppr = {e: float(p) for e, p, _ in ranked["ppr"]}
    sens = None
    if sensitivity_statistic:
        s_anom = gr.node_anomaly_scores(indicators, nodes=ranked_candidates, statistic=sensitivity_statistic)
        s_scores = {e: float(s_anom[e]["score"]) for e in ranked_candidates}
        sens = {"statistic": sensitivity_statistic,
                "anomaly_only": [(row["node"], round(row["anomaly"], 6))
                                 for row in gr.anomaly_only_rank(s_anom)["node_ranking"]],
                "truth": truth_rank(s_scores, truth_entity, unsighted=truth_unsighted)}

    service_rows = {}
    for svc in services:
        mine = [a for a in attrs if a.service == svc.service]
        known = [a for a in mine if truth_of(a) is not None]
        answered = [a for a in mine if a.entity is not None]
        reasons: dict[str, int] = {}
        for a in mine:
            if a.entity is None:
                reasons[a.reason] = reasons.get(a.reason, 0) + 1
        service_rows[svc.service] = {
            "requests": len(mine), "attributed": len(answered),
            "correct": sum(1 for a in known if a.entity == truth_of(a)),
            "mis_attributed": sum(1 for a in known if a.entity is not None and a.entity != truth_of(a)),
            "abstained": len(mine) - len(answered),
            "truth_unknown": len(mine) - len(known),
            "unattributable_unsighted": sum(1 for a in mine if unsighted(a)),
            "coverage": round(len(answered) / len(mine), 4) if mine else None,
            "confirmed": sum(1 for a in mine if a.status == R.CONFIRMED),
            "fallback": sum(1 for a in mine if a.status == R.FALLBACK),
            "mis_attributed_confirmed": sum(1 for a in known if a.entity is not None and a.entity != truth_of(a)
                                            and a.status == R.CONFIRMED),
            "mis_attributed_fallback": sum(1 for a in known if a.entity is not None and a.entity != truth_of(a)
                                           and a.status == R.FALLBACK),
            "abstain_reasons": dict(sorted(reasons.items())),
            "answers": "".join(_code(label_of.get(a.entity)) for a in mine),
            "statuses": "".join(a.status[0] for a in mine),
            "request_ids": [a.request_id for a in mine],
            "wrong_request_ids": [a.request_id for a in known if a.entity is not None and a.entity != truth_of(a)],
            "abstained_request_ids": [a.request_id for a in mine if a.entity is None],
        }
        if deferred_bucket:   # v1.1 M2: the abstentions feed the service's bucket (still not attributions)
            row = service_rows[svc.service]
            row["deferred"] = row["abstained"]
            row["evidence_coverage"] = (round((row["attributed"] + row["deferred"]) / len(mine), 4) if mine
                                        else None)

    hindsight_set = sorted({truth_of(a) for a in attrs if truth_of(a) is not None and not unsighted(a)})
    shown = sorted(set(candidates) | set(hindsight_set) | {k for k, v in view.items() if v})
    entities = {}
    for e in shown:
        anom = ranked["anomaly"].get(e)
        entities[e] = {
            "service": entity_service[e], "label": label_of[e], "in_view": view[e], "candidate": e in candidates,
            "hindsight_candidate": e in hindsight_set,
            NORMAL: _window_summary(e, NORMAL, attrs, by_id, truth_of),
            ANOMALOUS: _window_summary(e, ANOMALOUS, attrs, by_id, truth_of),
            "anomaly": _anomaly_summary(anom),
            "unscorable_reason": None if anom is None or anom["usable_count"] else _unscorable(e, effective, feats,
                                                                                               entity_service),
        }
        if variant:
            entities[e].update(vin["baseline"].get(e) or {"baseline_source": None, "baseline_n": None,
                                                          "own_normal_n": None})
    # Unsighted Pods (no candidate of any service): reporting rows only; n is always 0 (nothing can feed them) and
    # lost_to_other / lost_to_abstain show where the requests they served went.
    unsighted_rows: dict[str, str] = {}
    for a in attrs:
        if unsighted(a) and truth_of(a) not in entity_service:
            unsighted_rows.setdefault(truth_of(a), a.service)
    for e, service in sorted(unsighted_rows.items()):
        entities[e] = {"service": service, "label": "unsighted", "in_view": False, "candidate": False,
                       "hindsight_candidate": False,
                       NORMAL: _window_summary(e, NORMAL, attrs, by_id, truth_of),
                       ANOMALOUS: _window_summary(e, ANOMALOUS, attrs, by_id, truth_of),
                       "anomaly": None, "unscorable_reason": None}
        if variant:
            entities[e].update({"baseline_source": None, "baseline_n": None, "own_normal_n": None})
    buckets = [e for e in ranked_candidates if e not in entity_service] if variant else []
    for b in buckets:   # v1.1 M2: one row per bucket that holds at least one deferred window request
        anom = ranked["anomaly"].get(b)
        entities[b] = {"service": vin["entity_service"][b], "label": UNRESOLVED, "in_view": None, "candidate": True,
                       "hindsight_candidate": False, "deferred": True,
                       NORMAL: _bucket_summary(b, NORMAL, vin["attributions"], by_id, truth_of),
                       ANOMALOUS: _bucket_summary(b, ANOMALOUS, vin["attributions"], by_id, truth_of),
                       "anomaly": _anomaly_summary(anom),
                       "unscorable_reason": None if anom is None or anom["usable_count"] else _unscorable(
                           b, effective, feats, vin["entity_service"]),
                       **vin["baseline"][b]}
    truth = truth_rank(scores, truth_entity, unsighted=truth_unsighted)
    truth["ppr"] = truth_rank(ppr, truth_entity, secondary=scores, evidence=scores, unsighted=truth_unsighted)
    top1 = top1_decision(ranked["anomaly_only"])
    wrong = None if truth_entity is None else top1 not in (None, truth_entity)
    if deferred_bucket and truth_entity is not None:
        # v1.1 M2 scoring (evaluator only): the truth service's bucket as Top-1 defers to the correct service.
        truth_service = entity_service.get(truth_entity) or unsighted_rows.get(truth_entity)
        own_bucket = bucket_key(truth_service) if truth_service else None
        pods = {e: s for e, s in scores.items() if e not in buckets}
        truth["rank_among_pods"] = truth_rank(pods, truth_entity, unsighted=truth_unsighted)["rank_pessimistic"]
        truth["deferred_bucket"] = own_bucket
        _defer(truth, top1, own_bucket)
        _defer(truth["ppr"], top1_decision(ranked["ppr"]), own_bucket)
        if sens is not None:
            _defer(sens["truth"], top1_decision([(row["node"], row["anomaly"]) for row in
                                                 gr.anomaly_only_rank(s_anom)["node_ranking"]]), own_bucket)
        wrong = top1 not in (None, truth_entity, own_bucket)
    out = {
        "policy": HINDSIGHT if policy is None else policy.name,
        "cutoff": R.iso(c),
        "requests": {w: {"observed": observed[w], "not_yet_observed": pending[w]} for w in WINDOWS},
        "services": service_rows,
        "mis_attributed_total": sum(v["mis_attributed"] for v in service_rows.values()),
        "abstained_total": sum(v["abstained"] for v in service_rows.values()),
        "unattributable_unsighted_total": sum(v["unattributable_unsighted"] for v in service_rows.values()),
        "candidates": {"policy": candidates, "hindsight": hindsight_set,
                       "missing_vs_hindsight": sorted(set(hindsight_set) - set(candidates)),
                       "extra_vs_hindsight": sorted(set(candidates) - set(hindsight_set)),
                       "in_view": sorted(k for k, v in view.items() if v)},
        "entities": entities,
        "ranking": {"statistic": statistic,
                    "anomaly_only": [(e, round(s, 6)) for e, s in ranked["anomaly_only"]],
                    "ppr": [(e, round(p, 6), round(s, 6)) for e, p, s in ranked["ppr"]],
                    "edges": [list(x) for x in edges],
                    "top1_entity": top1,
                    "ppr_top1_entity": top1_decision(ranked["ppr"])},
        "truth": truth,
        "wrong_entity_decision": wrong,
        "sensitivity": sens,
    }
    if variant:
        if deferred_bucket:
            out["candidates"]["deferred_buckets"] = buckets
        out["variant"] = {"version": V1_1["version"], "baseline_fallback": baseline_fallback,
                          "k_min": k_min if baseline_fallback else None, "deferred_bucket": bool(deferred_bucket)}
    return out


def _unscorable(entity, aggs, feats, entity_service) -> str:
    slots = aggs.get(entity, {NORMAL: {}, ANOMALOUS: {}})
    names = feats.get(entity_service[entity], ())
    if not any(slots[NORMAL].get(n) for n in names) and not any(slots[ANOMALOUS].get(n) for n in names):
        return "no_requests_in_windows"
    if not any(slots[NORMAL].get(n) for n in names):
        return "empty_normal_window"
    if not any(slots[ANOMALOUS].get(n) for n in names):
        return "empty_anomalous_window"
    return "constant_normal_window"


# ---------------------------------------------------------------------------
# Telemetry from span rows (model input) and span-verified serving Pods (evaluator only)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SpanTable:
    requests: tuple[RequestTelemetry, ...]
    served_by: Mapping[str, Mapping[str, str | None]]   # EVALUATOR ONLY: request_id -> service -> Pod key
    frontend_service: str
    services: tuple[str, ...]                            # frontend first, then downstream services (sorted)
    trace_of: Mapping[str, str]
    index_of: Mapping[str, int]
    block_of: Mapping[str, str | None]
    notes: tuple[str, ...] = ()


def _duration_ms(span: Mapping) -> float:
    return (int(span["endTimeUnixNano"]) - int(span["startTimeUnixNano"])) / 1_000_000


def _error(span: Mapping) -> float:
    return 1.0 if (span.get("status") or {}).get("code") in ERROR_CODES else 0.0


def requests_from_span_rows(rows: Iterable[Mapping]) -> SpanTable:
    """Workload requests from evidence rows (``span_claim``; ``client_request`` only for the block name).

    A workload request is a trace whose root span (no parent) carries ``aiops.request.index``. t = root
    startTimeUnixNano floored to the microsecond (as replay.load_capture_task), end = root endTimeUnixNano floored.
    The frontend service is the one service whose SERVER span is a direct child of the root in the workload
    traces; every request gives it the root span's duration and error flag (also a failed request with no server
    span). Each other service with a SERVER span in the trace gets that span's duration (max over its SERVER spans)
    and error flag (any). Requests are numbered 1..N by (t, block, index). served_by (evaluator only): the
    k8s.pod.uid shared by every span of the service in the trace, requiring exactly one SERVER span for the
    frontend service and at least one for the others (the rule of replay.load_capture_task)."""
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
    service = lambda p: (p.get("resource_attributes") or {}).get("service.name")
    workload = []
    for trace_id in sorted(spans_by_trace):
        spans = spans_by_trace[trace_id]
        roots = [p for p in spans if not p["span"].get("parentSpanId")
                 and "aiops.request.index" in (p.get("span_attributes") or {})]
        if len(roots) > 1:
            raise ValueError(f"trace {trace_id}: several workload root spans")
        if roots:
            workload.append((trace_id, roots[0], spans))
    if not workload:
        raise ValueError("no workload request (root span with aiops.request.index) in the evidence")
    first_hop = set()
    for _, root, spans in workload:
        rid = root["span"]["spanId"]
        first_hop.update(service(p) for p in spans
                         if p["span"].get("kind") == SPAN_SERVER and p["span"].get("parentSpanId") == rid)
    if len(first_hop) != 1:
        raise ValueError(f"expected one frontend (first-hop) service, found {sorted(first_hop)}")
    frontend = next(iter(first_hop))
    notes: list[str] = []
    items = []
    for trace_id, root, spans in workload:
        by_span = {p["span"]["spanId"]: p for p in spans}
        servers = [p for p in spans if p["span"].get("kind") == SPAN_SERVER and service(p)]
        root_service = service(root)
        feats: dict[str, dict[str, float]] = {frontend: {FRONTEND_FEATURES[0]: _duration_ms(root["span"]),
                                                         FRONTEND_FEATURES[1]: _error(root["span"])}}
        for p in servers:
            s = service(p)
            if s == frontend:
                continue
            slot = feats.setdefault(s, {DOWNSTREAM_FEATURES[0]: 0.0, DOWNSTREAM_FEATURES[1]: 0.0})
            slot[DOWNSTREAM_FEATURES[0]] = max(slot[DOWNSTREAM_FEATURES[0]], _duration_ms(p["span"]))
            slot[DOWNSTREAM_FEATURES[1]] = max(slot[DOWNSTREAM_FEATURES[1]], _error(p["span"]))
        calls = set()
        for p in servers:
            parent, caller = p["span"].get("parentSpanId"), None
            while parent and parent in by_span:
                q = by_span[parent]
                if q["span"].get("kind") == SPAN_SERVER and service(q) != service(p):
                    caller = service(q)
                    break
                parent = q["span"].get("parentSpanId")
            if caller is None:
                caller = root_service
            if caller != service(p):
                calls.add((caller, service(p)))
        truth: dict[str, str | None] = {}
        for s in feats:
            mine = [p for p in spans if service(p) == s]
            uids = {(p.get("resource_attributes") or {}).get("k8s.pod.uid") for p in mine}
            n_server = sum(1 for p in mine if p["span"].get("kind") == SPAN_SERVER)
            ok = len(uids) == 1 and None not in uids and (n_server == 1 if s == frontend else n_server >= 1)
            truth[s] = "Pod/" + next(iter(uids)) if ok else None
        span = root["span"]
        items.append({"trace_id": trace_id, "block": block_of_trace.get(trace_id),
                      "index": int(root["span_attributes"]["aiops.request.index"]),
                      "t": int(span["startTimeUnixNano"]) // 1000, "end": int(span["endTimeUnixNano"]) // 1000,
                      "features": feats, "calls": tuple(sorted(calls)), "truth": truth})
    items.sort(key=lambda r: (r["t"], r["block"] or "", r["index"]))
    services = [frontend] + sorted({s for r in items for s in r["features"]} - {frontend})
    app = set(services)
    requests, served_by, trace_of, index_of, block_of = [], {}, {}, {}, {}
    for number, r in enumerate(items, start=1):
        rid = f"request/{number}"
        requests.append(RequestTelemetry(rid, r["t"], r["end"], r["features"],
                                         tuple(x for x in r["calls"] if x[0] in app and x[1] in app)))
        served_by[rid] = r["truth"]
        trace_of[rid], index_of[rid], block_of[rid] = r["trace_id"], r["index"], r["block"]
    unverified = sum(1 for per in served_by.values() for v in per.values() if v is None)
    if unverified:
        notes.append(f"{unverified} (request, service) pairs without a span-verified Pod (not scored as right/wrong)")
    return SpanTable(tuple(requests), served_by, frontend, tuple(services), trace_of, index_of, block_of,
                     tuple(notes))


# ---------------------------------------------------------------------------
# Bridge inputs: the 22 Sep 2026 rollout (default) and a converted Phase 3 capture (--capture)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class BridgeInput:
    """Everything a policy may see (services, records, requests) plus evaluator-only material kept apart."""
    name: str
    services: tuple[ServiceContext, ...]
    records: tuple[R.Record, ...]           # union of every service's Pod STATE records, as captured
    spans: SpanTable                        # requests (model input) + served_by (evaluator only)
    changed_service: str | None             # the service whose rollout the switch-based streams perturb
    primary_task: object | None             # the replay task of the changed service (for the streams)
    tasks: Mapping[str, object] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


def _us(text: str) -> int:
    return R.to_us(datetime.fromisoformat(text.replace("Z", "+00:00")))


@contextmanager
def _attribution_lag_service(module, service: str):
    """Point attribution-lag's module-level SERVICE at another service while its pod_observations() runs (in memory
    only; the file is not touched), so every service's Pod records are derived by the same read-only code."""
    previous = module.SERVICE
    module.SERVICE = service
    try:
        yield
    finally:
        module.SERVICE = previous


def _labels(order: Sequence[str]) -> list[str]:
    if len(order) > 9:
        raise ValueError("more than 9 Pods of one service; widen the answer codes first")
    return ["old", "new"] if len(order) == 2 else [f"p{i}" for i in range(1, len(order) + 1)]


def load_rollout_input(root: Path | str) -> BridgeInput:
    """The 22 Sep 2026 rollout (no fault): recommendationservice from ``replay.load_attribution_lag_task`` (the
    replay-policy-v1 reference task, unchanged); every other application service's Pods from attribution-lag's own
    ``pod_observations()`` with its SERVICE pointed at that service; requests and features from the same evidence
    file's span rows."""
    root = Path(root).resolve()
    task = R.load_attribution_lag_task(root)
    module, ctx = task.module, task.context
    rows = [json.loads(line) for line in Path(module.EVIDENCE).read_text(encoding="utf-8").splitlines() if line.strip()]
    spans = requests_from_span_rows(rows)
    if spans.frontend_service != module.SERVICE:
        raise ValueError(f"frontend service {spans.frontend_service} is not the rollout task's {module.SERVICE}")
    snapshot_of = {row["record_id"]: row["snapshot_id"] for row in ctx["sightings"]}
    services, records, tasks = [], list(task.records), {module.SERVICE: task}
    services.append(ServiceContext(module.SERVICE, task.candidates, task.predicate, task.serving_value,
                                   task.retired_values))
    for name in spans.services[1:]:
        with _attribution_lag_service(module, name):
            pods, _ = module.pod_observations(ctx["sightings"], ctx["patch"], ctx["protocol"])
        if not pods:
            raise ValueError(f"no Pod of {name} in the rollout's API sightings")
        ids = dict(snapshot_of)
        for pod in pods.values():
            for _, _, _, record_id in pod["observations"]:
                if record_id.startswith("absence:"):
                    ids[record_id] = record_id.split(":")[1]
        records.extend(R.records_from_pods(pods, ids, task.predicate))
        order = sorted(pods, key=lambda k: (pods[k]["created_floor_us"], k))
        candidates = tuple(R.Candidate(k, lab, pods[k]["created_floor_us"]) for k, lab in zip(order, _labels(order)))
        services.append(ServiceContext(name, candidates, task.predicate, task.serving_value, task.retired_values))
    R.Stream(records)  # validates unique record IDs across services
    return BridgeInput("rollout-22sep2026-pilot001", tuple(services), tuple(records), spans, module.SERVICE, task,
                       tasks, spans.notes)


def rollout_onset(bridge: BridgeInput) -> tuple[int, str]:
    """Onset yardstick of the rollout: host receipt of the rollout-patch response (the change is accepted)."""
    patch = bridge.primary_task.context["patch"]
    return _us(patch["response_received_at"]), "capture.json command_receipts rollout-patch response_received_at"


def load_capture_input(capture: Path | str, *, root: Path | str) -> BridgeInput:
    """A converted Phase 3 capture (phase3/CAPTURE_FORMAT.md). Model input is read from ``<capture>/evidence/`` only:
    ``accepted_evidence.jsonl`` (span_claim, client_request, api_observation rows) and ``protocol.json``.

    Services = the frontend and downstream services of the workload spans. Each service's Pod records and
    candidates come from ``replay.load_capture_task(capture, service)`` (explicit service, so ``incident.json`` is
    not consulted). The changed service is ``protocol.json`` ``replacement_service`` (null: no change). Nothing is
    written and ``ground_truth/`` is not read here (see ``load_capture_truth``)."""
    capture = Path(capture).resolve()
    evidence_file = capture / "evidence" / "accepted_evidence.jsonl"
    if not evidence_file.exists():
        raise FileNotFoundError(f"{evidence_file} not found: run phase3/convert_capture.py --capture {capture} first")
    protocol = json.loads((capture / "evidence" / "protocol.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in evidence_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    spans = requests_from_span_rows(rows)
    services, records, tasks, notes = [], [], {}, list(spans.notes)
    changed = protocol.get("replacement_service") or None
    for name in spans.services:
        try:
            task = R.load_capture_task(capture, name, root=root)
        except ValueError as error:
            if name in (spans.frontend_service, changed):
                raise
            notes.append(f"{name}: not a candidate service ({error}); its features are not used")
            continue
        tasks[name] = task
        services.append(ServiceContext(name, task.candidates, task.predicate, task.serving_value, task.retired_values))
        records.extend(task.records)
        # Cross-check: the replay loader's span-verified requests agree with this table (same rule, same rows).
        mine = {spans.trace_of[r.request_id]: r for r in spans.requests}
        for r in task.context["requests"]:
            req = mine.get(r["trace_id"])
            if req is None or req.t != r["t_req_us"] or spans.served_by[req.request_id].get(name) != "Pod/" + r["truth_uid"]:
                raise ValueError(f"{name}: request {r['trace_id']} disagrees with replay.load_capture_task")
        notes.extend(f"{name}: {n}" for n in task.context["notes"])
    R.Stream(records)
    if changed is not None and changed not in tasks:
        raise ValueError(f"changed service {changed!r} has no workload span in the capture")
    return BridgeInput(capture.name, tuple(services), tuple(records), spans, changed,
                       tasks.get(changed) if changed else None, tasks, tuple(notes))


_STATUS_LINE = re.compile(r"\s*status\s*=\s*([A-Za-z0-9_.-]+)\s*")   # a well-formed marker line status=<value>
_STATUS_LIKE = re.compile(r"\s*status\b", re.IGNORECASE)              # any other line that tries to state a status


def load_capture_truth(capture: Path | str) -> dict:
    """EVALUATOR ONLY: onset yardstick, truth entity, labels and inclusion facts from ``ground_truth/`` and the
    status markers. Never passed to a policy.

    onset = timeline_host.fault_launch.host_utc, else timeline_host.pre_fault_end.host_utc (the sham boundary
    F = T0 + 20 s of a no-fault incident). truth entity = "Pod/" + observed.fault_target.pod_uid (None without a
    fault). Status: each present marker (COMPLETE.txt, INVALID.txt, FAILED.txt) is parsed for lines
    ``status=<value>``; ``status`` is their value when all agree, else None. ``status_problems`` lists a marker
    without a status line, a malformed status line and conflicting status lines (``inclusion`` excludes on any)."""
    capture = Path(capture).resolve()
    path = capture / "ground_truth" / "ground_truth.json"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found: the evaluator's ground truth is required for scoring")
    gt = json.loads(path.read_text(encoding="utf-8"))
    timeline = gt.get("timeline_host") or gt.get("timeline") or {}
    for key in ("fault_launch", "pre_fault_end"):
        entry = timeline.get(key)
        if isinstance(entry, Mapping) and entry.get("host_utc"):
            onset, onset_source = _us(entry["host_utc"]), f"ground_truth.json timeline_host.{key}.host_utc"
            break
    else:
        raise ValueError("ground_truth.json has neither timeline_host.fault_launch nor pre_fault_end")
    observed = gt.get("observed") or {}
    planned = gt.get("planned") or {}
    labels = planned.get("labels") or {}
    target = observed.get("fault_target") or gt.get("fault_target")
    fault_present = labels.get("fault_present")
    truth = None
    if isinstance(target, Mapping) and target.get("pod_uid"):
        truth = "Pod/" + target["pod_uid"]
    if fault_present and truth is None:
        raise ValueError("planned fault_present but no observed fault_target.pod_uid")
    markers = sorted(name for name in ("COMPLETE.txt", "INVALID.txt", "FAILED.txt") if (capture / name).exists())
    statuses, problems, errors = [], [], []
    for name in markers:
        found, malformed = [], False
        for line in (capture / name).read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            match = _STATUS_LINE.fullmatch(line)
            if match:
                found.append(match.group(1))
            elif _STATUS_LIKE.match(line):
                malformed = True
                problems.append(f"{name}: malformed status line {line.strip()!r}")
            elif sep and key.strip() == "error":
                errors.append(value.strip())
        if len(set(found)) > 1:
            problems.append(f"{name}: conflicting status lines ({', '.join(found)})")
        elif not found and not malformed:
            problems.append(f"{name}: no status= line")
        statuses.extend(found)
    invalid = sorted(p.name for p in capture.glob("INVALID*"))
    return {"onset": onset, "onset_source": onset_source, "truth_entity": truth,
            "truth_source": "ground_truth.json observed.fault_target.pod_uid" if truth else "no fault target",
            "incident_id": gt.get("incident_id"), "labels": labels,
            "fault_target": target if isinstance(target, Mapping) else None,
            "evaluation_summary": gt.get("evaluation_summary"), "timeline_host": timeline,
            "runner_validity": gt.get("validity"),
            "status_marker": markers[0] if len(markers) == 1 else (markers or None),
            "status": statuses[0] if len(set(statuses)) == 1 else None, "status_problems": problems,
            "status_error": errors[0] if errors else None, "invalid_markers": invalid,
            # Read only by inclusion_secondary and reporting.
            "fault_control": fault_control_facts(capture / "ground_truth" / FAULT_CONTROL_FILE)}


FAULT_CONTROL_FILE = "fault_control_evaluation.json"
FAULT_CONTROL_SCHEMA = "bounded_cpu_fault_control_v1"
FAULT_CONTROL_PHASES = ("nominal", "active", "recovery")


def fault_control_facts(path: Path) -> dict | None:
    """EVALUATOR ONLY: the fields of ``ground_truth/fault_control_evaluation.json`` that the secondary rule reads, for the
    evaluator's target service; None when the file is absent. Values are copied as recorded (exact fractions stay
    ``{numerator, denominator}``); ``nonfunctional_target_probes`` lists the target-service probe records with
    ``functional_ok`` false (the evaluator's definition behind ``all_attempted_functional``). Never a model input."""
    path = Path(path)
    if not path.exists():
        return None
    raw = path.read_bytes()
    ev = json.loads(raw.decode("utf-8"))
    out = {"file": f"ground_truth/{path.name}", "sha256": hashlib.sha256(raw).hexdigest(),
           "schema": ev.get("schema") if isinstance(ev, Mapping) else None,
           "kind": ev.get("kind") if isinstance(ev, Mapping) else None}
    if not isinstance(ev, Mapping) or ev.get("schema") != FAULT_CONTROL_SCHEMA:
        return out
    target = ev.get("target_service")
    phases = ((ev.get("services") or {}).get(target) or {}) if isinstance(ev.get("services"), Mapping) else {}
    out.update({
        "target_service": target,
        "activation_verified": ev.get("activation_verified"), "activation_checks": ev.get("activation_checks"),
        "support_checks": ev.get("support_checks"),
        "target_phases": {phase: {key: (phases.get(phase) or {}).get(key) for key in
                                  ("attempted", "eligible_attempts", "successful", "boundary_ambiguous",
                                   "all_attempted_functional", "outcomes_all_attempts")}
                          for phase in FAULT_CONTROL_PHASES},
        "effect_threshold_ns": ev.get("effect_threshold_ns"),
        "active_minus_nominal_median_ns": ev.get("active_minus_nominal_median_ns"),
        "latency_threshold_crossed_descriptively": ev.get("latency_threshold_crossed_descriptively"),
        "all_nominal_and_active_target_responses_functional":
            ev.get("all_nominal_and_active_target_responses_functional"),
        "latency_effect_established": ev.get("latency_effect_established"),
        "recovery_established": ev.get("recovery_established"),
        "fault_control_passed": ev.get("fault_control_passed"),
        "reasons": ev.get("reasons"),
        "nonfunctional_target_probes": [
            {key: r.get(key) for key in ("probe_id", "phase", "outcome", "error_type", "grpc_status", "elapsed_ns",
                                         "timeout_seconds", "control_classification")}
            for r in (ev.get("probe_records") or [])
            if isinstance(r, Mapping) and r.get("service") == target and r.get("functional_ok") is not True],
    })
    return out


def _rule1_reasons(truth: Mapping) -> list[str]:
    """Inclusion rule 1: exactly one marker, COMPLETE.txt, status exactly ``finished``, no INVALID*
    marker, runner validity true when recorded."""
    reasons = []
    marker, status, problems = truth["status_marker"], truth["status"], list(truth.get("status_problems") or [])
    if marker is None:
        reasons.append("no status marker: COMPLETE.txt with status=finished is required")
    elif not isinstance(marker, str):
        reasons.append(f"conflicting status markers {', '.join(marker)}: only COMPLETE.txt with status=finished "
                       "is accepted")
    elif marker != "COMPLETE.txt" or status != "finished" or problems:
        reasons.append(f"status marker {marker} status={status}" + (f" ({'; '.join(problems)})" if problems else "")
                       + ": COMPLETE.txt with status=finished is required")
    if truth["invalid_markers"]:
        reasons.append("invalid markers: " + ", ".join(truth["invalid_markers"]))
    validity = truth.get("runner_validity")
    if isinstance(validity, Mapping) and validity.get("valid") is not True:
        reasons.append("runner validity: " + "; ".join(str(r) for r in validity.get("reasons") or ["not valid"]))
    return reasons


def _sighted_truth_reasons(truth: Mapping, bridge: BridgeInput) -> list[str]:
    """Inclusion item 2, second half: a fault capture's target Pod is a sighted Pod of a workload service."""
    if not (truth["labels"] or {}).get("fault_present"):
        return []
    keys = {c.key for s in bridge.services for c in s.candidates}
    return [] if truth["truth_entity"] in keys else ["fault target Pod is not a sighted Pod of any workload service"]


def _rule3_reasons(truth: Mapping, bridge: BridgeInput) -> list[str]:
    """Inclusion rule 3: the change is verified (two Pods sighted) and, for a fault on the changed
    service, the fault target is not the pre-change Pod."""
    reasons = []
    labels = truth["labels"] or {}
    if bridge.changed_service:
        svc = next(s for s in bridge.services if s.service == bridge.changed_service)
        if len(svc.candidates) < 2:
            reasons.append(f"change of {bridge.changed_service} not verified: fewer than two Pods sighted")
        if labels.get("fault_present") and truth["truth_entity"] and \
                (truth["fault_target"] or {}).get("service") == bridge.changed_service:
            oldest = min(svc.candidates, key=lambda c: (c.created_floor or 0, c.key))
            if truth["truth_entity"] == oldest.key:
                reasons.append("fault target is the pre-change Pod of the changed service (not the new Pod)")
    return reasons


def inclusion(truth: Mapping, bridge: BridgeInput) -> dict:
    """The inclusion rule, checked from the files.

    Rule 1 requires exactly one marker, COMPLETE.txt, whose status is exactly ``finished``: no marker, a
    conflicting marker set (COMPLETE.txt with INVALID.txt or FAILED.txt), another status, or a missing, malformed or
    conflicting status line excludes the capture, with the reason. (Split into _rule1_reasons, _sighted_truth_reasons
    and _rule3_reasons so that the secondary rule reuses them; the reasons and their order are unchanged.)"""
    reasons = _rule1_reasons(truth)
    labels = truth["labels"] or {}
    summary = truth["evaluation_summary"] or {}
    if labels.get("fault_present"):
        for key in ("activation_verified", "latency_effect_established"):
            if summary.get(key) is not True:
                reasons.append(f"fault manipulation not confirmed: {key}={summary.get(key)}")
    reasons += _sighted_truth_reasons(truth, bridge)
    reasons += _rule3_reasons(truth, bridge)
    return {"included": not reasons, "reasons": reasons}


# The secondary inclusion rule: a SECONDARY analysis, never pooled with the primary.
SECONDARY_RULE = {
    "evaluation_file": "ground_truth/" + FAULT_CONTROL_FILE,
    "evaluation_schema": FAULT_CONTROL_SCHEMA,
    "only_effect_reason": "nonfunctional_nominal_or_active_target_responses",
    # The evaluator reasons whose conditions enter latency_effect_established (src/aiops_kg/fault_control.py
    # evaluate_fault_control: control/identity feeds activation; activation; nominal+active support; all nominal and
    # active target responses functional; shift >= threshold). "latency_effect_established false ONLY because of
    # nonfunctional_nominal_or_active_target_responses" = of these, exactly that one is present.
    "effect_reasons": ("control_or_identity_not_established", "activation_not_established",
                       "insufficient_nominal_or_unambiguous_active_support",
                       "nonfunctional_nominal_or_active_target_responses",
                       "latency_effect_threshold_not_met_or_unavailable"),
    # Known evaluator reasons that do not enter the effect: reported as a note, not a refusal (the secondary rule
    # requires support_checks.recovery, which is checked on its own). Any reason outside both lists refuses.
    "non_effect_reasons": ("service_recovery_not_established",),
}


def _fraction(value) -> Fraction | None:
    """An exact ``{numerator, denominator}`` value of the evaluation file, or None when absent or malformed."""
    if not isinstance(value, Mapping):
        return None
    num, den = value.get("numerator"), value.get("denominator")
    if isinstance(num, bool) or isinstance(den, bool) or not isinstance(num, int) or not isinstance(den, int) \
            or den <= 0:
        return None
    return Fraction(num, den)


def _ms(value: Fraction | None) -> str:
    return "unavailable" if value is None else f"{float(value) / 1e6:.3f} ms"


def inclusion_secondary(truth: Mapping, bridge: BridgeInput) -> dict:
    """The secondary inclusion rule, checked from the files: may a fault capture that item 2 of the inclusion rule
    excludes enter the SECONDARY analysis of failure-effect captures?

    Admitted iff every check passes, in this order (the evaluation fields come from
    ``ground_truth/fault_control_evaluation.json`` via ``load_capture_truth()["fault_control"]``):

    1. rule 1 (``_rule1_reasons``: COMPLETE.txt, status=finished, runner validity true);
    2. a fault capture (``labels.fault_present`` true);
    3. the evaluation file exists with schema ``bounded_cpu_fault_control_v1``;
    4. ``activation_verified`` true;
    5. ``support_checks`` nominal, active and recovery all true;
    6. every nominal-phase target response functional (``services[target].nominal.all_attempted_functional``);
    7. ``active_minus_nominal_median_ns`` >= ``effect_threshold_ns`` (exact fractions, both present);
    8. ``latency_effect_established`` false (true means the capture belongs to the primary analysis);
    9. of the evaluator's ``reasons`` that enter the effect (``SECONDARY_RULE["effect_reasons"]``) exactly
       ``nonfunctional_nominal_or_active_target_responses`` is present, and no unknown reason is present;
       ``service_recovery_not_established`` is reported as a note;
    10. ``ground_truth.json`` ``evaluation_summary`` agrees with the evaluation file on activation_verified,
        latency_effect_established and reasons (when it records them);
    11. the fault target Pod is a sighted Pod (``_sighted_truth_reasons``);
    12. rule 3 unchanged (``_rule3_reasons``).

    Returns ``admitted``, ``reasons`` (the failed checks' details when refused, every check's detail when admitted),
    ``checks`` (name, passed, detail, in order) and ``notes``. EVALUATOR ONLY; never a policy input."""
    checks, notes = [], []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    rule1 = _rule1_reasons(truth)
    check("rule 1", not rule1, "; ".join(rule1) or "COMPLETE.txt with status=finished; runner validity true")
    labels = truth["labels"] or {}
    check("fault capture", bool(labels.get("fault_present")) and truth["truth_entity"] is not None,
          "labels.fault_present true, fault target recorded" if labels.get("fault_present")
          else "The secondary rule applies to fault captures only (labels.fault_present is not true)")
    fc = truth.get("fault_control")
    if fc is None or fc.get("schema") != FAULT_CONTROL_SCHEMA:
        check("evaluation file", False, f"no {SECONDARY_RULE['evaluation_file']} with schema {FAULT_CONTROL_SCHEMA}"
              + ("" if fc is None else f" (found schema {fc.get('schema')!r}, kind {fc.get('kind')!r})"))
    else:
        check("evaluation file", True, f"{fc['file']} (schema {fc['schema']}, SHA-256 {fc['sha256'][:16]}…)")
        check("activation_verified", fc.get("activation_verified") is True,
              f"activation_verified={fc.get('activation_verified')}")
        support = fc.get("support_checks") or {}
        successes = {p: ((fc.get("target_phases") or {}).get(p) or {}).get("successful") for p in FAULT_CONTROL_PHASES}
        check("support_checks", all(support.get(p) is True for p in FAULT_CONTROL_PHASES),
              "support_checks " + ", ".join(f"{p}={support.get(p)}" for p in FAULT_CONTROL_PHASES)
              + " (target successes: " + ", ".join(f"{p} {n}" for p, n in successes.items()) + ")")
        nominal = (fc.get("target_phases") or {}).get("nominal") or {}
        check("nominal target responses functional", nominal.get("all_attempted_functional") is True,
              f"{fc.get('target_service')} nominal all_attempted_functional={nominal.get('all_attempted_functional')} "
              f"(outcomes {nominal.get('outcomes_all_attempts')})")
        shift, threshold = _fraction(fc.get("active_minus_nominal_median_ns")), _fraction(fc.get("effect_threshold_ns"))
        check("shift >= threshold", shift is not None and threshold is not None and shift >= threshold,
              f"active - nominal median shift {_ms(shift)} vs effect threshold {_ms(threshold)}")
        effect = fc.get("latency_effect_established")
        check("latency_effect_established false", effect is False,
              "latency_effect_established=False" if effect is False else
              ("latency_effect_established=True: the capture belongs to the primary analysis (inclusion item 2)"
               if effect is True else f"latency_effect_established={effect!r} (not recorded as false)"))
        reasons = fc.get("reasons")
        if not isinstance(reasons, list):
            check("only the functional reason", False, f"evaluator reasons not recorded as a list: {reasons!r}")
        else:
            effect_reasons = [r for r in reasons if r in SECONDARY_RULE["effect_reasons"]]
            unknown = [r for r in reasons if r not in SECONDARY_RULE["effect_reasons"] and r not in SECONDARY_RULE["non_effect_reasons"]]
            ok = effect_reasons == [SECONDARY_RULE["only_effect_reason"]] and not unknown
            check("only the functional reason", ok,
                  f"evaluator reasons {reasons}: effect reasons {effect_reasons}"
                  + (f"; unknown reasons {unknown}" if unknown else "")
                  + ("" if ok else " (the secondary rule requires exactly "
                                   f"['{SECONDARY_RULE['only_effect_reason']}'] among the effect reasons and no unknown reason)"))
            notes += [f"evaluator reason {r!r} does not concern the latency effect (reported, not a refusal)"
                      for r in reasons if r in SECONDARY_RULE["non_effect_reasons"]]
        summary = truth.get("evaluation_summary")
        if isinstance(summary, Mapping):
            differ = [k for k in ("activation_verified", "latency_effect_established", "reasons")
                      if k in summary and summary[k] != fc.get(k)]
            check("evaluation summary agrees", not differ,
                  "ground_truth.json evaluation_summary agrees with the evaluation file" if not differ else
                  f"ground_truth.json evaluation_summary differs from the evaluation file on {differ}")
    sighted = _sighted_truth_reasons(truth, bridge)
    check("sighted truth Pod", not sighted, "; ".join(sighted) or "fault target Pod is a sighted Pod")
    rule3 = _rule3_reasons(truth, bridge)
    check("rule 3", not rule3, "; ".join(rule3) or (f"change of {bridge.changed_service} verified"
                                                  if bridge.changed_service else "no change incident"))
    admitted = all(c["passed"] for c in checks)
    return {"admitted": admitted,
            "reasons": [c["detail"] for c in checks if admitted or not c["passed"]],
            "checks": checks, "notes": notes}
