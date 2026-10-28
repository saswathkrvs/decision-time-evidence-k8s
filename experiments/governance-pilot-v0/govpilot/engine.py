"""Execution model of the development rollback pilot and its per-capture decision logs.

Posing. Request k is posed at d = t_k + Delta if d >= P (the patch request start of the unperturbed patch row; a
design constant, never view knowledge); never in a capture without a planned change. No rule reads a request's
existence or timing.

Re-evaluation instants. A request is evaluated at d, then at every later candidate instant tau with d < tau <= H and
tau < d + E, in increasing order, until a terminal verdict. The candidate schedule is computed from the stream once
and is shared by every causal view (so (L) and (T) see identical instants; the request rows reference it). It holds
every instant at which a causal view's verdict can change without being evaluated otherwise: the availability of every
derived observation, identity fact, completion receipt and freeze record and every withdrawal; the freshness
boundaries observed_at + F (F in {30 s, 600 s}) of every observation that can still be the newest of its (subject,
predicate) at that instant; R2's window ends and R6's limits (knowledge instant + S + 1 us); recorded validity starts
and identity creation times; freeze window starts and ends; and H. The hindsight schedule of (c-hind) adds the valid
time of every cluster sighting. Verdicts are constant between consecutive candidate instants.

Terminal outcomes. At instant tau the view uses every record with available_at <= tau, after applying every boundary
<= tau. ALLOW executes at tau (dispatch time, counterfactual); DENY and NEEDS_APPROVAL end the request with their rule;
ABSTAIN waits, except in (d), where a first-verdict ABSTAIN is a terminal escalation. A request still open at d + E is
EXPIRED (or CENSORED at H).

Decision logs. One gzipped JSON-lines log per capture, streamed as the verdicts are computed; ``LogIndex`` lists them
with the SHA-256 of their uncompressed text and is closed after the last capture; only then may the evaluator read
the request rows back, through the index.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from aiops_kg.policy_gate import ABSTAIN, ALLOW, DENY, GENERATION, NEEDS_APPROVAL

from .common import R, canonical, s_to_us, seconds, sha256_text, ts_us
from .inputs import CHANGE_KINDS, STREAM_BY_NAME, StreamSpec, perturb
from .views import (CAUSAL_VIEWS, FUTURE, N_SECONDS, S_SECONDS, CaptureModel, HindsightRequired, StreamContext,
                    ViewSpec, causal_view, entry_fact_ids, evaluate_causal, evaluate_hindsight, hindsight_view)

DELTAS = (0, 5, 30)
F_SCHEDULE = (30.0, 600.0)
NOT_POSED, EXPIRED, CENSORED, ESCALATED = "NOT_POSED", "EXPIRED", "CENSORED", "ESCALATED"
DISPOSITIONS = (ALLOW, DENY, NEEDS_APPROVAL, ESCALATED, EXPIRED, CENSORED)


# ---------------------------------------------------------------------------------------------------------------
# The candidate schedule
# ---------------------------------------------------------------------------------------------------------------
def _freshness_boundaries(observations, withdrawals, f_us: list[int]) -> set[int]:
    """observed_at + F for every observation that can still be the newest of its (subject, predicate) at that
    instant. A boundary is dropped only when a strictly newer observation of the same group is usable by then (the
    resolver then reads the newer one in every view); groups with a withdrawal keep every boundary."""
    groups: dict[tuple, list] = {}
    for o in observations:
        groups.setdefault((o.subject, o.predicate), []).append(o)
    out = set()
    for items in groups.values():
        keep_all = any(o.record_id in withdrawals for o in items)
        for o in items:
            observed = R.to_us(o.observed_at)
            for f in f_us:
                boundary = observed + f
                if keep_all or not any(R.to_us(q.observed_at) > observed and R.to_us(q.available_at) <= boundary
                                       for q in items):
                    out.add(boundary)
    return out


def candidate_schedule(sctx: StreamContext, *, hindsight: bool = False) -> tuple[int, ...]:
    """Every candidate re-evaluation instant <= H of one stream (view-independent; see the module docstring).

    The causal schedule is shared by every causal view; the hindsight schedule adds the valid times of every
    cluster sighting, at which (c-hind)'s "first sighting at or after the cutoff" changes."""
    key = "__schedule_hindsight__" if hindsight else "__schedule__"
    cached = sctx.memo.get(key)
    if cached is not None:
        return cached
    m, H = sctx.model, sctx.capture.H
    n_us, s_us = s_to_us(N_SECONDS), s_to_us(S_SECONDS) + 1
    instants = {H} | _freshness_boundaries(m.observations, m.withdrawals, [s_to_us(f) for f in F_SCHEDULE])
    for o in m.observations:
        observed, available = R.to_us(o.observed_at), R.to_us(o.available_at)
        instants.update((available, available + s_us))
        starts = R.to_us(o.starts_at) if o.starts_at is not None else None
        if starts is not None:
            instants.add(starts)
        if o.predicate == GENERATION:
            instants.add(observed + n_us)
            if starts is not None:
                instants.add(starts + n_us)
        if hindsight and o.record_id in m.cluster_observations:
            instants.add(observed)
    for f in m.identity_facts:
        available = R.to_us(f.available_at)
        instants.update((available, available + s_us))
        if f.valid_from is not None:
            instants.add(R.to_us(f.valid_from))
    for when in list(m.withdrawals.values()) + list(m.completion_withdrawals.values()) \
            + list(m.freeze_withdrawals.values()):
        instants.update((when, when + s_us))
    for c in m.completion_receipts:
        instants.add(c.available_at)
    for f in m.freezes:
        payload = f.payload_view()
        instants.update((f.available_at, ts_us(payload["start"]), ts_us(payload["end"])))
    schedule = tuple(sorted(x for x in instants if x <= H))
    sctx.memo[key] = schedule
    return schedule


def request_instants(schedule: tuple[int, ...], d: int, H: int, E: float | None) -> tuple[int, ...]:
    """[d] + candidate instants in (d, H] that precede d + E."""
    end = None if E is None else d + s_to_us(E)
    later = tuple(t for t in schedule if d < t <= H and (end is None or t < end))
    return (d,) + later


# ---------------------------------------------------------------------------------------------------------------
# The decision log
# ---------------------------------------------------------------------------------------------------------------
class SealedLogError(RuntimeError):
    pass


class UnsealedLogError(PermissionError):
    """A decision-log index was read or written before it was sealed."""


@dataclass
class DecisionLog:
    """Evaluations (deduplicated per capture/view/stream/instant), the fact table they reference and per-request
    records; sealed after all verdicts (the evaluator refuses an unsealed log).

    Each evaluation lists, per rule, the store fact IDs, ``freeze:`` and ``input:`` record IDs it used; the fact table
    gives every referenced fact's validity, availability and supporting record IDs, so the exact record set behind
    every evaluation is derivable from the log alone (checked by ``checks.check_provenance``)."""
    meta: dict = field(default_factory=dict)
    evaluations: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    schedules: dict = field(default_factory=dict)
    requests: list = field(default_factory=list)
    sealed: bool = False

    def add_schedule(self, capture_id: str, stream: str, kind: str, schedule: tuple) -> None:
        key = (capture_id, stream, kind)
        if key not in self.schedules:
            self.schedules[key] = list(schedule)

    def evaluation_instants(self, row: dict) -> list[int]:
        """The exact instants at which a request was evaluated: d, then every schedule instant up to the last."""
        ev = row["evaluations"]
        if not ev["count"]:
            return []
        schedule = self.schedules[(row["capture"], row["stream"], ev["schedule"])]
        later = [t for t in schedule if ev["first_us"] < t <= ev["last_us"]]
        return [ev["first_us"]] + later

    def add_evaluation(self, capture_id: str, entry: dict, store=None) -> str:
        if self.sealed:
            raise SealedLogError("the decision log is sealed")
        key = f"{capture_id}|{entry['view']}|{entry['stream']}|{entry['instant_us']}"
        if key in self.evaluations:
            if self.evaluations[key]["verdict"] != entry["verdict"]:
                raise SealedLogError(f"two different evaluations for {key}")
            return key
        self.evaluations[key] = dict(entry, capture=capture_id, eval_id=key)
        if store is not None:
            self.add_facts(capture_id, entry["stream"], store, entry_fact_ids(entry))
        return key

    def add_facts(self, capture_id: str, stream: str, store, fact_ids) -> None:
        for fid in fact_ids:
            key = (capture_id, stream, store.label, fid)
            if key in self.facts:
                continue
            f = store.fact(fid)
            self.facts[key] = {"capture": capture_id, "stream": stream, "store": store.label, "fact_id": fid,
                               "valid_from": R.iso(R.to_us(f.valid_from)) if f.valid_from else None,
                               "valid_to": R.iso(R.to_us(f.valid_to)) if f.valid_to else None,
                               "available_at": R.iso(R.to_us(f.available_at)),
                               "superseded_at": R.iso(R.to_us(f.superseded_at)) if f.superseded_at else None,
                               "known_open": f.known_open,
                               "confirmed_at": R.iso(R.to_us(f.confirmed_at)) if f.confirmed_at else None,
                               "support": list(store.support.get(fid, ()))}

    def add_request(self, row: dict) -> None:
        if self.sealed:
            raise SealedLogError("the decision log is sealed")
        self.requests.append(row)

    def seal(self) -> str:
        self.sealed = True
        return self.digest()

    def iter_lines(self):
        """The log's canonical JSON lines, in a fixed order, generated one at a time."""
        yield canonical({"meta": self.meta})
        for k in sorted(self.schedules):
            schedule = {"capture": k[0], "stream": k[1], "kind": k[2], "instants": self.schedules[k]}
            yield canonical({"schedule": schedule})
        for k in sorted(self.facts):
            yield canonical({"fact": self.facts[k]})
        for k in sorted(self.evaluations):
            yield canonical({"evaluation": self.evaluations[k]})
        for r in sorted(self.requests, key=lambda r: (r["capture"], r["view"], r["stream"], r["delta_s"], r["k"])):
            yield canonical({"request": r})

    def lines(self) -> list[str]:
        return list(self.iter_lines())

    def text(self) -> str:
        return "".join(line + "\n" for line in self.iter_lines())

    def digest(self) -> str:
        digest = hashlib.sha256()
        for line in self.iter_lines():
            digest.update((line + "\n").encode("utf-8"))
        return digest.hexdigest()

    def write_gzip(self, path) -> dict:
        """Deterministic gzip (mtime 0, no file name), streamed in chunks without building the whole text; returns
        the SHA-256 and size of the uncompressed text and the size of the gzip file."""
        digest, size, chunk = hashlib.sha256(), 0, []
        with open(path, "wb") as raw, \
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as handle:
            pending = 0
            for line in self.iter_lines():
                data = (line + "\n").encode("utf-8")
                digest.update(data)
                size += len(data)
                chunk.append(data)
                pending += len(data)
                if pending >= 1 << 20:
                    handle.write(b"".join(chunk))
                    chunk, pending = [], 0
            if chunk:
                handle.write(b"".join(chunk))
        return {"sha256_of_uncompressed_text": digest.hexdigest(), "text_bytes": size,
                "gzip_bytes": Path(path).stat().st_size}


@dataclass(frozen=True)
class SealedRequests:
    """One capture's request rows, read back through a sealed ``LogIndex`` (all that ``outcomes.cells``, ``compare``
    and ``collapsed_cells`` need). Only ``LogIndex.read_requests`` builds one."""
    capture: str
    requests: list
    sealed: bool = True


@dataclass
class LogIndex:
    """The per-capture decision logs of one run.

    ``write`` closes a capture's ``DecisionLog`` (no later additions), streams it to ``<directory>/<capture>.jsonl.gz``
    and keeps only its index entry, so memory holds one capture's log at a time. ``seal`` follows the last capture:
    every verdict then exists, and only then do ``read_requests`` (for the evaluator) and the index file work."""
    directory: Path
    meta: dict = field(default_factory=dict)
    entries: dict = field(default_factory=dict)
    sealed: bool = False

    def write(self, log: DecisionLog, capture_id: str) -> dict:
        if self.sealed:
            raise SealedLogError("the decision-log index is sealed")
        if capture_id in self.entries:
            raise SealedLogError(f"{capture_id} already has a decision log")
        log.sealed = True
        name = f"{capture_id}.jsonl.gz"
        entry = {"capture": capture_id, "file": name, **log.write_gzip(Path(self.directory) / name),
                 "evaluations": len(log.evaluations), "requests": len(log.requests), "facts": len(log.facts),
                 "schedules": len(log.schedules)}
        self.entries[capture_id] = entry
        return entry

    def text(self) -> str:
        return canonical({"meta": self.meta, "logs": [self.entries[c] for c in sorted(self.entries)]}) + "\n"

    def seal(self) -> str:
        self.sealed = True
        return sha256_text(self.text())

    def write_index(self, path) -> str:
        if not self.sealed:
            raise UnsealedLogError("seal the decision-log index before writing it")
        text = self.text()
        Path(path).write_text(text, encoding="utf-8", newline="\n")
        return sha256_text(text)

    def read_requests(self, capture_id: str) -> SealedRequests:
        """One capture's request rows, for the evaluator; refuses before the seal or if the file changed."""
        if not self.sealed:
            raise UnsealedLogError("the evaluator reads decision logs only through a decision-log index")
        entry = self.entries[capture_id]
        digest, rows = hashlib.sha256(), []
        with gzip.open(Path(self.directory) / entry["file"], "rb") as handle:
            for line in handle:
                digest.update(line)
                if line.startswith(b'{"request":'):
                    rows.append(json.loads(line)["request"])
        if digest.hexdigest() != entry["sha256_of_uncompressed_text"]:
            raise SealedLogError(f"{entry['file']} differs from the log written for {capture_id}")
        return SealedRequests(capture_id, rows)

    def totals(self) -> dict:
        keys = ("evaluations", "requests", "facts", "text_bytes", "gzip_bytes")
        return {k: sum(e[k] for e in self.entries.values()) for k in keys}


# ---------------------------------------------------------------------------------------------------------------
# Running requests
# ---------------------------------------------------------------------------------------------------------------
def _evaluate(spec: ViewSpec, sctx: StreamContext, tau: int, hindsight: bool) -> dict:
    if spec.causal:
        return evaluate_causal(spec, sctx, tau)
    return evaluate_hindsight(spec, sctx, tau, hindsight=hindsight)


def run_request(spec: ViewSpec, sctx: StreamContext, k: int, t_us: int, delta_s: int, log: DecisionLog, *,
                hindsight: bool = False) -> dict:
    capture = sctx.capture
    d = t_us + s_to_us(delta_s)
    row = {"capture": capture.capture_id, "view": spec.name, "stream": sctx.stream, "delta_s": delta_s, "k": k,
           "t_k": R.iso(t_us), "d": R.iso(d), "d_us": d, "hindsight": not spec.causal}
    if capture.action is None or capture.P is None or d < capture.P:
        row.update(posed=False, disposition=NOT_POSED, evaluations={"count": 0})
        log.add_request(row)
        return row
    H = capture.H
    E = spec.E
    receipts = {}
    for rec in sctx.records:
        if rec.kind in CHANGE_KINDS:
            receipts[rec.id] = {"available_at": R.iso(rec.available_at),
                                "before_expiry": E is None or rec.available_at < d + s_to_us(E),
                                "by_horizon": rec.available_at <= H}
    row.update(posed=True, receipts=receipts)
    if d > H:
        row.update(first_verdict=None, disposition=CENSORED, disposition_at=R.iso(H), waiting_s=0.0, censored=True,
                   expired=False, posed_after_horizon=True, evaluations={"count": 0})
        log.add_request(row)
        return row
    schedule = candidate_schedule(sctx, hindsight=not spec.causal)
    log.add_schedule(capture.capture_id, sctx.stream, "causal" if spec.causal else "hindsight", schedule)
    instants = request_instants(schedule, d, H, E)
    keys, first, outcome, decided = [], None, None, None
    for index, tau in enumerate(instants):
        entry = _evaluate(spec, sctx, tau, hindsight)
        store = None if entry["store"] == FUTURE else sctx.store(entry["store"])
        keys.append(log.add_evaluation(capture.capture_id, entry, store))
        if index == 0:
            first = entry
            if spec.after_abstain == "escalate" and entry["verdict"] == ABSTAIN:
                outcome, decided = (ESCALATED, tau, ["escalation"]), entry
                break
        if entry["verdict"] != ABSTAIN:
            outcome = (entry["verdict"], tau, entry["deciding"] if entry["verdict"] != ALLOW else [])
            decided = entry
            break
    row.update(first_verdict=first["verdict"], first_eval=keys[0], first_deciding=first["deciding"],
               first_rules=[f"{r['rule']}:{r['verdict']}:{r['reason']}" for r in first["rules"]],
               evaluations={"count": len(keys), "first_us": instants[0], "last_us": instants[len(keys) - 1],
                            "schedule": "causal" if spec.causal else "hindsight"},
               posed_after_horizon=False)
    if outcome is not None:
        disposition, at, source = outcome
        row.update(disposition=disposition, disposition_at=R.iso(at), disposition_source=source,
                   disposition_r7_reason=next((r["reason"] for r in decided["rules"] if r["rule"] == "R7"), None),
                   waiting_s=seconds(at - d), censored=False, expired=False,
                   dispatch_at=R.iso(at) if disposition == ALLOW else None)
    elif E is not None and d + s_to_us(E) <= H:
        row.update(disposition=EXPIRED, disposition_at=R.iso(d + s_to_us(E)), disposition_source=["expiry"],
                   waiting_s=float(E), censored=False, expired=True, dispatch_at=None)
    else:
        row.update(disposition=CENSORED, disposition_at=R.iso(H), disposition_source=["horizon"],
                   waiting_s=seconds(H - d), censored=True, expired=False, dispatch_at=None)
    log.add_request(row)
    return row


def stream_context(capture: CaptureModel, spec: StreamSpec) -> StreamContext:
    records, manifest = perturb(capture.records, spec)
    return StreamContext(capture, spec.name, records, manifest)


def run_q2(capture: CaptureModel, log: DecisionLog, *, views=tuple(CAUSAL_VIEWS), streams=tuple(STREAM_BY_NAME),
           deltas=DELTAS, contexts: dict | None = None) -> dict:
    """The decision path: causal views only (a hindsight name raises ``HindsightRequired``). Returns stream contexts."""
    specs = [causal_view(name) for name in views]
    contexts = {} if contexts is None else contexts
    for stream_name in streams:
        sctx = contexts.get(stream_name) or stream_context(capture, STREAM_BY_NAME[stream_name])
        contexts[stream_name] = sctx
        for spec in specs:
            for delta in deltas:
                for k, t in capture.requests:
                    run_request(spec, sctx, k, t, delta, log)
    return contexts


def run_hindsight(capture: CaptureModel, log: DecisionLog, *, hindsight: bool, views=("c-hind",),
                  streams=tuple(STREAM_BY_NAME), deltas=DELTAS, contexts: dict | None = None) -> dict:
    """The sensitivity path for hindsight views; needs ``hindsight=True``; labelled in every log row."""
    if hindsight is not True:
        raise HindsightRequired("run_hindsight needs hindsight=True")
    specs = [hindsight_view(name, hindsight=True) for name in views]
    contexts = {} if contexts is None else contexts
    for stream_name in streams:
        sctx = contexts.get(stream_name) or stream_context(capture, STREAM_BY_NAME[stream_name])
        contexts[stream_name] = sctx
        for spec in specs:
            for delta in deltas:
                for k, t in capture.requests:
                    run_request(spec, sctx, k, t, delta, log, hindsight=True)
    return contexts
