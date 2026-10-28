#!/usr/bin/env python3
"""policy-gate live audit v1: a label-free bitemporal audit of the v1 policy gate on real rollouts.

No label, no safety claim, no executed action.

For each capture (the 22 Sep rollout, loaded as policy-gate v1 loads it, and the development captures) and each
request k = 1..120 of the target block (decision time t_k = the request's client root span start), a fixed rule
generates two proposed actions on the changed service S:

  * restart_pod on the Pod that the as-known view at t_k (store.as_known(t_k)) names as S's serving Pod (exactly one
    Pod certainly ready, no other possibly ready); otherwise a service-level reference ObjectRef("Pod", service=S);
  * scale_deployment of S's Deployment to 0 replicas (by UID if the as-known view at t_k resolves it, else by service).

Each action is judged AS-KNOWN at knowledge cutoff c = t_k + Delta (Delta in 0, 5, 30 s; observation time t_k) and
CORRECTED (all records, same observation time), with the graph and SQLite resolvers (any disagreement aborts). The
audit counts verdict flips, their direction and rules, the deciding late record of each flip (the first later
arrival at which the gate's own verdict changes) and its lag, and carried-forward reliance.

Model input: <capture>/evidence/{accepted_evidence.jsonl, protocol.json, capture.json} (22 Sep: the pilot-001 files
v1 reads), through replay.load_capture_task / replay.load_attribution_lag_task and policy-gate v1's
build_observations. Never read as input: ground_truth/, evidence/evaluation_only/, incident.json, span Pod claims.

    PYTHONDONTWRITEBYTECODE=1 python3 experiments/policy-gate-live-v1/run_policy_gate_live.py

Outputs (this folder, or --output DIR): results.json, results.csv (one row per decision), SUMMARY.md (rendered from
results.json only); --rerun-check writes rerun_check.txt. Deterministic: no wall clock, no randomness.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

sys.dont_write_bytecode = True  # before any project import: no __pycache__ anywhere
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from aiops_kg import replay as R  # noqa: E402
from aiops_kg.policy_gate import (  # noqa: E402
    ABSTAIN, ALLOW, DENY, NEEDS_APPROVAL, SEVERITY, STATE, Action, BitemporalStore, ObjectRef,
    evaluate, iso, materialize_facts, service_deployment, service_pods,
)

V1_AUDIT = ROOT / "experiments/policy-gate-v1/run_policy_gate_audit.py"
V1_RESULTS = ROOT / "experiments/policy-gate-v1/results.json"
PILOT_REPLAY_RESULTS = ROOT / "experiments/replay-policy-v1/results.json"
# Policy-gate v1's audit module, imported read-only: its loaders, mapping, make_config and late_records are reused.
pga = R.import_script(V1_AUDIT, "policy_gate_audit_v1_readonly_for_live_audit")

DELTAS = (0, 5, 30)                       # seconds after t_k (brief)
ACTION_KINDS = ("restart_pod", "scale_deployment")
ENGINES = ("graph", "sqlite")
CHANGE_WINDOW_SECONDS = 30.0              # v1 primary N; every other value is v1's make_config default
TARGET_BLOCK = "client-target"
EXPECTED_REQUESTS = tuple(range(1, 121))
RULE_IDS = ("R1", "R2", "R3", "R4", "R5", "R6")
LETTER = {ALLOW: "A", NEEDS_APPROVAL: "N", ABSTAIN: "?", DENY: "D"}
V1_CONFIG_FIELDS = ("change_window_seconds", "replica_floor", "blast_radius_k", "blast_radius_direction",
                    "blast_radius_transitive", "stale_view_seconds", "carry_forward_seconds")
# Explicit and ordered: the 22 Sep rollout (v1's comparison point), the recommendationservice rollouts at T0, the
# productcatalogservice rollouts at T0, then I7-001 (productcatalogservice rollout at the reference-block end, before
# the target block). I2-003, I6-003 and I7-001 were added on 1 Oct 2026.
CAPTURES = (
    {"id": "pilot-001", "kind": "pilot", "label": "22 Sep 2026 rollout (rollout-telemetry pilot-001), loaded as v1 loads it"},
    {"id": "I1-001", "kind": "phase3", "label": "Phase 3 I1-001: benign rollout of recommendationservice"},
    {"id": "I2-002", "kind": "phase3", "label": "Phase 3 I2-002: rollout of recommendationservice"},
    {"id": "I6-002", "kind": "phase3", "label": "Phase 3 I6-002: rollout of recommendationservice"},
    {"id": "I2-003", "kind": "phase3", "label": "Phase 3 I2-003: rollout of recommendationservice"},
    {"id": "I6-003", "kind": "phase3", "label": "Phase 3 I6-003: rollout of recommendationservice"},
    {"id": "I4-002", "kind": "phase3", "label": "Phase 3 I4-002: rollout of productcatalogservice"},
    {"id": "I4-003", "kind": "phase3", "label": "Phase 3 I4-003: rollout of productcatalogservice"},
    {"id": "I7-001", "kind": "phase3", "label": "Phase 3 I7-001: rollout of productcatalogservice at the reference-block "
                                                "end, before the target block"},
)
OUTPUT_NAMES = ("results.json", "results.csv", "SUMMARY.md")
REQUEST_FIELDS = ("k", "t_us", "block", "trace_id", "replay_event")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"policy-gate live audit aborted: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return Path(path).resolve().relative_to(ROOT).as_posix()


def seconds(delta: timedelta) -> float:
    return round(delta.total_seconds(), 6)


def vector(decision) -> str:
    """Rule verdict letters R1..R6 (A allow, N needs approval, ? abstain, D deny)."""
    return "".join(LETTER[r.verdict] for r in decision.rules)


def deciding_reasons(decision) -> list[str]:
    if decision.verdict == ALLOW:
        return []
    return [f"{r.rule}:{r.reason}" for r in decision.rules if r.verdict == decision.verdict]


def target_text(ref: ObjectRef) -> str:
    if ref.uid is not None:
        return f"{ref.kind}/{ref.uid}"
    if ref.name is not None:
        return f"{ref.kind} named {ref.name}"
    return f"{ref.kind} of service {ref.service}"


def lag_stats(values) -> dict:
    """n, min, median (statistics.median), max of a list of seconds; None entries are not allowed."""
    items = sorted(values)
    if not items:
        return {"n": 0, "min": None, "median": None, "max": None}
    return {"n": len(items), "min": items[0], "median": round(statistics.median(items), 6), "max": items[-1]}


class Tally:
    """Engine-agreement bookkeeping: every compared pair that agreed (a disagreement aborts the run)."""

    def __init__(self) -> None:
        self.counts = Counter()

    def add(self, what: str, n: int = 1) -> None:
        self.counts[what] += n

    def to_dict(self) -> dict:
        return dict(sorted(self.counts.items()))


# ---------------------------------------------------------------------------
# Loading (model input: evidence only) and cross-checks
# ---------------------------------------------------------------------------
def read_configuration(evidence_file: Path) -> dict:
    """The payload of the single evidence configuration row (what an operator knows at deployment time)."""
    rows = [json.loads(line) for line in evidence_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    config_rows = [row["record"] for row in rows if row["record"]["kind"] == "configuration"]
    check(len(config_rows) == 1, f"{evidence_file}: expected one configuration row, found {len(config_rows)}")
    return config_rows[0]["payload"]


def deployments_from_configuration(payload: dict) -> dict:
    """Immutable service -> Deployment map from the evidence configuration row (app label -> Deployment name)."""
    mapping = {}
    manifests = payload["deployment_manifests"]
    for name in sorted(manifests):
        doc = manifests[name]
        for item in (doc.get("items", []) if isinstance(doc, dict) else []):
            if item.get("kind") != "Deployment":
                continue
            app = item["metadata"].get("labels", {}).get("app")
            check(bool(app), f"Deployment {item['metadata']['name']} has no app label")
            check(mapping.setdefault(app, item["metadata"]["name"]) == item["metadata"]["name"],
                  f"two Deployments for app {app}")
    return dict(sorted(mapping.items()))


def load_pilot(spec: dict) -> dict:
    """22 Sep rollout: v1's inputs through the attribution replay's own loader (read-only)."""
    task = R.load_attribution_lag_task(ROOT)
    ctx = task.context
    protocol, capture, sightings, patch = ctx["protocol"], ctx["capture"], ctx["sightings"], ctx["patch"]
    check(capture["namespace"] == protocol["namespace"], "pilot: capture/protocol namespace")
    check(capture["cluster_incarnation_id"] == protocol["cluster_incarnation_id"], "pilot: cluster incarnation")
    service = protocol["replacement_service"]
    requests = []
    for r in sorted(ctx["requests"], key=lambda r: r["request_index"]):
        # Whitelisted fields only; the loader's span-verified labels are never copied.
        requests.append({"k": r["request_index"], "t_us": r["t_req_us"], "block": None,
                         "trace_id": r["trace_id"], "replay_event": r["request_index"]})
    events = {e.record_id: e.observed_at for e in task.events}
    check(all(events.get(f"request/{r['k']}") == r["t_us"] for r in requests), "pilot: task events differ from requests")
    return {"spec": spec, "service": service, "service_source": "data/raw/rollout-telemetry/pilot-001/protocol.json "
                                                                 "replacement_service",
            "protocol": protocol, "capture_doc": capture, "sightings": sightings, "patch": patch,
            "service_deployments": dict(sorted(protocol["service_deployments"].items())),
            "service_deployments_source": "protocol.json service_deployments (as in v1)",
            "planned_change": {"service": service, "kind": "rollout",
                               "at": f"request_trigger_index {protocol['request_trigger_index']}",
                               "source": "data/raw/rollout-telemetry/pilot-001/protocol.json"},
            "requests": requests, "task_records": task.records, "candidates": task.candidates,
            "input_files": [pga.INPUTS["api_sightings"], pga.INPUTS["protocol"], pga.INPUTS["capture"]],
            "evidence_file": pga.INPUTS["api_sightings"], "saved_replay": PILOT_REPLAY_RESULTS,
            "loader_side_reads_not_used": [
                "replay.load_attribution_lag_task computes span-verified labels (task.truth) inside its request loader; "
                "this audit copies only request index, time and trace ID"]}


def load_phase3(spec: dict) -> dict:
    """A Phase 3 capture: evidence/ only, through replay.load_capture_task (service passed explicitly)."""
    capture_dir = ROOT / "phase3/captures" / spec["id"]
    evidence_dir = capture_dir / "evidence"
    protocol = json.loads((evidence_dir / "protocol.json").read_text(encoding="utf-8"))
    service = protocol.get("replacement_service")
    check(bool(service), f"{spec['id']}: evidence/protocol.json names no replacement_service")
    task = R.load_capture_task(capture_dir, service, root=ROOT)
    ctx = task.context
    check(ctx["service_source"] == "--service", f"{spec['id']}: the loader chose the service itself")
    check(ctx["protocol"] == protocol, f"{spec['id']}: protocol differs")
    capture_doc = ctx["capture"]
    check(bool(capture_doc), f"{spec['id']}: evidence/capture.json missing")
    check(capture_doc.get("namespace") == protocol["namespace"], f"{spec['id']}: capture/protocol namespace")
    patch = pga.patch_receipt(capture_doc)
    check(patch["args"][2] == service, f"{spec['id']}: the rollout patch targets {patch['args'][2]}, not {service}")
    evidence_file = evidence_dir / "accepted_evidence.jsonl"
    configuration = read_configuration(evidence_file)
    mapping = deployments_from_configuration(configuration)
    check(service in mapping, f"{spec['id']}: {service} has no Deployment in the configuration row")
    change = dict(configuration.get("incident", {}).get("change") or {})
    check(change.get("service") == service, f"{spec['id']}: the configuration row's planned change is not {service}")
    items = [r for r in list(ctx["requests"]) + list(ctx["unverified_requests"]) if r.get("block") == TARGET_BLOCK]
    requests = [{"k": r["index"], "t_us": r["t_req_us"], "block": r["block"], "trace_id": r["trace_id"],
                 "replay_event": r.get("event")} for r in sorted(items, key=lambda r: (r["index"], r["t_req_us"]))]
    return {"spec": spec, "service": service, "service_source": "evidence/protocol.json replacement_service",
            "protocol": protocol, "capture_doc": capture_doc, "sightings": ctx["sightings"], "patch": patch,
            "service_deployments": mapping,
            "service_deployments_source": "evidence configuration row: Deployment manifests, app label -> name",
            "planned_change": {**change, "source": "evidence configuration row: incident.change"},
            "requests": requests, "task_records": task.records, "candidates": task.candidates,
            "input_files": [evidence_file, evidence_dir / "protocol.json", evidence_dir / "capture.json"],
            "evidence_file": evidence_file, "saved_replay": capture_dir / "replay/results.json",
            "loader_side_reads_not_used": [
                f"replay.load_capture_task loads {rel(capture_dir / 'ground_truth/ground_truth.json')} into its "
                "returned context and computes span-verified labels (task.truth); this audit reads neither",
                "span Pod claims are used by the loader only to decide which requests the replay scored; this audit "
                "takes every target-block request"]}


def check_requests(inputs: dict) -> dict:
    ks = [r["k"] for r in inputs["requests"]]
    check(tuple(ks) == EXPECTED_REQUESTS, f"{inputs['spec']['id']}: target block is not requests 1..120")
    times = [r["t_us"] for r in inputs["requests"]]
    check(all(a < b for a, b in zip(times, times[1:])), f"{inputs['spec']['id']}: request times not increasing")
    for r in inputs["requests"]:
        check(set(r) == set(REQUEST_FIELDS), "request carries fields beyond the whitelist")
    return {"requests": len(ks), "indices_1_to_120": True, "times_strictly_increasing": True,
            "scored_by_replay": sum(r["replay_event"] is not None for r in inputs["requests"]),
            "not_scored_by_replay": sum(r["replay_event"] is None for r in inputs["requests"])}


def crosscheck_state_records(observations, inputs: dict) -> dict:
    """(1) Pod STATE projection of the audit's record set == the attribution replay's stream."""
    keys = {c.key for c in inputs["candidates"]}
    mine = sorted((o.record_id, o.subject, o.value, R.to_us(o.observed_at), R.to_us(o.available_at))
                  for o in observations if o.predicate == STATE and o.subject in keys)
    theirs = sorted((r.record_id, r.subject, r.value, r.observed_at, r.available_at) for r in inputs["task_records"])
    check(mine == theirs, f"{inputs['spec']['id']}: Pod STATE records differ from the replay task's stream")
    return {"pod_state_records": len(mine), "candidate_pods": len(keys), "equal": True}


def crosscheck_saved_replay(inputs: dict) -> dict:
    """(2) The replay task's stream and request times == those saved by the replay run (identity/time fields only)."""
    path = inputs["saved_replay"]
    check(path.exists(), f"{inputs['spec']['id']}: saved replay output {rel(path)} missing")
    saved = json.loads(path.read_text(encoding="utf-8"))
    evidence = saved["evidence"]
    fields = ("record_id", "subject", "predicate", "value", "observed_at", "available_at", "kind")
    mine = sorted(tuple(r.to_dict()[f] for f in fields) for r in inputs["task_records"])
    theirs = sorted(tuple(d[f] for f in fields) for d in evidence["records"])
    check(mine == theirs, f"{inputs['spec']['id']}: saved replay records differ")
    hashes = saved["inputs_sha256"]
    evidence_key = (rel(inputs["evidence_file"]) if inputs["spec"]["kind"] == "pilot"
                    else "evidence/accepted_evidence.jsonl")
    check(hashes.get(evidence_key) == sha256(inputs["evidence_file"]),
          f"{inputs['spec']['id']}: evidence hash differs from the one the replay recorded")
    if inputs["spec"]["kind"] == "pilot":
        saved_times = {int(k): v for k, v in evidence["t_req"].items()}
        mine_times = {r["k"]: R.iso(r["t_us"]) for r in inputs["requests"]}
        check(saved_times == mine_times, "pilot: saved replay request times differ")
    else:
        mine_scored = sorted((r["k"], R.iso(r["t_us"]), r["trace_id"], r["replay_event"])
                             for r in inputs["requests"] if r["replay_event"] is not None)
        saved_scored = sorted((d["index"], d["t_req"], d["trace_id"], d["event"])
                              for d in evidence["requests"] if d["block"] == TARGET_BLOCK)
        mine_unscored = sorted((r["k"], R.iso(r["t_us"]), r["trace_id"])
                               for r in inputs["requests"] if r["replay_event"] is None)
        saved_unscored = sorted((d["index"], d["t_req_us"], d["trace_id"])
                                for d in evidence["unverified_requests"] if d.get("block") == TARGET_BLOCK)
        check(mine_scored == saved_scored, f"{inputs['spec']['id']}: saved replay requests differ")
        check(mine_unscored == saved_unscored, f"{inputs['spec']['id']}: saved unscored requests differ")
    return {"saved_replay_output": rel(path), "records_equal": True, "request_times_equal": True,
            "evidence_sha256_equals_replay_record": True}


def make_config(service_deployments: dict):
    """v1's own make_config(): N = 30 s, no freeze windows, every other value v1's primary default."""
    return pga.make_config({"service_deployments": service_deployments}, (), CHANGE_WINDOW_SECONDS)


def check_config_against_v1(config) -> dict:
    v1 = json.loads(V1_RESULTS.read_text(encoding="utf-8"))["config_primary"]
    for field in V1_CONFIG_FIELDS:
        check(getattr(config, field) == v1[field], f"configuration field {field} differs from v1's primary")
    check([list(e) for e in config.call_graph] == v1["call_graph"], "call graph differs from v1's")
    check(config.freeze_windows == (), "freeze windows must be empty")
    return {"source": rel(V1_RESULTS), "fields_equal": list(V1_CONFIG_FIELDS) + ["call_graph"], "equal": True}


def build_store(inputs: dict):
    """v1's mapping (rollout-evidence-v1, A1) with the rollout-patch receipt; graph + SQLite resolvers."""
    observations, identity_facts, info = pga.build_observations(inputs["sightings"], inputs["patch"], inputs["protocol"])
    facts, support = materialize_facts(observations)
    all_facts = list(facts) + list(identity_facts)
    return BitemporalStore(all_facts, engines=ENGINES), observations, support, info


# ---------------------------------------------------------------------------
# The scenario-generation rule
# ---------------------------------------------------------------------------
def name_serving_pod(view, config, service: str) -> dict:
    """Which Pod the view names as the service's serving Pod, using only the gate's own helpers."""
    status, deployment_key, _ = service_deployment(view, config, service)
    if status != "resolved":
        return {"class": "none", "reason": f"deployment_{status}", "pod": None, "deployment": None,
                "certainly_ready": 0, "possibly_ready": 0}
    pods = service_pods(view, deployment_key)
    certain = [p.key for p in pods if p.certainly_ready]
    possible = [p.key for p in pods if p.possibly_ready]
    if len(certain) == 1 and len(possible) == 1:
        cls, reason, pod = "named", "single_ready_pod", certain[0]
    elif not possible:
        cls, reason, pod = "none", "no_possibly_ready_pod", None
    else:
        cls, pod = "ambiguous", None
        reason = "several_possibly_ready_pods" if len(possible) > 1 else "ready_pod_unconfirmed"
    return {"class": cls, "reason": reason, "pod": pod, "deployment": deployment_key,
            "certainly_ready": len(certain), "possibly_ready": len(possible)}


def generate(store, config, service: str, t: datetime, request_key: str, *, engines=ENGINES, tally=None):
    """The fixed rule: two proposed actions from the as-known view at t (knowledge cutoff = t). No label input."""
    namings = [name_serving_pod(store.as_known(t, carry_forward_seconds=config.carry_forward_seconds, engine=e),
                                config, service) for e in engines]
    for other in namings[1:]:
        check(other == namings[0], f"graph/SQLite disagree on the naming view of {request_key}")
    if tally is not None:
        tally.add("naming_views_compared", len(engines) - 1)
    naming = namings[0]
    if naming["class"] == "named":
        restart_target = ObjectRef("Pod", uid=naming["pod"].split("/", 1)[1])
    else:
        restart_target = ObjectRef("Pod", service=service)
    if naming["deployment"] is not None:
        scale_target = ObjectRef("Deployment", uid=naming["deployment"].split("/", 1)[1])
        scale_class, scale_reason = "named", "deployment_resolved"
    else:
        scale_target, scale_class, scale_reason = ObjectRef("Deployment", service=service), "none", naming["reason"]
    actions = {
        "restart_pod": (Action(f"{request_key}/restart_pod", "restart_pod", restart_target, service=service),
                        naming["class"], naming["reason"]),
        "scale_deployment": (Action(f"{request_key}/scale_deployment", "scale_deployment", scale_target,
                                    service=service, replicas=0), scale_class, scale_reason),
    }
    return naming, actions


# ---------------------------------------------------------------------------
# Evaluation, flips, deciding records, v1-method attribution, carry-forward
# ---------------------------------------------------------------------------
def evaluate_checked(action, store, config, t: datetime, cutoff: datetime | None, *, engines=ENGINES, tally=None):
    """evaluate() with every engine; cutoff None = the corrected view. Any disagreement aborts."""
    decisions = []
    for engine in engines:
        if cutoff is None:
            view = store.corrected(t, carry_forward_seconds=config.carry_forward_seconds, engine=engine)
        else:
            view = store.view(t, cutoff, carry_forward_seconds=config.carry_forward_seconds, engine=engine)
        decisions.append(evaluate(action, view, config))
    reference = decisions[0].to_dict()
    for other in decisions[1:]:
        check(other.to_dict() == reference,
              f"graph/SQLite disagreement on {action.action_id} at cutoff {iso(cutoff) if cutoff else 'corrected'}")
    if tally is not None:
        tally.add("evaluations_compared", len(engines) - 1)
    return decisions[0]


def classify_flip(known_verdict: str, corrected_verdict: str) -> tuple[str, str, str]:
    """(kind, type, direction): kind none | block_allow | severity_only."""
    if known_verdict == corrected_verdict:
        return "none", "", ""
    kind_type = f"{known_verdict}->{corrected_verdict}"
    if (known_verdict == ALLOW) != (corrected_verdict == ALLOW):
        direction = ("allowed_as_known_blocked_corrected" if known_verdict == ALLOW
                     else "blocked_as_known_allowed_corrected")
        return "block_allow", kind_type, direction
    direction = ("less_severe_corrected" if SEVERITY[corrected_verdict] < SEVERITY[known_verdict]
                 else "more_severe_corrected")
    return "severity_only", kind_type, direction


def rules_differing(a, b) -> list[str]:
    check([r.rule for r in a.rules] == [r.rule for r in b.rules], "rule order differs")
    return [x.rule for x, y in zip(a.rules, b.rules) if x.verdict != y.verdict]


def knowledge_instants(store) -> tuple:
    """Every instant at which the store's knowledge changes (fact versions become available or are superseded)."""
    instants = set()
    for fact in store.facts:
        instants.add(fact.available_at)
        if fact.superseded_at is not None:
            instants.add(fact.superseded_at)
    return tuple(sorted(instants))


def arrivals_index(store) -> dict:
    index = defaultdict(list)
    for fact in store.facts:
        index[fact.available_at].append(fact)
    return {k: tuple(sorted(v, key=lambda f: f.fact_id)) for k, v in index.items()}


def withdrawals_index(store) -> dict:
    index = defaultdict(list)
    for fact in store.facts:
        if fact.superseded_at is not None:
            index[fact.superseded_at].append(fact)
    return {k: tuple(sorted(v, key=lambda f: f.fact_id)) for k, v in index.items()}


def describe_arrivals(arrived, withdrawn) -> tuple[list[str], str]:
    """What the records that arrived at one knowledge instant showed, per subject, and a category for counting.

    first sighting: the object's identity record arrived; a transition: the superseded known-open version held
    another value; a re-sighting: the same value was confirmed again."""
    texts, categories = [], set()
    for subject in sorted({f.subject for f in arrived}):
        mine = [f for f in arrived if f.subject == subject]
        kind = subject.split("/", 1)[0]
        if any(f.predicate == "NAME" for f in mine):
            state = sorted({f.object for f in mine if f.predicate == STATE and f.known_open})
            texts.append(f"{pga.short(subject)} first sighting" + (f" (STATE={'/'.join(state)})" if state else ""))
            categories.add(f"first sighting of a {kind}")
            continue
        parts, changed = [], False
        for predicate in sorted({f.predicate for f in mine}):
            new = sorted({pga.short(f.object) for f in mine if f.predicate == predicate and f.known_open})
            old = sorted({pga.short(f.object) for f in withdrawn
                          if f.subject == subject and f.predicate == predicate and f.known_open})
            if new and old and new != old:
                parts.append(f"{predicate} {'/'.join(old)}→{'/'.join(new)}")
                categories.add(f"{kind} {predicate} {'/'.join(old)}→{'/'.join(new)}")
                changed = True
            elif new and not old:
                parts.append(f"{predicate}={'/'.join(new)} (first value)")
                categories.add(f"{kind} {predicate} first value")
                changed = True
            elif new:
                parts.append(f"{predicate}={'/'.join(new)} (re-sighted)")
        texts.append(f"{pga.short(subject)} " + (", ".join(parts) if parts else "closing version only"))
        if not changed and not parts:
            categories.add(f"{kind} closing version only")
    return texts, ("; ".join(sorted(categories)) or "re-sightings only")


def relied_subjects(store, *decisions) -> set:
    return {store.fact(rid).subject for d in decisions for rid in d.record_ids if not rid.startswith("freeze:")}


def find_deciding(store, action, config, t: datetime, cutoff: datetime, known, corrected, instants, arrivals,
                  withdrawals=None, *, engines=ENGINES, tally=None) -> dict | None:
    """The first knowledge instant after the cutoff at which the gate's own verdict (same action, same observation
    time t) differs from the as-known verdict, and the evidence records that became available at that instant."""
    withdrawals = withdrawals if withdrawals is not None else withdrawals_index(store)
    for instant in instants[bisect_right(instants, cutoff):]:
        decision = evaluate_checked(action, store, config, t, instant, engines=engines, tally=tally)
        if tally is not None:
            tally.add("scan_evaluations")
        if decision.verdict == known.verdict:
            continue
        subjects = relied_subjects(store, known, decision, corrected)
        arrived = [f for f in arrivals.get(instant, ()) if f.subject in subjects]
        relied = bool(arrived)
        if not arrived:
            arrived = list(arrivals.get(instant, ()))
        texts, category = describe_arrivals(arrived, withdrawals.get(instant, ()))
        return {"instant": iso(instant), "lag_seconds": seconds(instant - t),
                "lag_beyond_cutoff_seconds": seconds(instant - cutoff),
                "verdict_at_instant": decision.verdict, "vector_at_instant": vector(decision),
                "equals_corrected_verdict": decision.verdict == corrected.verdict,
                "rules_changed_at_instant": rules_differing(known, decision),
                "records": sorted({f.source_id for f in arrived}),
                "shows": texts, "category": category,
                "facts": [pga._describe_fact(f) for f in arrived],
                "arrived_for_relied_subject": relied}
    return None


def v1_method_late_records(store, pair_index, t: datetime, cutoff: datetime, known, corrected,
                           carry_forward_seconds: float, *, engine: str = "graph") -> list[dict]:
    """policy-gate v1's late_records() with the as-known cutoff generalised from t to ``cutoff`` (no freeze windows).

    At cutoff == t it must return exactly what v1's own function returns (checked in the run)."""
    rows = []
    resolver, freshness = store.engine(engine), carry_forward_seconds
    pairs = set()
    for decision in (known, corrected):
        for rid in decision.record_ids:
            if not rid.startswith("freeze:"):
                fact = store.fact(rid)
                pairs.add((fact.subject, fact.predicate))
    for subject, predicate in sorted(pairs):
        if predicate == "NAME":
            continue
        before = resolver.resolve(subject, predicate, t, cutoff, freshness)
        after = resolver.resolve(subject, predicate, t, corrected.knowledge_cutoff, freshness)
        if pga._answer(store, before) == pga._answer(store, after):
            continue
        for instant in sorted({f.available_at for f in pair_index[(subject, predicate)] if f.available_at > cutoff}):
            probe = resolver.resolve(subject, predicate, t, instant, freshness)
            if pga._answer(store, probe) != pga._answer(store, before):
                arrived = sorted(f.fact_id for f in pair_index[(subject, predicate)] if f.available_at == instant)
                rows.append({
                    "source": "evidence", "kind": "changed_resolution", "subject": subject, "predicate": predicate,
                    "as_known_answer": f"{before.status}:{before.value if before.value else before.reason}",
                    "corrected_answer": f"{after.status}:{after.value if after.value else after.reason}",
                    "available_at": iso(instant), "late_by_seconds": round((instant - t).total_seconds(), 6),
                    "record_ids": arrived,
                    "evidence": sorted({store.fact(fid).source_id for fid in arrived}),
                    "statement": "; ".join(pga._describe_fact(store.fact(fid)) for fid in arrived)})
                break
    for rid in corrected.record_ids:
        if rid.startswith("freeze:"):
            continue
        fact = store.fact(rid)
        if fact.predicate == "NAME" and fact.available_at > cutoff and fact.valid_from <= t:
            rows.append({"source": "evidence", "kind": "identity_discovered_late", "subject": fact.subject,
                         "predicate": "NAME", "as_known_answer": "not visible",
                         "corrected_answer": f"{fact.object} (created {iso(fact.valid_from)})",
                         "available_at": iso(fact.available_at),
                         "late_by_seconds": round((fact.available_at - t).total_seconds(), 6),
                         "record_ids": [rid], "evidence": [fact.source_id],
                         "statement": f"{fact.subject} exists (first sighting)"})
    return sorted(rows, key=lambda r: (r["available_at"], r["subject"], r["predicate"]))


def carried_forward(store, decision, t: datetime) -> dict:
    """Does the verdict rely on a fact carried forward past its last confirming sighting (A1)?

    Verdict-supporting records = record IDs of the rules whose verdict equals the combined verdict (all rules for
    ALLOW). Carried forward = Fact.known_open and confirmed_at < t. Returns whether it does, the largest carried
    age, the number of such facts and, per predicate, the largest carried age."""
    supporting = sorted({rid for r in decision.rules if r.verdict == decision.verdict
                         for rid in r.record_ids if not rid.startswith("freeze:")})
    carried = [f for f in (store.fact(rid) for rid in supporting)
               if f.known_open and f.confirmed_at is not None and f.confirmed_at < t]
    by_predicate = {}
    for fact in carried:
        age = seconds(t - fact.confirmed_at)
        by_predicate[fact.predicate] = max(by_predicate.get(fact.predicate, age), age)
    cutoff = decision.knowledge_cutoff
    listed_absent = {f.subject for f in store.facts_for(STATE)
                     if f.object == "absent" and f.available_at <= cutoff and f.subject in {c.subject for c in carried}}
    only_links_of_absent = bool(carried) and all(f.predicate in ("CONTROLLER", "NODE") and f.subject in listed_absent
                                                 for f in carried)
    return {"relies": bool(carried), "max_age_seconds": max(by_predicate.values()) if carried else None,
            "facts": len(carried), "max_age_by_predicate": dict(sorted(by_predicate.items())),
            "only_links_of_pods_listed_absent": only_links_of_absent}


RETIRING_STATES = frozenset({"terminating", "failed", "succeeded", "absent"})


def hindsight_unknowns(store, config, service: str, action, t: datetime, cutoff: datetime, *, engines=ENGINES,
                       tally=None) -> list[dict]:
    """Descriptive: the service's Pods whose STATE the corrected view cannot resolve at t (so R1/R3 treat them as
    possibly ready), with their role (the restart target or another Pod) and their state in the as-known view.
    Uses only the gate's helpers; computed with every engine and compared."""
    target = f"{action.target.kind}/{action.target.uid}" if action.target.uid else None
    results = []
    for engine in engines:
        corrected = store.corrected(t, carry_forward_seconds=config.carry_forward_seconds, engine=engine)
        known = store.view(t, cutoff, carry_forward_seconds=config.carry_forward_seconds, engine=engine)
        _, deployment_key, _ = service_deployment(corrected, config, service)
        rows = []
        for pod in (service_pods(corrected, deployment_key) if deployment_key else ()):
            if pod.state is not None or not pod.possibly_member:
                continue
            res = known.resolve(pod.key, STATE)
            before = res.value if res.status == "resolved" else (
                "not visible" if res.reason == "no_available_facts" else f"{res.status}:{res.reason}")
            starts = [f.valid_from for f in store.facts_for(STATE)
                      if f.subject == pod.key and f.available_at <= cutoff and f.valid_from is not None]
            first_listed_after_t = bool(starts) and min(starts) > t
            if first_listed_after_t and before == "unknown:outside_validity":
                before = "first listed after t_k"
            kind = ("retiring" if before in RETIRING_STATES else
                    "new" if before in ("not visible", "not_ready", "first listed after t_k") else
                    "was_ready" if before == "ready" else "other")
            rows.append({"pod": pod.key, "role": "target" if pod.key == target else "other",
                         "as_known_state": before, "kind": kind})
        results.append(rows)
    for other in results[1:]:
        check(other == results[0], f"graph/SQLite disagree on the hindsight description of {action.action_id}")
    if tally is not None:
        tally.add("hindsight_descriptions_compared", len(engines) - 1)
    return results[0]


def compact_v1_row(row: dict) -> dict:
    return {"kind": row["kind"], "subject": row["subject"], "predicate": row["predicate"],
            "as_known_answer": row["as_known_answer"], "corrected_answer": row["corrected_answer"],
            "available_at": row["available_at"], "late_by_seconds": row["late_by_seconds"],
            "evidence": row["evidence"]}


def audit_store(store, config, service: str, requests, *, capture_id: str, support=None, deltas=DELTAS,
                engines=ENGINES, tally=None, check_v1_equivalence: bool = True) -> tuple[list[dict], list[dict], dict]:
    """The audit core on one store. Returns (decision rows, flip details, naming per request)."""
    tally = tally if tally is not None else Tally()
    instants = knowledge_instants(store)
    arrivals = arrivals_index(store)
    withdrawals = withdrawals_index(store)
    pair_index = defaultdict(list)
    for fact in store.facts:
        pair_index[(fact.subject, fact.predicate)].append(fact)
    rows, flips, namings = [], [], []
    for request in requests:
        t = R.from_us(request["t_us"])
        request_key = f"{capture_id}/request/{request['k']}"
        naming, actions = generate(store, config, service, t, request_key, engines=engines, tally=tally)
        namings.append({"request": request["k"], **{k: naming[k] for k in ("class", "reason", "pod", "deployment",
                                                                           "certainly_ready", "possibly_ready")}})
        for kind in ACTION_KINDS:
            action, target_class, target_reason = actions[kind]
            corrected = evaluate_checked(action, store, config, t, None, engines=engines, tally=tally)
            for delta in deltas:
                cutoff = t + timedelta(seconds=delta)
                known = evaluate_checked(action, store, config, t, cutoff, engines=engines, tally=tally)
                flip_kind, flip_type, flip_direction = classify_flip(known.verdict, corrected.verdict)
                diffs = rules_differing(known, corrected)
                v1_rows = None
                if diffs:
                    v1_rows = v1_method_late_records(store, pair_index, t, cutoff, known, corrected,
                                                     config.carry_forward_seconds, engine=engines[0])
                    for engine in engines[1:]:
                        check(v1_method_late_records(store, pair_index, t, cutoff, known, corrected,
                                                     config.carry_forward_seconds, engine=engine) == v1_rows,
                              f"graph/SQLite disagree on the v1-method attribution of {action.action_id}")
                        tally.add("v1_method_attributions_compared")
                    if check_v1_equivalence and delta == 0:
                        own = pga.late_records(store, pair_index, {"time": t}, known, corrected, support, config)
                        check(own == v1_rows, f"generalised attribution differs from v1's late_records at Delta=0 "
                                              f"for {action.action_id}")
                        tally.add("v1_late_records_equal_at_delta0")
                deciding, unknowns = None, []
                if flip_kind != "none":
                    deciding = find_deciding(store, action, config, t, cutoff, known, corrected, instants, arrivals,
                                             withdrawals, engines=engines, tally=tally)
                    check(deciding is not None, f"flip without a verdict-changing arrival: {action.action_id}")
                    unknowns = hindsight_unknowns(store, config, service, action, t, cutoff, engines=engines,
                                                  tally=tally)
                unknown_labels = sorted({f"{u['role']} Pod {u['kind']}" for u in unknowns})
                carried = carried_forward(store, known, t)
                earliest = min((r["late_by_seconds"] for r in v1_rows), default=None) if v1_rows else None
                row = {
                    "capture": capture_id, "service": service, "request": request["k"],
                    "replay_event": request["replay_event"], "t_decision": iso(t), "action": kind,
                    "delta_s": delta, "cutoff": iso(cutoff), "target_class": target_class,
                    "target": target_text(action.target), "naming_reason": target_reason,
                    "as_known_verdict": known.verdict, "as_known_vector": vector(known),
                    "as_known_deciding": deciding_reasons(known), "as_known_r1_reason": known.rule("R1").reason,
                    "corrected_verdict": corrected.verdict, "corrected_vector": vector(corrected),
                    "corrected_deciding": deciding_reasons(corrected),
                    "flip": flip_kind != "none", "flip_kind": flip_kind, "flip_type": flip_type,
                    "flip_direction": flip_direction, "rules_differing": diffs,
                    "deciding_instant": deciding["instant"] if deciding else None,
                    "deciding_lag_s": deciding["lag_seconds"] if deciding else None,
                    "deciding_lag_beyond_cutoff_s": deciding["lag_beyond_cutoff_seconds"] if deciding else None,
                    "deciding_records": deciding["records"] if deciding else [],
                    "deciding_category": deciding["category"] if deciding else "",
                    "deciding_shows": deciding["shows"] if deciding else [],
                    "deciding_equals_corrected": deciding["equals_corrected_verdict"] if deciding else None,
                    "deciding_for_relied_subject": deciding["arrived_for_relied_subject"] if deciding else None,
                    "hindsight_unknown": unknown_labels,
                    "v1_method_earliest_lag_s": earliest if flip_kind != "none" else None,
                    "v1_method_earliest_source": (min(v1_rows, key=lambda r: (r["late_by_seconds"], r["subject"],
                                                                              r["predicate"]))["evidence"][0].split(":")[0]
                                                  if (v1_rows and flip_kind != "none") else ""),
                    "v1_method_records": (sorted({e for r in v1_rows for e in r["evidence"]})
                                          if (v1_rows and flip_kind != "none") else []),
                    "carried_forward": carried["relies"], "carried_forward_max_age_s": carried["max_age_seconds"],
                    "carried_forward_facts": carried["facts"],
                    "carried_forward_predicates": sorted(carried["max_age_by_predicate"]),
                    "carried_forward_state_age_s": carried["max_age_by_predicate"].get(STATE),
                    "carried_forward_only_absent_links": carried["only_links_of_pods_listed_absent"],
                    "as_known_r6": known.rule("R6").verdict,
                }
                rows.append(row)
                if flip_kind != "none":
                    flips.append({
                        "capture": capture_id, "request": request["k"], "replay_event": request["replay_event"],
                        "action": kind, "delta_s": delta, "t_decision": iso(t), "cutoff": iso(cutoff),
                        "target": target_text(action.target), "target_class": target_class,
                        "as_known": {"verdict": known.verdict, "vector": vector(known),
                                     "deciding": deciding_reasons(known)},
                        "corrected": {"verdict": corrected.verdict, "vector": vector(corrected),
                                      "deciding": deciding_reasons(corrected)},
                        "flip_kind": flip_kind, "flip_type": flip_type, "flip_direction": flip_direction,
                        "rules_differing": diffs, "deciding_record": deciding,
                        "hindsight_unknown_pods": unknowns,
                        "v1_method": {"earliest_lag_seconds": earliest,
                                      "records": [compact_v1_row(r) for r in (v1_rows or [])]},
                        "carried_forward": carried,
                    })
    return rows, flips, {"requests": namings}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def verdict_counts(values) -> dict:
    counter = Counter(values)
    return {v: counter[v] for v in (DENY, ABSTAIN, NEEDS_APPROVAL, ALLOW)}


def rule_verdict_counts(vectors) -> dict:
    vectors = list(vectors)  # iterated once per rule
    inverse = {letter: verdict for verdict, letter in LETTER.items()}
    out = {}
    for index, rule in enumerate(RULE_IDS):
        counter = Counter(inverse[v[index]] for v in vectors)
        out[rule] = {v: counter[v] for v in (DENY, ABSTAIN, NEEDS_APPROVAL, ALLOW) if counter[v]}
    return out


def aggregate_cell(rows: list[dict]) -> dict:
    flips = [r for r in rows if r["flip"]]
    block_allow = [r for r in flips if r["flip_kind"] == "block_allow"]
    severity = [r for r in flips if r["flip_kind"] == "severity_only"]
    rule_counter = Counter(rule for r in flips for rule in r["rules_differing"])
    carried = [r for r in rows if r["carried_forward"]]
    carried_state = [r for r in carried if r["carried_forward_state_age_s"] is not None]
    predicate_counter = Counter(p for r in carried for p in r["carried_forward_predicates"])
    return {
        "decisions": len(rows),
        "target_classes": dict(sorted(Counter(r["target_class"] for r in rows).items())),
        "as_known_verdicts": verdict_counts(r["as_known_verdict"] for r in rows),
        "corrected_verdicts": verdict_counts(r["corrected_verdict"] for r in rows),
        "as_known_rule_verdicts": rule_verdict_counts(r["as_known_vector"] for r in rows),
        "corrected_rule_verdicts": rule_verdict_counts(r["corrected_vector"] for r in rows),
        "flips": len(flips),
        "block_allow_flips": len(block_allow),
        "block_allow_by_direction": dict(sorted(Counter(r["flip_direction"] for r in block_allow).items())),
        "severity_only_flips": len(severity),
        "severity_only_by_direction": dict(sorted(Counter(r["flip_direction"] for r in severity).items())),
        "flip_types": dict(sorted(Counter(r["flip_type"] for r in flips).items())),
        "flips_by_target_class": dict(sorted(Counter(r["target_class"] for r in flips).items())),
        "rules_differing_in_flips": {rule: rule_counter[rule] for rule in RULE_IDS if rule_counter[rule]},
        "rule_level_differences": sum(bool(r["rules_differing"]) for r in rows),
        "rule_level_differences_without_flip": sum(bool(r["rules_differing"]) and not r["flip"] for r in rows),
        "rules_differing_all_decisions": {rule: n for rule, n in sorted(
            Counter(rule for r in rows for rule in r["rules_differing"]).items())},
        "deciding_lag_seconds": lag_stats(r["deciding_lag_s"] for r in flips),
        "deciding_lag_beyond_cutoff_seconds": lag_stats(r["deciding_lag_beyond_cutoff_s"] for r in flips),
        "deciding_verdict_equals_corrected": sum(bool(r["deciding_equals_corrected"]) for r in flips),
        "v1_method_earliest_lag_seconds": lag_stats(r["v1_method_earliest_lag_s"] for r in flips
                                                    if r["v1_method_earliest_lag_s"] is not None),
        "flips_without_v1_method_record": sum(r["v1_method_earliest_lag_s"] is None for r in flips),
        "deciding_categories": dict(sorted(Counter(r["deciding_category"] for r in flips).items(),
                                           key=lambda kv: (-kv[1], kv[0]))),
        "deciding_without_relied_subject": sum(r["deciding_for_relied_subject"] is False for r in flips),
        "deciding_record_sources": dict(sorted(Counter(src for r in flips for src in
                                                       sorted({rid.split(":")[0] for rid in r["deciding_records"]})
                                                       ).items())),
        "v1_method_earliest_sources": dict(sorted(Counter(r["v1_method_earliest_source"] for r in flips
                                                          if r["v1_method_earliest_source"]).items())),
        "hindsight_unknown_in_flips": dict(sorted(Counter(label for r in flips
                                                          for label in r["hindsight_unknown"]).items())),
        "flips_without_hindsight_unknown": sum(not r["hindsight_unknown"] for r in flips),
        "carried_forward_reliance": len(carried),
        "carried_forward_by_predicate": {p: predicate_counter[p] for p in sorted(predicate_counter)},
        "carried_forward_max_age_seconds": lag_stats(r["carried_forward_max_age_s"] for r in carried),
        "carried_forward_state_reliance": len(carried_state),
        "carried_forward_only_links_of_pods_listed_absent": sum(bool(r["carried_forward_only_absent_links"])
                                                                for r in carried),
        "carried_forward_state_age_seconds": lag_stats(r["carried_forward_state_age_s"] for r in carried_state),
        "as_known_r6_needs_approval": sum(r["as_known_r6"] == NEEDS_APPROVAL for r in rows),
    }


def cells_for(rows: list[dict], capture_id: str) -> list[dict]:
    cells = []
    for kind in ACTION_KINDS:
        for delta in DELTAS:
            subset = [r for r in rows if r["action"] == kind and r["delta_s"] == delta]
            cells.append({"capture": capture_id, "action": kind, "delta_s": delta, **aggregate_cell(subset)})
    return cells


def list_intervals(sightings, window_start: datetime, window_end: datetime) -> dict:
    """Seconds between consecutive complete lists of each resource kind (host receipt clock): over the whole capture,
    and for the intervals ending inside the decision window [t_1, t_120 + max Delta]."""
    lists = defaultdict(set)
    for row in sightings:
        lists[row["resource"]].add((row["observed_at"], row["snapshot_id"]))
    out = {}
    for resource in sorted(lists):
        items = sorted(lists[resource])
        pairs = list(zip(items, items[1:]))
        out[resource] = {
            "lists": len(items),
            "whole_capture": lag_stats(seconds(b[0] - a[0]) for a, b in pairs),
            "decision_window": lag_stats(seconds(b[0] - a[0]) for a, b in pairs
                                         if window_start < b[0] <= window_end)}
    return out


def requests_in_transition_gaps(transitions: list[dict], requests) -> list[int]:
    """Requests whose decision time t_k lies inside the uncertainty interval of a value change of the changed
    service's objects: [last old sighting, first new sighting), or [recorded creation, first sighting) for an object
    created during the capture. Only there can the as-known view at t_k (last sightings carried forward) and the
    corrected view resolve different states for these objects (descriptive; added 1 Oct 2026)."""
    gaps = [(pga.ts(t["last_old_observed_at"]), pga.ts(t["first_new_observed_at"])) for t in transitions]
    return [r["k"] for r in requests if any(a <= R.from_us(r["t_us"]) < b for a, b in gaps)]


def rollout_timing(transitions: list[dict], inputs: dict, patch: dict | None, rows: list[dict]) -> dict:
    """Where the decision times fall relative to the changed service's transitions (descriptive, from the evidence)."""
    requests = inputs["requests"]
    t_1, t_n = R.from_us(requests[0]["t_us"]), R.from_us(requests[-1]["t_us"])
    inside = requests_in_transition_gaps(transitions, requests)
    last_listed = max((pga.ts(t["first_new_observed_at"]) for t in transitions), default=None)
    last_available = max((pga.ts(t["first_new_available_at"]) for t in transitions), default=None)
    flips0 = sorted({r["request"] for r in rows if r["flip"] and r["delta_s"] == DELTAS[0]})
    response = pga.ts(patch["response_received_at"]) if patch else None
    return {
        "planned_change": inputs["planned_change"],
        "patch_response_minus_t1_seconds": seconds(response - t_1) if response else None,
        "last_change_first_listed_at": iso(last_listed), "last_change_first_available_at": iso(last_available),
        "last_change_first_available_minus_t1_seconds": seconds(last_available - t_1) if last_available else None,
        "first_change_listed_after_t1": iso(min((pga.ts(t["first_new_observed_at"]) for t in transitions
                                                 if pga.ts(t["first_new_observed_at"]) > t_1), default=None)),
        "decision_window": [iso(t_1), iso(t_n)],
        "requests_inside_transition_gaps": len(inside),
        "requests_inside_transition_gaps_range": [inside[0], inside[-1]] if inside else None,
        "flips_at_delta0_requests": len(flips0),
        "flips_at_delta0_inside_gaps": sum(k in set(inside) for k in flips0),
    }


def service_transitions(observations, info, inputs: dict) -> list[dict]:
    """v1's transitions() restricted to the changed service's Deployment, ReplicaSets and Pods (context only)."""
    deployment_name = inputs["service_deployments"][inputs["service"]]
    identities = info["identities"]
    deployments = {k for k, v in identities.items() if k.startswith("Deployment/") and v["name"] == deployment_name}
    replicasets, pods = set(), set()
    for row in inputs["sightings"]:
        owners = [o for o in row["resource_data"]["metadata"].get("ownerReferences", []) if o.get("controller")]
        if row["kind"] == "ReplicaSet" and owners and f"Deployment/{owners[0]['uid']}" in deployments:
            replicasets.add(row["subject"])
    for row in inputs["sightings"]:
        owners = [o for o in row["resource_data"]["metadata"].get("ownerReferences", []) if o.get("controller")]
        if row["kind"] == "Pod" and owners and f"ReplicaSet/{owners[0]['uid']}" in replicasets:
            pods.add(row["subject"])
    check(pods == {c.key for c in inputs["candidates"]}, "service Pods by owner chain differ from the replay's")
    subjects = deployments | replicasets | pods
    started = pga.ts(inputs["capture_doc"]["started_at"])
    return pga.transitions(observations, {k: v for k, v in identities.items() if k in subjects}, started)


# ---------------------------------------------------------------------------
# One capture, the whole run
# ---------------------------------------------------------------------------
def run_capture(spec: dict, tally: Tally) -> dict:
    inputs = load_pilot(spec) if spec["kind"] == "pilot" else load_phase3(spec)
    request_check = check_requests(inputs)
    store, observations, support, info = build_store(inputs)
    try:
        config = make_config(inputs["service_deployments"])
        config_check = check_config_against_v1(config)
        cross = {"state_records_vs_replay_task": crosscheck_state_records(observations, inputs),
                 "replay_task_vs_saved_replay_output": crosscheck_saved_replay(inputs),
                 "target_block": request_check, "configuration_vs_v1": config_check}
        rows, flips, naming = audit_store(store, config, inputs["service"], inputs["requests"],
                                          capture_id=spec["id"], support=support, tally=tally)
        facts = store.facts
        transitions = service_transitions(observations, info, inputs)
        timing = rollout_timing(transitions, inputs, info["patch"], rows)
    finally:
        store.close()
    service = inputs["service"]
    deployment_name = inputs["service_deployments"][service]
    service_objects = {k: {"name": v["name"], "created_at": iso(v["created_at"]),
                           "first_available_at": iso(v["available_at"])}
                       for k, v in sorted(info["identities"].items())
                       if v["name"] == deployment_name or v["name"].startswith(deployment_name + "-")}
    times = [r["t_us"] for r in inputs["requests"]]
    classes = Counter(n["class"] for n in naming["requests"])
    named_pods = Counter(n["pod"] for n in naming["requests"] if n["pod"])
    capture = {
        "capture": spec["id"], "label": spec["label"], "kind": spec["kind"], "service": service,
        "service_source": inputs["service_source"],
        "loader_side_reads_not_used": inputs["loader_side_reads_not_used"],
        "service_deployments": inputs["service_deployments"],
        "service_deployments_source": inputs["service_deployments_source"],
        "evidence": {
            "namespace": inputs["protocol"]["namespace"],
            "cluster_incarnation_id": inputs["protocol"]["cluster_incarnation_id"],
            "node_names": sorted({s["name"] for s in inputs["sightings"] if s["kind"] == "Node"}),
            "api_sightings": len(inputs["sightings"]),
            "sightings_by_resource": dict(sorted(Counter(s["resource"] for s in inputs["sightings"]).items())),
            "observations_by_predicate": dict(sorted(Counter(o.predicate for o in observations).items())),
            "fact_versions": len(facts),
            "fact_versions_by_predicate": dict(sorted(Counter(f.predicate for f in facts).items())),
            "knowledge_instants": len(knowledge_instants_from(facts)),
            "first_sighting_observed_at": iso(min(s["observed_at"] for s in inputs["sightings"])),
            "last_record_available_at": iso(max(f.available_at for f in facts)),
            "rollout_patch_receipt": info["patch"],
            "service_objects": service_objects,
            "service_transitions": transitions,
            "service_value_change_gap_seconds": lag_stats(t["uncertainty_gap_seconds"] for t in transitions
                                                          if t["predicate"] != "EXISTS"
                                                          and not t["first_new_record"].startswith("receipt:")),
            "list_interval_seconds": list_intervals(inputs["sightings"], R.from_us(times[0]),
                                                    R.from_us(times[-1]) + timedelta(seconds=max(DELTAS))),
            "target_block": {"requests": len(times), "first_t": R.iso(times[0]), "last_t": R.iso(times[-1]),
                             "request_30_t": R.iso(inputs["requests"][29]["t_us"]),
                             "request_spacing_seconds": lag_stats(round((b - a) / 1e6, 6)
                                                                  for a, b in zip(times, times[1:])),
                             "scored_by_replay": request_check["scored_by_replay"],
                             "not_scored_by_replay": request_check["not_scored_by_replay"]},
        },
        "cross_checks": cross,
        "rollout_timing": timing,
        "naming": {"classes": {c: classes[c] for c in ("named", "none", "ambiguous")},
                   "named_pods": dict(sorted(named_pods.items())),
                   "first_request_naming_each_pod": {pod: min(n["request"] for n in naming["requests"]
                                                              if n["pod"] == pod) for pod in sorted(named_pods)}},
        "cells": cells_for(rows, spec["id"]),
    }
    return {"capture": capture, "rows": rows, "flips": flips}


def knowledge_instants_from(facts) -> set:
    instants = {f.available_at for f in facts}
    instants.update(f.superseded_at for f in facts if f.superseded_at is not None)
    return instants


def v1_reference() -> dict:
    """v1's own counts, recomputed from its results.json (read-only) the way its key findings computed them."""
    v1 = json.loads(V1_RESULTS.read_text(encoding="utf-8"))
    flips = v1["flips_primary"]
    evidence = [s for s in v1["scenarios"] if s["verdict_flip"] and "evidence" in s["late_record_sources"]]
    earliest = [min(x["late_by_seconds"] for x in s["late_records"] if x["source"] == "evidence") for s in evidence]
    return {"source": rel(V1_RESULTS), "scenarios": flips["scenarios"],
            "verdict_flips": flips["verdict_flips"], "evidence_driven_flips": len(evidence),
            "earliest_evidence_late_record_seconds": lag_stats(earliest),
            "labels": "constructed scenarios labelled together with the gate rules; not used here"}


def build_limitations(captures: list[dict], config, v1: dict) -> list[str]:
    """'What this does not show', with every number taken from the computed results."""
    n = len(captures)
    services = Counter(c["service"] for c in captures)
    incarnations = sorted({c["evidence"]["cluster_incarnation_id"] for c in captures})
    nodes = sorted({name for c in captures for name in c["evidence"]["node_names"]})
    spacing = [c["evidence"]["target_block"]["request_spacing_seconds"]["median"] for c in captures]
    return [
        "No labels: nothing here says which verdict is right, and there is no safety, precision or correctness rate. "
        "A flip says only that the verdict depended on records not yet available at the cutoff.",
        "The actions are generated by a fixed rule (restart the Pod the as-known view names as serving; scale the "
        "Deployment to 0), not proposed by an operator or an automation. With single-replica services and floor "
        f"{config.replica_floor}, both actions are blocked by R3 whenever one ready Pod is known, so block↔allow flips "
        "are rare by construction.",
        f"Placement: one decision per target-block request (median spacing {min(spacing):.3f}–{max(spacing):.3f} s "
        "per capture), not around transitions. Flip counts are therefore not comparable to v1's "
        f"{v1['verdict_flips']}/{v1['scenarios']}, whose scenarios were placed around real transitions on purpose; "
        "consecutive decisions share most of their evidence and are not independent observations.",
        f"{n} rollouts (" + ", ".join(f"{v} of {k}" for k, v in sorted(services.items())) + ") of single-replica "
        "services, " + (f"all on the same kind cluster incarnation ({incarnations[0][:8]}) with one node "
                        f"({nodes[0]})" if len(incarnations) == 1 and len(nodes) == 1 else
                        f"on cluster incarnations {', '.join(i[:8] for i in incarnations)} with nodes "
                        f"{', '.join(nodes)}")
        + ", run on one laptop. The Phase 3 incidents I2, I4, I6 and I7 also injected a CPU fault (I1 did not); its "
        "specification is evaluator-only and was not read, so only its Kubernetes-visible traces, if any, are part "
        "of the evidence.",
        "Assumption A1 (snapshot carry-forward) shapes both views: as-known carries the last sighting forward, and "
        "hindsight leaves the interval between two different sightings unknown. A hindsight ABSTAIN inside a polling "
        "gap is a property of this mapping and of the gate treating an unknown Pod state as possibly ready, not "
        "evidence that the Pod was ready.",
        f"R4 (no freeze windows), R5 (constant per service) and R6 (S = {config.stale_view_seconds:g} s) are not "
        "exercised by these actions.",
        "Lags compare the request's span clock (t_k) with the host pipeline clock (availability); the clocks are not "
        "calibrated against each other.",
        "No baseline gate without time handling is evaluated.",
    ]


def cross_capture_table(captures: list[dict]) -> list[dict]:
    table = []
    for kind in ACTION_KINDS:
        for delta in DELTAS:
            for cap in captures:
                cell = next(c for c in cap["cells"] if c["action"] == kind and c["delta_s"] == delta)
                table.append({"capture": cap["capture"], "service": cap["service"], "action": kind, "delta_s": delta,
                              "decisions": cell["decisions"], "flips": cell["flips"],
                              "block_allow_flips": cell["block_allow_flips"],
                              "severity_only_flips": cell["severity_only_flips"],
                              "rule_level_differences": cell["rule_level_differences"],
                              "deciding_lag_seconds": cell["deciding_lag_seconds"],
                              "deciding_lag_beyond_cutoff_seconds": cell["deciding_lag_beyond_cutoff_seconds"],
                              "v1_method_earliest_lag_seconds": cell["v1_method_earliest_lag_seconds"],
                              "carried_forward_reliance": cell["carried_forward_reliance"],
                              "carried_forward_state_reliance": cell["carried_forward_state_reliance"]})
    return table


def build_results() -> tuple[dict, list[dict]]:
    tally = Tally()
    per_capture = [run_capture(spec, tally) for spec in CAPTURES]
    captures = [p["capture"] for p in per_capture]
    rows = [r for p in per_capture for r in p["rows"]]
    flips = [f for p in per_capture for f in p["flips"]]
    config = make_config({})  # scalar fields only; the service map is per capture
    v1 = v1_reference()
    requests_per_capture = sorted({c["evidence"]["target_block"]["requests"] for c in captures})
    check(requests_per_capture == [len(EXPECTED_REQUESTS)], "every capture must hold the same target block size")
    results = {
        "kind": "policy_gate_live_audit_label_free_not_a_safety_evaluation",
        "python": platform.python_version(),
        "configuration": {
            "built_with": "experiments/policy-gate-v1/run_policy_gate_audit.py make_config(protocol, (), 30.0)",
            **{f: getattr(config, f) for f in V1_CONFIG_FIELDS},
            "freeze_windows": [], "call_graph": [list(e) for e in config.call_graph],
            "service_deployments": "per capture (see captures[*].service_deployments)",
            "checked_equal_to": {"source": v1["source"], "section": "config_primary"}},
        "generation_rule": {
            "target_block_requests": requests_per_capture[0], "scale_replicas": 0,
            "decision_time": "t_k = client root span start of target-block request k, as in the attribution replay",
            "naming_view": "store.as_known(t_k): observation time = knowledge cutoff = t_k; graph and SQLite",
            "restart_pod": "the Pod the naming view names as the changed service's serving Pod (exactly one Pod "
                           "certainly ready and no other possibly ready; gate helpers service_deployment/"
                           "service_pods/PodInfo); otherwise ObjectRef('Pod', service=S) (class none or ambiguous)",
            "scale_deployment": "replicas 0; the service's Deployment by UID if the naming view resolves it, else "
                                "ObjectRef('Deployment', service=S)",
            "as_known": "evaluate(action, store.view(t_k, t_k + Delta)) for every Delta in deltas_seconds",
            "corrected": "evaluate(action, store.corrected(t_k)): all records, same observation time",
            "labels": "none"},
        "deltas_seconds": list(DELTAS), "actions": list(ACTION_KINDS), "engines": list(ENGINES),
        "definitions": {
            "flip": "as-known verdict != corrected verdict",
            "block_allow_flip": "exactly one of the two verdicts is ALLOW",
            "severity_only_flip": "both verdicts blocking (DENY, ABSTAIN or NEEDS_APPROVAL), different",
            "deciding_late_record": "first knowledge instant after the cutoff at which the gate's own verdict (same "
                                    "action, observation time t_k) differs from the as-known verdict; the records "
                                    "whose fact versions became available then, for subjects the decisions relied on",
            "deciding_lag": "deciding instant - t_k (s); lag beyond cutoff = deciding instant - (t_k + Delta)",
            "v1_method_earliest_lag": "v1 late_records() generalised to cutoff t_k + Delta; earliest row per flip",
            "carried_forward": "a verdict-supporting fact with known_open and confirmed_at < t_k (A1 carry-forward "
                               "past the last confirming sighting)",
            "hindsight_unknown": "descriptive, added after the first run: Pods of the service whose STATE the "
                                 "corrected view cannot resolve at t_k (R1/R3 treat them as possibly ready), by role "
                                 "(target / other) and as-known state (retiring = terminating, failed, succeeded or "
                                 "absent; new = not visible or not_ready; was_ready = ready)",
            "deciding_category": "descriptive, added after the first run: what the deciding records showed (first "
                                 "sighting of an object; a transition old->new revealed by a sighting; re-sighting)",
            "median": "statistics.median (mean of the two middle values for an even count)"},
        "v1_reference": v1,
        "captures": captures,
        "n_captures": len(captures),
        "cross_capture_table": cross_capture_table(captures),
        "engine_agreement": {**tally.to_dict(), "disagreements": 0,
                             "statement": "graph and SQLite returned identical results for every naming view, every "
                                          "gate evaluation (including the deciding-record scan evaluations), every "
                                          "v1-method attribution and every hindsight description; any disagreement "
                                          "would have aborted the run"},
        "design_size": {"as_known_decisions": len(rows), "per_capture": {c["capture"]: sum(x["decisions"]
                                                                                          for x in c["cells"])
                                                                          for c in captures},
                        "note": "counts are reported per capture x action x Delta; nothing is pooled into a rate"},
        "gate_api_wrappers": [
            "The gate has no 'serving Pod' query: the naming step calls its public helpers service_deployment() and "
            "service_pods() and reads PodInfo.certainly_ready / possibly_ready.",
            "The gate exposes no carried-forward flag on a decision: the script reads Fact.known_open and "
            "Fact.confirmed_at of the verdict-supporting records from the store.",
            "The gate has no 'deciding record' query: the script re-evaluates the unchanged gate at every later "
            "knowledge instant (store.view(t_k, instant)) and reports the first verdict change.",
            "v1's late_records() hard-codes the as-known cutoff = t; the script carries a generalised copy and "
            "checks it against v1's own function at Delta = 0.",
            "A cutoff later than the observation time uses the public store.view(observed_at, knowledge_cutoff); "
            "as_known() is only the Delta = 0 case.",
            "The gate's Decision does not say which Pod made R3 uncertain: the hindsight description re-runs the "
            "gate's service_pods() on the corrected view and resolves each unknown Pod's STATE on the as-known view."],
        "flips": flips,
        "limitations": build_limitations(captures, config, v1),
    }
    return results, rows


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
CSV_COLUMNS = ("capture", "service", "request", "replay_event", "t_decision", "action", "delta_s", "cutoff",
               "target_class", "target", "naming_reason", "as_known_verdict", "as_known_vector",
               "as_known_deciding", "as_known_r1_reason", "corrected_verdict", "corrected_vector",
               "corrected_deciding", "flip", "flip_kind", "flip_type", "flip_direction", "rules_differing",
               "deciding_instant", "deciding_lag_s", "deciding_lag_beyond_cutoff_s", "deciding_records",
               "deciding_category", "deciding_equals_corrected", "hindsight_unknown", "v1_method_earliest_lag_s",
               "v1_method_earliest_source", "v1_method_records", "carried_forward", "carried_forward_max_age_s",
               "carried_forward_facts", "carried_forward_predicates", "carried_forward_state_age_s",
               "carried_forward_only_absent_links", "as_known_r6")


def csv_text(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        values = []
        for column in CSV_COLUMNS:
            value = row[column]
            if isinstance(value, list):
                value = ";".join(value)
            elif value is None:
                value = ""
            elif isinstance(value, bool):
                value = "true" if value else "false"
            values.append(value)
        writer.writerow(values)
    return buffer.getvalue()


def fmt_stats(stats: dict) -> str:
    if not stats or not stats["n"]:
        return "-"
    return f"{stats['min']:.3f} / {stats['median']:.3f} / {stats['max']:.3f}"


def fmt_range(stats: dict) -> str:
    if not stats or not stats["n"]:
        return "-"
    return f"{stats['min']:.3f}–{stats['max']:.3f}"


def fmt_verdicts(counts: dict) -> str:
    return " / ".join(str(counts.get(v, 0)) for v in (DENY, ABSTAIN, NEEDS_APPROVAL, ALLOW))


def fmt_counter(counter: dict) -> str:
    return ", ".join(f"{k} {v}" for k, v in counter.items()) or "-"


def cell_of(capture: dict, action: str, delta: int) -> dict:
    return next(c for c in capture["cells"] if c["action"] == action and c["delta_s"] == delta)


def change_text(change: dict) -> str:
    text = str(change.get("at", "-"))
    if change.get("settle_seconds") is not None:
        text += f", settle {change['settle_seconds']:g} s"
    return text


def settled_capture_paragraph(c: dict, config: dict) -> str | None:
    """For a capture whose rollout finished before its first decision time: what the rule-generated actions can
    observe, stated only as far as results.json supports it (every clause below is checked)."""
    timing, ev = c["rollout_timing"], c["evidence"]
    if timing["requests_inside_transition_gaps"] != 0 or timing["last_change_first_available_minus_t1_seconds"] is None:
        return None
    if timing["last_change_first_available_minus_t1_seconds"] >= 0:
        return None
    named = c["naming"]["named_pods"]
    t_1 = timing["decision_window"][0]
    absent_before = [tr for tr in ev["service_transitions"] if tr["predicate"] == "STATE" and tr["to"] == "absent"
                     and tr["first_new_available_at"] < t_1]
    zero = all(cell["flips"] == 0 for cell in c["cells"])
    parts = [f"`{c['capture']}` (planned change at {change_text(timing['planned_change'])}): the rollout finished "
             "before the first target request. The patch response came "
             f"{-timing['patch_response_minus_t1_seconds']:.3f} s before t_1 ({t_1[11:23]}), and the last change of "
             f"the service's objects was first listed at {timing['last_change_first_listed_at'][11:23]} (available "
             f"{-timing['last_change_first_available_minus_t1_seconds']:.3f} s before t_1). None of the "
             f"{c['evidence']['target_block']['requests']} decision times lies inside a transition gap, so at every "
             "t_k the as-known view (last sightings carried forward) and the corrected view (all records) resolve "
             "the same states for the service's objects"]
    if len(named) == 1 and c["naming"]["classes"]["named"] == c["evidence"]["target_block"]["requests"]:
        parts[-1] += (f": the rule named the same Pod (`{next(iter(named))[4:12]}`, first listed "
                      f"{ev['service_objects'].get(next(iter(named)), {}).get('first_available_at', '-')[11:23]}) "
                      "for every request")
    if absent_before:
        parts[-1] += (", the replaced Pod had been listed absent at "
                      + ", ".join(tr["first_new_observed_at"][11:23] for tr in absent_before))
    if all(set(cell["as_known_rule_verdicts"]["R2"]) == {ALLOW} for cell in c["cells"]):
        parts[-1] += (f", and R2 returned ALLOW in every decision (the latest generation change of the target's "
                      f"ReplicaSet and Deployment began at least N = {config['change_window_seconds']:g} s before "
                      "every t_k)")
    parts[-1] += "."
    same = all(cell["as_known_verdicts"] == cell["corrected_verdicts"] == {DENY: cell["decisions"], ABSTAIN: 0,
                                                                          NEEDS_APPROVAL: 0, ALLOW: 0}
               and cell["as_known_rule_verdicts"]["R3"] == cell["corrected_rule_verdicts"]["R3"]
               == {DENY: cell["decisions"]} for cell in c["cells"])
    if same and zero:
        parts.append("Both actions therefore get the same verdict in both views at every Δ: DENY by R3, because "
                     f"with floor {config['replica_floor']} the named Pod is the only ready replica (restart) and "
                     "scaling to 0 removes it; so there are 0 flips at every Δ.")
    parts.append("The rule-generated actions observe only the settled post-rollout state: late records can change a "
                 "verdict only for decision times inside a transition gap, and this capture's target block has none.")
    return " ".join(parts)


def computed_observations(res: dict) -> list[str]:
    """Statements computed from results.json; each is per capture or per cell, never a pooled rate."""
    caps, deltas = res["captures"], res["deltas_seconds"]
    cells = [cell for c in caps for cell in c["cells"]]
    n_cells = len(cells)
    lines = []
    classes = {c["capture"]: c["naming"]["classes"] for c in caps}
    if all(cls["none"] == 0 and cls["ambiguous"] == 0 for cls in classes.values()):
        lines.append("The as-known view at t_k named exactly one serving Pod for every request of every capture ("
                     + ", ".join(f"`{cap}` {cls['named']}" for cap, cls in classes.items())
                     + "), so no service-level reference was generated and the gate's unresolved-target path was not "
                     "exercised by these captures (the unit tests exercise it).")
    else:
        lines.append("Target classes per capture: " + "; ".join(
            f"`{cap}` " + ", ".join(f"{k} {v}" for k, v in cls.items()) for cap, cls in classes.items()) + ".")
    types = sorted({t for cell in cells for t in cell["flip_types"]})
    with_flips = [cell for cell in cells if cell["flips"]]
    if types == ["DENY->ABSTAIN"]:
        lines.append(f"Every flip in every one of the {n_cells} capture × action × Δ cells is DENY→ABSTAIN: the "
                     "as-known view denied and the corrected view abstained. No flip went the other way and none "
                     "involved NEEDS_APPROVAL or ALLOW.")
    else:
        lines.append("Flip types seen (per cell in the per-capture tables): " + ", ".join(types) + ".")
    block_cells = [cell for cell in cells if cell["block_allow_flips"]]
    if not block_cells:
        lines.append(f"block↔allow flips: 0 in each of the {n_cells} cells.")
    else:
        lines.append("block↔allow flips: " + "; ".join(
            f"`{cell['capture']}` {cell['action']} Δ={cell['delta_s']}: {cell['block_allow_flips']} "
            f"({fmt_counter(cell['block_allow_by_direction'])})" for cell in block_cells) + ".")
    if with_flips and all(cell["rules_differing_in_flips"].get("R3", 0) == cell["flips"] for cell in with_flips):
        lines.append("R3 (replica floor) differs between the two views in every flip. "
                     + "Other rules that also differ, per cell: " + "; ".join(
                         f"`{cell['capture']}` {cell['action']} Δ={cell['delta_s']}: "
                         + (fmt_counter({k: v for k, v in cell["rules_differing_in_flips"].items() if k != "R3"})
                            if any(k != "R3" for k in cell["rules_differing_in_flips"]) else "none")
                         for cell in with_flips) + ".")
    for action in res["actions"]:
        per = [(c["capture"], [cell_of(c, action, d)["flips"] for d in deltas]) for c in caps]
        lines.append(f"`{action}` flips at Δ = {' / '.join(str(d) for d in deltas)} s, per capture: "
                     + "; ".join(f"`{cap}` {' / '.join(str(x) for x in counts)}" for cap, counts in per) + ".")
    scale = [cell_of(c, "scale_deployment", d) for c in caps for d in deltas]
    if all(cell["flips"] == 0 for cell in scale):
        r3_deny = all(cell["as_known_rule_verdicts"]["R3"] == {DENY: cell["decisions"]}
                      and cell["corrected_rule_verdicts"]["R3"] == {DENY: cell["decisions"]} for cell in scale)
        diff_rules = sorted({r for cell in scale for r in cell["rules_differing_all_decisions"]})
        lines.append("`scale_deployment` to 0 never flips"
                     + (": R3 returns DENY in both views for every scale decision" if r3_deny else "")
                     + (f", so its rule-level differences (rules: {', '.join(diff_rules)}; per capture at Δ = 0: "
                        + ", ".join(f"`{c['capture']}` {cell_of(c, 'scale_deployment', 0)['rule_level_differences']}"
                                    for c in caps) + ") never change the combined verdict" if diff_rules else "")
                     + ".")
    first = deltas[0]
    def lag_range(c, key):
        cell = cell_of(c, "restart_pod", first)
        return f"{fmt_range(cell[key])} s (n = {cell['flips']})" if cell["flips"] else "no flips"
    lines.append(f"Deciding lag at Δ = {first} s (restart_pod; min–max over the cell's flips), per capture: "
                 + "; ".join(f"`{c['capture']}` {lag_range(c, 'deciding_lag_seconds')}" for c in caps)
                 + ". The v1-method earliest-record lag for the same flips: "
                 + "; ".join(f"`{c['capture']}` {lag_range(c, 'v1_method_earliest_lag_seconds')}" for c in caps)
                 + f". v1 reported {fmt_range(res['v1_reference']['earliest_evidence_late_record_seconds'])} s (earliest "
                 f"causal record) for its {res['v1_reference']['evidence_driven_flips']} evidence-driven flips on the "
                 "22 Sep rollout; those scenarios were placed around transitions, these decisions at every request.")
    mech = []
    for c in caps:
        cell = cell_of(c, "restart_pod", first)
        if cell["flips"]:
            mech.append(f"`{c['capture']}` " + fmt_counter(cell["hindsight_unknown_in_flips"])
                        + f" (of {cell['flips']})")
    if mech:
        lines.append(f"Why the corrected view abstains, at Δ = {first} s (restart_pod; Pods whose STATE the corrected "
                     "view cannot resolve at t_k, by role and as-known state; a flip can count under several): "
                     + "; ".join(mech) + ". 'other Pod new' is a replacement Pod that at the cutoff was not yet listed, was "
                     "listed not_ready, or was first listed only after t_k; 'other Pod retiring' is a Pod the as-known "
                     "view held as terminating "
                     "or failed, whose state between two sightings is unknown in hindsight and is counted by R3 as "
                     "possibly ready: the gate has no lifecycle rule (unlike the replay's K1) that a Pod seen "
                     "terminating or failed cannot be ready later; 'target Pod was_ready' is the named target itself, "
                     "ready as-known and unknown in hindsight (R1).")
    gaps = "; ".join(f"`{c['capture']}` {fmt_range(c['evidence']['service_value_change_gap_seconds'])} s"
                     for c in caps)
    lines.append("Polling gaps at the changed service's value changes (last old sighting to first new sighting, "
                 f"per capture): {gaps}. A decision taken inside such a gap is carried forward as-known and becomes "
                 "unknown in hindsight (assumption A1).")
    lists = "; ".join(f"`{c['capture']}` {fmt_stats(c['evidence']['list_interval_seconds']['pods']['decision_window'])}"
                      f" (whole capture {fmt_stats(c['evidence']['list_interval_seconds']['pods']['whole_capture'])})"
                      for c in caps)
    n_req = res["generation_rule"]["target_block_requests"]
    lines.append(f"Interval between consecutive Pod lists inside the decision window [t_1, t_{n_req} + "
                 f"{deltas[-1]} s], min / median / max s, per capture: {lists}.")
    sources = Counter()
    for cell in with_flips:
        sources.update(cell["deciding_record_sources"])
    if with_flips and set(sources) <= {"api", "absence"}:
        lines.append("Every deciding record in every cell is an API list sighting (`api:`), in some flips together "
                     "with an absence derived from the same list (`absence:`); per capture at Δ = "
                     f"{first} s (flips with each source): "
                     + "; ".join(f"`{c['capture']}` {fmt_counter(cell_of(c, 'restart_pod', first)['deciding_record_sources'])}"
                                 for c in caps if cell_of(c, 'restart_pod', first)['flips'])
                     + ". The deciding lags are therefore set by the list intervals above and by where t_k falls "
                     "between two lists. The v1 method's earliest record, per capture at the same Δ: "
                     + "; ".join(f"`{c['capture']}` {fmt_counter(cell_of(c, 'restart_pod', first)['v1_method_earliest_sources'])}"
                                 for c in caps if cell_of(c, 'restart_pod', first)['flips'])
                     + " (`receipt` = the rollout-patch receipt, which changes R2's input but not the combined "
                     "verdict on its own).")
    else:
        lines.append("Deciding records by source (flips): " + fmt_counter(dict(sorted(sources.items()))) + ".")
    top = []
    for c in caps:
        cats = cell_of(c, "restart_pod", first)["deciding_categories"]
        if cats:
            name, n = next(iter(cats.items()))
            top.append(f"`{c['capture']}` {name} ({n} of {cell_of(c, 'restart_pod', first)['flips']})")
    if top:
        lines.append(f"Most frequent deciding record at Δ = {first} s (restart_pod), per capture: " + "; ".join(top)
                     + ".")
    cf0 = [(c["capture"], cell_of(c, "restart_pod", first)) for c in caps]
    lines.append(f"Carried-forward reliance at Δ = {first} s (restart_pod): "
                 + "; ".join(f"`{cap}` {cell['carried_forward_reliance']}/{cell['decisions']} "
                             f"(STATE {cell['carried_forward_state_reliance']}, largest STATE age "
                             f"{fmt_range(cell['carried_forward_state_age_seconds']).split('–')[-1]} s)"
                             for cap, cell in cf0)
                 + f". At Δ = {deltas[-1]} s the remaining reliance is on: "
                 + "; ".join(f"`{c['capture']}` {fmt_counter(cell_of(c, 'restart_pod', deltas[-1])['carried_forward_by_predicate'])}"
                             f" ({cell_of(c, 'restart_pod', deltas[-1])['carried_forward_only_links_of_pods_listed_absent']}"
                             f" of {cell_of(c, 'restart_pod', deltas[-1])['carried_forward_reliance']} decisions carry "
                             "only CONTROLLER/NODE links of a Pod already listed absent)"
                             for c in caps)
                 + ". A Pod's controller and node links are re-confirmed only by sightings of that Pod, so after it "
                 "leaves the list they stay known-open until F expires.")
    timing = [(c["capture"], c["rollout_timing"]) for c in caps]
    if all(tm["flips_at_delta0_inside_gaps"] == tm["flips_at_delta0_requests"] for _, tm in timing):
        lines.append("Every Δ = 0 flip is at a decision time inside a transition gap of the changed service's objects "
                     "(between the last sighting of an old value and the first sighting of the new one, or between "
                     "an object's recorded creation and its first sighting); per capture, decision times inside a gap "
                     "/ requests with a Δ = 0 flip: "
                     + "; ".join(f"`{cap}` {tm['requests_inside_transition_gaps']} / {tm['flips_at_delta0_requests']}"
                                 for cap, tm in timing) + ".")
    for c in caps:
        paragraph = settled_capture_paragraph(c, res["configuration"])
        if paragraph:
            lines.append(paragraph)
    r456 = all(set(cell[view][rule]) == {ALLOW} for cell in cells for view in ("as_known_rule_verdicts",
                                                                                 "corrected_rule_verdicts")
               for rule in ("R4", "R5", "R6"))
    if r456:
        lines.append("R4, R5 and R6 returned ALLOW in every as-known and corrected decision (no freeze windows; R5 "
                     "is constant per service; no view was older than S).")
    return lines


def render_summary(res: dict) -> str:
    """SUMMARY.md from results.json alone (every number below is read from it)."""
    caps = res["captures"]
    cfg = res["configuration"]
    eng = res["engine_agreement"]
    size = res["design_size"]
    n_req = res["generation_rule"]["target_block_requests"]
    compared = sum(v for k, v in eng.items() if k.endswith("_compared"))
    L = [f"# Policy gate live audit v1: label-free audit on {res['n_captures']} real rollouts", "",
         "**Label-free. No action was executed, no action carries an unsafe/safe label, and nothing here is a "
         "safety, precision or correctness rate. The actions were generated by a fixed rule, not proposed by an "
         "operator. A flip shows that the gate's verdict "
         "depended on records that were not yet available; it does not show which verdict was right.**", "",
         "Generated by `experiments/policy-gate-live-v1/run_policy_gate_live.py` from `results.json` (every number "
         "below is read from it; `results.csv` has one row per decision; `results.json` `flips` has every flip with "
         "its deciding record).", "",
         "## Setup", "",
         f"- **Captures (n = {res['n_captures']}):** " + "; ".join(f"`{c['capture']}` ({c['service']})" for c in caps)
         + ". Model input is each capture's `evidence/` (22 Sep: the pilot-001 files v1 reads).",
         f"- **Configuration (v1 primary, built with v1's `make_config`):** N = {cfg['change_window_seconds']:g} s, "
         f"floor = {cfg['replica_floor']}, k = {cfg['blast_radius_k']} ({cfg['blast_radius_direction']}, "
         f"transitive), S = {cfg['stale_view_seconds']:g} s, F = {cfg['carry_forward_seconds']:g} s, no freeze "
         "windows; equal to v1's `config_primary` (checked). Not tuned.",
         f"- **Rule (no labels):** for each target-block request k = 1..{n_req} at its decision time t_k, "
         "`restart_pod` on the Pod the as-known view at t_k names as the changed service's serving Pod (else a "
         "service-level reference) and `scale_deployment` of the service's Deployment to "
         f"{res['generation_rule']['scale_replicas']} replicas. Each action is judged "
         f"as-known at knowledge cutoff t_k + Δ (Δ = {', '.join(str(d) for d in res['deltas_seconds'])} s) and "
         "corrected (all records), both at observation time t_k.",
         f"- **Size:** {size['as_known_decisions']} as-known decisions ("
         + ", ".join(f"`{k}` {v}" for k, v in size["per_capture"].items())
         + "), each paired with the corrected decision of the same action and request.",
         f"- **Engine agreement ({100 * (compared - eng['disagreements']) / compared:.0f} %):** naming views "
         f"{eng.get('naming_views_compared', 0)}/{eng.get('naming_views_compared', 0)}, gate evaluations "
         f"{eng.get('evaluations_compared', 0)}/{eng.get('evaluations_compared', 0)} (including "
         f"{eng.get('scan_evaluations', 0)} deciding-record scan evaluations), v1-method attributions "
         f"{eng.get('v1_method_attributions_compared', 0)}/{eng.get('v1_method_attributions_compared', 0)}, "
         f"hindsight descriptions {eng.get('hindsight_descriptions_compared', 0)}/"
         f"{eng.get('hindsight_descriptions_compared', 0)}: graph and SQLite gave identical results; disagreements "
         f"{eng['disagreements']} (any disagreement aborts the run).",
         f"- **v1 equivalence:** the late-record attribution generalised to cutoff t_k + Δ returned exactly what "
         f"v1's own `late_records()` returns on all {eng.get('v1_late_records_equal_at_delta0', 0)} Δ = 0 decisions "
         "with a rule-level difference.", ""]
    L += ["## Inputs and cross-checks", "",
          "| Capture | Service | API sightings | Fact versions | Target requests (replay-scored / not) | "
          f"t_1 .. t_{n_req} (UTC) | Patch receipt (request → response) | Pod-list interval in the decision window "
          "(min / median / max s) | Pod STATE records = replay stream | = saved replay output | Named Pods (first k) |",
          "| --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- | --- |"]
    for c in caps:
        ev, cc = c["evidence"], c["cross_checks"]
        tb, p = ev["target_block"], ev["rollout_patch_receipt"]
        named = ", ".join(f"`{pod[4:12]}` (k={k})" for pod, k in sorted(
            c["naming"]["first_request_naming_each_pod"].items(), key=lambda kv: kv[1]))
        L.append(f"| `{c['capture']}` | {c['service']} | {ev['api_sightings']} | {ev['fact_versions']} | "
                 f"{tb['requests']} ({tb['scored_by_replay']} / {tb['not_scored_by_replay']}) | "
                 f"{tb['first_t'][11:23]} .. {tb['last_t'][11:23]} | "
                 f"{p['request_started_at'][11:23]} → {p['response_received_at'][11:23]} | "
                 f"{fmt_stats(ev['list_interval_seconds']['pods']['decision_window'])} | "
                 f"{'equal' if cc['state_records_vs_replay_task']['equal'] else 'DIFFERENT'} "
                 f"({cc['state_records_vs_replay_task']['pod_state_records']}) | "
                 f"{'equal' if cc['replay_task_vs_saved_replay_output']['records_equal'] else 'DIFFERENT'} | "
                 f"{named} |")
    L += ["", "Target classes of the generation rule (restart_pod), per capture: "
          + "; ".join(f"`{c['capture']}` " + ", ".join(f"{k} {v}" for k, v in c["naming"]["classes"].items())
                      for c in caps)
          + ". Requests the replay did not score (no span-verified Pod) are included: decision times need no span "
          "Pod claim.", ""]
    L += ["## Decision times relative to the rollout", "",
          "Where each capture's decision times fall relative to the changed service's transitions (value changes of "
          "its Deployment, ReplicaSets and Pods, and recorded creation to first sighting for objects created during "
          "the capture). Only a decision time inside such an interval can see the as-known view (last sightings "
          "carried forward) and the corrected view resolve different states for these objects.", "",
          "| Capture | Planned change (evidence) | Patch response − t_1 (s) | Last change first listed (UTC) | "
          "Last change available − t_1 (s) | Decision times inside a transition gap (requests) | Requests with a "
          "Δ = 0 flip (inside a gap) |",
          "| --- | --- | ---: | --- | ---: | --- | --- |"]
    for c in caps:
        tm = c["rollout_timing"]
        rng = tm["requests_inside_transition_gaps_range"]
        L.append(f"| `{c['capture']}` | {change_text(tm['planned_change'])} | "
                 f"{tm['patch_response_minus_t1_seconds']:.3f} | {tm['last_change_first_listed_at'][11:23]} | "
                 f"{tm['last_change_first_available_minus_t1_seconds']:.3f} | "
                 f"{tm['requests_inside_transition_gaps']}" + (f" (k = {rng[0]}..{rng[1]})" if rng else "") + " | "
                 f"{tm['flips_at_delta0_requests']} ({tm['flips_at_delta0_inside_gaps']}) |")
    L.append("")
    L += ["## Computed observations", ""] + [f"- {x}" for x in computed_observations(res)] + [""]
    L += [f"## Cross-capture table (n = {res['n_captures']} captures; counts, not rates)", "",
          f"One row per capture × action × Δ, {n_req} decisions each. Flips = as-known verdict ≠ corrected verdict; "
          "block↔allow = exactly one of the two is ALLOW; severity-only = both blocking, different verdicts. "
          "Deciding lag = the first later knowledge instant at which the gate's own verdict changes, minus t_k "
          "(min / median / max over the cell's flips, seconds). Carried-forward = as-known verdicts relying on a "
          "fact carried past its last sighting (all predicates; STATE only).", "",
          "| Action | Δ (s) | Capture | Decisions | Flips | block↔allow | severity-only | Rule-level diffs | "
          "Deciding lag (s) | Carried-forward (all / STATE) |",
          "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |"]
    for row in res["cross_capture_table"]:
        L.append(f"| {row['action']} | {row['delta_s']} | `{row['capture']}` | {row['decisions']} | {row['flips']} | "
                 f"{row['block_allow_flips']} | {row['severity_only_flips']} | {row['rule_level_differences']} | "
                 f"{fmt_stats(row['deciding_lag_seconds'])} | "
                 f"{row['carried_forward_reliance']} / {row['carried_forward_state_reliance']} |")
    L += ["", "## Lag distributions (cells with at least one flip)", "",
          "Seconds, min / median / max over the cell's flips. *From t_k*: deciding instant minus the decision's "
          "valid time. *Beyond cutoff*: deciding instant minus t_k + Δ. *v1 method*: the earliest record that v1's "
          "attribution (generalised to the cutoff) finds for the flip; it can precede the verdict change because it "
          "follows single relations, not the verdict. *At deciding instant = corrected*: flips whose verdict at the "
          "deciding instant already equals the corrected verdict.", "",
          "| Capture | Action | Δ (s) | Flips | From t_k | Beyond cutoff | v1 method | At deciding instant = corrected |",
          "| --- | --- | ---: | ---: | --- | --- | --- | ---: |"]
    for c in caps:
        for cell in c["cells"]:
            if not cell["flips"]:
                continue
            L.append(f"| `{c['capture']}` | {cell['action']} | {cell['delta_s']} | {cell['flips']} | "
                     f"{fmt_stats(cell['deciding_lag_seconds'])} | "
                     f"{fmt_stats(cell['deciding_lag_beyond_cutoff_seconds'])} | "
                     f"{fmt_stats(cell['v1_method_earliest_lag_seconds'])} | "
                     f"{cell['deciding_verdict_equals_corrected']}/{cell['flips']} |")
    L += ["", "## What the deciding records showed", "",
          "Category of the records that arrived at each flip's deciding instant, for the objects the decisions "
          "relied on (first sighting of an object, a state transition revealed by a new sighting, or a re-sighting). "
          "Counts are flips; one record can decide several flips.", "",
          "| Capture | Action | Δ (s) | Flips | Deciding instants | Categories (flips) |",
          "| --- | --- | ---: | ---: | ---: | --- |"]
    for c in caps:
        for cell in c["cells"]:
            if not cell["flips"]:
                continue
            instants = len({f["deciding_record"]["instant"] for f in res["flips"]
                            if f["capture"] == c["capture"] and f["action"] == cell["action"]
                            and f["delta_s"] == cell["delta_s"]})
            L.append(f"| `{c['capture']}` | {cell['action']} | {cell['delta_s']} | {cell['flips']} | {instants} | "
                     + "<br>".join(f"{name} ({n})" for name, n in cell["deciding_categories"].items()) + " |")
    L += ["", "## Why the corrected view abstains", "",
          "For each flip, the Pods of the service whose STATE the corrected view cannot resolve at t_k (R1 and R3 "
          "treat an unknown state as possibly ready), by role and by their state in the as-known view: *new* = not "
          "yet listed at the cutoff, listed not_ready, or first listed only after t_k; *retiring* = terminating or "
          "failed; *was_ready* = ready. A flip can count under more than one entry.", "",
          "| Capture | Action | Δ (s) | Flips | Pods unknown in hindsight (flips) | Flips with none |",
          "| --- | --- | ---: | ---: | --- | ---: |"]
    for c in caps:
        for cell in c["cells"]:
            if not cell["flips"]:
                continue
            L.append(f"| `{c['capture']}` | {cell['action']} | {cell['delta_s']} | {cell['flips']} | "
                     + "<br>".join(f"{name} ({n})" for name, n in cell["hindsight_unknown_in_flips"].items())
                     + f" | {cell['flips_without_hindsight_unknown']} |")
    L += ["", "## Per-capture verdicts and rules", "",
          "Verdict counts are DENY / ABSTAIN / NEEDS_APPROVAL / ALLOW. R1–R3 columns give each rule's verdict counts "
          "in the same order (R4–R6 are listed only if not all ALLOW). Rules differing counts each flip once per rule "
          "whose verdict differs between the two views.", ""]
    for c in caps:
        L += [f"### `{c['capture']}`: {c['label']}", "",
              f"Service `{c['service']}`; service→Deployment map from {c['service_deployments_source']}.", "",
              "| Action | Δ (s) | As-known | Corrected | As-known R1 / R2 / R3 | Corrected R1 / R2 / R3 | Flips | "
              "Flip types | Rules differing (flips) | Rule-level diffs without flip | R6 N (as-known) |",
              "| --- | ---: | --- | --- | --- | --- | ---: | --- | --- | ---: | ---: |"]
        for cell in c["cells"]:
            ak = " · ".join(fmt_verdicts(cell["as_known_rule_verdicts"][r]) for r in ("R1", "R2", "R3"))
            co = " · ".join(fmt_verdicts(cell["corrected_rule_verdicts"][r]) for r in ("R1", "R2", "R3"))
            extra = [r for r in ("R4", "R5", "R6") for view in ("as_known_rule_verdicts", "corrected_rule_verdicts")
                     if set(cell[view][r]) != {ALLOW}]
            L.append(f"| {cell['action']} | {cell['delta_s']} | {fmt_verdicts(cell['as_known_verdicts'])} | "
                     f"{fmt_verdicts(cell['corrected_verdicts'])} | {ak} | {co} | {cell['flips']} | "
                     f"{fmt_counter(cell['flip_types'])} | {fmt_counter(cell['rules_differing_in_flips'])} | "
                     f"{cell['rule_level_differences_without_flip']} | {cell['as_known_r6_needs_approval']} |"
                     + (f" R4–R6 not all ALLOW: {', '.join(sorted(set(extra)))}" if extra else ""))
        L.append("")
    L += ["## Where the gate's API forced a choice", ""] + [f"- {x}" for x in res["gate_api_wrappers"]]
    L += ["", "## What this does not show", ""] + [f"- {x}" for x in res["limitations"]] + [""]
    return "\n".join(L)


def write_outputs(results: dict, rows: list[dict], out_dir: Path) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(results, indent=1, ensure_ascii=False) + "\n"
    with open(out_dir / "results.json", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    with open(out_dir / "results.csv", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(csv_text(rows))
    summary = render_summary(json.loads(text))  # rendered from the serialised results.json only
    with open(out_dir / "SUMMARY.md", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(summary)
    return [str(out_dir / name) for name in OUTPUT_NAMES]


def rerun_check() -> int:
    """Run the audit twice in separate interpreters (different hash seeds) and compare every output byte for byte,
    with each other and with the published files in this folder. Writes rerun_check.txt."""
    runs = {}
    with tempfile.TemporaryDirectory(prefix="policy-gate-live-rerun-") as tmp:
        for label, seed in (("run_a", "1"), ("run_b", "2")):
            out = Path(tmp) / label
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE="1")
            proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--output", str(out)],
                                  cwd=str(ROOT), env=env, capture_output=True, text=True)
            check(proc.returncode == 0, f"{label} failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
            runs[label] = {name: sha256(out / name) for name in OUTPUT_NAMES}
    published = {name: (sha256(HERE / name) if (HERE / name).exists() else None) for name in OUTPUT_NAMES}
    identical = runs["run_a"] == runs["run_b"]
    matches = runs["run_a"] == published
    lines = ["policy-gate live audit v1: rerun check",
             "Two separate interpreter runs (PYTHONHASHSEED=1 and 2) of run_policy_gate_live.py --output <tmp>, "
             "compared byte for byte with each other and with the published outputs in this folder.", ""]
    for name in OUTPUT_NAMES:
        lines.append(f"{name}")
        lines.append(f"  run_a     {runs['run_a'][name]}")
        lines.append(f"  run_b     {runs['run_b'][name]}")
        lines.append(f"  published {published[name]}")
    lines += ["", f"run_a == run_b: {str(identical).lower()}", f"run_a == published: {str(matches).lower()}", ""]
    with open(HERE / "rerun_check.txt", "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
    print("\n".join(lines))
    return 0 if identical and matches else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--output", type=Path, default=None, help="output directory (default: this folder)")
    parser.add_argument("--rerun-check", action="store_true",
                        help="run twice in separate interpreters and compare all outputs; writes rerun_check.txt")
    args = parser.parse_args(argv)
    if args.rerun_check:
        return rerun_check()
    results, rows = build_results()
    outputs = write_outputs(results, rows, (args.output or HERE).resolve())
    for c in results["captures"]:
        print(c["capture"], " ".join(f"{x['action']}@{x['delta_s']}:{x['flips']}" for x in c["cells"]))
    print(json.dumps({"design_size": results["design_size"], "engine_agreement": results["engine_agreement"],
                      "outputs": [Path(o).name for o in outputs]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
