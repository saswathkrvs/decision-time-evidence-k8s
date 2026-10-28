#!/usr/bin/env python3
"""attribution-lag v1: request-to-Pod attribution under record lag, on the 22 Sep 2026 rollout capture.

When a diagnosis must say which recommendationservice Pod served a request, how much does the answer depend on which
Kubernetes records have arrived by the time it is asked?

For each of the 120 requests of rollout-telemetry pilot-001, at the request's own time t_req (its client root span
start), the script attributes the request to the old Pod, the new Pod or "unknown", using ONLY API observations
available by t_req + Delta, for Delta in {0, 5, 30, 120 s, hindsight}. The span-verified serving Pod is the ground
truth and is never an input to the attribution.

    PYTHONDONTWRITEBYTECODE=1 python3 experiments/attribution-lag-v1/run_attribution_lag.py

Inputs (read-only): results/evidence-index-pilot-002/accepted_evidence.jsonl (span claims + API observations),
data/raw/rollout-telemetry/pilot-001/{protocol,capture}.json. API observations are mapped to Pod STATE observations by
the policy-gate audit's own functions (experiments/policy-gate-v1/run_policy_gate_audit.py: load_sightings,
build_observations), imported read-only. Outputs (this folder only): results.json, results.csv, SUMMARY.md.
Deterministic.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import math
import platform
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True  # must precede every project import (no __pycache__ anywhere)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aiops_kg.policy_gate import STATE, materialize_facts  # noqa: E402
from aiops_kg.temporal import GraphStore, SqliteStore  # noqa: E402

AUDIT_PATH = ROOT / "experiments/policy-gate-v1/run_policy_gate_audit.py"
_spec = importlib.util.spec_from_file_location("policy_gate_audit_v1_readonly", AUDIT_PATH)
pga = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pga)

UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
EVIDENCE = ROOT / "results/evidence-index-pilot-002/accepted_evidence.jsonl"
SERVICE = "recommendationservice"
OLD_UID = "18c38f03-dcc9-493e-9d26-ddeda4493c53"  # re-derived below
NEW_UID = "f43ab1d9-9d3a-4caf-848b-f9e937b54272"
LABEL = {OLD_UID: "old", NEW_UID: "new"}
DELTAS = (("0 s", 0), ("5 s", 5), ("30 s", 30), ("120 s", 120), ("hindsight", None))
CARRY_FORWARD_US = 600 * 10**6  # F = 600 s, the policy-gate audit's carry_forward_seconds
RETIRED = frozenset({"terminating", "failed", "succeeded", "absent"})
CLOCK_OFFSETS = (-1.5, -1.0, -0.5, 0.0, 0.5, 1.0, 1.5)
FEED_DELAYS = (0, 1, 3, 10, 30, 60)  # the policy-gate audit's simulated delay set
HINDSIGHT_US = 2**62


# ---------------------------------------------------------------------------
# Time helpers (all internal times are integer microseconds since the Unix epoch, UTC)
# ---------------------------------------------------------------------------
def us(dt: datetime) -> int:
    delta = dt.astimezone(UTC) - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10**6 + delta.microseconds


def dt_of(value_us: int) -> datetime:
    return EPOCH + timedelta(microseconds=value_us)


def iso(value_us: int | None) -> str | None:
    return None if value_us is None else dt_of(value_us).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hms(value_us: int | None) -> str:
    return "-" if value_us is None else dt_of(value_us).strftime("%H:%M:%S.%f")


def ns_to_us_floor(ns: int) -> int:
    return ns // 1000


def ns_to_us_ceil(ns: int) -> int:
    return -((-ns) // 1000)


def parse_iso_ns(text: str) -> int:
    """'2026-09-22T17:53:12.671537603Z' -> integer ns (exact)."""
    body = text.rstrip("Z")
    whole, _, frac = body.partition(".")
    base = datetime.fromisoformat(whole + "+00:00")
    return us(base) * 1000 + int((frac or "0").ljust(9, "0")[:9])


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("verification failed: " + message)


# ---------------------------------------------------------------------------
# Ground truth from span identity (never an attribution input)
# ---------------------------------------------------------------------------
def load_requests() -> list[dict]:
    spans = []
    with EVIDENCE.open(encoding="utf-8") as handle:
        for line in handle:
            entry = json.loads(line)
            record = entry["record"]
            if record["kind"] == "span_claim":
                spans.append((entry, record))
    check(len(spans) == 727, f"expected 727 span claims, got {len(spans)}")
    by_trace = defaultdict(list)
    for entry, record in spans:
        by_trace[record["payload"]["trace_id"]].append((entry, record))
    roots = [(e, r) for e, r in spans if r["payload"]["resource_attributes"].get("service.name") == "pilot-client"]
    check(len(roots) == 120, "expected 120 client root spans")
    expected = [("pilot-client", "pilot.ListRecommendations", 3),
                ("recommendationservice", "/hipstershop.RecommendationService/ListRecommendations", 2),
                ("recommendationservice", "/hipstershop.ProductCatalogService/ListProducts", 3),
                ("productcatalogservice", "hipstershop.ProductCatalogService/ListProducts", 2)]
    requests = []
    for entry, record in roots:
        payload = record["payload"]
        root = payload["span"]
        check(not root.get("parentSpanId"), "client root span has a parent")
        index = int(payload["span_attributes"]["aiops.request.index"])
        path = [(entry, record)]
        current = root["spanId"]
        for _ in range(3):
            children = [(e, r) for e, r in by_trace[payload["trace_id"]]
                        if r["payload"]["span"].get("parentSpanId") == current]
            check(len(children) == 1, f"request {index}: path is not a unique chain")
            path.append(children[0])
            current = children[0][1]["payload"]["span"]["spanId"]
        for (e, r), (svc, name, kind) in zip(path, expected):
            p = r["payload"]
            check((p["resource_attributes"]["service.name"], p["span"]["name"], p["span"]["kind"]) == (svc, name, kind),
                  f"request {index}: unexpected span on the verified path")
        server, rec_client = path[1][1]["payload"], path[2][1]["payload"]
        uid = server["resource_attributes"]["k8s.pod.uid"]
        check(rec_client["resource_attributes"]["k8s.pod.uid"] == uid, f"request {index}: server/client Pod differ")
        start_ns = int(root["startTimeUnixNano"])
        requests.append({
            "request_index": index, "trace_id": payload["trace_id"],
            "t_req_us": ns_to_us_floor(start_ns), "t_req_ns": start_ns,
            "root_end_ns": int(root["endTimeUnixNano"]),
            "truth_uid": uid, "truth": LABEL.get(uid, "other"),
            "truth_pod_name": server["resource_attributes"]["k8s.pod.name"],
            "server_span_id": server["span"]["spanId"],
            # Span availability, variant V2a: collector transform-stage processing time (collector clock).
            "path_collector_processed_us": [ns_to_us_ceil(parse_iso_ns(json.loads(r["payload"]["collector_processed_at_raw"])))
                                            for _, r in path],
            # Span availability, variant V2b: host acquisition of the saved trace file (host clock).
            "path_host_acquired_us": [us(datetime.fromisoformat(r["acquired_at"].replace("Z", "+00:00"))) for _, r in path],
            # Span availability, variant V3: offline evidence-index readiness (available_ns).
            "path_index_available_us": [ns_to_us_ceil(e["available_ns"]) for e, _ in path],
        })
    requests.sort(key=lambda r: r["request_index"])
    check([r["request_index"] for r in requests] == list(range(1, 121)), "request indexes are not 1..120")
    check(all(r["truth"] == "old" for r in requests[:43]) and all(r["truth"] == "new" for r in requests[43:]),
          "span identity does not give requests 1-43 old / 44-120 new")
    check(all(a["t_req_us"] < b["t_req_us"] for a, b in zip(requests, requests[1:])), "request times not increasing")
    return requests


# ---------------------------------------------------------------------------
# Pod STATE observations, derived exactly as in the policy-gate audit
# ---------------------------------------------------------------------------
def pod_observations(sightings, patch, protocol, *, delay_s: float = 0.0, availability: str = "capture"):
    observations, _, info = pga.build_observations(
        sightings, patch, protocol, delay=timedelta(seconds=delay_s), availability=availability,
        include_receipts=(availability == "capture"))
    labels = {}
    for row in sightings:
        if row["kind"] == "Pod":
            app = row["resource_data"]["metadata"].get("labels", {}).get("app")
            check(labels.setdefault(row["subject"], app) == app, f"label changed for {row['subject']}")
    members = sorted(s for s, app in labels.items() if app == SERVICE)
    per_pod = {}
    for subject in members:
        rows = sorted(((us(o.observed_at), us(o.available_at), o.value, o.record_id)
                       for o in observations if o.subject == subject and o.predicate == STATE),
                      key=lambda x: (x[0], x[3]))
        ident = info["identities"][subject]
        per_pod[subject] = {"uid": subject.split("/", 1)[1], "name": ident["name"],
                            "created_floor_us": us(ident["created_at"]), "observations": rows}
    return per_pod, [o for o in observations if o.subject in per_pod and o.predicate == STATE]


# ---------------------------------------------------------------------------
# The attribution rule
# ---------------------------------------------------------------------------
def raw_a1_state(obs_rows, t, c):
    """Assumption A1 only (the policy-gate materialisation): value if covered at t under cutoff c, else None."""
    visible = [o for o in obs_rows if o[1] <= c]
    prev = [o for o in visible if o[0] <= t]
    nxt = [o for o in visible if o[0] > t]
    if not prev:
        return None
    p = prev[-1]
    if nxt:
        return p[2] if nxt[0][2] == p[2] else None
    return p[2] if t - p[0] < CARRY_FORWARD_US else None


def classify_pod(pod, t, c, *, k1=True, k3=False):
    """Serving class of one Pod at valid time t, using only its observations available by cutoff c."""
    visible = [o for o in pod["observations"] if o[1] <= c]
    if not visible:
        return {"class": "not_in_view", "rule": "no_record_available", "records": []}
    prev = [o for o in visible if o[0] <= t]
    nxt = [o for o in visible if o[0] > t]
    p, n = (prev[-1] if prev else None), (nxt[0] if nxt else None)
    records = [x[3] for x in (p, n) if x is not None]
    if t < pod["created_floor_us"]:
        return {"class": "not_serving", "rule": "K2_created_after_t", "records": records}
    if k1 and p is not None and p[2] in RETIRED:
        return {"class": "not_serving", "rule": "K1_retired_before_t:" + p[2], "records": records}
    if p is not None and n is not None:
        if p[2] == n[2]:
            return {"class": "serving" if p[2] == "ready" else "not_serving",
                    "rule": "A1_bracketed_same_state:" + p[2], "records": records}
        return {"class": "possibly_serving", "rule": "A1_transition_between_sightings:%s->%s" % (p[2], n[2]),
                "records": records}
    if p is not None:
        if t - p[0] >= CARRY_FORWARD_US:
            return {"class": "possibly_serving", "rule": "carry_forward_expired", "records": records}
        return {"class": "serving" if p[2] == "ready" else "not_serving",
                "rule": "A1_carried_forward:" + p[2], "records": records}
    if k3 and n[2] == "not_ready":
        return {"class": "not_serving", "rule": "K3_first_sighting_not_ready", "records": records}
    return {"class": "possibly_serving", "rule": "before_first_sighting:" + n[2], "records": records}


def attribute(pods, t, c, *, k1=True, k3=False):
    classes = {LABEL[pod["uid"]]: classify_pod(pod, t, c, k1=k1, k3=k3) for pod in pods.values()}
    certain = [k for k, v in classes.items() if v["class"] == "serving"]
    possible = [k for k, v in classes.items() if v["class"] in ("serving", "possibly_serving")]
    if len(possible) == 1 and len(certain) == 1:
        return certain[0], "single_confirmed_serving_pod", classes
    if not possible:
        return "unknown", "no_serving_pod_confirmed", classes
    if len(possible) >= 2:
        return "unknown", "two_pods_possible", classes
    return "unknown", "serving_pod_unconfirmed", classes


def span_arrival(request, variant):
    if variant == "V2a":
        return max(request["path_collector_processed_us"])
    if variant == "V2b":
        return max(request["path_host_acquired_us"])
    if variant == "V3":
        return max(request["path_index_available_us"])
    return None


def evaluate(requests, pods, variant, delta_s, *, offset_s=0.0, k1=True, k3=False):
    rows = []
    for r in requests:
        t = r["t_req_us"] + round(offset_s * 10**6)
        c = HINDSIGHT_US if delta_s is None else t + delta_s * 10**6
        arrival = span_arrival(r, variant)
        # The span-arrival condition compares two node-clock times (collector and client); the offset cancels.
        trace_visible = arrival is None or delta_s is None or arrival <= r["t_req_us"] + delta_s * 10**6
        answer, reason, classes = attribute(pods, t, c, k1=k1, k3=k3)
        if not trace_visible:
            answer, reason = "unknown", "trace_not_yet_arrived"
        outcome = "unknown" if answer == "unknown" else ("correct" if answer == r["truth"] else "wrong")
        rows.append({"request_index": r["request_index"], "t_req": iso(t), "cutoff": None if delta_s is None else iso(c),
                     "truth": r["truth"], "attribution": answer, "outcome": outcome, "reason": reason,
                     "trace_arrived_by_cutoff": trace_visible,
                     "span_arrival": iso(arrival) if arrival is not None else None,
                     "pod_classes": classes})
    return rows


def counts(rows):
    c = Counter(r["outcome"] for r in rows)
    reasons = Counter(r["reason"] for r in rows if r["outcome"] == "unknown")
    return {"correct": c["correct"], "wrong": c["wrong"], "unknown": c["unknown"],
            "unknown_reasons": dict(sorted(reasons.items())),
            "wrong_requests": [r["request_index"] for r in rows if r["outcome"] == "wrong"],
            "unknown_requests": [r["request_index"] for r in rows if r["outcome"] == "unknown"]}


# ---------------------------------------------------------------------------
# Transition gaps (hindsight sightings)
# ---------------------------------------------------------------------------
def pod_transitions(pods):
    out = []
    for pod in pods.values():
        rows = pod["observations"]
        first = rows[0]
        out.append({"pod": LABEL[pod["uid"]], "change": "not created -> first sighting (%s)" % first[2],
                    "last_old_us": pod["created_floor_us"], "first_new_us": first[0],
                    "first_new_available_us": first[1], "first_new_record": first[3],
                    "note": "API creationTimestamp, 1 s resolution, API-server clock"})
        for a, b in zip(rows, rows[1:]):
            if a[2] != b[2]:
                out.append({"pod": LABEL[pod["uid"]], "change": "%s -> %s" % (a[2], b[2]),
                            "last_old_us": a[0], "first_new_us": b[0], "first_new_available_us": b[1],
                            "first_new_record": b[3], "note": "host receipt clock"})
    return sorted(out, key=lambda x: (x["first_new_us"], x["pod"]))


def owner_chain_check(sightings):
    """Hindsight check: Pod -> controller ReplicaSet -> controller Deployment named recommendationservice."""
    rs_owner, deployment_name, pod_rs, pod_app = {}, {}, {}, {}
    for row in sightings:
        meta = row["resource_data"]["metadata"]
        owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
        if row["kind"] == "Deployment":
            deployment_name[meta["uid"]] = meta["name"]
        elif row["kind"] == "ReplicaSet" and owners:
            rs_owner[meta["uid"]] = owners[0]["uid"]
        elif row["kind"] == "Pod" and owners:
            pod_rs[meta["uid"]] = owners[0]["uid"]
            pod_app[meta["uid"]] = meta.get("labels", {}).get("app")
    by_label = sorted(u for u, app in pod_app.items() if app == SERVICE)
    by_chain = sorted(u for u, rs in pod_rs.items() if deployment_name.get(rs_owner.get(rs)) == SERVICE)
    check(by_label == by_chain == sorted([OLD_UID, NEW_UID]), "label membership and owner chain disagree")
    return {"members_by_label": by_label, "members_by_owner_chain": by_chain, "agree": True}


def in_gap(t, gap):
    return gap["last_old_us"] <= t < gap["first_new_us"]


# ---------------------------------------------------------------------------
# Cross-check of the per-Pod state lookup against the project's temporal resolver
# ---------------------------------------------------------------------------
def resolver_crosscheck(requests, pods, state_observations):
    facts, _ = materialize_facts(state_observations)
    stores = {"graph": GraphStore(facts), "sqlite": SqliteStore(facts)}
    total = agree = 0
    mismatches = []
    try:
        for r in requests:
            for _, delta_s in DELTAS:
                t = r["t_req_us"]
                c = max(us(f.available_at) for f in facts) if delta_s is None else t + delta_s * 10**6
                for subject, pod in pods.items():
                    mine = raw_a1_state(pod["observations"], t, c)
                    for name, store in stores.items():
                        res = store.resolve(subject, STATE, dt_of(t), dt_of(c), CARRY_FORWARD_US / 10**6)
                        theirs = res.value if res.status == "resolved" else None
                        total += 1
                        if mine == theirs:
                            agree += 1
                        elif len(mismatches) < 10:
                            mismatches.append({"request": r["request_index"], "delta": delta_s, "pod": subject,
                                               "engine": name, "mine": mine, "resolver": theirs})
    finally:
        stores["sqlite"].close()
    return {"queries": total, "agreements": agree, "mismatches": mismatches,
            "scope": "per-Pod STATE under assumption A1 only (before K1/K2); graph and SQLite engines of "
                     "src/aiops_kg/temporal.py over facts from src/aiops_kg/policy_gate.materialize_facts"}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def summary_stats(values):
    return {"n": len(values), "min": min(values), "median": statistics.median(values), "max": max(values)}


def run(requests, sightings, patch, protocol):
    pods, state_obs = pod_observations(sightings, patch, protocol)
    check({p["uid"] for p in pods.values()} == {OLD_UID, NEW_UID}, "recommendation Pods are not exactly old+new")
    pods_index, _ = pod_observations(sightings, patch, protocol, availability="index")
    variants = {"V1": pods, "V2a": pods, "V2b": pods, "V3": pods_index}
    main = {}
    for variant, pod_view in variants.items():
        main[variant] = {}
        for label, delta_s in DELTAS:
            rows = evaluate(requests, pod_view, variant, delta_s)
            main[variant][label] = {"counts": counts(rows), "rows": rows}
    clock = {}
    for offset in CLOCK_OFFSETS:
        clock["%+.2f" % offset] = {label: counts(evaluate(requests, pods, "V1", d, offset_s=offset))
                                   for label, d in DELTAS}
    k3 = {label: counts(evaluate(requests, pods, "V1", d, k3=True)) for label, d in DELTAS}
    no_k1 = {label: counts(evaluate(requests, pods, "V1", d, k1=False)) for label, d in DELTAS}
    delay = {}
    for d in FEED_DELAYS:
        delayed, _ = pod_observations(sightings, patch, protocol, delay_s=d)
        delay[str(d)] = {label: counts(evaluate(requests, delayed, "V1", dl)) for label, dl in DELTAS}
    return pods, state_obs, main, {"clock_offset_seconds": clock, "k3_startup_assumption": k3,
                                   "without_k1": no_k1, "simulated_api_feed_delay_seconds": delay}


def main() -> int:
    protocol = json.loads(pga.INPUTS["protocol"].read_text(encoding="utf-8"))
    capture = json.loads(pga.INPUTS["capture"].read_text(encoding="utf-8"))
    sightings = pga.load_sightings(protocol)
    patch = pga.patch_receipt(capture)
    requests = load_requests()

    pods, state_obs, main_results, sensitivity = run(requests, sightings, patch, protocol)
    again = run(requests, sightings, patch, protocol)
    check(json.dumps([main_results, sensitivity], sort_keys=True, default=str)
          == json.dumps([again[2], again[3]], sort_keys=True, default=str), "two passes differ")
    crosscheck = resolver_crosscheck(requests, pods, state_obs)
    check(crosscheck["agreements"] == crosscheck["queries"], "per-Pod state lookup disagrees with the resolver")

    chain = owner_chain_check(sightings)
    claim_margin_s = min((r["t_req_us"] - min(o[1] for o in next(p for p in pods.values()
                                                                  if p["uid"] == r["truth_uid"])["observations"])) / 1e6
                         for r in requests)
    check(claim_margin_s > 0, "a serving Pod had no available API observation before a request it served")
    transitions = pod_transitions(pods)
    serving_switch = {"last_old_us": max(t["last_old_us"] for t in transitions
                                         if t["pod"] == "old" and t["change"] == "ready -> terminating"),
                      "first_new_us": min(t["first_new_us"] for t in transitions
                                          if t["pod"] == "new" and t["change"] == "not_ready -> ready")}
    check(serving_switch["last_old_us"] < serving_switch["first_new_us"], "serving switch gap malformed")
    creation_gap = next(t for t in transitions if t["pod"] == "new" and t["change"].startswith("not created"))
    gaps = {"serving_switch": serving_switch, "new_pod_creation": creation_gap}
    for t in transitions:
        t["requests_inside"] = [r["request_index"] for r in requests if in_gap(r["t_req_us"], t)]
    gap_requests = {name: [r["request_index"] for r in requests if in_gap(r["t_req_us"], g)] for name, g in gaps.items()}
    # Requests whose view at t + Delta already contains both sightings that bracket the serving switch.
    gap_visible = {}
    for label, delta_s in DELTAS:
        first_new_avail = max(t["first_new_available_us"] for t in transitions
                              if t["change"] in ("ready -> terminating", "not_ready -> ready"))
        gap_visible[label] = [i for i in gap_requests["serving_switch"]
                              if delta_s is None or requests[i - 1]["t_req_us"] + delta_s * 10**6 >= first_new_avail]

    api_rows = sightings
    lag = [(us(r["available_at"]) - us(r["observed_at"])) / 1e3 for r in api_rows]  # ms
    pod_snapshots = sorted({us(r["observed_at"]) for r in api_rows if r["resource"] == "pods"})
    poll = [(b - a) / 1e6 for a, b in zip(pod_snapshots, pod_snapshots[1:])]
    span_lag_a = [(max(r["path_collector_processed_us"]) - r["t_req_us"]) / 1e6 for r in requests]
    span_lag_b = [(max(r["path_host_acquired_us"]) - r["t_req_us"]) / 1e6 for r in requests]
    index_api = min(us(r["index_available_at"]) for r in api_rows)

    results = {
        "kind": "request_to_pod_attribution_under_record_lag_one_rollout_not_diagnosis_accuracy",
        "question": "At t_req + Delta, which recommendationservice Pod does the record-based view attribute each "
                    "request to, compared with the span-verified serving Pod?",
        "inputs_sha256": {rel(p): sha256(p) for p in (EVIDENCE, pga.INPUTS["protocol"], pga.INPUTS["capture"])},
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "deterministic_two_pass_identical": True,
        "rules": RULES,
        "evidence": {
            "api_observations": len(api_rows),
            "api_by_resource": dict(sorted(Counter(r["resource"] for r in api_rows).items())),
            "api_available_minus_observed_ms": summary_stats(lag),
            "pods_list_poll_interval_s": summary_stats(poll),
            "offline_index_first_api_acceptance": iso(index_api),
            "span_claims": 727, "requests": len(requests),
            "trace_arrival_minus_t_req_s": {"V2a_collector_processing": summary_stats(span_lag_a),
                                            "V2b_host_acquisition": summary_stats(span_lag_b)},
            "recommendation_pods": {LABEL[p["uid"]]: {"uid": p["uid"], "name": p["name"],
                                                      "created_floor": iso(p["created_floor_us"]),
                                                      "state_observations": [
                                                          {"observed_at": iso(o[0]), "available_at": iso(o[1]),
                                                           "value": o[2], "record_id": o[3]} for o in p["observations"]]}
                                    for p in pods.values()},
            "transitions": [{**{k: v for k, v in t.items() if not k.endswith("_us")},
                             "last_old": iso(t["last_old_us"]), "first_new": iso(t["first_new_us"]),
                             "first_new_available": iso(t["first_new_available_us"]),
                             "gap_seconds": (t["first_new_us"] - t["last_old_us"]) / 1e6} for t in transitions],
            "rollout_patch_receipt": {k: patch[k] for k in ("request_started_at", "response_received_at", "collector_available_at")},
            "rollout_wait_receipt": {k: v for k, v in {r["id"]: r for r in capture["command_receipts"]}["rollout-wait"].items()
                                     if k in ("request_started_at", "response_received_at", "collector_available_at")},
            "capture": {"started_at": capture["started_at"], "finished_at": capture["finished_at"]},
        },
        "truth": {"source": "server span k8s.pod.uid on each request's verified 4-span path (client root -> "
                            "recommendation server -> recommendation client -> catalog server)",
                  "old_pod": {"uid": OLD_UID, "requests": [r["request_index"] for r in requests if r["truth"] == "old"]},
                  "new_pod": {"uid": NEW_UID, "requests": [r["request_index"] for r in requests if r["truth"] == "new"]},
                  "t_req": {r["request_index"]: iso(r["t_req_us"]) for r in requests}},
        "gaps": {"serving_switch": {"last_old_sighting": iso(serving_switch["last_old_us"]),
                                    "first_new_sighting": iso(serving_switch["first_new_us"]),
                                    "gap_seconds": (serving_switch["first_new_us"] - serving_switch["last_old_us"]) / 1e6,
                                    "requests_inside": gap_requests["serving_switch"],
                                    "requests_inside_and_bracketing_sightings_visible_at_cutoff": gap_visible},
                 "new_pod_creation": {"creation_floor": iso(creation_gap["last_old_us"]),
                                      "first_sighting": iso(creation_gap["first_new_us"]),
                                      "gap_seconds": (creation_gap["first_new_us"] - creation_gap["last_old_us"]) / 1e6,
                                      "requests_inside": gap_requests["new_pod_creation"]}},
        "results": {v: {label: main_results[v][label]["counts"] for label, _ in DELTAS} for v in main_results},
        "per_request": {v: {label: main_results[v][label]["rows"] for label, _ in DELTAS} for v in main_results},
        "sensitivity": sensitivity,
        "resolver_crosscheck": crosscheck,
        "owner_chain_check": chain,
        "span_claim_contrast": {"min_seconds_between_first_available_observation_of_serving_pod_and_request": claim_margin_s,
                                "statement": "An API observation of the span-claimed serving Pod was available before "
                                             "every request that Pod served."},
        "limitations": LIMITATIONS,
    }
    (HERE / "results.json").write_text(json.dumps(results, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    (HERE / "results.csv").write_text(to_csv(main_results, gaps, requests), encoding="utf-8")
    (HERE / "SUMMARY.md").write_text(render_summary(results, requests), encoding="utf-8")
    for v in main_results:
        print(v, {label: {k: main_results[v][label]["counts"][k] for k in ("correct", "wrong", "unknown")}
                  for label, _ in DELTAS})
    print("resolver cross-check: %d/%d agree" % (crosscheck["agreements"], crosscheck["queries"]))
    print("serving-switch gap requests:", gap_requests["serving_switch"], "creation gap requests:", gap_requests["new_pod_creation"])
    return 0


def to_csv(main_results, gaps, requests):
    buffer = io.StringIO()
    w = csv.writer(buffer, lineterminator="\n")
    w.writerow(["variant", "delta", "request_index", "t_req", "cutoff", "truth", "attribution", "outcome", "reason",
                "trace_arrived_by_cutoff", "in_serving_switch_gap", "in_new_pod_creation_gap",
                "old_pod_class", "old_pod_rule", "new_pod_class", "new_pod_rule", "records_used"])
    t_of = {r["request_index"]: r["t_req_us"] for r in requests}
    for v in main_results:
        for label, _ in DELTAS:
            for row in main_results[v][label]["rows"]:
                i = row["request_index"]
                cl = row["pod_classes"]
                w.writerow([v, label, i, row["t_req"], row["cutoff"] or "hindsight", row["truth"], row["attribution"],
                            row["outcome"], row["reason"], row["trace_arrived_by_cutoff"],
                            in_gap(t_of[i], gaps["serving_switch"]), in_gap(t_of[i], gaps["new_pod_creation"]),
                            cl["old"]["class"], cl["old"]["rule"], cl["new"]["class"], cl["new"]["rule"],
                            ";".join(cl["old"]["records"] + cl["new"]["records"])])
    return buffer.getvalue()


RULES = {
    "t_req": "start of the request's client root span (pilot-client 'pilot.ListRecommendations', startTimeUnixNano), "
             "floored to the microsecond; client (kind-node) clock",
    "truth": "k8s.pod.uid of the recommendationservice SERVER span on the request's verified 4-span path "
             "(exact trace and parent IDs); never an attribution input",
    "api_record_available_by": "V1/V2a/V2b: the capture-era pipeline receipt time payload.available_at of each API "
                               "observation (host clock; the same field the policy-gate audit uses); an absence "
                               "(Pod missing from a later complete Pods list) is available when every row of that "
                               "list is available. V3: the offline evidence-index readiness time entry.available_ns.",
    "cutoff": "c = t_req + Delta on the same time line (clocks assumed aligned; see clock-offset sensitivity); "
              "hindsight = every record",
    "span_available_by": "V1: the request is assumed known at t_req (its trace is not required). V2a: all four spans "
                         "of the request's path must have aiops.collector_processed_at <= t_req + Delta (collector "
                         "transform stage, collector/node clock, rounded up to the microsecond). V2b: all four spans "
                         "must have been acquired by the host, record.acquired_at = trace-file receipt "
                         "2026-09-22T17:54:19.748032Z. V3: offline index readiness entry.available_ns. Otherwise the "
                         "answer is unknown (trace_not_yet_arrived).",
    "membership": "a Pod is a recommendationservice candidate iff one of its available observations has label "
                  "app=recommendationservice (the testbed's service mapping; the Pod->ReplicaSet->Deployment chain "
                  "agrees in hindsight)",
    "pod_state_mapping": "policy-gate audit pod_state(): Failed->failed, Succeeded->succeeded, deletionTimestamp->"
                         "terminating, Running with all containers ready->ready, otherwise not_ready; absent = missing "
                         "from a later complete Pods list",
    "serving": "S0: a Pod counts as serving at t iff its state at t is ready. This is an assumption about routing "
               "(Service endpoints list ready Pods), not a guarantee: a terminating Pod can still finish work on an "
               "established connection during its grace period",
    "pod_class_at_t": [
        "not_in_view: no observation of the Pod is available by c (the Pod is unknown to the view)",
        "K2 not_serving: creationTimestamp (1 s floor) > t",
        "K1 not_serving: the last available sighting at or before t is terminating/failed/succeeded/absent "
        "(deletionTimestamp and terminal phases are irreversible; a UID never returns)",
        "A1 bracketed: last sighting <= t and first sighting > t (both available by c) have the same state -> that "
        "state; different states -> possibly_serving (the change happened somewhere in between)",
        "A1 carried forward: last sighting <= t exists and no later sighting is available by c -> its state, for up "
        "to F = 600 s (the policy-gate audit's carry-forward)",
        "before first sighting (created <= t, first sighting > t) -> possibly_serving (a snapshot is not extended "
        "backwards); sensitivity K3 instead says not_serving when that first sighting is not_ready",
    ],
    "attribution": "exactly one candidate Pod possibly serving and it is serving (confirmed) -> that Pod; none "
                   "possibly serving -> unknown (no_serving_pod_confirmed); two possibly serving -> unknown "
                   "(two_pods_possible); one possibly serving but unconfirmed -> unknown (serving_pod_unconfirmed)",
    "outcome": "correct / wrong against the span-verified Pod; unknown is neither",
}

LIMITATIONS = [
    "One rollout of one single-replica service (maxSurge 1, maxUnavailable 0) on a single-node kind cluster; no fault.",
    "Pods were listed by polling every 2.4-3.8 s; state changes inside a polling gap cannot be placed.",
    "t_req is on the client/node clock and API receipt times are on the host clock; they are not calibrated against "
    "each other (the rollout clock audit saw apparent host-minus-client differences of -736 to +1432 ms, which are not "
    "an offset estimate). The clock-offset sensitivity shows which answers depend on this.",
    "creationTimestamp has 1 s resolution and comes from the API-server clock.",
    "Assumption A1 (no state flap between consecutive sightings) is a modelling assumption, as in the policy-gate audit.",
    "Assumption S0 (serving = ready) ignores gRPC connection reuse: a client can keep using one Pod while another is also "
    "ready, and a terminating Pod can finish work on an open connection. The clock-offset sensitivity shows where this matters.",
    "Delta is the query lag after the request; the measured record-delivery lag itself (available_at - observed_at) is "
    "sub-millisecond here, so the capture-era view changes with Delta only because later polls become visible. "
    "Feed delays beyond that are simulated (sensitivity), not measured.",
    "The attribution does not use the span's own Pod UID claim; a pipeline that does would need that span to arrive "
    "(V2a/V2b) and an API observation of that Pod to verify it.",
]


def reading_paragraph(res, requests) -> str:
    R = res["results"]["V1"]
    rows0 = res["per_request"]["V1"]["0 s"]
    sw, cg = res["gaps"]["serving_switch"], res["gaps"]["new_pod_creation"]
    ev = res["evidence"]
    carried = sum(1 for r in rows0 if r["attribution"] in ("old", "new")
                  and r["pod_classes"][r["attribution"]]["rule"].startswith("A1_carried_forward"))
    later = [label for label, d in DELTAS if d != 0]
    expected_unknown = sorted(set(sw["requests_inside"]) | set(cg["requests_inside"]))
    for label in later:
        check(R[label]["unknown_requests"] == expected_unknown, "unknown set differs from the gap requests at " + label)
        check(set(R[label]["unknown_reasons"]) == {"two_pods_possible"}, "unexpected unknown reason at " + label)
    check(all(R[label]["wrong"] == 0 for label, _ in DELTAS), "a V1 attribution is wrong with aligned clocks")
    check(R["0 s"]["unknown"] == 0 and carried == R["0 s"]["correct"], "Delta = 0 answers are not all carried forward")
    switch = next(t for t in ev["transitions"] if t["change"] == "not_ready -> ready")
    return ("**Reading.** At Delta = 0 the view attributes %d of 120 requests correctly (%d wrong, %d unknown). "
            "Every one of these answers rests on a carried-forward sighting (%d/%d), because nothing observed after "
            "t_req can be available at t_req. For the %d requests %s inside the serving-switch gap, that answer "
            "('old') happens to be right, but no record supported it. The gap runs from the last sighting with the old "
            "Pod ready and the new Pod not ready (%s) to the first sighting with the old Pod terminating and the new "
            "Pod ready (%s), a %.3f s polling gap. That later sighting was available %.1f ms after it was observed. "
            "From Delta = 5 s on, the view brackets these requests and answers two_pods_possible. The same happens to "
            "the %d requests %s inside the new Pod's creation gap, from creationTimestamp %s (1 s resolution) to the "
            "first sighting at %s: no record says whether the just-created Pod was already ready. The unknown set is "
            "the same %d requests at 5 s, 30 s, 120 s and in hindsight. **In this capture, later records made the view "
            "more cautious, not more correct.** No attribution is wrong at any Delta when the two clocks are taken as "
            "aligned." % (
                R["0 s"]["correct"], R["0 s"]["wrong"], R["0 s"]["unknown"], carried, R["0 s"]["correct"],
                len(sw["requests_inside"]), fmt_list(sw["requests_inside"]), hms(us_of(sw["last_old_sighting"])),
                hms(us_of(sw["first_new_sighting"])), sw["gap_seconds"],
                (us_of(switch["first_new_available"]) - us_of(switch["first_new"])) / 1e3,
                len(cg["requests_inside"]), fmt_list(cg["requests_inside"]), hms(us_of(cg["creation_floor"])),
                hms(us_of(cg["first_sighting"])), len(expected_unknown)))


def check_variant_claims(res) -> None:
    R = res["results"]
    for label, d in DELTAS:
        if d == 0:
            check(R["V2a"][label]["unknown"] == 120 and set(R["V2a"][label]["unknown_reasons"]) == {"trace_not_yet_arrived"},
                  "V2a Delta 0 claim")
        else:
            check({k: R["V2a"][label][k] for k in ("correct", "wrong", "unknown")}
                  == {k: R["V1"][label][k] for k in ("correct", "wrong", "unknown")}, "V2a = V1 claim at " + label)
        if d is not None and d <= 30:
            check(set(R["V2b"][label]["unknown_reasons"]) == {"trace_not_yet_arrived"} and R["V2b"][label]["unknown"] == 120,
                  "V2b claim at " + label)
        else:
            check(R["V2b"][label]["unknown_requests"] == R["V1"][label]["unknown_requests"]
                  and R["V2b"][label]["correct"] == R["V1"][label]["correct"], "V2b = V1 claim at " + label)
        if d is not None:
            check(R["V3"][label]["unknown"] == 120, "V3 claim at " + label)
    S = res["sensitivity"]
    for off, per in S["clock_offset_seconds"].items():
        value = float(off)
        if value < 0:
            check(all(per[l]["wrong"] == 0 for l, dd in DELTAS if dd != 0), "negative-offset claim")
        if value > 0:
            sets = {tuple(per[l]["wrong_requests"]) for l, _ in DELTAS}
            check(len(sets) == 1 and per["hindsight"]["wrong"] > 0, "positive-offset claim")
    for d, per in S["simulated_api_feed_delay_seconds"].items():
        for label, dd in DELTAS:
            late = dd is not None and dd < int(d)
            check((per[label]["wrong"] > 0) == late, "feed-delay claim (wrong iff Delta < d) at d=%s %s" % (d, label))


def render_summary(res, requests) -> str:
    check_variant_claims(res)
    R = res["results"]
    ev = res["evidence"]
    gaps = res["gaps"]
    sw, cg = gaps["serving_switch"], gaps["new_pod_creation"]
    L = ["# attribution-lag v1: request-to-Pod attribution under record lag (real rollout, 120 requests)", "",
         "**One real rollout, one service, no fault. This measures what the record-based view could know at each "
         "cutoff, compared with span-verified truth. It is not a diagnosis-accuracy result.** Same capture as the "
         "policy-gate audit (`experiments/policy-gate-v1`): rollout-telemetry pilot-001, namespace "
         "`aiops-rollout-pilot001`, 22 Sep 2026, %s to %s (host clock). The API observations are mapped to Pod "
         "states by that audit's own `load_sightings` / `build_observations`, imported read-only, so the "
         "observed and available times are derived exactly as there." % (ev["capture"]["started_at"], ev["capture"]["finished_at"]), "",
         "`run_attribution_lag.py` generates this file; every number is computed. Each run computes everything twice "
         "and aborts if the passes differ; `rerun_check.txt` holds output hashes from two separate runs.", "",
         "## Main result (V1: request known at t_req; API records at their measured capture-era availability)", "",
         "| Delta after t_req | Correct | Wrong | Unknown | Unknown because two Pods possible | Unknown for other reasons | "
         "Serving-switch-gap requests (%d) whose view already brackets the gap |" % len(sw["requests_inside"]),
         "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for label, _ in DELTAS:
        c = R["V1"][label]
        two = c["unknown_reasons"].get("two_pods_possible", 0)
        L.append("| %s | %d | %d | %d | %d | %d | %d |" % (label, c["correct"], c["wrong"], c["unknown"], two,
                                                        c["unknown"] - two,
                                                        len(sw["requests_inside_and_bracketing_sightings_visible_at_cutoff"][label])))
    v1 = R["V1"]
    L += ["", "Ground truth, re-derived from span identity in `accepted_evidence.jsonl`: requests 1-43 were served by "
          "the old Pod `%s` and 44-120 by the replacement `%s`, matching." % (
              OLD_UID[:8], NEW_UID[:8]), "",
          reading_paragraph(res, requests), ""]

    # Span-arrival variants
    L += ["## When the request's own trace must also have arrived", "",
          "| Delta | V1 (trace not required) | V2a: spans at collector processing time | V2b: spans at host acquisition of the trace file | V3: offline evidence index (API and spans) |",
          "| --- | --- | --- | --- | --- |"]
    for label, _ in DELTAS:
        cells = []
        for v in ("V1", "V2a", "V2b", "V3"):
            c = R[v][label]
            cells.append("%d / %d / %d" % (c["correct"], c["wrong"], c["unknown"]))
        L.append("| %s | %s |" % (label, " | ".join(cells)))
    a, b = ev["trace_arrival_minus_t_req_s"]["V2a_collector_processing"], ev["trace_arrival_minus_t_req_s"]["V2b_host_acquisition"]
    L += ["", "Cells are correct / wrong / unknown. The request's four spans reached the collector transform stage "
          "%.3f-%.3f s after t_req (median %.3f s), so under V2a nothing is attributable at Delta = 0 and V1's answers "
          "apply from Delta = 5 s. The host acquired the whole trace file once, at 17:54:19.748032, %.1f-%.1f s after "
          "the requests. Under V2b no trace has arrived within 30 s; by 120 s every trace has arrived and V1's answers "
          "apply. The offline evidence index (V3) accepted the API observations from %s, about 2.5 h later, so every "
          "request is unknown at every Delta up to 120 s. These are measured times; the collector processing time is a "
          "lower bound on availability to a downstream reader (a 1 s batch timeout and a 1 s file flush follow it)." % (
              a["min"], a["max"], a["median"], b["min"], b["max"], ev["offline_index_first_api_acceptance"]), "",
          "Contrast (not a table row): the server span itself carries the serving Pod's UID, which is the truth "
          "source here, so it is not used for attribution. A pipeline that trusted that claim would be limited only by "
          "the span's arrival (V2a/V2b). Verifying the claim against the API records would never have been blocked by "
          "record lag in this capture: an API observation of the serving Pod was available at least %.3f s before "
          "every request that Pod served." % (res["span_claim_contrast"]["min_seconds_between_first_available_observation_of_serving_pod_and_request"],), ""]

    # Rules
    rules = res["rules"]
    L += ["## Exact rules", ""]
    L += ["- **t_req:** " + rules["t_req"] + ".", "- **Truth:** " + rules["truth"] + ".",
          "- **API record available by:** " + rules["api_record_available_by"],
          "- **Cutoff:** " + rules["cutoff"] + ".", "- **Trace available by:** " + rules["span_available_by"],
          "- **Candidates:** " + rules["membership"] + ".", "- **Pod state:** " + rules["pod_state_mapping"] + ".",
          "- **Serving:** " + rules["serving"] + ".",
          "- **Pod class at t (first matching rule):**"]
    L += ["  %d. %s." % (i, text) for i, text in enumerate(rules["pod_class_at_t"], start=1)]
    L += ["- **Attribution:** " + rules["attribution"] + ".", "- **Outcome:** " + rules["outcome"] + ".", "",
          "Consistency check: before K1/K2 are applied, the per-Pod state lookup equals the project's temporal "
          "resolver (`src/aiops_kg/temporal.py`, graph and SQLite engines, over facts from "
          "`policy_gate.materialize_facts`) in %d/%d queries (every request x Delta x Pod x engine)." % (
              res["resolver_crosscheck"]["agreements"], res["resolver_crosscheck"]["queries"]), ""]

    # Evidence facts
    lag = ev["api_available_minus_observed_ms"]
    poll = ev["pods_list_poll_interval_s"]
    L += ["## Evidence timeline (recommendationservice Pods; host receipt clock unless noted)", "",
          "| Pod | Change | Last old sighting | First new sighting | First new available | Gap (s) | Requests inside the gap |",
          "| --- | --- | --- | --- | --- | ---: | --- |"]
    for t in ev["transitions"]:
        L.append("| %s | %s | %s | %s | %s | %.3f | %s |" % (
            t["pod"], t["change"], hms(us_of(t["last_old"])), hms(us_of(t["first_new"])),
            hms(us_of(t["first_new_available"])), t["gap_seconds"], fmt_list(t["requests_inside"]) or "none"))
    L += ["", "Creation rows use the API creationTimestamp (1 s resolution, API-server clock) as the last-old time. "
          "The old Pod's terminating -> failed -> absent gaps contain requests, but by rule K1 the old Pod cannot "
          "serve again once it is seen terminating, so they cause no ambiguity. Measured record-delivery lag "
          "(available_at - observed_at) over all %d API observations: median %.3f ms, max %.3f ms. Pods-list "
          "polling interval: %.3f-%.3f s (median %.3f s). Rollout patch request %s; rollout-wait returned %s." % (
              ev["api_observations"], lag["median"], lag["max"], poll["min"], poll["max"], poll["median"],
              ev["rollout_patch_receipt"]["request_started_at"][11:26], ev["rollout_wait_receipt"]["response_received_at"][11:26]), ""]

    # Sensitivity
    S = res["sensitivity"]
    L += ["## Sensitivity", "", "**Clock offset** (the request's host-clock time = t_req + offset; V1). Cells: correct / wrong / unknown.", "",
          "| Offset (s) | " + " | ".join(label for label, _ in DELTAS) + " |", "| ---: | " + " | ".join("---" for _ in DELTAS) + " |"]
    for off, per in S["clock_offset_seconds"].items():
        L.append("| %s | %s |" % (off, " | ".join("%d / %d / %d%s" % (per[l]["correct"], per[l]["wrong"], per[l]["unknown"],
                                                                       (" (wrong: %s)" % fmt_list(per[l]["wrong_requests"])) if per[l]["wrong"] else "")
                                                  for l, _ in DELTAS)))
    t43 = us_of(res["truth"]["t_req"][43])
    t44 = us_of(res["truth"]["t_req"][44])
    switch = next(t for t in ev["transitions"] if t["change"] == "not_ready -> ready")
    L += ["", "Negative offsets (the request earlier on the host clock than recorded) produce wrong answers only at "
          "Delta = 0. They place the first new-Pod requests before the switch sighting, and the carried-forward view "
          "names the old Pod; once that sighting is available, those requests become unknown. Request 44 is affected "
          "from an offset of about -%.2f s. Positive offsets place the last old-Pod requests after the sighting that "
          "already shows the old Pod terminating and the new Pod ready. The rule then names the new Pod at every "
          "Delta, hindsight included, because it counts only ready Pods as serving (S0). Request 43 is affected "
          "from about +%.2f s. A terminating Pod can still finish work on an existing connection during its grace "
          "period (20 s here), so this is a limit of S0 as much as of the clocks. The offset range covers the -0.74 "
          "to +1.43 s apparent differences seen in the rollout clock audit, which are not an offset estimate." % (
              (t44 - us_of(switch["first_new_available"])) / 1e6, (us_of(switch["first_new"]) - t43) / 1e6), "",
          "**Simulated API feed delay** d (every API record's availability shifted by d seconds, as in the policy-gate "
          "audit's delay sweep; valid times unchanged; V1). This is simulated, not measured.", "",
          "| d (s) | " + " | ".join(label for label, _ in DELTAS) + " |", "| ---: | " + " | ".join("---" for _ in DELTAS) + " |"]
    for d, per in S["simulated_api_feed_delay_seconds"].items():
        L.append("| %s | %s |" % (d, " | ".join("%d / %d / %d%s" % (per[l]["correct"], per[l]["wrong"], per[l]["unknown"],
                                                                     (" (wrong: %s)" % fmt_list(per[l]["wrong_requests"])) if per[l]["wrong"] else "")
                                                for l, _ in DELTAS)))
    L += ["", "A late record feed turns carried-forward state into wrong answers, not just unknown ones: requests "
          "after the switch are attributed to the old Pod until the sighting that shows the switch arrives. In every "
          "cell of this table, wrong answers occur exactly when Delta < d, that is, when the view lacks records "
          "observed before the request itself. With Delta >= d the view contains every record observed up to "
          "t_req + (Delta - d), so it holds at least what the undelayed Delta = 0 view held, and that view had no "
          "wrong answers with aligned clocks. Unknown reasons per cell are in `results.json`.", ""]
    k3, nk1 = S["k3_startup_assumption"], S["without_k1"]
    L += ["**Rule variants (V1).** With K3 (a Pod whose first sighting is not_ready was not serving before it), "
          "hindsight gives %d / %d / %d (correct / wrong / unknown), against %d / %d / %d without K3. The creation-gap "
          "requests are then attributed to the old Pod. Without K1 (pure A1, as in the policy-gate resolver), "
          "hindsight gives %d / %d / %d: the old Pod's terminating -> failed -> absent gaps make it 'possibly serving' "
          "again, which Kubernetes rules out." % (
              k3["hindsight"]["correct"], k3["hindsight"]["wrong"], k3["hindsight"]["unknown"],
              R["V1"]["hindsight"]["correct"], R["V1"]["hindsight"]["wrong"], R["V1"]["hindsight"]["unknown"],
              nk1["hindsight"]["correct"], nk1["hindsight"]["wrong"], nk1["hindsight"]["unknown"]), ""]

    L += ["## Limitations", ""] + ["- " + x for x in res["limitations"]] + [""]
    L += ["## Files", "",
          "- `run_attribution_lag.py`: this analysis (reads only; writes only into this folder).",
          "- `results.json`: rules, evidence timeline, gaps, counts per variant and Delta, per-request answers with "
          "the Pod classes and the record IDs used, sensitivity tables, the resolver cross-check and input-file hashes.",
          "- `results.csv`: one row per variant x Delta x request.",
          "- `rerun_check.txt`: SHA-256 of all outputs from two separate runs.", ""]
    return "\n".join(L)


def us_of(text: str) -> int:
    return us(datetime.fromisoformat(text.replace("Z", "+00:00")))


def fmt_list(items) -> str:
    items = list(items)
    if not items:
        return ""
    out, start, prev = [], items[0], items[0]
    for x in items[1:] + [None]:
        if x is not None and x == prev + 1:
            prev = x
            continue
        out.append(str(start) if start == prev else "%d-%d" % (start, prev))
        if x is not None:
            start = prev = x
    return ", ".join(out)


if __name__ == "__main__":
    raise SystemExit(main())
