"""Bitemporal decision audit of the v1 policy gate on the real rollout evidence.

Evaluates a constructed scenario set (labelled together with the gate rules, not independently) twice per scenario:
AS-KNOWN (only records available at the decision cutoff) and CORRECTED (all records; hindsight), with the graph and
SQLite resolvers, and reports blocked / allowed counts, flips and the late records behind each flip. Its loaders and
mapping (``load_sightings``, ``build_observations``, ``make_config``) are imported read-only by the live audit and by
the governance adapters.

Inputs (read-only, real capture of 22 Sep 2026, Online Boutique subset):
  results/evidence-index-pilot-002/accepted_evidence.jsonl  API sightings (capture-era clocks)
  data/raw/rollout-telemetry/pilot-001/capture.json         command receipts (rollout patch)
  data/raw/rollout-telemetry/pilot-001/protocol.json        namespace, cluster, service map
  data/raw/rollout-telemetry/pilot-001/deployment-manifest.json, rollout-patch.json
Outputs (this directory): results.json, results.csv, SUMMARY.md.

No action is executed. No network access. Deterministic: re-running produces byte-identical outputs.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import platform
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aiops_kg.policy_gate import (  # noqa: E402
    ABSTAIN, ALLOW, CONTROLLER, DENY, GENERATION, NEEDS_APPROVAL, NODE, ONLINE_BOUTIQUE_CALL_GRAPH,
    STATE, VERDICTS, Action, BitemporalStore, FreezeWindow, GateConfig, ObjectRef, Observation,
    evaluate, identity_fact, iso, materialize_facts,
)

UTC = timezone.utc
PILOT = ROOT / "data/raw/rollout-telemetry/pilot-001"
INPUTS = {
    "api_sightings": ROOT / "results/evidence-index-pilot-002/accepted_evidence.jsonl",
    "capture": PILOT / "capture.json",
    "protocol": PILOT / "protocol.json",
    "deployment_manifest": PILOT / "deployment-manifest.json",
    "rollout_patch": PILOT / "rollout-patch.json",
    "scenarios": HERE / "scenarios.json",
    "gate_source": ROOT / "src/aiops_kg/policy_gate.py",
    "temporal_source": ROOT / "src/aiops_kg/temporal.py",
    "audit_source": Path(__file__).resolve(),
}
# UIDs reported; cross-checked below.
REPORTED_UIDS = {
    "Pod/18c38f03-dcc9-493e-9d26-ddeda4493c53": "recommendationservice-5c8859fcbf-kp2n4",
    "Pod/f43ab1d9-9d3a-4caf-848b-f9e937b54272": "recommendationservice-f59c9476-8pfpz",
    "ReplicaSet/36ceac8e-eb54-4646-9f1c-dbe26a3c41b9": "recommendationservice-5c8859fcbf",
    "ReplicaSet/e775e6b0-0205-45b4-8322-6b570526dccd": "recommendationservice-f59c9476",
    "Deployment/0d86f2f2-a008-43bd-86e0-e0d77421a492": "recommendationservice",
    "Pod/6112bca2-93c8-4763-a23b-d0023aa4ea3b": "productcatalogservice-7cd5497c86-52vnr",
    "Pod/17de07b8-f056-45ea-9c65-bf04a24e685b": "otel-collector-bd5cf76f7-wz5t4",
}
ONE_SECOND = timedelta(seconds=1)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def ts(text: str | None) -> datetime | None:
    if text is None:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"input verification failed: {message}")


# --------------------------------------------------------------------------
# Evidence loading and mapping (mapping version rollout-evidence-v1)
# --------------------------------------------------------------------------
def pod_state(resource: dict) -> str:
    status = resource.get("status", {})
    phase = status.get("phase")
    if phase == "Failed":
        return "failed"
    if phase == "Succeeded":
        return "succeeded"
    if resource["metadata"].get("deletionTimestamp"):
        return "terminating"
    statuses = status.get("containerStatuses") or []
    if phase == "Running" and statuses and all(c.get("ready") is True for c in statuses):
        return "ready"
    return "not_ready"


def load_sightings(protocol: dict) -> list[dict]:
    rows = []
    with INPUTS["api_sightings"].open(encoding="utf-8") as handle:
        for line in handle:
            entry = json.loads(line)
            record = entry["record"]
            if record["kind"] != "api_observation":
                continue
            payload = record["payload"]
            resource = payload["resource_data"]
            meta = resource["metadata"]
            check(payload["record_type"] == "resource_observation", "unexpected API record type")
            check(payload.get("observation_basis") == "snapshot_receipt", "unexpected observation basis")
            if resource["kind"] != "Node":
                check(meta.get("namespace") == protocol["namespace"], "namespace mismatch")
            rows.append({
                "record_id": record["evidence_id"], "collection_id": payload["collection_id"],
                "snapshot_id": payload["snapshot_id"], "resource": payload["resource"],
                "kind": resource["kind"], "uid": meta["uid"], "name": meta["name"],
                "subject": f"{resource['kind']}/{meta['uid']}",
                "created_at": ts(meta["creationTimestamp"]),
                "observed_at": ts(payload["observed_at"]), "available_at": ts(payload["available_at"]),
                # Offline evidence-index acceptance (integer ns -> exact microseconds).
                "index_available_at": EPOCH + timedelta(microseconds=entry["available_ns"] // 1000),
                "clock_adjusted": payload.get("clock_adjusted"),
                "source_sha256": payload.get("_source_record_sha256"), "resource_data": resource,
            })
    check(len({r["collection_id"] for r in rows}) == 1, "API sightings span several collections")
    check(all(r["observed_at"] <= r["available_at"] for r in rows), "availability precedes observation")
    return sorted(rows, key=lambda r: (r["observed_at"], r["record_id"]))


def patch_receipt(capture: dict) -> dict:
    receipts = {r["id"]: r for r in capture["command_receipts"]}
    patch = receipts["rollout-patch"]
    check(patch["exit_code"] == 0, "rollout patch did not succeed")
    check(patch["args"][:2] == ["patch", "deployment"], "unexpected rollout patch command")
    return patch


def build_observations(sightings: list[dict], patch: dict, protocol: dict, *,
                       delay: timedelta = timedelta(0), availability: str = "capture",
                       include_receipts: bool = True) -> tuple[list[Observation], list, dict]:
    """Map sightings (+ the patch receipt) to Observations and identity facts.

    availability='capture' uses the capture-era collector acceptance time plus
    an optional simulated ``delay``; 'index' uses the offline evidence-index
    acceptance time (measured, ~2.5 h later).
    """
    def avail(row):
        base = row["available_at"] if availability == "capture" else row["index_available_at"]
        return base + delay

    observations: list[Observation] = []
    identities: dict[str, dict] = {}
    snapshots: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in sightings:
        snapshots[(row["resource"], row["snapshot_id"])].append(row)
        subject, resource, meta = row["subject"], row["resource_data"], row["resource_data"]["metadata"]
        rid, observed = row["record_id"], row["observed_at"]
        created_ceiling = row["created_at"] + ONE_SECOND  # creationTimestamp has 1 s resolution
        known = identities.get(subject)
        if known is None:
            identities[subject] = {"name": row["name"], "created_at": row["created_at"],
                                   "available_at": avail(row), "record_id": rid}
        else:
            check(known["name"] == row["name"] and known["created_at"] == row["created_at"],
                  f"identity changed for {subject}")
        add = lambda predicate, value, starts=None: observations.append(
            Observation(rid, subject, predicate, value, observed, avail(row), starts))
        if row["kind"] == "Pod":
            add(STATE, pod_state(resource))
            owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
            check(len(owners) == 1, f"{subject} lacks a single controller reference")
            add(CONTROLLER, f"{owners[0]['kind']}/{owners[0]['uid']}")
            node = resource.get("spec", {}).get("nodeName")
            if node:
                add(NODE, f"NodeName/{node}")
        else:
            add(STATE, "present", created_ceiling)
            if row["kind"] in ("ReplicaSet", "Deployment"):
                generation = meta["generation"]
                add(GENERATION, str(generation), created_ceiling if generation == 1 else None)
            if row["kind"] == "ReplicaSet":
                owners = [o for o in meta.get("ownerReferences", []) if o.get("controller") is True]
                check(len(owners) == 1, f"{subject} lacks a single controller reference")
                add(CONTROLLER, f"{owners[0]['kind']}/{owners[0]['uid']}")
    # Absence: a previously seen UID missing from a later complete list of its kind.
    by_resource: dict[str, list[tuple[datetime, str, list[dict]]]] = defaultdict(list)
    for (resource, snapshot_id), rows in snapshots.items():
        check(len({r["observed_at"] for r in rows}) == 1, f"{snapshot_id} has several receipt times")
        by_resource[resource].append((rows[0]["observed_at"], snapshot_id, rows))
    for resource, items in by_resource.items():
        seen: dict[str, str] = {}
        for observed, snapshot_id, rows in sorted(items):
            present = {r["subject"] for r in rows}
            list_available = max(avail(r) for r in rows)  # the list is complete once all rows are accepted
            for subject in sorted(set(seen) - present):
                observations.append(Observation(f"absence:{snapshot_id}:{subject.split('/', 1)[1]}", subject,
                                                STATE, "absent", observed, list_available))
            for r in rows:
                seen[r["subject"]] = r["kind"]
    # Change feed: the rollout patch bounds the Deployment's generation change.
    receipt_info = None
    if include_receipts:
        target = protocol["replacement_service"]
        deployment_rows = [r for r in sightings if r["kind"] == "Deployment" and r["name"] == target]
        start, end = ts(patch["request_started_at"]), ts(patch["response_received_at"])
        receipt_available = ts(patch["collector_available_at"])
        before = [r for r in deployment_rows if r["observed_at"] < start]
        after = [r for r in deployment_rows if r["observed_at"] > end]
        previous = before[-1]["resource_data"]["metadata"]["generation"]
        following = after[0]["resource_data"]["metadata"]["generation"]
        check(following == previous + 1,
              "exactly one spec change must separate the sightings around the patch")
        subject = deployment_rows[0]["subject"]
        observations.append(Observation("receipt:rollout-patch#request_started_at", subject, GENERATION,
                                        str(previous), start, receipt_available))
        observations.append(Observation("receipt:rollout-patch#response_received_at", subject, GENERATION,
                                        str(following), end, receipt_available))
        receipt_info = {"subject": subject, "request_started_at": iso(start), "response_received_at": iso(end),
                        "collector_available_at": iso(receipt_available),
                        "generation_before": previous, "generation_after": following}
    identity_facts = [identity_fact(subject, info["name"], info["created_at"], info["available_at"],
                                    info["record_id"]) for subject, info in sorted(identities.items())]
    return observations, identity_facts, {"identities": identities, "patch": receipt_info}


def build_facts(sightings, patch, protocol, **kwargs):
    observations, identity_facts, info = build_observations(sightings, patch, protocol, **kwargs)
    facts, support = materialize_facts(observations)
    return list(facts) + identity_facts, support, observations, info


# --------------------------------------------------------------------------
# Scenario evaluation
# --------------------------------------------------------------------------
def load_scenarios():
    spec = json.loads(INPUTS["scenarios"].read_text(encoding="utf-8"))
    windows = tuple(FreezeWindow(w["label"], ts(w["start"]), ts(w["end"]), ts(w["declared_at"]))
                    for w in spec["freeze_windows"])
    scenarios = []
    for s in spec["scenarios"]:
        target = ObjectRef(**s["target"])
        action = Action(s["id"], s["action"], target, service=s.get("service"), replicas=s.get("replicas"))
        check(s["label"] in ("safe", "unsafe"), f"{s['id']} label")
        scenarios.append({**s, "time": ts(s["decision_time"]), "action_obj": action})
    check(len({s["id"] for s in scenarios}) == len(scenarios), "duplicate scenario IDs")
    return spec, windows, scenarios


def make_config(protocol, windows, change_window_seconds=30.0):
    return GateConfig(change_window_seconds=change_window_seconds, replica_floor=1,
                      freeze_windows=windows, call_graph=ONLINE_BOUTIQUE_CALL_GRAPH, blast_radius_k=3,
                      blast_radius_direction="downstream", blast_radius_transitive=True,
                      stale_view_seconds=300.0, carry_forward_seconds=600.0,
                      service_deployments=protocol["service_deployments"])


def evaluate_all(facts, scenarios, config, engines=("graph", "sqlite")):
    store = BitemporalStore(facts, engines=engines)
    policy_horizon = max((w.declared_at for w in config.freeze_windows if w.declared_at), default=None)
    out = {}
    try:
        for s in scenarios:
            per_engine = {}
            for engine in engines:
                known = evaluate(s["action_obj"], store.as_known(
                    s["time"], carry_forward_seconds=config.carry_forward_seconds, engine=engine), config)
                corrected = evaluate(s["action_obj"], store.corrected(
                    s["time"], carry_forward_seconds=config.carry_forward_seconds, engine=engine,
                    horizon=policy_horizon), config)
                per_engine[engine] = (known, corrected)
            reference = per_engine[engines[0]]
            for engine in engines[1:]:
                other = per_engine[engine]
                if (reference[0].to_dict(), reference[1].to_dict()) != (other[0].to_dict(), other[1].to_dict()):
                    raise SystemExit(f"graph/SQLite disagreement on {s['id']}")
            out[s["id"]] = reference
    finally:
        store.close()
    return out, store


def _answer(store, resolution):
    """Comparable resolver answer: status, value and the eligible validity starts."""
    starts = tuple(sorted(iso(store.fact(fid).valid_from) for fid in resolution.fact_ids)) \
        if resolution.status == "resolved" else ()
    return resolution.status, resolution.value, starts


def _describe_fact(fact):
    interval = (f"[{iso(fact.valid_from)}, {iso(fact.valid_to)})" if not fact.known_open
                else f"[{iso(fact.valid_from)}, open; confirmed {iso(fact.confirmed_at)}]")
    return f"{fact.subject} {fact.predicate}={fact.object} valid {interval}"


def late_records(store, pair_index, scenario, known, corrected, support, config):
    """Records that arrived after the decision and changed what it relied on.

    For every (subject, predicate) either decision relied on, compare the
    resolver's answer at the decision's observation time under the as-known
    cutoff and the hindsight cutoff. Where they differ, replay the cutoff over
    that pair's later arrivals and report the first arrival that changes the
    answer. Identity records (NAME) that arrived later and were relied on in
    hindsight reveal objects unknown at decision time. Late freeze
    declarations are reported as constructed policy records.
    """
    t, rows = scenario["time"], []
    engine, freshness = store.engine("graph"), config.carry_forward_seconds
    pairs = set()
    for decision in (known, corrected):
        for rid in decision.record_ids:
            if not rid.startswith("freeze:"):
                fact = store.fact(rid)
                pairs.add((fact.subject, fact.predicate))
    for subject, predicate in sorted(pairs):
        if predicate == "NAME":
            continue
        before = engine.resolve(subject, predicate, t, t, freshness)
        after = engine.resolve(subject, predicate, t, corrected.knowledge_cutoff, freshness)
        if _answer(store, before) == _answer(store, after):
            continue
        for instant in sorted({f.available_at for f in pair_index[(subject, predicate)] if f.available_at > t}):
            probe = engine.resolve(subject, predicate, t, instant, freshness)
            if _answer(store, probe) != _answer(store, before):
                arrived = sorted(f.fact_id for f in pair_index[(subject, predicate)] if f.available_at == instant)
                rows.append({
                    "source": "evidence", "kind": "changed_resolution", "subject": subject, "predicate": predicate,
                    "as_known_answer": f"{before.status}:{before.value if before.value else before.reason}",
                    "corrected_answer": f"{after.status}:{after.value if after.value else after.reason}",
                    "available_at": iso(instant), "late_by_seconds": round((instant - t).total_seconds(), 6),
                    "record_ids": arrived,
                    "evidence": sorted({store.fact(fid).source_id for fid in arrived}),
                    "statement": "; ".join(_describe_fact(store.fact(fid)) for fid in arrived)})
                break
    for rid in corrected.record_ids:
        if rid.startswith("freeze:"):
            continue
        fact = store.fact(rid)
        # Only objects that already existed at the observation time can change
        # the decision; later-created ones are (correctly) excluded by the gate.
        if fact.predicate == "NAME" and fact.available_at > t and fact.valid_from <= t:
            rows.append({"source": "evidence", "kind": "identity_discovered_late", "subject": fact.subject,
                         "predicate": "NAME", "as_known_answer": "not visible",
                         "corrected_answer": f"{fact.object} (created {iso(fact.valid_from)})",
                         "available_at": iso(fact.available_at),
                         "late_by_seconds": round((fact.available_at - t).total_seconds(), 6),
                         "record_ids": [rid], "evidence": [fact.source_id],
                         "statement": f"{fact.subject} exists (first sighting)"})
    windows = {f"freeze:{w.label}": w for w in config.freeze_windows}
    for rid in corrected.record_ids:
        w = windows.get(rid)
        if w is not None and w.declared_at is not None and w.declared_at > t:
            rows.append({"source": "constructed", "kind": "policy_declaration", "subject": w.label,
                         "predicate": "declaration", "as_known_answer": "not declared",
                         "corrected_answer": f"freeze [{iso(w.start)}, {iso(w.end)})",
                         "available_at": iso(w.declared_at),
                         "late_by_seconds": round((w.declared_at - t).total_seconds(), 6),
                         "record_ids": [rid], "evidence": [], "statement": "constructed freeze declaration"})
    return sorted(rows, key=lambda r: (r["available_at"], r["subject"], r["predicate"]))


def superseded_inputs(store, decision, scenario):
    rows = []
    for rid in decision.record_ids:
        if rid.startswith("freeze:"):
            continue
        fact = store.fact(rid)
        if fact.superseded_at is not None:
            rows.append({"record_id": rid, "superseded_at": iso(fact.superseded_at)})
    return sorted(rows, key=lambda r: r["record_id"])


def metrics(scenarios, decisions, view_index):
    counts = Counter()
    verdicts = Counter()
    for s in scenarios:
        d = decisions[s["id"]][view_index]
        verdicts[d.verdict] += 1
        blocked = d.blocked
        if s["label"] == "unsafe":
            counts["unsafe_total"] += 1
            counts["unsafe_blocked" if blocked else "unsafe_allowed"] += 1
        else:
            counts["safe_total"] += 1
            counts["safe_wrongly_blocked" if blocked else "safe_allowed"] += 1
    keys = ["unsafe_total", "unsafe_blocked", "unsafe_allowed", "safe_total", "safe_wrongly_blocked", "safe_allowed"]
    return {**{k: counts[k] for k in keys}, "verdicts": {v: verdicts[v] for v in VERDICTS}}


def flip_summary(scenarios, decisions):
    verdict_flips = [s["id"] for s in scenarios if decisions[s["id"]][0].verdict != decisions[s["id"]][1].verdict]
    block_flips = [s["id"] for s in scenarios if decisions[s["id"]][0].blocked != decisions[s["id"]][1].blocked]
    rule_level = [s["id"] for s in scenarios
                  if any(a.verdict != b.verdict for a, b in zip(decisions[s["id"]][0].rules, decisions[s["id"]][1].rules))]
    kinds = Counter(f"{decisions[i][0].verdict}->{decisions[i][1].verdict}" for i in verdict_flips)
    n = len(scenarios)
    return {"scenarios": n, "verdict_flips": len(verdict_flips), "verdict_flip_share": round(len(verdict_flips) / n, 4),
            "block_status_flips": len(block_flips), "block_status_flip_share": round(len(block_flips) / n, 4),
            "rule_level_differences": len(rule_level), "flip_types": dict(sorted(kinds.items())),
            "verdict_flip_ids": verdict_flips, "block_flip_ids": block_flips, "rule_level_ids": rule_level}


def transitions(observations, identities, capture_start):
    """Value changes per (subject, predicate) with the last-old / first-new sightings,
    plus objects created during the capture (creation time -> first sighting)."""
    groups = defaultdict(list)
    for o in observations:
        if o.subject in identities:
            groups[(o.subject, o.predicate)].append(o)
    rows = []
    for subject, info in sorted(identities.items()):
        if info["created_at"] >= capture_start:
            first = min((o for o in observations if o.subject == subject and o.record_id.startswith("api:")),
                        key=lambda o: (o.observed_at, o.record_id))
            rows.append({"subject": subject, "predicate": "EXISTS", "from": "not created",
                         "to": f"created {iso(info['created_at'])[11:19]}Z (API clock, 1 s resolution)",
                         "last_old_observed_at": iso(info["created_at"]),
                         "first_new_observed_at": iso(first.observed_at),
                         "first_new_available_at": iso(first.available_at),
                         "uncertainty_gap_seconds": round((first.observed_at - info["created_at"]).total_seconds(), 6),
                         "first_new_record": first.record_id})
    for (subject, predicate), items in sorted(groups.items()):
        items.sort(key=lambda o: (o.observed_at, o.record_id))
        for prev, cur in zip(items, items[1:]):
            if prev.value != cur.value:
                rows.append({"subject": subject, "predicate": predicate, "from": prev.value, "to": cur.value,
                             "last_old_observed_at": iso(prev.observed_at), "first_new_observed_at": iso(cur.observed_at),
                             "first_new_available_at": iso(cur.available_at),
                             "uncertainty_gap_seconds": round((cur.observed_at - prev.observed_at).total_seconds(), 6),
                             "first_new_record": cur.record_id})
    return sorted(rows, key=lambda r: (r["first_new_observed_at"], r["subject"], r["predicate"]))


def run_variant(sightings, patch, protocol, scenarios, config, **kwargs):
    facts, support, observations, info = build_facts(sightings, patch, protocol, **kwargs)
    decisions, store = evaluate_all(facts, scenarios, config)
    return {"facts": facts, "support": support, "observations": observations, "info": info,
            "decisions": decisions, "store": store}


def compact(variant, scenarios):
    decisions = variant["decisions"]
    unsafe_allowed = {view: [s["id"] for s in scenarios
                             if s["label"] == "unsafe" and not decisions[s["id"]][index].blocked]
                      for view, index in (("as_known", 0), ("corrected", 1))}
    return {"as_known": metrics(scenarios, decisions, 0), "corrected": metrics(scenarios, decisions, 1),
            "flips": {k: v for k, v in flip_summary(scenarios, decisions).items() if not k.endswith("_ids")},
            "verdict_flip_ids": flip_summary(scenarios, decisions)["verdict_flip_ids"],
            "unsafe_allowed_ids": unsafe_allowed}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def short(key: str) -> str:
    kind, _, rest = key.partition("/")
    return f"{kind}/{rest[:8]}" if kind in ("Pod", "ReplicaSet", "Deployment") and len(rest) > 8 else key


def describe_target(s) -> str:
    t = s["target"]
    if "uid" in t:
        return short(f"{t['kind']}/{t['uid']}")
    if "name" in t:
        return f"{t['kind']} named {t['name']}"
    return f"{t['kind']} of service {t['service']}"


def action_text(s) -> str:
    extra = f" to {s['replicas']}" if "replicas" in s else ""
    return f"{s['action']} {describe_target(s)}{extra}"


def main() -> int:
    protocol = json.loads(INPUTS["protocol"].read_text(encoding="utf-8"))
    capture = json.loads(INPUTS["capture"].read_text(encoding="utf-8"))
    manifest = json.loads(INPUTS["deployment_manifest"].read_text(encoding="utf-8"))
    patch_doc = json.loads(INPUTS["rollout_patch"].read_text(encoding="utf-8"))
    check(capture["namespace"] == protocol["namespace"], "capture/protocol namespace")
    check(capture["cluster_incarnation_id"] == protocol["cluster_incarnation_id"], "cluster incarnation")
    check(patch_doc["spec"]["template"]["metadata"]["annotations"]["aiops.project/revision"] == "2", "patch content")
    deployments = {i["metadata"]["name"]: i for i in manifest["items"] if i["kind"] == "Deployment"}
    strategy = deployments[protocol["replacement_service"]]["spec"]["strategy"]["rollingUpdate"]
    check(strategy == {"maxSurge": 1, "maxUnavailable": 0}, "rollback surge assumption needs maxUnavailable=0")

    sightings = load_sightings(protocol)
    patch = patch_receipt(capture)
    spec, windows, scenarios = load_scenarios()
    primary_config = make_config(protocol, windows, 30.0)

    primary = run_variant(sightings, patch, protocol, scenarios, primary_config)
    identities = primary["info"]["identities"]
    for key, name in REPORTED_UIDS.items():
        check(key in identities and identities[key]["name"] == name, f"reported identity {key} not found")
    repeat = run_variant(sightings, patch, protocol, scenarios, primary_config)
    deterministic = all(primary["decisions"][k][i].to_dict() == repeat["decisions"][k][i].to_dict()
                        for k in primary["decisions"] for i in (0, 1))

    store, support, decisions = primary["store"], primary["support"], primary["decisions"]
    facts = primary["facts"]
    pair_index = defaultdict(list)
    for fact in facts:
        pair_index[(fact.subject, fact.predicate)].append(fact)
    per_scenario = []
    for s in scenarios:
        known, corrected = decisions[s["id"]]
        rule_diffs = [a.rule for a, b in zip(known.rules, corrected.rules) if a.verdict != b.verdict]
        late = late_records(store, pair_index, s, known, corrected, support, primary_config) if rule_diffs else []
        sources = sorted({r["source"] for r in late})
        per_scenario.append({
            "id": s["id"], "decision_time": iso(s["time"]), "action": s["action"], "service": s.get("service"),
            "target": s["target"], "replicas": s.get("replicas"), "label": s["label"], "rubric": s["rubric"],
            "justification": s["justification"],
            "as_known": known.to_dict(), "corrected": corrected.to_dict(),
            "verdict_flip": known.verdict != corrected.verdict, "block_flip": known.blocked != corrected.blocked,
            "rule_differences": rule_diffs, "late_records": late, "late_record_sources": sources,
            "as_known_inputs_later_superseded": superseded_inputs(store, known, s),
        })

    # Sensitivity analyses (same scenarios and labels).
    n_sweep = {}
    for n in (10.0, 30.0, 60.0, 120.0, 600.0):
        config = make_config(protocol, windows, n)
        variant = run_variant(sightings, patch, protocol, scenarios, config)
        n_sweep[f"{n:g}"] = compact(variant, scenarios)
    delay_sweep = {}
    for d in (0, 1, 3, 10, 30, 60):
        variant = run_variant(sightings, patch, protocol, scenarios, primary_config, delay=timedelta(seconds=d))
        delay_sweep[str(d)] = compact(variant, scenarios)
    indexed = run_variant(sightings, patch, protocol, scenarios, primary_config, availability="index",
                          include_receipts=False)
    earliest_index = min(r["index_available_at"] for r in sightings)

    timeline = transitions(primary["observations"], identities, ts(capture["started_at"]))
    fact_counts = Counter(f.predicate for f in facts)
    obs_counts = Counter(o.predicate for o in primary["observations"])
    engine_note = "graph and SQLite resolvers returned identical decisions for every scenario, view and variant"

    results = {
        "kind": "bitemporal_policy_decision_audit_constructed_scenarios_not_safety_evaluation",
        "mapping_version": "rollout-evidence-v1 (assumption A1: snapshot carry-forward)",
        "python": platform.python_version(),
        "inputs_sha256": {k: {"path": str(p.relative_to(ROOT)), "sha256": sha256(p)} for k, p in INPUTS.items()
                          if not k.endswith("_source")},
        "evidence": {
            "namespace": protocol["namespace"], "cluster_incarnation_id": protocol["cluster_incarnation_id"],
            "collection_id": sightings[0]["collection_id"], "api_sightings": len(sightings),
            "sightings_by_resource": dict(sorted(Counter(r["resource"] for r in sightings).items())),
            "clock_adjusted_sightings": sum(bool(r["clock_adjusted"]) for r in sightings),
            "first_sighting_observed_at": iso(sightings[0]["observed_at"]),
            "last_sighting_available_at": iso(max(r["available_at"] for r in sightings)),
            "capture_started_at": capture["started_at"], "capture_finished_at": capture["finished_at"],
            "rollout_patch_receipt": primary["info"]["patch"],
            "rollout_wait_receipt": {k: v for k, v in {r["id"]: r for r in capture["command_receipts"]}["rollout-wait"].items()
                                     if k in ("request_started_at", "response_received_at", "collector_available_at", "exit_code")},
            "offline_index_earliest_acceptance": iso(earliest_index),
            "identities": {k: {"name": v["name"], "created_at": iso(v["created_at"]),
                               "first_available_at": iso(v["available_at"])} for k, v in sorted(identities.items())},
            "observations_by_predicate": dict(sorted(obs_counts.items())),
            "facts_by_predicate": dict(sorted(fact_counts.items())), "facts_total": len(facts),
            "transitions": timeline,
        },
        "config_primary": {
            "change_window_seconds": primary_config.change_window_seconds, "library_default_change_window_seconds": GateConfig().change_window_seconds,
            "replica_floor": primary_config.replica_floor, "blast_radius_k": primary_config.blast_radius_k,
            "blast_radius_direction": primary_config.blast_radius_direction, "blast_radius_transitive": primary_config.blast_radius_transitive,
            "stale_view_seconds": primary_config.stale_view_seconds, "carry_forward_seconds": primary_config.carry_forward_seconds,
            "service_deployments": dict(primary_config.service_deployments),
            "freeze_windows": [{"label": w.label, "start": iso(w.start), "end": iso(w.end), "declared_at": iso(w.declared_at)}
                               for w in primary_config.freeze_windows],
            "call_graph": [list(e) for e in primary_config.call_graph],
        },
        "label_provenance": spec["label_provenance"], "label_rubric": spec["label_rubric"],
        "metrics_primary": {"as_known": metrics(scenarios, decisions, 0), "corrected": metrics(scenarios, decisions, 1)},
        "flips_primary": flip_summary(scenarios, decisions),
        "sensitivity_change_window": n_sweep,
        "sensitivity_simulated_api_feed_delay_seconds": delay_sweep,
        "as_indexed_offline_availability": compact(indexed, scenarios),
        "engine_equivalence": engine_note, "deterministic_rerun_identical": deterministic,
        "scenarios": per_scenario,
        "limitations": [
            "Scenarios and freeze windows are constructed; the labels were written together with the gate rules, not independently (rubric in scenarios.json).",
            "One real rollout of one single-replica service on a single-node kind cluster; no fault, no live execution.",
            "Snapshot-derived validity uses carry-forward assumption A1; transition times inside polling gaps remain unknown.",
            "API-server creationTimestamps (1 s resolution) and host receipt clocks are not calibrated against each other.",
            "The primary change window N=30 s is time-scaled for a 113 s capture; the 600 s default is reported as sensitivity.",
            "Delay-sweep availability is simulated by shifting measured capture-era availability; it is not measured.",
        ],
    }
    outputs = write_outputs(results, scenarios, per_scenario)
    print(json.dumps({"scenarios": len(scenarios), "facts": len(facts), "deterministic": deterministic,
                      "primary": results["metrics_primary"], "flips": {k: v for k, v in results["flips_primary"].items()
                                                                        if not k.endswith("_ids")},
                      "outputs": outputs}, indent=2))
    return 0


def write_outputs(results, scenarios, per_scenario):
    (HERE / "results.json").write_text(json.dumps(results, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["id", "decision_time", "action", "service", "target", "replicas", "label",
                     "as_known_verdict", "as_known_deciding_rules", "corrected_verdict", "corrected_deciding_rules",
                     "verdict_flip", "block_flip", "rule_differences", "late_records", "late_record_sources"])
    for row, s in zip(per_scenario, scenarios):
        writer.writerow([row["id"], row["decision_time"], row["action"], row["service"] or "",
                         describe_target(s), row["replicas"] if row["replicas"] is not None else "", row["label"],
                         row["as_known"]["verdict"], ";".join(row["as_known"]["deciding_rules"]),
                         row["corrected"]["verdict"], ";".join(row["corrected"]["deciding_rules"]),
                         row["verdict_flip"], row["block_flip"], ";".join(row["rule_differences"]),
                         ";".join(f"{r['subject']} {r['predicate']} {r['as_known_answer']}->{r['corrected_answer']} "
                                  f"@{r['available_at']} via {'|'.join(r['evidence'] or r['record_ids'])}"
                                  for r in row["late_records"]),
                         ";".join(row["late_record_sources"])])
    (HERE / "results.csv").write_text(buffer.getvalue(), encoding="utf-8")
    (HERE / "SUMMARY.md").write_text(render_summary(results, scenarios, per_scenario), encoding="utf-8")
    return [str((HERE / name).relative_to(ROOT)) for name in ("results.json", "results.csv", "SUMMARY.md")]


def key_findings(results, per_scenario) -> list[str]:
    """Findings computed from the results (no hand-entered numbers)."""
    m, f = results["metrics_primary"], results["flips_primary"]
    evidence = [r for r in per_scenario if r["verdict_flip"] and "evidence" in r["late_record_sources"]]
    constructed = [r for r in per_scenario if r["verdict_flip"] and r["late_record_sources"] == ["constructed"]]
    first_late = [min(x["late_by_seconds"] for x in r["late_records"] if x["source"] == "evidence") for r in evidence]
    gaps = [t["uncertainty_gap_seconds"] for t in results["evidence"]["transitions"]]
    evidence_block = [r["id"] for r in evidence if r["block_flip"]]
    unsafe_known = [r["id"] for r in per_scenario if r["label"] == "unsafe" and r["as_known"]["verdict"] == ALLOW]
    safe_blocked = Counter()
    for r in per_scenario:
        if r["label"] == "safe":
            for view in ("as_known", "corrected"):
                if r[view]["verdict"] != ALLOW:
                    safe_blocked[(view, ",".join(r[view]["deciding_rules"]))] += 1
    n_all = [n for n, v in results["sensitivity_change_window"].items()
             if v["as_known"]["safe_wrongly_blocked"] == v["as_known"]["safe_total"]]
    delays = results["sensitivity_simulated_api_feed_delay_seconds"]
    worst = max(delays, key=lambda d: float(d))
    lines = ["## Key findings", ""]
    lines.append(f"- {len(evidence)} of {f['scenarios']} decisions flip because of late real records. Each was taken between "
                 f"a real change and the arrival of the record showing it ({len(gaps)} changes in the transition table; "
                 f"gaps {min(gaps):.3f}-{max(gaps):.3f} s); the earliest causal record for each flip arrived "
                 f"{min(first_late):.3f}-{max(first_late):.3f} s after the decision.")
    lines.append(f"- Only {len(evidence_block)} of these changes blocked-versus-allowed ({', '.join(evidence_block) or 'none'}); "
                 f"the other {len(evidence) - len(evidence_block)} are blocked in both views but for different rules "
                 "(typically a definite as-known DENY becomes ABSTAIN because hindsight cannot place the transition).")
    lines.append(f"- As-known, {m['as_known']['unsafe_allowed']}/{m['as_known']['unsafe_total']} unsafe actions were "
                 f"allowed ({', '.join(unsafe_known) or 'none'}); the cause is the constructed late freeze "
                 f"declaration ({len(constructed)} flip), not cluster evidence.")
    lines.append("- Safe actions blocked (view, deciding rules: count): "
                 + "; ".join(f"{v} {rules or '-'}: {n}" for (v, rules), n in sorted(safe_blocked.items())) + ".")
    lines.append(f"- With N >= {min(n_all, key=float) if n_all else 'n/a'} s every safe action is blocked as-known (R2), "
                 f"because the testbed was created shortly before capture. With a simulated {worst} s feed delay, "
                 f"{delays[worst]['flips']['verdict_flips']} decisions flip and "
                 f"{delays[worst]['as_known']['safe_wrongly_blocked']}/{delays[worst]['as_known']['safe_total']} safe actions "
                 f"are blocked as-known; unsafe allowed as-known: "
                 f"{', '.join(delays[worst]['unsafe_allowed_ids']['as_known']) or 'none'} (R6 measures arrival recency, "
                 "so a slower feed can make an older view look fresh).")
    lines.append("")
    return lines


def render_summary(results, scenarios, per_scenario) -> str:
    m, f = results["metrics_primary"], results["flips_primary"]
    ev, cfg = results["evidence"], results["config_primary"]
    L = []
    L += ["# Policy gate v1: bitemporal decision audit", "",
          "**Constructed scenarios over one real rollout. The labels were written together with the gate rules "
          "(not independently validated); no action was executed. "
          "This is a consistency audit of the gate, not a safety evaluation.**", "",
          f"Evidence: {ev['api_sightings']} real API sightings (collection `{ev['collection_id']}`, namespace "
          f"`{ev['namespace']}`) plus the rollout-patch command receipt from the 22 Sep 2026 Online Boutique rollout "
          f"(capture {ev['capture_started_at']} to {ev['capture_finished_at']}). They map to {ev['facts_total']} "
          f"immutable fact versions under mapping `{results['mapping_version']}`.", "",
          f"Primary configuration: N (R2) = {cfg['change_window_seconds']:g} s (library default "
          f"{cfg['library_default_change_window_seconds']:g} s; see sensitivity), floor = {cfg['replica_floor']}, "
          f"k = {cfg['blast_radius_k']} ({cfg['blast_radius_direction']}, transitive), S (R6) = "
          f"{cfg['stale_view_seconds']:g} s, carry-forward F = {cfg['carry_forward_seconds']:g} s. "
          "Blocked = DENY, NEEDS_APPROVAL or ABSTAIN.", ""]
    L += key_findings(results, per_scenario)
    L += ["## Results for both views", "",
          "| View | Unsafe blocked | Unsafe allowed | Valid (safe) wrongly blocked | Valid allowed | DENY | ABSTAIN | NEEDS_APPROVAL | ALLOW |",
          "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, key in (("AS-KNOWN (records available at the decision cutoff)", "as_known"),
                      ("CORRECTED (all records, hindsight)", "corrected")):
        x = m[key]
        L.append(f"| {name} | {x['unsafe_blocked']}/{x['unsafe_total']} | {x['unsafe_allowed']}/{x['unsafe_total']} | "
                 f"{x['safe_wrongly_blocked']}/{x['safe_total']} | {x['safe_allowed']}/{x['safe_total']} | "
                 f"{x['verdicts']['DENY']} | {x['verdicts']['ABSTAIN']} | {x['verdicts']['NEEDS_APPROVAL']} | "
                 f"{x['verdicts']['ALLOW']} |")
    flip_types = ", ".join(f"{k} x{v}" for k, v in f["flip_types"].items())
    L += ["", f"**Flips between AS-KNOWN and CORRECTED:** {f['verdict_flips']}/{f['scenarios']} decisions "
          f"({100 * f['verdict_flip_share']:.1f}%) change verdict ({flip_types}); {f['block_status_flips']}/{f['scenarios']} "
          f"({100 * f['block_status_flip_share']:.1f}%) change between blocked and allowed; "
          f"{f['rule_level_differences']}/{f['scenarios']} differ in at least one rule.", ""]
    L += ["## Flips and the records that arrived late", "",
          "For each (object, predicate) the decision relied on, the resolver's answer at the decision's observation time "
          "is compared under the as-known and hindsight cutoffs; the late record is the first arrival after the decision "
          "that changes that answer. Identity records that arrived later reveal objects the as-known view could not see.", "",
          "| Scenario | Decision time | Action | Label | AS-KNOWN | CORRECTED | Rules that differ | What changed, and the late record (available at, late by) |",
          "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row, s in zip(per_scenario, scenarios):
        if not row["verdict_flip"]:
            continue
        late = "<br>".join(
            f"{short(r['subject'])} {r['predicate']}: {r['as_known_answer']} -> {r['corrected_answer']}; "
            f"`{(r['evidence'] or r['record_ids'])[0]}` ({r['available_at'][11:26]}, +{r['late_by_seconds']:.3f}s)"
            for r in row["late_records"]) or "none"
        L.append(f"| {row['id']} | {row['decision_time'][11:26]} | {action_text(s)} | {row['label']} | "
                 f"{row['as_known']['verdict']} ({', '.join(row['as_known']['deciding_rules']) or '-'}) | "
                 f"{row['corrected']['verdict']} ({', '.join(row['corrected']['deciding_rules']) or '-'}) | "
                 f"{', '.join(row['rule_differences'])} | {late} |")
    evidence_flips = [r["id"] for r in per_scenario if r["verdict_flip"] and "evidence" in r["late_record_sources"]]
    policy_flips = [r["id"] for r in per_scenario if r["verdict_flip"] and r["late_record_sources"] == ["constructed"]]
    both_blocked = [r["id"] for r in per_scenario if r["verdict_flip"] and not r["block_flip"]]
    L += ["", f"Evidence-driven flips (late real records): {len(evidence_flips)} ({', '.join(evidence_flips) or 'none'}). "
          f"Flips caused only by the constructed late freeze declaration: {len(policy_flips)} ({', '.join(policy_flips) or 'none'}). "
          f"Flips where both views block but for different rules: {len(both_blocked)} ({', '.join(both_blocked) or 'none'}).", ""]
    L += ["## Real transitions behind the late records", "",
          "Last sighting of the old value and first sighting of the new one (host receipt clock). The interval between them "
          "is an explicit uncertainty gap: no fact covers it in hindsight, while an as-known view carries the old value forward. "
          "EXISTS rows are objects created during the capture: API creation time (1 s resolution, uncalibrated against the "
          "host clock) to first sighting.", "",
          "| Object | Predicate | Change | Last old sighting | First new sighting | First new available | Gap (s) |",
          "| --- | --- | --- | --- | --- | --- | ---: |"]
    for t in ev["transitions"]:
        L.append(f"| {short(t['subject'])} | {t['predicate']} | {t['from']} -> {t['to']} | {t['last_old_observed_at'][11:26]} | "
                 f"{t['first_new_observed_at'][11:26]} | {t['first_new_available_at'][11:26]} | {t['uncertainty_gap_seconds']:.3f} |")
    p = ev["rollout_patch_receipt"]
    L += ["", f"The rollout patch receipt bounds the Deployment's generation {p['generation_before']} -> {p['generation_after']} "
          f"change to [{p['request_started_at'][11:26]}, {p['response_received_at'][11:26]}] and was available at "
          f"{p['collector_available_at'][11:26]}.", ""]
    L += ["## Sensitivity (same scenarios and labels)", "",
          "Change window N for R2 (primary uses 30 s because the whole testbed was created 54 s before capture and the capture lasts 113 s):", "",
          "| N (s) | AS-KNOWN unsafe allowed | AS-KNOWN safe wrongly blocked | CORRECTED unsafe allowed | CORRECTED safe wrongly blocked | Verdict flips |",
          "| ---: | ---: | ---: | ---: | ---: | ---: |"]
    for n, v in results["sensitivity_change_window"].items():
        L.append(f"| {n} | {v['as_known']['unsafe_allowed']}/{v['as_known']['unsafe_total']} | "
                 f"{v['as_known']['safe_wrongly_blocked']}/{v['as_known']['safe_total']} | "
                 f"{v['corrected']['unsafe_allowed']}/{v['corrected']['unsafe_total']} | "
                 f"{v['corrected']['safe_wrongly_blocked']}/{v['corrected']['safe_total']} | {v['flips']['verdict_flips']} |")
    L += ["", "**Simulated** delay of the API sighting feed (availability shifted by d seconds; valid times and the patch receipt unchanged). "
          "Not measured; it shows how the as-known view degrades as records arrive later:", "",
          "| Delay d (s) | AS-KNOWN unsafe allowed (IDs) | AS-KNOWN safe wrongly blocked | Verdict flips | Block-status flips | Flipped scenarios |",
          "| ---: | ---: | ---: | ---: | ---: | --- |"]
    for d, v in results["sensitivity_simulated_api_feed_delay_seconds"].items():
        ids = ", ".join(v["unsafe_allowed_ids"]["as_known"])
        L.append(f"| {d} | {v['as_known']['unsafe_allowed']}/{v['as_known']['unsafe_total']}{f' ({ids})' if ids else ''} | "
                 f"{v['as_known']['safe_wrongly_blocked']}/{v['as_known']['safe_total']} | {v['flips']['verdict_flips']} | "
                 f"{v['flips']['block_status_flips']} | {', '.join(v['verdict_flip_ids'])} |")
    ix = results["as_indexed_offline_availability"]
    L += ["", f"Measured offline index availability: the evidence index accepted these sightings from "
          f"{ev['offline_index_earliest_acceptance']} (about 2.5 h after capture). A gate reading that index live would have "
          f"returned {ix['as_known']['verdicts']['ABSTAIN']} ABSTAIN / {ix['as_known']['verdicts']['DENY']} DENY / "
          f"{ix['as_known']['verdicts']['NEEDS_APPROVAL']} NEEDS_APPROVAL / {ix['as_known']['verdicts']['ALLOW']} ALLOW as-known "
          f"for the {f['scenarios']} scenarios.", ""]
    letter = {ALLOW: "A", NEEDS_APPROVAL: "N", ABSTAIN: "?", DENY: "D"}
    vector = lambda d: " ".join(letter[r["verdict"]] for r in d["rules"])
    deciding = lambda d: "; ".join(f"{r['rule']} {r['reason']}" for r in d["rules"]
                                   if r["verdict"] == d["verdict"] and d["verdict"] != ALLOW) or "all rules ALLOW"
    L += ["## Per-scenario trace (primary configuration)", "",
          "Rule vector = verdicts of R1 R2 R3 R4 R5 R6 (A = ALLOW, N = NEEDS_APPROVAL, ? = ABSTAIN, D = DENY). "
          "The full trace (every rule's reason, human-readable detail and fact IDs, plus the label justification) "
          "is in `results.json` under `scenarios[*].as_known`, `.corrected` and `.late_records`.", "",
          "| ID | Decision time | Action | Label (rubric) | AS-KNOWN | R1-R6 | Deciding rule(s) and reason | CORRECTED | R1-R6 | Deciding rule(s) and reason |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row, s in zip(per_scenario, scenarios):
        k, c = row["as_known"], row["corrected"]
        mark = " (flip)" if row["verdict_flip"] else ""
        L.append(f"| {row['id']}{mark} | {row['decision_time'][11:23]} | {action_text(s)} | "
                 f"{row['label']} ({', '.join(row['rubric']) or '-'}) | {k['verdict']} | `{vector(k)}` | {deciding(k)} | "
                 f"{c['verdict']} | `{vector(c)}` | {deciding(c)} |")
    L += ["", "Label justifications (written with the scenarios):", ""]
    for row in per_scenario:
        L.append(f"- {row['id']}: {row['justification']}")
    L += ["", "## What this does not show", ""] + [f"- {x}" for x in results["limitations"]]
    L += [f"- {results['engine_equivalence']}; deterministic re-run identical: {results['deterministic_rerun_identical']}.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())
