#!/usr/bin/env python3
"""replay-policy v1: availability replay of three context policies on the real rollout evidence.

Question: during a rollout, how much do DELAYED, MISSING and CORRECTED deployment/topology records change what a
diagnostic pipeline can decide, and does an availability-aware (two-clock) policy with an explicit use / fall-back /
abstain rule do better than latest-state and plain temporal-join alternatives that receive identical evidence at the
same cutoff?

Decision task (from experiments/attribution-lag-v1, imported read-only): which recommendationservice Pod served
request i (1..120) of the 22 Sep 2026 rollout, at the request's own time t_req, decided at cutoff t_req + Delta
for Delta in {0, 5, 30, 120 s, hindsight}. Truth = the span-verified serving Pod (never an input).

Record streams: complete (as measured); API records delayed by d in {1, 3, 10, 30, 60 s}; missing (the
transition-revealing poll dropped; separately, the new Pod's first sighting dropped); corrected-late (the first
post-transition sightings first report the pre-transition state and are corrected 3 / 10 / 30 s later as new
versions); request clock offset -0.5 s / +0.5 s and uniform jitter +-0.5 s (5 seeds). Policies: latest_state,
temporal_join, bitemporal_abstain F = 600 s (primary) and F = 30 s (sensitivity).

    PYTHONDONTWRITEBYTECODE=1 python3 experiments/replay-policy-v1/run_replay_policy_v1.py
    PYTHONDONTWRITEBYTECODE=1 python3 experiments/replay-policy-v1/run_replay_policy_v1.py --capture <converted capture>

Outputs: results.json, results.csv, per_request.csv.gz and SUMMARY.md (this folder; capture mode: <capture>/replay/).
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import platform
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

sys.dont_write_bytecode = True  # before any project import
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aiops_kg import replay as R  # noqa: E402
from aiops_kg.policy_gate import Observation, materialize_facts  # noqa: E402
from aiops_kg.temporal import GraphStore, SqliteStore  # noqa: E402

POLICY_SPECS = (("latest_state", {}), ("temporal_join", {}),
                ("bitemporal_abstain", {"freshness_seconds": 600.0}),
                ("bitemporal_abstain", {"freshness_seconds": 30.0}))
PRIMARY_BITEMPORAL = "bitemporal_abstain_F600"
FEED_DELAYS = (1, 3, 10, 30, 60)
CORRECTION_DELAYS = (3, 10, 30)
CLOCK_OFFSETS = (-0.5, 0.5)
JITTER_BOUND = 0.5
JITTER_SEEDS = (1, 2, 3, 4, 5)
HEADLINE_DELTAS = ("0 s", "30 s")
API_KINDS = ("api", "absence")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("verification failed: " + message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return Path(path).resolve().relative_to(ROOT).as_posix()      # POSIX separators on every platform


def short(record_id: str) -> str:
    """'api:<collection>/240' -> 'api/240'; 'absence:023-pods:<uid>' -> 'absence/023-pods:<uid8>'."""
    head, _, suffix = record_id.partition("#")
    if head.startswith("api:"):
        head = "api/" + head.rsplit("/", 1)[1]
    elif head.startswith("absence:"):
        _, snapshot, uid = head.split(":")
        head = f"absence/{snapshot}:{uid[:8]}"
    return head + ("#" + suffix if suffix else "")


def hms(value_us: int | None) -> str:
    return "-" if value_us is None else R.from_us(value_us).strftime("%H:%M:%S.%f")


def fmt_list(items) -> str:
    items = sorted(items)
    if not items:
        return "none"
    out, start, prev = [], items[0], items[0]
    for x in items[1:] + [None]:
        if x is not None and x == prev + 1:
            prev = x
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        if x is not None:
            start = prev = x
    return ", ".join(out)


# ---------------------------------------------------------------------------
# Perturbed streams
# ---------------------------------------------------------------------------
def build_perturbations(task) -> list[dict]:
    base = task.records
    old = next(c for c in task.candidates if c.label == "old")
    new = next(c for c in task.candidates if c.label == "new")
    out = [{"name": "complete", "family": "complete", "records": base, "events": task.events,
            "description": "as measured (capture-era availability; measured record-delivery lag is sub-millisecond)",
            "manifest": {"perturbation": "none"}}]
    for d in FEED_DELAYS:
        records, manifest = R.delay(base, d, kinds=API_KINDS)
        out.append({"name": f"delayed_api_{d}s", "family": "delayed", "records": records, "events": task.events,
                    "description": f"every API record (sightings and derived absences) available {d} s later; "
                                   "valid times unchanged (simulated)", "manifest": manifest})
    reveal = R.revealing_records(base, mode="change")
    switch = [r for r, prev in reveal if r.subject == old.key and prev == "ready" and r.value == "terminating"]
    check(len(switch) == 1, "exactly one ready -> terminating sighting of the old Pod")
    switch_time = switch[0].observed_at
    records, manifest = R.drop_transition(base, mode="change", where=lambda r: r.observed_at == switch_time)
    dropped = {(e["subject"], e["from"], e["to"]) for e in manifest["records"]}
    check(dropped == {(old.key, "ready", "terminating"), (new.key, "not_ready", "ready")},
          "the switch poll's revealing records are old ready->terminating and new not_ready->ready")
    out.append({"name": "missing_switch_poll", "family": "missing", "records": records, "events": task.events,
                "description": f"the poll at {hms(switch_time)} that first shows old=terminating / new=ready is "
                               "never delivered (both revealing records dropped)", "manifest": manifest})
    records, manifest = R.drop_transition(base, mode="first", where=lambda r: r.subject == new.key)
    check(manifest["dropped"] == 1, "one first sighting of the new Pod")
    out.append({"name": "missing_new_pod_first_sighting", "family": "missing", "records": records,
                "events": task.events,
                "description": "the new Pod's first sighting (not_ready) is never delivered", "manifest": manifest})
    targets = frozenset(e["record_id"] for e in out[len(FEED_DELAYS) + 1]["manifest"]["records"])
    for s in CORRECTION_DELAYS:
        records, manifest = R.correct_late(base, s, where=lambda r: r.record_id in targets)
        stale = {e["subject"]: e["stale"]["value"] for e in manifest["records"]}
        check(stale == {old.key: "ready", new.key: "not_ready"}, "stale versions carry the pre-transition state")
        out.append({"name": f"corrected_late_{s}s", "family": "corrected", "records": records, "events": task.events,
                    "description": f"the switch poll's two records first arrive with the pre-transition state "
                                   f"(old=ready, new=not_ready); corrected versions arrive {s} s later",
                    "manifest": manifest})
    for off in CLOCK_OFFSETS:
        events, manifest = R.jitter_clock(task.events, off, kinds=("request",))
        out.append({"name": f"request_clock_{off:+.1f}s", "family": "clock", "records": base, "events": events,
                    "description": f"every request time shifted by {off:+.1f} s (constant offset of the request "
                                   "clock); cutoffs move with it", "manifest": manifest})
    for seed in JITTER_SEEDS:
        events, manifest = R.jitter_clock(task.events, JITTER_BOUND, seed=seed, kinds=("request",))
        out.append({"name": f"request_jitter_pm0.5s_seed{seed}", "family": "clock", "records": base,
                    "events": events,
                    "description": f"each request time shifted by an independent uniform offset in [-0.5, +0.5] s "
                                   f"(random.Random({seed}))", "manifest": manifest})
    return out


def make_policies():
    return tuple(R.make_policy(name, **params) for name, params in POLICY_SPECS)


# ---------------------------------------------------------------------------
# Grid evaluation
# ---------------------------------------------------------------------------
ANSWER_CODES = {"old": "O", "new": "N", None: "?"}


def answer_code(label) -> str:
    """One character per answer: O / N for the two-Pod labels, the digit K for label pK, ? for no answer."""
    return ANSWER_CODES[label] if label in ANSWER_CODES else label[1:]

def evaluate_grid(task, perturbations, policies):
    cells, rows_out = [], []
    for p in perturbations:
        stream = R.Stream(p["records"])
        withdrawn = stream.ever_withdrawn
        for policy in policies:
            per_delta = {}
            events = sorted(p["events"], key=lambda e: task.request_index[e.record_id])
            for label, delta in task.deltas:
                rows = []
                for event in events:
                    decision = task.decide(stream, event, delta, policy)
                    t = event.observed_at
                    truth = task.truth[event.record_id]
                    rows.append({"event": task.request_index[event.record_id], "t": t,
                                 "cutoff": None if delta is None else t + R.seconds_to_us(delta),
                                 "truth": truth, "answer": decision.answer, "status": decision.status,
                                 "reason": decision.reason, "outcome": R.outcome(decision.answer, truth),
                                 "record_ids": decision.record_ids, "classes": decision.classes})
                per_delta[label] = rows
            later = per_delta["hindsight"]
            for label, delta in task.deltas:
                rows = per_delta[label]
                flips = R.flips(rows, later)
                cells.append({"policy": policy.name, "perturbation": p["name"], "family": p["family"],
                              "delta": label, **R.score(rows, withdrawn=withdrawn), **flips,
                              "answers": "".join(answer_code(r["answer"]) for r in rows),
                              "statuses": "".join(r["status"][0] for r in rows)})
                flip_set = set(flips["flip_to_other_events"]) | set(flips["flip_to_abstain_events"])
                for r in rows:
                    rows_out.append((policy.name, p["name"], label, r, r["event"] in flip_set))
    return cells, rows_out


def cell(cells, policy, perturbation, delta):
    matches = [c for c in cells if (c["policy"], c["perturbation"], c["delta"]) == (policy, perturbation, delta)]
    check(len(matches) == 1, f"cell {policy} {perturbation} {delta}")
    return matches[0]


# ---------------------------------------------------------------------------
# Cross-checks
# ---------------------------------------------------------------------------
@contextmanager
def carry_forward(module, seconds: float):
    """Temporarily set the attribution-lag module's F (in memory only; the file is not touched)."""
    previous = module.CARRY_FORWARD_US
    module.CARRY_FORWARD_US = R.seconds_to_us(seconds)
    try:
        yield
    finally:
        module.CARRY_FORWARD_US = previous


def ala_pods_at(task, stream, cutoff, cache):
    """attribution-lag pods structure holding only the versions usable at the cutoff (corrections applied)."""
    key = tuple(sorted(stream.withdrawn(cutoff)))
    if key not in cache:
        withdrawn = frozenset(key)
        pods = {}
        for subject, pod in task.context["pods"].items():
            rows = [r for r in stream.versions(subject, task.predicate) if r.record_id not in withdrawn]
            pods[subject] = {**pod, "observations": [(r.observed_at, r.available_at, r.value, r.record_id)
                                                     for r in sorted(rows, key=lambda r: (r.observed_at, r.record_id))]}
        cache[key] = pods
    return cache[key]


def crosscheck_attribution_lag(task, perturbations, cells_rows):
    """bitemporal_abstain (F = 600 s and 30 s) + lifecycle rules == attribution-lag's attribute() on every
    perturbed stream, request and Delta (answer and reason)."""
    module = task.module
    rows_index = {}
    for policy, pert, label, row, _ in cells_rows:
        rows_index[(policy, pert, label, row["event"])] = row
    total = agree = 0
    mismatches = []
    for seconds, name in ((600.0, "bitemporal_abstain_F600"), (30.0, "bitemporal_abstain_F30")):
        with carry_forward(module, seconds):
            for p in perturbations:
                stream = R.Stream(p["records"])
                cache = {}
                for event in p["events"]:
                    t = event.observed_at
                    for label, delta in task.deltas:
                        c = R.HINDSIGHT if delta is None else t + R.seconds_to_us(delta)
                        # attribution-lag filters by availability itself; withdrawn versions are removed here.
                        pods = ala_pods_at(task, stream, c, cache)
                        answer, reason, _ = module.attribute(pods, t, c)
                        mine = rows_index[(name, p["name"], label, task.request_index[event.record_id])]
                        total += 1
                        if (answer, reason) == (mine["answer"] or "unknown", mine["reason"]):
                            agree += 1
                        elif len(mismatches) < 10:
                            mismatches.append({"policy": name, "perturbation": p["name"], "delta": label,
                                               "request": task.request_index[event.record_id],
                                               "attribution_lag": [answer, reason],
                                               "replay": [mine["answer"], mine["reason"]]})
    return {"decisions": total, "agreements": agree, "mismatches": mismatches,
            "scope": "bitemporal_abstain (F = 600 s and 30 s) with lifecycle rules K2/K1 versus "
                     "experiments/attribution-lag-v1 attribute() (K2, K1, A1, S0; its F set to the same value in "
                     "memory), on every perturbed stream x request x Delta; withdrawn (corrected) versions are "
                     "removed before calling attribute(), which applies the availability cutoff itself"}


def resolver_class(store_facts, resolution, t_us):
    if resolution.status != "resolved":
        return (R.ABSTAIN, None)
    facts = [store_facts[fid] for fid in resolution.fact_ids]
    fallback = any(f.known_open and f.confirmed_at is not None and t_us > R.to_us(f.confirmed_at) for f in facts)
    return (R.FALLBACK if fallback else R.CONFIRMED, resolution.value)


def crosscheck_resolver(task, perturbations):
    """Per-Pod state (before K1/K2): bitemporal_abstain versus the project's temporal resolver (graph and SQLite
    engines of src/aiops_kg/temporal.py over policy_gate.materialize_facts of the usable versions), and
    temporal_join versus an independent as-of lookup."""
    policies = {600.0: R.make_policy("bitemporal_abstain", freshness_seconds=600.0),
                30.0: R.make_policy("bitemporal_abstain", freshness_seconds=30.0)}
    join = R.make_policy("temporal_join")
    total = agree = asof_total = asof_agree = 0
    mismatches = []
    for p in perturbations:
        stream = R.Stream(p["records"])
        cache = {}
        for event in p["events"]:
            t = event.observed_at
            for label, delta in task.deltas:
                c = R.HINDSIGHT if delta is None else t + R.seconds_to_us(delta)
                for cand in task.candidates:
                    rows = stream.visible(cand.key, task.predicate, c)
                    key = tuple(r.record_id for r in rows)
                    if key not in cache:
                        observations = [Observation(r.record_id, r.subject, r.predicate, r.value,
                                                    R.from_us(r.observed_at), R.from_us(r.available_at)) for r in rows]
                        facts, _ = materialize_facts(observations)
                        cache[key] = ({f.fact_id: f for f in facts}, GraphStore(facts), SqliteStore(facts))
                    by_id, graph, sqlite = cache[key]
                    decision_at = R.from_us(max([t] + [r.available_at for r in rows]))
                    for seconds, policy in policies.items():
                        mine_answer = policy(stream, cand.key, task.predicate, t, c)
                        mine = (mine_answer.status, mine_answer.value)
                        for engine in (graph, sqlite):
                            res = engine.resolve(cand.key, task.predicate, R.from_us(t), decision_at, seconds)
                            theirs = resolver_class(by_id, res, t)
                            total += 1
                            if theirs == mine:
                                agree += 1
                            elif len(mismatches) < 10:
                                mismatches.append({"perturbation": p["name"], "delta": label, "F": seconds,
                                                   "request": task.request_index[event.record_id],
                                                   "pod": cand.label, "replay": list(mine), "resolver": list(theirs),
                                                   "resolver_reason": res.reason})
                    j = join(stream, cand.key, task.predicate, t, c)
                    before = [r for r in rows if r.observed_at <= t]
                    asof = before[-1].value if before else None
                    asof_total += 1
                    asof_agree += int(asof == j.value)
        for _, _, sqlite in cache.values():
            sqlite.close()
    return {"queries": total, "agreements": agree, "mismatches": mismatches,
            "temporal_join_vs_independent_asof": {"queries": asof_total, "agreements": asof_agree},
            "scope": "per-Pod STATE before K1/K2, every perturbed stream x request x Delta x Pod; bitemporal_abstain "
                     "(F = 600 s and 30 s) status/value versus GraphStore and SqliteStore resolve() over "
                     "materialize_facts() of the versions usable at the cutoff (resolved via a known-open fact "
                     "beyond its confirmation = FALLBACK; other resolved = CONFIRMED; unknown/conflict = ABSTAIN)"}


def crosscheck_delay_records(task):
    """R.delay on the loaded records == attribution-lag's own delayed pod observations, for every d."""
    module, ctx = task.module, task.context
    results = {}
    for d in FEED_DELAYS:
        mine, _ = R.delay(task.records, d, kinds=API_KINDS)
        pods, _ = module.pod_observations(ctx["sightings"], ctx["patch"], ctx["protocol"], delay_s=d)
        theirs = sorted((subject, o[3], o[0], o[1], o[2]) for subject, pod in pods.items() for o in pod["observations"])
        ours = sorted((r.subject, r.record_id, r.observed_at, r.available_at, r.value) for r in mine)
        results[str(d)] = ours == theirs
    return results


def crosscheck_join_lifecycle(task, perturbations, cells_rows):
    """temporal_join with and without the K1/K2 lifecycle rules gives identical answers everywhere."""
    join = R.make_policy("temporal_join")
    rows_index = {(pol, pert, label, row["event"]): row for pol, pert, label, row, _ in cells_rows}
    total = agree = 0
    for p in perturbations:
        stream = R.Stream(p["records"])
        for event in p["events"]:
            for label, delta in task.deltas:
                bare = task.decide(stream, event, delta, join, lifecycle_rules=False)
                row = rows_index[("temporal_join", p["name"], label, task.request_index[event.record_id])]
                total += 1
                agree += int((bare.answer, bare.status) == (row["answer"], row["status"]))
    return {"decisions": total, "agreements": agree}


# ---------------------------------------------------------------------------
# One full pass
# ---------------------------------------------------------------------------
def run_once(task):
    perturbations = build_perturbations(task)
    policies = make_policies()
    cells, rows = evaluate_grid(task, perturbations, policies)
    return perturbations, policies, cells, rows


def fingerprint(cells, rows) -> str:
    payload = json.dumps([cells, [(a, b, c, {k: v for k, v in r.items()}, f) for a, b, c, r, f in rows]],
                         sort_keys=True, default=list)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Availability replay of three context policies (replay-policy v1).")
    parser.add_argument("--capture", type=Path,
                        help="a converted Phase 3 capture directory (reads <capture>/evidence/, writes <capture>/replay/)")
    parser.add_argument("--service", help="target service (default: from <capture>/incident.json)")
    parser.add_argument("--output", type=Path, help="with --capture: output directory (default <capture>/replay; "
                                                    "must not exist yet)")
    args = parser.parse_args(argv)
    if args.capture is not None:
        return run_capture(args.capture, args.service, args.output)
    if args.service or args.output:
        parser.error("--service and --output need --capture")
    return run_default()


def run_default() -> int:
    task = R.load_attribution_lag_task(ROOT)
    check(len(task.records) == 61 and len(task.events) == 120, "expected 61 Pod STATE records and 120 requests")
    perturbations, policies, cells, rows = run_once(task)
    again = run_once(R.load_attribution_lag_task(ROOT))
    check(fingerprint(cells, rows) == fingerprint(again[2], again[3]), "two passes differ")

    checks = {
        "delay_records_equal_attribution_lag": crosscheck_delay_records(task),
        "bitemporal_vs_attribution_lag_rules": crosscheck_attribution_lag(task, perturbations, rows),
        "per_pod_state_vs_temporal_resolver": crosscheck_resolver(task, perturbations),
        "temporal_join_lifecycle_rules_noop": crosscheck_join_lifecycle(task, perturbations, rows),
    }
    check(all(checks["delay_records_equal_attribution_lag"].values()), "delayed records differ from attribution-lag")
    a = checks["bitemporal_vs_attribution_lag_rules"]
    check(a["agreements"] == a["decisions"], f"bitemporal vs attribution-lag: {a['mismatches'][:3]}")
    b = checks["per_pod_state_vs_temporal_resolver"]
    check(b["agreements"] == b["queries"], f"resolver cross-check: {b['mismatches'][:3]}")
    j = b["temporal_join_vs_independent_asof"]
    check(j["agreements"] == j["queries"], "temporal_join differs from the independent as-of lookup")
    k = checks["temporal_join_lifecycle_rules_noop"]
    check(k["agreements"] == k["decisions"], "lifecycle rules change a temporal_join answer")

    results = build_results(task, perturbations, policies, cells, checks)
    index = {(pol, pert, label, row["event"]): row for pol, pert, label, row, _ in rows}
    summary = render_summary(results, index)  # verifies every stated claim before anything is written
    (HERE / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    (HERE / "results.csv").write_text(cells_csv(cells), encoding="utf-8")
    (HERE / "per_request.csv.gz").write_bytes(per_request_gz(rows))
    (HERE / "SUMMARY.md").write_text(summary, encoding="utf-8")
    for c in cells:
        if c["delta"] in HEADLINE_DELTAS and not c["perturbation"].startswith("request_jitter"):
            print(f"{c['perturbation']:34s} {c['policy']:24s} {c['delta']:5s} "
                  f"{c['correct']:3d}/{c['wrong']:3d}/{c['abstain']:3d} flips {c['flips']:3d}")
    print("cross-checks:", json.dumps({k: (v if not isinstance(v, dict) or "agreements" not in v
                                          else f"{v['agreements']}/{v.get('decisions', v.get('queries'))}")
                                       for k, v in checks.items()}))
    return 0


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
CELL_COLUMNS = ("policy", "perturbation", "family", "delta", "n", "correct", "wrong", "abstain", "harmful",
                "coverage", "confirmed", "fallback", "wrong_confirmed", "wrong_fallback", "tie_breaks", "flips",
                "flip_to_other", "flip_to_abstain", "resolved_later", "answers_using_withdrawn_version")


def cells_csv(cells) -> str:
    """One row per policy x perturbation x Delta (the grid's results table)."""
    buffer = io.StringIO()
    w = csv.writer(buffer, lineterminator="\n")
    w.writerow(CELL_COLUMNS + ("wrong_requests", "abstain_requests", "abstain_reasons", "flip_requests"))
    for c in cells:
        w.writerow([c[k] for k in CELL_COLUMNS] + [
            fmt_list(c["wrong_events"]), fmt_list(c["abstain_events"]),
            ";".join(f"{k}={v}" for k, v in c["abstain_reasons"].items()),
            fmt_list(c["flip_to_other_events"] + c["flip_to_abstain_events"])])
    return buffer.getvalue()


def per_request_gz(rows) -> bytes:
    """One row per policy x perturbation x Delta x request, gzip-compressed with a fixed header (deterministic)."""
    buffer = io.StringIO()
    w = csv.writer(buffer, lineterminator="\n")
    w.writerow(["policy", "perturbation", "delta", "request_index", "t_req", "cutoff", "truth", "answer", "status",
                "outcome", "reason", "flips_by_hindsight", "old_pod_class", "old_pod_rule", "new_pod_class",
                "new_pod_rule", "records_used"])
    for policy, pert, label, r, flipped in rows:
        classes = {label_: (cls, rule) for label_, cls, rule, _ in r["classes"]}
        w.writerow([policy, pert, label, r["event"], R.iso(r["t"]), R.iso(r["cutoff"]) or "hindsight", r["truth"],
                    r["answer"] or "", r["status"], r["outcome"], r["reason"], flipped,
                    classes["old"][0], classes["old"][1], classes["new"][0], classes["new"][1],
                    ";".join(short(x) for x in r["record_ids"])])
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as handle:
        handle.write(buffer.getvalue().encode("utf-8"))
    return out.getvalue()


def build_results(task, perturbations, policies, cells, checks):
    module = task.module
    inputs = [ROOT / "results/evidence-index-pilot-002/accepted_evidence.jsonl", module.pga.INPUTS["protocol"],
              module.pga.INPUTS["capture"]]
    records = [{**r.to_dict(), "short_id": short(r.record_id)} for r in task.records]
    return {
        "kind": "availability_replay_policy_comparison_one_rollout_not_diagnosis_accuracy",
        "question": ("During a rollout, how much do delayed, missing and corrected deployment/topology records change "
                     "which Pod a pipeline attributes a request to, and does the two-clock use / fall-back / abstain "
                     "policy do better than latest-state and plain temporal-join policies given identical records "
                     "and the same cutoff?"),
        "inputs_sha256": {rel(p): sha256(p) for p in inputs},
        "environment": {"python": platform.python_version()},
        "deterministic_two_pass_identical": True,
        "rules": RULES,
        "policies": [{"name": p.name, "abstains_by_design": p.abstains, "uses_observation_time": p.valid_time,
                      "params": dict(p.params)} for p in policies],
        "deltas": [label for label, _ in task.deltas],
        "perturbations": [{"name": p["name"], "family": p["family"], "description": p["description"],
                           "records": len(p["records"]), "manifest": p["manifest"]} for p in perturbations],
        "evidence": {
            "pod_state_records": len(task.records), "requests": len(task.events),
            "candidates": [{"label": c.label, "key": c.key, "created_floor": R.iso(c.created_floor)}
                           for c in task.candidates],
            "truth": {"old": [task.request_index[e] for e, v in task.truth.items() if v == "old"],
                      "new": [task.request_index[e] for e, v in task.truth.items() if v == "new"]},
            "t_req": {task.request_index[e.record_id]: R.iso(e.observed_at) for e in task.events},
            "key_records": key_records(task),
            "records": records,
        },
        "cells": cells,
        "cross_checks": checks,
        "limitations": LIMITATIONS,
    }


def key_records(task) -> dict:
    """The records around the serving switch, found from the data (not typed in)."""
    old = next(c for c in task.candidates if c.label == "old")
    new = next(c for c in task.candidates if c.label == "new")
    stream = R.Stream(task.records)
    reveal = R.revealing_records(task.records, mode="change")
    switch = next(r for r, prev in reveal if r.subject == old.key and prev == "ready" and r.value == "terminating")
    at = switch.observed_at

    def info(r):
        return {"id": short(r.record_id), "record_id": r.record_id, "value": r.value,
                "observed_at": R.iso(r.observed_at), "available_at": R.iso(r.available_at)}

    out = {"switch_time": R.iso(at)}
    for cand in (old, new):
        rows = stream.versions(cand.key, task.predicate)
        out[cand.label] = {"before": info([r for r in rows if r.observed_at < at][-1]),
                           "switch": info(next(r for r in rows if r.observed_at == at)),
                           "after": info(next(r for r in rows if r.observed_at > at)),
                           "first": info(rows[0]), "created_floor": R.iso(cand.created_floor)}
    return out


RULES = {
    "time_and_cutoff": "t = request i's t_req (client root span start, microseconds, client clock); cutoff c = t + "
                       "Delta on the same time line (Delta in {0, 5, 30, 120 s}); hindsight = every record and every "
                       "correction. The request itself is known at t (attribution-lag variant V1).",
    "usable_record": "a record version is usable at c iff available_at <= c and no correction of it has "
                     "available_at <= c (append-only: a correction withdraws its predecessor from its own "
                     "availability on; nothing is deleted or overwritten). Every policy receives exactly the "
                     "usable versions at the same c.",
    "records": "Pod STATE records of the two recommendationservice Pods, derived by attribution-lag-v1's "
               "pod_observations() from policy-gate-v1's load_sightings()/build_observations() (pod_state(): "
               "Failed->failed, Succeeded->succeeded, deletionTimestamp->terminating, Running with all containers "
               "ready->ready, else not_ready; absent = missing from a later complete Pods list, available when the "
               "whole list is). observed_at = host receipt of the list response; available_at = capture-era "
               "pipeline receipt. Record IDs: api/N = api:<collection 1e40730b-...>/N; absence/NNN-pods:<uid8>.",
    "latest_state": "per Pod, the usable record with the greatest observed_at (then available_at, record_id) at c; "
                    "t is ignored; always CONFIRMED; no lifecycle rules (they need t).",
    "temporal_join": "per Pod, valid intervals [observed_at, next observed_at of that Pod) over the usable records "
                     "(as-of / SCD-2 reading; a record with a recorded end uses it); the interval covering t is used "
                     "(CONFIRMED); if none covers t, the nearest earlier record (FALLBACK; never happens with these "
                     "sightings); no row at or before t -> the Pod is absent from the join (not serving). No "
                     "abstention. Lifecycle rules K2/K1 are applied but never change an answer (checked).",
    "bitemporal_abstain": "per Pod, with p = last usable sighting at or before t and n = first usable sighting after "
                          "t: p and n same value -> CONFIRMED (assumption A1); a sighting exactly at t and none "
                          "later -> CONFIRMED; p and n differ -> ABSTAIN transition_between_records; no p -> ABSTAIN "
                          "no_record_at_or_before_t (a snapshot is not extended backwards); only p: t - p < F -> "
                          "FALLBACK (carried forward), else ABSTAIN stale_beyond_freshness. F = 600 s (primary, the "
                          "policy-gate audit's carry-forward) or 30 s (sensitivity).",
    "lifecycle_rules": "for the two valid-time policies, before the policy: K2 creationTimestamp floor > t -> not "
                       "serving; K1 last usable sighting at or before t is terminating/failed/succeeded/absent -> not "
                       "serving (irreversible). Both CONFIRMED. Same order as attribution-lag's classify_pod.",
    "serving": "S0: a Pod serves at t iff its state at t is ready (routing assumption, as in attribution-lag).",
    "attribution": "exactly one Pod serving and no other Pod possibly serving -> that Pod (CONFIRMED if every "
                   "in-view Pod's status is CONFIRMED, else FALLBACK); no Pod possibly serving -> ABSTAIN "
                   "no_serving_pod_confirmed; one possibly serving but unconfirmed -> ABSTAIN serving_pod_unconfirmed; "
                   "two possibly serving -> ABSTAIN two_pods_possible for bitemporal_abstain; for the non-abstaining "
                   "policies two serving Pods would be broken towards the newest Pod (tie_break_newest; counted). A "
                   "Pod with no usable record is not in view and not a candidate.",
    "metrics": "correct / wrong against the span-verified Pod; abstain = no Pod named; harmful = wrong (a wrong "
               "instance is harmful, an abstention is not); coverage = (correct + wrong) / 120; wrong_confirmed / "
               "wrong_fallback split the wrong answers by the status the policy attached.",
    "flips": "a saved answer at cutoff c flips if the same policy, re-deciding the same request on the same stream "
             "with every record and correction (hindsight), names another Pod (flip_to_other) or abstains "
             "(flip_to_abstain). resolved_later = abstained at c, answers in hindsight (not a flip). "
             "answers_using_withdrawn_version = answers at c whose records include a version later withdrawn by a "
             "correction.",
}

LIMITATIONS = [
    "One rollout of one single-replica service (maxSurge 1, maxUnavailable 0) on a single-node kind cluster; no fault.",
    "Pods were listed by polling every 2.4-3.8 s; a change inside a polling gap cannot be placed.",
    "Request times (client clock) and API receipt times (host clock) are not calibrated against each other; "
    "creationTimestamp has 1 s resolution (API-server clock). The clock perturbations show where this matters.",
    "Perturbations are simulated on top of measured timestamps. The measured record-delivery lag "
    "(available_at - observed_at) was sub-millisecond; delays, drops and corrections are not measured events.",
    "The policies are simple by design (one rule each). Assumption A1 (no flap between equal sightings) and S0 "
    "(serving = ready) are modelling assumptions, as in attribution-lag-v1.",
    "n is tiny: 120 requests from one rollout, most of them far from any transition. Apart from the 10-60 s "
    "simulated feed delays, only 5-13 requests near the switch differ between policies. Replay variants are not "
    "independent incidents. No accuracy claim.",
    "The decision is instance attribution (which Pod served a request), not root-cause ranking; no fault, "
    "diagnosis baseline or remediation is involved.",
]


# ---------------------------------------------------------------------------
# SUMMARY.md: every number is read from the cells; every qualitative claim is checked before it is written
# ---------------------------------------------------------------------------
LS, TJ, BA, B30 = "latest_state", "temporal_join", "bitemporal_abstain_F600", "bitemporal_abstain_F30"
POLICY_ORDER = (LS, TJ, BA, B30)
POLICY_LABEL = {LS: "latest_state", TJ: "temporal_join", BA: "bitemporal_abstain F=600 s",
                B30: "bitemporal_abstain F=30 s"}


def us_of(text: str) -> int:
    return R.to_us(datetime.fromisoformat(text.replace("Z", "+00:00")))


def render_summary(res, index) -> str:
    cells = res["cells"]
    C = lambda pol, pert, d: cell(cells, pol, pert, d)
    ROW = lambda pol, pert, d, i: index[(pol, pert, d, i)]
    perts = [p["name"] for p in res["perturbations"]]
    manifests = {p["name"]: p["manifest"] for p in res["perturbations"]}
    headline = [p for p in perts if not p.startswith("request_jitter") or p.endswith("seed1")]
    seeds = [p for p in perts if p.startswith("request_jitter")]
    delays = [p for p in perts if p.startswith("delayed_api_")]
    finite = [d for d in res["deltas"] if d != "hindsight"]
    secs = lambda label: float(label.split()[0])
    ev = res["evidence"]
    key = ev["key_records"]
    old_reqs, new_reqs = ev["truth"]["old"], ev["truth"]["new"]
    t_of = {int(k): us_of(v) for k, v in ev["t_req"].items()}
    rec_by_short = {r["short_id"]: r for r in ev["records"]}
    ko, kn = key["old"], key["new"]
    sw = key["switch_time"]
    span = lambda a, b: list(range(a, b + 1))
    ids = lambda row: ", ".join(short(x) for x in row["record_ids"])
    rule = lambda row, label: next(r for lab, _, r, _ in row["classes"] if lab == label)
    checks = res["cross_checks"]
    n_req = ev["requests"]

    # ---- claim checks -------------------------------------------------------------------------------
    # (1) Delta = 0: identical answers; F only.
    for p in perts:
        a = C(LS, p, "0 s")["answers"]
        check(a == C(TJ, p, "0 s")["answers"] == C(BA, p, "0 s")["answers"], f"Delta 0 answers differ in {p}")
        check(C(BA, p, "0 s")["confirmed"] == 0 and C(B30, p, "0 s")["confirmed"] == 0, f"BA CONFIRMED at 0 in {p}")
        check(C(TJ, p, "0 s")["wrong_confirmed"] == C(TJ, p, "0 s")["wrong"], "TJ wrong answers are CONFIRMED")
    b30_differs = [p for p in perts if C(B30, p, "0 s")["answers"] != C(BA, p, "0 s")["answers"]]
    check(b30_differs == ["delayed_api_30s", "delayed_api_60s"], f"F=30 differs at Delta 0 in {b30_differs}")
    check(all(C(B30, p, "0 s")["abstain"] == n_req for p in b30_differs), "F=30 abstains on all when it differs")
    stale_streams = ["missing_switch_poll"] + [p for p in perts if p.startswith("corrected_late_")]
    for p in stale_streams:
        check(C(TJ, p, "0 s")["wrong_events"] == span(44, 49), f"{p}: Delta 0 wrong set")
    # (2) complete stream.
    comp_abs = C(BA, "complete", "30 s")["abstain_events"]
    check(comp_abs == [31, 32] + span(39, 43), "complete-stream abstentions")
    check(all(C(TJ, "complete", d)["correct"] == n_req for d in res["deltas"]), "TJ perfect on complete stream")
    check(all(C(BA, "complete", d)["abstain_events"] == comp_abs for d in res["deltas"] if d != "0 s"),
          "BA abstentions stable from 5 s")
    creation_first = kn["first"]
    check(all(t_of[i] < us_of(creation_first["observed_at"]) and t_of[i] >= us_of(kn["created_floor"])
              for i in (31, 32)), "31-32 lie in the creation gap")
    check(all(us_of(ko["before"]["observed_at"]) < t_of[i] < us_of(sw) for i in span(39, 43)), "39-43 in the gap")
    # (3) latest_state.
    ls30 = {p: C(LS, p, "30 s") for p in headline}
    ls_all_old = [p for p in headline if ls30[p]["wrong_events"] == old_reqs]
    ls_other = [p for p in headline if p not in ls_all_old]
    check(set(ls_other) <= set(delays), f"latest_state exceptions are delayed feeds only: {ls_other}")
    r1 = ROW(LS, "complete", "30 s", 1)
    check(r1["answer"] == "new" and r1["truth"] == "old", "request 1 example")
    r1_ids = [short(x) for x in r1["record_ids"]]
    r1_vals = {rec_by_short[x]["value"] for x in r1_ids}
    check(r1_vals == {"terminating", "ready"}, f"request 1 records {r1_ids} {r1_vals}")
    # (4) missing switch poll.
    for d in res["deltas"]:
        check(C(TJ, "missing_switch_poll", d)["wrong_events"] == span(44, 49), f"TJ missing poll {d}")
    check(C(TJ, "missing_switch_poll", "0 s")["flips"] == 0, "TJ never revises")
    msp = C(BA, "missing_switch_poll", "30 s")
    check(msp["wrong"] == 0 and msp["abstain_events"] == [31, 32] + span(39, 49), "BA missing poll abstentions")
    r44 = ROW(TJ, "missing_switch_poll", "30 s", 44)
    check(set(short(x) for x in r44["record_ids"]) == {ko["before"]["id"], kn["before"]["id"]}, "TJ 44 records")
    b44 = ROW(BA, "missing_switch_poll", "30 s", 44)
    check(rule(b44, "old").startswith("transition_between_records")
          and {ko["before"]["id"], ko["after"]["id"]} <= set(short(x) for x in b44["record_ids"]), "BA 44 rule")
    # (5) missing first sighting of the new Pod.
    mfs = "missing_new_pod_first_sighting"
    check(all(C(TJ, mfs, d)["wrong"] == 0 and C(BA, mfs, d)["wrong"] == 0 for d in res["deltas"]), "no harm")
    extra = sorted(set(C(BA, mfs, "30 s")["abstain_events"]) - set(comp_abs))
    check(extra == span(33, 38), f"extra abstentions {extra}")
    check(manifests[mfs]["records"][0]["record_id"] == kn["first"]["record_id"], "dropped first sighting")
    b33 = ROW(BA, mfs, "30 s", 33)
    check(rule(b33, "new").startswith("no_record_at_or_before_t"), "BA 33 new-Pod rule")
    # (6) corrected-late.
    corr = [p for p in perts if p.startswith("corrected_late_")]
    late_corr = [p for p in corr if float(p.split("_")[-1][:-1]) > 5]
    for p in corr:
        check(C(TJ, p, "0 s")["answers_using_withdrawn_version"] == 6, f"{p} stale use at 0")
    for p in late_corr:
        c5 = C(TJ, p, "5 s")
        check(c5["wrong_events"] == span(44, 49) and c5["wrong_confirmed"] == 6, f"{p} TJ at 5 s")
        b5 = C(BA, p, "5 s")
        check(b5["wrong"] == 0 and b5["flip_to_abstain_events"] == span(39, 43)
              and b5["answers_using_withdrawn_version"] == 5, f"{p} BA at 5 s")
        check(set(span(44, 49)) <= set(b5["abstain_events"]), f"{p} BA abstains on 44-49 at 5 s")
    check(C(TJ, "corrected_late_3s", "5 s")["wrong"] == 0, "3 s correction already usable at 5 s")
    c30 = C(BA, "corrected_late_30s", "30 s")
    check(c30["flip_to_abstain_events"] == span(39, 43) and c30["wrong"] == 0, "C30 at 30 s")
    b41 = ROW(BA, "corrected_late_10s", "5 s", 41)
    check(b41["status"] == R.CONFIRMED and any(x.endswith("#stale") for x in b41["record_ids"]), "BA 41 stale")
    b45 = ROW(BA, "corrected_late_10s", "5 s", 45)
    check(rule(b45, "old").startswith("transition_between_records"), "BA 45 transition")
    # (7) delayed feed.
    delay_rows = []
    for p in delays:
        d_s = float(p.split("_")[-1][:-1])
        for d in finite:
            tj, ba = C(TJ, p, d), C(BA, p, d)
            check((tj["wrong"] > 0) == (secs(d) < d_s), f"{p} {d}: wrong iff Delta < d")
            check(ba["wrong"] == tj["wrong"] and ba["wrong_confirmed"] == 0, f"{p} {d}: BA = TJ wrong, FALLBACK")
            if secs(d) < d_s:
                check(ba["answers"] == tj["answers"], f"{p} {d}: identical answers while Delta < d")
    ages = {}
    for p, d in (("delayed_api_10s", "0 s"), ("delayed_api_30s", "5 s"), ("delayed_api_30s", "0 s")):
        vals = []
        for i in range(1, n_req + 1):
            row = ROW(BA, p, d, i)
            if row["status"] == R.FALLBACK:
                used = [rec_by_short[short(x)] for x in row["record_ids"] if short(x) in rec_by_short]
                vals.append(min((row["t"] - us_of(u["observed_at"])) / 1e6 for u in used))
        ages[(p, d)] = (min(vals), max(vals)) if vals else None
    check(C(B30, "delayed_api_10s", "0 s")["wrong"] == C(TJ, "delayed_api_10s", "0 s")["wrong"], "F30 d10")
    check(C(B30, "delayed_api_30s", "5 s")["wrong"] == C(TJ, "delayed_api_30s", "5 s")["wrong"], "F30 d30 5s")
    check(all(C(B30, "delayed_api_60s", d)["abstain"] == n_req for d in ("0 s", "5 s", "30 s")), "F30 d60")
    # (8) clock offsets.
    for d in res["deltas"]:
        check(C(TJ, "request_clock_-0.5s", d)["wrong_events"] == [44], f"TJ -0.5 {d}")
        check(C(TJ, "request_clock_+0.5s", d)["wrong_events"] == [43], f"TJ +0.5 {d}")
    check(C(BA, "request_clock_-0.5s", "0 s")["wrong_events"] == [44], "BA -0.5 at 0")
    for d in res["deltas"]:
        if d != "0 s":
            m, pl = C(BA, "request_clock_-0.5s", d), C(BA, "request_clock_+0.5s", d)
            check(m["wrong"] == 0 and 44 in m["abstain_events"], f"BA -0.5 {d}")
            check(pl["wrong_events"] == [43] and pl["wrong_confirmed"] == 1, f"BA +0.5 {d}")
    p43 = ROW(BA, "request_clock_+0.5s", "30 s", 43)
    check(rule(p43, "old").startswith("K1_retired_before_t:terminating") and rule(p43, "new") == "valid_at_t:ready",
          "BA +0.5 request 43 rules")
    t44m = ROW(TJ, "request_clock_-0.5s", "30 s", 44)["t"]
    t43p = p43["t"]
    # (9) Does the two-clock policy ever make a wrong answer the temporal join did not make?
    extra_wrong = [(p, d, sorted(set(C(BA, p, d)["wrong_events"]) - set(C(TJ, p, d)["wrong_events"])))
                   for p in perts for d in res["deltas"]]
    extra_wrong = [x for x in extra_wrong if x[2]]
    check(not extra_wrong, f"BA wrong where TJ right: {extra_wrong}")
    ba_wc = [(p, d) for p in perts for d in res["deltas"] if C(BA, p, d)["wrong_confirmed"]]
    check({p for p, _ in ba_wc} <= {"request_clock_+0.5s"} | set(seeds), f"BA confirmed-wrong cells {ba_wc}")
    for p, d in ba_wc:
        for i in C(BA, p, d)["wrong_events"]:
            row = ROW(BA, p, d, i)
            if row["status"] == R.CONFIRMED:
                check(i == 43 and rule(row, "old") == "K1_retired_before_t:terminating"
                      and rule(row, "new") == "valid_at_t:ready"
                      and {kn["switch"]["id"], kn["after"]["id"]} <= {short(x) for x in row["record_ids"]},
                      f"BA CONFIRMED wrong answer is the request-43 mechanism: {p} {d} {i}")
    for pol in (BA, B30):
        check(all(C(pol, "complete", d)["wrong"] == 0 for d in res["deltas"]), f"{pol} never wrong on complete")
    for d in res["deltas"]:
        check(C(LS, "complete", d)["wrong"] > 0 or d == "0 s", "latest_state harmful on complete from 5 s")
    check(C(TJ, "corrected_late_30s", "5 s")["answers"] == C(TJ, "corrected_late_10s", "5 s")["answers"]
          and C(BA, "corrected_late_30s", "5 s")["answers"] == C(BA, "corrected_late_10s", "5 s")["answers"],
          "10 s and 30 s corrections decide identically at 5 s")
    for p, d in (("missing_switch_poll", "5 s"), ("corrected_late_10s", "5 s"), ("request_clock_-0.5s", "5 s")):
        check(C(TJ, p, d)["wrong"] > 0 and C(BA, p, d)["wrong"] == 0, f"removed harm {p} {d}")
    for d in ("30 s", "120 s", "hindsight"):
        check(C(BA, "missing_switch_poll", d)["wrong"] == 0 and C(BA, "request_clock_-0.5s", d)["wrong"] == 0,
              f"BA stays harmless later {d}")

    # ---- document ----------------------------------------------------------------------------------
    cc = checks
    kinds_count = {}
    for r in ev["records"]:
        kinds_count[r["kind"]] = kinds_count.get(r["kind"], 0) + 1
    L = ["# replay-policy v1: availability replay of three context policies on the real rollout (120 requests)", "",
         "**One real rollout, one service, no fault. The record-stream perturbations are simulated on top of measured "
         "timestamps (the measured record-delivery lag was sub-millisecond). The decision is which "
         "recommendationservice Pod served each request, compared with span-verified truth. n is tiny: apart from "
         "the 10-60 s simulated feed delays, only 5-13 requests near the switch differ between policies, and replay "
         "variants are not independent incidents. This is not a diagnosis-accuracy result and makes no accuracy "
         "claim.**", "",
         "`run_replay_policy_v1.py` generates this file from `src/aiops_kg/replay.py`. Every number below is read "
         "from the computed cells, and every stated pattern is checked in code before this file is written. The run "
         "computes everything twice and aborts if the two passes differ.", "",
         "## Setup", "",
         f"- **Task (reused read-only from `experiments/attribution-lag-v1`).** For each request i = 1..{n_req} at its "
         "own time t_req, which of the two recommendationservice Pods served it, using only records usable at "
         "cutoff c = t_req + Δ, for Δ ∈ {0, 5, 30, 120 s, hindsight}. Truth is the span-verified serving Pod: requests "
         f"{fmt_list(old_reqs)} old `{ev['candidates'][0]['key'][4:12]}`, {fmt_list(new_reqs)} new "
         f"`{ev['candidates'][1]['key'][4:12]}`. The span's own Pod claim is never an input.",
         f"- **Records.** {ev['pod_state_records']} Pod STATE records ({kinds_count.get('api', 0)} API sightings "
         f"`api/N`, {kinds_count.get('absence', 0)} derived absences), from the attribution-lag / policy-gate loaders. "
         "All policies get exactly the versions usable at the same cutoff.",
         "- **Policies.** `latest_state` (newest record at c, ignores t); `temporal_join` (as-of valid-time join, "
         "no abstention); `bitemporal_abstain` (use a value valid at t, else fall back to the latest sighting within "
         "F and mark FALLBACK, else ABSTAIN), with F = 600 s (primary) and F = 30 s (sensitivity). Exact rules "
         "are below.",
         f"- **Consistency checks (all passed).** `bitemporal_abstain` with the lifecycle rules equals attribution-lag's "
         f"own `attribute()` (K2/K1/A1/S0) in {cc['bitemporal_vs_attribution_lag_rules']['agreements']}/"
         f"{cc['bitemporal_vs_attribution_lag_rules']['decisions']} decisions over every stream, F, request and Δ. "
         f"Its per-Pod state equals the project's temporal resolver (graph and SQLite engines over "
         f"`materialize_facts`) in {cc['per_pod_state_vs_temporal_resolver']['agreements']}/"
         f"{cc['per_pod_state_vs_temporal_resolver']['queries']} queries. `temporal_join` equals an independent "
         f"as-of lookup in {cc['per_pod_state_vs_temporal_resolver']['temporal_join_vs_independent_asof']['agreements']}/"
         f"{cc['per_pod_state_vs_temporal_resolver']['temporal_join_vs_independent_asof']['queries']} queries, and the "
         f"lifecycle rules never change its answer ({cc['temporal_join_lifecycle_rules_noop']['agreements']}/"
         f"{cc['temporal_join_lifecycle_rules_noop']['decisions']}). The delayed streams equal attribution-lag's own "
         "delayed observations for every d.", ""]

    # Evidence around the switch.
    lo, hi = us_of(kn["first"]["observed_at"]), us_of(ko["after"]["observed_at"])
    window = sorted((r for r in ev["records"] if lo <= us_of(r["observed_at"]) <= hi),
                    key=lambda r: (r["observed_at"], r["record_id"]))
    label_of = {c["key"]: c["label"] for c in ev["candidates"]}
    L += ["### Records around the serving switch (host receipt clock)", "",
          "| Record | Pod | STATE | observed_at | available_at |", "| --- | --- | --- | --- | --- |"]
    for r in window:
        L.append(f"| `{r['short_id']}` | {label_of[r['subject']]} | {r['value']} | {r['observed_at'][11:26]} | "
                 f"{r['available_at'][11:26]} |")
    L += ["", f"The new Pod's creationTimestamp floor is {kn['created_floor'][11:19]} (1 s resolution, API-server "
          f"clock). Requests 39-43 (t_req {R.iso(t_of[39])[11:26]} to {R.iso(t_of[43])[11:26]}) fall between "
          f"`{ko['before']['id']}`/`{kn['before']['id']}` and the switch poll `{ko['switch']['id']}`/"
          f"`{kn['switch']['id']}`; request 44 is at {R.iso(t_of[44])[11:26]}.", ""]

    # Perturbations.
    L += ["### Record streams (perturbations)", "", "| Stream | What changed |", "| --- | --- |"]
    for p in res["perturbations"]:
        if p["name"] in seeds and not p["name"].endswith("seed1"):
            continue
        m = p["manifest"]
        if m["perturbation"] == "drop_transition":
            what = "dropped " + ", ".join(f"`{short(e['record_id'])}` ({e['from'] or 'first sighting'} -> {e['to']})"
                                          for e in m["records"])
        elif m["perturbation"] == "correct_late":
            what = "; ".join(f"`{short(e['original'])}` -> `{short(e['stale']['record_id'])}` = {e['stale']['value']} "
                             f"(available {e['stale']['available_at'][11:26]}) + `{short(e['corrected']['record_id'])}` "
                             f"= {e['corrected']['value']} (available {e['corrected']['available_at'][11:26]})"
                             for e in m["records"])
        elif m["perturbation"] == "delay":
            what = f"available_at + {m['seconds']} s on all {m['changed']} records"
        elif m["perturbation"] == "jitter_clock":
            what = (f"all {m['shifted']} request times {m['seconds']:+} s" if m["seed"] is None else
                    f"all {m['shifted']} request times, uniform in ±{m['seconds']} s, seed {m['seed']} "
                    f"(seeds {', '.join(s[-1] for s in seeds)} in results.json)")
        else:
            what = "none"
        L.append(f"| `{p['name']}` | {what} |")
    L.append("")

    # (a) Headline table.
    L += ["## (a) Headline: policy x stream at Δ = 0 and Δ = 30 s", "",
          "Cells: correct / wrong / abstain out of 120. Harmful = wrong answers (a wrong Pod is harmful; an "
          "abstention is not); in brackets, how many of them the policy marked CONFIRMED rather than FALLBACK. "
          "Coverage = answered share.", "",
          "| Stream | Policy | Δ=0: C / W / A | Δ=0 harmful (CONFIRMED) | Δ=0 coverage | Δ=30 s: C / W / A | "
          "Δ=30 s harmful (CONFIRMED) | Δ=30 s coverage |",
          "| --- | --- | --- | ---: | ---: | --- | ---: | ---: |"]
    for p in headline:
        for pol in POLICY_ORDER:
            a, b = C(pol, p, "0 s"), C(pol, p, "30 s")
            L.append(f"| `{p}` | {POLICY_LABEL[pol]} | {a['correct']} / {a['wrong']} / {a['abstain']} | "
                     f"{a['harmful']} ({a['wrong_confirmed']}) | {100 * a['coverage']:.1f}% | "
                     f"{b['correct']} / {b['wrong']} / {b['abstain']} | {b['harmful']} ({b['wrong_confirmed']}) | "
                     f"{100 * b['coverage']:.1f}% |")
    rng = lambda pol, d, k: (min(C(pol, s, d)[k] for s in seeds), max(C(pol, s, d)[k] for s in seeds))
    fr = lambda lohi: f"{lohi[0]}" if lohi[0] == lohi[1] else f"{lohi[0]}-{lohi[1]}"
    L += ["", f"Uniform request-clock jitter ±0.5 s over {len(seeds)} seeds, Δ = 30 s (wrong / abstain): "
          + "; ".join(f"{POLICY_LABEL[pol]} {fr(rng(pol, '30 s', 'wrong'))} / {fr(rng(pol, '30 s', 'abstain'))}"
                      for pol in POLICY_ORDER) + ". Δ = 5 s and 120 s cells for every stream are in `results.csv`.", ""]

    # (b) Flips.
    L += ["## (b) Answers that later flip", "",
          "A saved answer flips if the same policy, re-deciding the same request on the same stream with every record "
          "and correction (hindsight), names the other Pod or abstains. Cells: flips at Δ = 0 (to other Pod + to "
          "abstain) · flips at Δ = 30 s (same split). `latest_state`'s hindsight picture is itself wrong for "
          "old-Pod requests, so its flips measure instability, not repair.", "",
          "| Stream | " + " | ".join(POLICY_LABEL[p] for p in POLICY_ORDER) + " |",
          "| --- | " + " | ".join("---" for _ in POLICY_ORDER) + " |"]
    for p in headline:
        cells_txt = []
        for pol in POLICY_ORDER:
            a, b = C(pol, p, "0 s"), C(pol, p, "30 s")
            cells_txt.append(f"{a['flips']} ({a['flip_to_other']}+{a['flip_to_abstain']}) | "
                             f"{b['flips']} ({b['flip_to_other']}+{b['flip_to_abstain']})".replace(" | ", " · "))
        L.append(f"| `{p}` | " + " | ".join(cells_txt) + " |")
    L += ["", "**When the corrected record arrives** (corrected-late streams). Cells: wrong / answers that used the "
          "stale version / flips, at Δ = 0, 5 s and 30 s.", "",
          "| Stream | Policy | Δ=0 | Δ=5 s | Δ=30 s |", "| --- | --- | --- | --- | --- |"]
    for p in corr:
        for pol in POLICY_ORDER:
            parts = [f"{C(pol, p, d)['wrong']} / {C(pol, p, d)['answers_using_withdrawn_version']} / "
                     f"{C(pol, p, d)['flips']}" for d in ("0 s", "5 s", "30 s")]
            L.append(f"| `{p}` | {POLICY_LABEL[pol]} | " + " | ".join(parts) + " |")
    L.append("")

    # (c) Findings.
    ls_ex = "; ".join(f"`{p}` {ls30[p]['wrong']}" for p in ls_other)
    tj_msp = C(TJ, "missing_switch_poll", "30 s")
    a10, a30_5 = ages[("delayed_api_10s", "0 s")], ages[("delayed_api_30s", "5 s")]
    delay_wrong0 = ", ".join(f"{p.split('_')[-1][:-1]} s: {C(TJ, p, '0 s')['wrong']}" for p in delays)
    removed = [(f"`missing_switch_poll` from Δ = 5 s", C(TJ, "missing_switch_poll", "5 s")["wrong"],
                C(BA, "missing_switch_poll", "5 s")["wrong"]),
               ("`corrected_late_10s`/`_30s` at Δ = 5 s", C(TJ, "corrected_late_10s", "5 s")["wrong"],
                C(BA, "corrected_late_10s", "5 s")["wrong"]),
               ("`request_clock_-0.5s` from Δ = 5 s", C(TJ, "request_clock_-0.5s", "5 s")["wrong"],
                C(BA, "request_clock_-0.5s", "5 s")["wrong"])]
    L += ["## (c) Findings and why", "",
          f"1. **At Δ = 0 the policies differ only through F.** In all {len(perts)} streams `latest_state`, "
          "`temporal_join` and `bitemporal_abstain` F=600 s name the same Pod for every request: at c = t no record "
          "observed after t is usable, so all three rest on the last sighting at or before t, and the two-clock rule "
          "falls back on it (0 CONFIRMED answers at Δ = 0 in any stream; its bracketing and transition rules need a "
          "later sighting). The only difference is F = 30 s, which abstains on all 120 requests when the feed is 30 s "
          f"or 60 s late. So the Δ = 0 errors (e.g. requests 44-49 when `{ko['switch']['id']}`/`{kn['switch']['id']}` "
          "are missing or first arrive stale) are shared by every policy; only the two-clock rule labels them FALLBACK.",
          f"2. **On the complete stream the two-clock rule is more cautious, not more correct.** From Δ = 5 s it "
          f"abstains on {len(comp_abs)} requests ({fmt_list(comp_abs)}, the same set as attribution-lag-v1) where "
          f"`temporal_join` is right: 31-32 lie between the new Pod's creation floor ({kn['created_floor'][11:19]}) "
          f"and its first sighting `{kn['first']['id']}`, and 39-43 between `{ko['before']['id']}`/"
          f"`{kn['before']['id']}` (old ready, new not_ready) and `{ko['switch']['id']}`/`{kn['switch']['id']}` (old "
          "terminating, new ready), so `transition_between_records` fires. The join's answers in that gap are right "
          "only because the switch fell after request 43; finding 6 shows the opposite case.",
          f"3. **`latest_state` is harmful even with complete records.** At Δ = 30 s it names the new Pod for all "
          f"{len(old_reqs)} old-Pod requests in {len(ls_all_old)} of {len(headline)} headline streams (wrong in the "
          f"delayed exceptions: {ls_ex}), because it answers with the newest records at c and ignores t: request 1 "
          f"(t = {R.iso(t_of[1])[11:26]}) is decided from {' and '.join('`' + x + '`' for x in r1_ids)} (old "
          f"terminating, new ready). It is already wrong on {C(LS, 'complete', '5 s')['wrong']} requests "
          f"({fmt_list(C(LS, 'complete', '5 s')['wrong_events'])}) at Δ = 5 s.",
          f"4. **A missing transition record leaves the plain temporal join permanently wrong; the two-clock rule "
          f"abstains.** Without `{ko['switch']['id']}`/`{kn['switch']['id']}`, `temporal_join` names the old Pod for "
          f"requests 44-49 at every cutoff including hindsight ({tj_msp['harmful']} CONFIRMED wrong, "
          f"{C(TJ, 'missing_switch_poll', '0 s')['flips']} flips), because the interval of `{ko['before']['id']}` "
          f"(old ready) runs until the next sighting `{ko['after']['id']}` (terminating, "
          f"{ko['after']['observed_at'][11:26]}). `bitemporal_abstain` sees those two sightings disagree "
          f"(`transition_between_records`) and at Δ = 30 s abstains on {msp['abstain']} requests "
          f"({fmt_list(msp['abstain_events'])}) with 0 wrong, coverage {100 * msp['coverage']:.1f}%; at Δ = 0 it "
          "shares the 6 FALLBACK errors.",
          f"5. **A late correction misleads every policy until something contradicts the stale version.** At Δ = 0 "
          f"all policies name the old Pod for 44-49 from `{ko['switch']['id']}#stale` (old ready) and "
          f"`{kn['switch']['id']}#stale` (new not_ready), and `temporal_join` keeps these 6 CONFIRMED errors at "
          f"Δ = 5 s when the correction takes 10 s or 30 s. `bitemporal_abstain` abstains on 44-49 as soon as "
          f"`{ko['after']['id']}`/`{kn['after']['id']}` contradict the stale versions, but `{ko['switch']['id']}#stale` "
          f"also brackets 39-43 with `{ko['before']['id']}`, so it answers those 5 CONFIRMED 'old' from a version "
          f"that is later withdrawn (request 41 at Δ = 5 s: {', '.join('`' + short(x) + '`' for x in b41['record_ids'])}). "
          "They are right only because the switch came after request 43, and all 5 flip to ABSTAIN when the "
          "correction arrives.",
          f"6. **Clock offsets are a valid-time and S0 problem, not an availability problem.** With request times "
          f"0.5 s earlier, request 44 (t = {R.iso(t44m)[11:26]}) precedes the switch poll: `temporal_join` names the "
          "old Pod at every cutoff, while `bitemporal_abstain` does so only at Δ = 0 (FALLBACK) and abstains from "
          f"Δ = 5 s. With request times 0.5 s later, request 43 (t = {R.iso(t43p)[11:26]}) follows the switch poll and "
          f"both valid-time policies name the new Pod; the two-clock rule marks it CONFIRMED from Δ = 5 s (new ready "
          f"between `{kn['switch']['id']}` and `{kn['after']['id']}`; old excluded by K1 from `{ko['switch']['id']}` "
          f"terminating). Its only CONFIRMED wrong answers in any stream are this request-43 case "
          f"({', '.join('`' + p + '`' for p in sorted({p for p, _ in ba_wc}))}), caused by S0 (a terminating Pod can "
          "still finish a request) and uncalibrated clocks, which availability handling does not address.",
          f"7. **A delayed feed causes wrong answers exactly when Δ < d; F helps only when the lag exceeds it.** In "
          "every delayed stream `temporal_join` and `bitemporal_abstain` F=600 s give identical answers while Δ < d, "
          f"wrong on post-switch requests (at Δ = 0, d = {delay_wrong0}) because the sighting that shows the switch "
          "has not arrived, and none are wrong once Δ ≥ d; the two-clock rule labels every such error FALLBACK. "
          "F = 30 s converts them into abstentions only when the newest usable sighting is at least 30 s old "
          f"(d = 30 s at Δ = 0; d = 60 s up to Δ = 30 s), not at d = 10 s, Δ = 0 ({a10[0]:.1f}-{a10[1]:.1f} s old: "
          f"{C(B30, 'delayed_api_10s', '0 s')['wrong']} wrong) or d = 30 s, Δ = 5 s ({a30_5[0]:.1f}-{a30_5[1]:.1f} s "
          f"old: {C(B30, 'delayed_api_30s', '5 s')['wrong']} wrong).",
          "8. **Answer on this capture.** The use / fall-back / abstain rule never made a wrong answer that "
          "`temporal_join` did not also make (checked for every stream and Δ), and it removed the join's harmful "
          "answers only after later records arrived ("
          + "; ".join(f"{name}: {a} -> {b}" for name, a, b in removed)
          + f"). It paid with abstentions where the join was right ({len(comp_abs)} on the complete stream, "
          f"{C(BA, mfs, '30 s')['abstain']} with the new Pod's first sighting missing) and changed nothing at Δ = 0 "
          "unless the lag exceeded F. These are mechanisms on real timestamps from one rollout, not rates.", ""]

    # (d) Rules.
    rules = res["rules"]
    L += ["## (d) Exact rules", ""] + [f"- **`{k}`:** {v}" if k in ("latest_state", "temporal_join", "bitemporal_abstain")
                                          else f"- **{k.replace('_', ' ')}:** {v}" for k, v in rules.items()] + [""]
    # (e) Limitations.
    L += ["## (e) Limitations", ""] + [f"- {x}" for x in res["limitations"]] + [
        "- **Next captures.** This engine (`src/aiops_kg/replay.py`) is written to be applied unchanged to the new "
        "captures (rollout + fault) described once they exist. Only a task adapter for "
        "their decision (for example, root-cause ranking inputs) needs to be added.", ""]
    L += ["## Files", "",
          "- `run_replay_policy_v1.py`: this experiment (reads only; writes only into this folder).",
          "- `results.json`: rules, the 61 records, perturbation manifests (every changed record), every policy x "
          "stream x Δ cell with per-request answer and status strings (O = old, N = new, ? = abstain; C/F/A), "
          "cross-checks, input-file SHA-256.",
          "- `results.csv`: one row per policy x stream x Δ (counts, harmful, coverage, flips, request lists).",
          "- `per_request.csv.gz`: one row per policy x stream x Δ x request with the per-Pod rule and the record IDs "
          "behind each answer (gzip, fixed header).",
          "- `rerun_check.txt`: SHA-256 of all outputs from two separate runs.", ""]
    return "\n".join(L)


# ---------------------------------------------------------------------------
# --capture: the same grid on a converted Phase 3 capture (phase3/CAPTURE_FORMAT.md)
# ---------------------------------------------------------------------------
def build_capture_perturbations(task) -> tuple[list[dict], list[dict]]:
    """The default grid's streams, with every record located from the capture's own rows (nothing about the
    22 Sep rollout is assumed). Returns (streams, skipped streams with the reason)."""
    base, service = task.records, task.context["service"]
    keys = {c.key for c in task.candidates}
    stream = R.Stream(base)
    out = [{"name": "complete", "family": "complete", "records": base, "events": task.events,
            "description": "as captured (capture-era availability)", "manifest": {"perturbation": "none"}}]
    skipped = []
    for d in FEED_DELAYS:
        records, manifest = R.delay(base, d, kinds=API_KINDS)
        out.append({"name": f"delayed_api_{d}s", "family": "delayed", "records": records, "events": task.events,
                    "description": f"every API record (sightings and derived absences) available {d} s later; "
                                   "valid times unchanged (simulated)", "manifest": manifest})
    switch = sorted((r for r, prev in R.revealing_records(base, mode="change")
                     if r.subject in keys and prev == task.serving_value and r.value in task.retired_values),
                    key=lambda r: (r.observed_at, r.record_id))
    targets = frozenset()
    if switch:
        at = switch[0].observed_at
        records, manifest = R.drop_transition(base, mode="change", where=lambda r: r.observed_at == at)
        targets = frozenset(e["record_id"] for e in manifest["records"])
        out.append({"name": "missing_switch_poll", "family": "missing", "records": records, "events": task.events,
                    "description": f"the poll at {hms(at)} that first shows a {service} Pod leaving "
                                   f"{task.serving_value} is never delivered ({len(targets)} revealing records "
                                   "dropped)", "manifest": manifest})
    else:
        skipped.append({"name": "missing_switch_poll", "reason": f"no {task.serving_value} -> retired transition "
                                                                  f"of a {service} Pod in the capture"})
    first_seen = min(r.observed_at for r in base)
    late = [c for c in task.candidates if stream.versions(c.key, task.predicate)[0].observed_at > first_seen]
    if late:
        newest = max(late, key=lambda c: (c.created_floor or 0, c.key))
        records, manifest = R.drop_transition(base, mode="first", where=lambda r: r.subject == newest.key)
        out.append({"name": "missing_new_pod_first_sighting", "family": "missing", "records": records,
                    "events": task.events, "description": f"the first sighting of the newest {service} Pod "
                                                          f"({newest.label}) is never delivered", "manifest": manifest})
    else:
        skipped.append({"name": "missing_new_pod_first_sighting",
                        "reason": f"no {service} Pod first appears after the first API sighting"})
    for s in CORRECTION_DELAYS:
        if targets:
            records, manifest = R.correct_late(base, s, where=lambda r: r.record_id in targets)
            out.append({"name": f"corrected_late_{s}s", "family": "corrected", "records": records,
                        "events": task.events, "description": f"the switch poll's revealing records first arrive "
                                                              f"with the preceding state; corrected versions arrive "
                                                              f"{s} s later", "manifest": manifest})
        else:
            skipped.append({"name": f"corrected_late_{s}s", "reason": "no switch poll to correct"})
    for off in CLOCK_OFFSETS:
        events, manifest = R.jitter_clock(task.events, off, kinds=("request",))
        out.append({"name": f"request_clock_{off:+.1f}s", "family": "clock", "records": base, "events": events,
                    "description": f"every request time shifted by {off:+.1f} s", "manifest": manifest})
    for seed in JITTER_SEEDS:
        events, manifest = R.jitter_clock(task.events, JITTER_BOUND, seed=seed, kinds=("request",))
        out.append({"name": f"request_jitter_pm0.5s_seed{seed}", "family": "clock", "records": base,
                    "events": events, "description": f"each request time shifted by an independent uniform offset "
                                                     f"in [-0.5, +0.5] s (random.Random({seed}))", "manifest": manifest})
    return out, skipped


def ala_pods_from_task(task) -> dict:
    """attribution-lag's per-Pod structure built from the task's records (for its attribute() cross-check)."""
    stream = R.Stream(task.records)
    return {c.key: {"uid": c.key.split("/", 1)[1], "created_floor_us": c.created_floor,
                    "observations": [(r.observed_at, r.available_at, r.value, r.record_id)
                                     for r in stream.versions(c.key, task.predicate)]} for c in task.candidates}


def run_capture(capture: Path, service: str | None, output: Path | None) -> int:
    capture = capture.resolve()
    out_dir = (output or capture / "replay").resolve()
    if out_dir.exists():
        raise SystemExit(f"output directory exists; remove it or pass --output: {out_dir}")
    task = R.load_capture_task(capture, service, root=ROOT)
    check(len(task.events) > 0, "no request with a span-verified Pod of the target service")
    perturbations, skipped = build_capture_perturbations(task)
    policies = make_policies()
    cells, rows = evaluate_grid(task, perturbations, policies)
    again = R.load_capture_task(capture, service, root=ROOT)
    again_cells, again_rows = evaluate_grid(again, build_capture_perturbations(again)[0], make_policies())
    check(fingerprint(cells, rows) == fingerprint(again_cells, again_rows), "two passes differ")

    checks = {"per_pod_state_vs_temporal_resolver": crosscheck_resolver(task, perturbations),
              "temporal_join_lifecycle_rules_noop": crosscheck_join_lifecycle(task, perturbations, rows)}
    labels = {c.key.split("/", 1)[1]: c.label for c in task.candidates}
    if all(task.module.LABEL.get(uid) == label for uid, label in labels.items()):
        task.context["pods"] = ala_pods_from_task(task)
        checks["bitemporal_vs_attribution_lag_rules"] = crosscheck_attribution_lag(task, perturbations, rows)
    else:
        checks["bitemporal_vs_attribution_lag_rules"] = {
            "skipped": "attribution-lag's attribute() only knows the two 22 Sep Pod UIDs"}
    b = checks["per_pod_state_vs_temporal_resolver"]
    check(b["agreements"] == b["queries"], f"resolver cross-check: {b['mismatches'][:3]}")
    j = b["temporal_join_vs_independent_asof"]
    check(j["agreements"] == j["queries"], "temporal_join differs from the independent as-of lookup")
    k = checks["temporal_join_lifecycle_rules_noop"]
    check(k["agreements"] == k["decisions"], "lifecycle rules change a temporal_join answer")
    a = checks["bitemporal_vs_attribution_lag_rules"]
    check("skipped" in a or a["agreements"] == a["decisions"], f"bitemporal vs attribution-lag: {a.get('mismatches')}")

    results = build_capture_results(task, perturbations, skipped, policies, cells, checks)
    index = {(pol, pert, label, row["event"]): row for pol, pert, label, row, _ in rows}
    summary = render_capture_summary(results, index)
    out_dir.mkdir(parents=True)
    (out_dir / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    (out_dir / "results.csv").write_text(cells_csv(cells), encoding="utf-8")
    (out_dir / "per_request.csv.gz").write_bytes(capture_per_request_gz(rows, task))
    (out_dir / "SUMMARY.md").write_text(summary, encoding="utf-8")
    for c in cells:
        if c["delta"] in HEADLINE_DELTAS and not c["perturbation"].startswith("request_jitter"):
            print(f"{c['perturbation']:34s} {c['policy']:24s} {c['delta']:5s} "
                  f"{c['correct']:3d}/{c['wrong']:3d}/{c['abstain']:3d} flips {c['flips']:3d}")
    print("cross-checks:", json.dumps({k: (v.get("skipped") if "skipped" in v else
                                          f"{v['agreements']}/{v.get('decisions', v.get('queries'))}")
                                       for k, v in checks.items()}))
    print("outputs:", str(out_dir))
    return 0


def capture_per_request_gz(rows, task) -> bytes:
    requests = {r["event"]: r for r in task.context["requests"]}
    buffer = io.StringIO()
    w = csv.writer(buffer, lineterminator="\n")
    w.writerow(["policy", "perturbation", "delta", "event", "request", "t_req", "cutoff", "truth", "answer", "status",
                "outcome", "reason", "flips_by_hindsight", "pod_classes", "records_used"])
    for policy, pert, label, r, flipped in rows:
        w.writerow([policy, pert, label, r["event"], requests[r["event"]]["label"], R.iso(r["t"]),
                    R.iso(r["cutoff"]) or "hindsight", r["truth"], r["answer"] or "", r["status"], r["outcome"],
                    r["reason"], flipped, "|".join(f"{lab}={cls}:{rule}" for lab, cls, rule, _ in r["classes"]),
                    ";".join(short(x) for x in r["record_ids"])])
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as handle:
        handle.write(buffer.getvalue().encode("utf-8"))
    return out.getvalue()


def build_capture_results(task, perturbations, skipped, policies, cells, checks):
    ctx, capture = task.context, task.context["capture_dir"]
    inputs = [p for p in (ctx["evidence_file"], capture / "evidence/protocol.json", capture / "evidence/capture.json",
                          capture / "incident.json", capture / "ground_truth/ground_truth.json") if p.exists()]
    stream = R.Stream(task.records)
    gt = ctx["ground_truth"] or {}
    return {
        "kind": "availability_replay_policy_comparison_one_capture_not_diagnosis_accuracy",
        "question": ("Which Pod of the target service served each request, decided at t_req + Delta from the records "
                     "usable then, under complete / delayed / missing / corrected / clock-shifted record streams?"),
        "capture": {"directory": capture.name, "capture_id": ctx["capture"].get("run_id") or ctx["protocol"].get("capture_id"),
                    "incident_id": ctx["protocol"].get("incident_id"), "service": ctx["service"],
                    "service_source": ctx["service_source"], "evidence_rows_by_kind": ctx["rows_by_kind"],
                    "api_rows_available_ns_vs_payload_mismatch": ctx["api_rows_available_mismatch"],
                    "notes": ctx["notes"], "ground_truth_present": bool(ctx["ground_truth"]),
                    "ground_truth_context_not_model_input": {k: gt.get(k) for k in ("fault_target", "change", "trigger")
                                                             if k in gt}},
        "inputs_sha256": {p.relative_to(capture).as_posix(): sha256(p) for p in inputs},
        "environment": {"python": platform.python_version()},
        "deterministic_two_pass_identical": True,
        "rules": {**RULES, "time_and_cutoff": RULES["time_and_cutoff"].replace(" (attribution-lag variant V1)", ""),
                  "requests_and_truth": "requests = span_claim rows with no parent and aiops.request.index; t = "
                                        "startTimeUnixNano floored to the microsecond; events are numbered 1..N by "
                                        "t (then block, index); block = client_request row with the same trace_id; "
                                        "truth = the k8s.pod.uid shared by every span of the target service in the "
                                        "trace (exactly one SERVER span required), which must be a sighted "
                                        "candidate; otherwise the request is listed as unverified and not scored",
                  "candidates": "Pods whose label app == target service (checked against the owner chain to the "
                                "Deployment of that name); labelled old/new by creation floor when there are two, "
                                "else p1..pN"},
        "policies": [{"name": p.name, "abstains_by_design": p.abstains, "uses_observation_time": p.valid_time,
                      "params": dict(p.params)} for p in policies],
        "deltas": [label for label, _ in task.deltas],
        "perturbations": [{"name": p["name"], "family": p["family"], "description": p["description"],
                           "records": len(p["records"]), "manifest": p["manifest"]} for p in perturbations],
        "skipped_perturbations": skipped,
        "evidence": {
            "pod_state_records": len(task.records),
            "candidates": [{"label": c.label, "key": c.key, "created_floor": R.iso(c.created_floor),
                            "first_record": short(stream.versions(c.key, task.predicate)[0].record_id),
                            "first_observed_at": R.iso(stream.versions(c.key, task.predicate)[0].observed_at)}
                           for c in task.candidates],
            "requests": [{"event": r["event"], "request": r["label"], "block": r["block"], "index": r["index"],
                          "t_req": R.iso(r["t_req_us"]), "truth": task.truth[f"request/{r['event']}"],
                          "trace_id": r["trace_id"]} for r in ctx["requests"]],
            "unverified_requests": [{k: (R.iso(v) if k == "t_req_us" else v) for k, v in r.items()}
                                    for r in ctx["unverified_requests"]],
            "records": [{**r.to_dict(), "short_id": short(r.record_id)} for r in task.records],
        },
        "cells": cells,
        "cross_checks": checks,
        "limitations": [
            "One capture. Replay variants of it are not independent incidents; hold out whole incidents.",
            "Perturbations are simulated on top of the capture's measured timestamps; delays, drops and corrections "
            "are not measured events.",
            "Request times (client clock) and API receipt times (host clock) are not calibrated against each other; "
            "creationTimestamp has 1 s resolution.",
            "The policies are simple by design; A1 (no flap between equal sightings) and S0 (serving = ready) are "
            "modelling assumptions. The decision is instance attribution, not root-cause ranking.",
            "Span Pod claims are used only as truth, never as input; ground_truth/ is read only as context.",
        ],
    }


def render_capture_summary(res, index) -> str:
    cells, cap, ev = res["cells"], res["capture"], res["evidence"]
    C = lambda pol, pert, d: cell(cells, pol, pert, d)
    perts = [p["name"] for p in res["perturbations"]]
    seeds = [p for p in perts if p.startswith("request_jitter")]
    headline = [p for p in perts if p not in seeds or p.endswith("seed1")]
    n = len(ev["requests"])
    split = {}
    for r in ev["requests"]:
        split[r["truth"]] = split.get(r["truth"], 0) + 1
    blocks = {}
    for r in ev["requests"]:
        blocks[r["block"] or "-"] = blocks.get(r["block"] or "-", 0) + 1
    ck = res["cross_checks"]
    fmt_check = lambda v: v["skipped"] if "skipped" in v else f"{v['agreements']}/{v.get('decisions', v.get('queries'))}"
    L = [f"# replay-policy v1 on capture `{cap['directory']}`: which `{cap['service']}` Pod served each request", "",
         f"**One capture ({cap['incident_id'] or 'no incident id'}). Perturbations are simulated on top of the "
         "capture's measured timestamps. Truth is the span-verified serving Pod, never an input. Replay variants "
         "are not independent incidents. This is not a diagnosis-accuracy result.**", "",
         "Generated by `experiments/replay-policy-v1/run_replay_policy_v1.py --capture` from `evidence/` only "
         "(`ground_truth/` is read as context, never as input). Every number is computed; the grid is computed twice "
         "and the run aborts if the passes differ.", "",
         "## Setup", "",
         f"- **Target service:** `{cap['service']}` (from {cap['service_source']}).",
         f"- **Evidence rows by kind:** " + ", ".join(f"{k} {v}" for k, v in cap["evidence_rows_by_kind"].items()) + ".",
         f"- **Candidates:** " + "; ".join(f"{c['label']} = `{c['key'][4:12]}` (created {c['created_floor'][11:19]}, "
                                            f"first sighting `{c['first_record']}` {c['first_observed_at'][11:26]})"
                                            for c in ev["candidates"]) + ".",
         f"- **Requests scored:** {n} ("
         + ("no client_request rows, so no blocks" if set(blocks) == {"-"} else
            "blocks: " + ", ".join(f"{k} {v}" for k, v in blocks.items())) + "); truth "
         + ", ".join(f"{k} {v}" for k, v in sorted(split.items())) + f"; not scored (no span-verified Pod): "
         f"{len(ev['unverified_requests'])}.",
         f"- **Records:** {ev['pod_state_records']} Pod STATE records. API rows whose `available_ns` // 1000 differs from "
         f"the payload `available_at`: {cap['api_rows_available_ns_vs_payload_mismatch']}.",
         "- **Consistency checks:** " + "; ".join(f"{k} {fmt_check(v)}" for k, v in ck.items()) + ".",
         "- **Notes:** " + ("; ".join(cap["notes"]) if cap["notes"] else "none") + ".", ""]
    L += ["## Record streams", "", "| Stream | What changed |", "| --- | --- |"]
    for p in res["perturbations"]:
        if p["name"] in seeds and not p["name"].endswith("seed1"):
            continue
        m = p["manifest"]
        if m["perturbation"] == "drop_transition":
            what = "dropped " + ", ".join(f"`{short(e['record_id'])}` ({e['from'] or 'first sighting'} -> {e['to']})"
                                          for e in m["records"])
        elif m["perturbation"] == "correct_late":
            what = "; ".join(f"`{short(e['stale']['record_id'])}` = {e['stale']['value']} then "
                             f"`{short(e['corrected']['record_id'])}` = {e['corrected']['value']} "
                             f"(+{m['seconds']} s)" for e in m["records"])
        elif m["perturbation"] == "delay":
            what = f"available_at + {m['seconds']} s on all {m['changed']} records"
        elif m["perturbation"] == "jitter_clock":
            what = (f"all {m['shifted']} request times {m['seconds']:+} s" if m["seed"] is None else
                    f"all {m['shifted']} request times, uniform in ±{m['seconds']} s, seed {m['seed']}")
        else:
            what = "none"
        L.append(f"| `{p['name']}` | {what} |")
    for s in res["skipped_perturbations"]:
        L.append(f"| `{s['name']}` | not applicable: {s['reason']} |")
    L += ["", f"## (a) Headline: policy x stream at Δ = 0 and Δ = 30 s (out of {n})", "",
          "Harmful = wrong answers; in brackets, how many the policy marked CONFIRMED. Coverage = answered share.", "",
          "| Stream | Policy | Δ=0: C / W / A | Δ=0 harmful (CONFIRMED) | Δ=0 coverage | Δ=30 s: C / W / A | "
          "Δ=30 s harmful (CONFIRMED) | Δ=30 s coverage |", "| --- | --- | --- | ---: | ---: | --- | ---: | ---: |"]
    for p in headline:
        for pol in POLICY_ORDER:
            a, b = C(pol, p, "0 s"), C(pol, p, "30 s")
            L.append(f"| `{p}` | {POLICY_LABEL[pol]} | {a['correct']} / {a['wrong']} / {a['abstain']} | "
                     f"{a['harmful']} ({a['wrong_confirmed']}) | {100 * a['coverage']:.1f}% | "
                     f"{b['correct']} / {b['wrong']} / {b['abstain']} | {b['harmful']} ({b['wrong_confirmed']}) | "
                     f"{100 * b['coverage']:.1f}% |")
    L += ["", "## (b) Answers that later flip", "", "Cells: flips at Δ = 0 (to other Pod + to abstain) · flips at "
          "Δ = 30 s, against the same policy's hindsight answer on the same stream.", "",
          "| Stream | " + " | ".join(POLICY_LABEL[p] for p in POLICY_ORDER) + " |",
          "| --- | " + " | ".join("---" for _ in POLICY_ORDER) + " |"]
    for p in headline:
        parts = []
        for pol in POLICY_ORDER:
            a, b = C(pol, p, "0 s"), C(pol, p, "30 s")
            parts.append(f"{a['flips']} ({a['flip_to_other']}+{a['flip_to_abstain']}) · "
                         f"{b['flips']} ({b['flip_to_other']}+{b['flip_to_abstain']})")
        L.append(f"| `{p}` | " + " | ".join(parts) + " |")
    L += ["", "## (c) Two-clock rule versus the plain temporal join (computed, per stream)", "",
          "Harm removed = requests temporal_join got wrong on which bitemporal_abstain F=600 s abstained; coverage "
          "cost = requests temporal_join got right on which it abstained; extra harm = requests it got wrong that "
          "temporal_join got right.", "",
          "| Stream | Δ | temporal_join wrong | harm removed | coverage cost | extra harm | latest_state wrong |",
          "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    for p in headline:
        for d in HEADLINE_DELTAS:
            tj, ba, ls = C(TJ, p, d), C(BA, p, d), C(LS, p, d)
            tj_wrong, tj_abs = set(tj["wrong_events"]), set(tj["abstain_events"])
            ba_abs, ba_wrong = set(ba["abstain_events"]), set(ba["wrong_events"])
            L.append(f"| `{p}` | {d} | {len(tj_wrong)} | {len(tj_wrong & ba_abs)} | "
                     f"{len(ba_abs - tj_wrong - tj_abs)} | {len(ba_wrong - tj_wrong)} | {ls['wrong']} |")
    L += ["", "## (d) Exact rules", ""] + [f"- **{k.replace('_', ' ')}:** {v}" for k, v in res["rules"].items()]
    L += ["", "## (e) Limitations", ""] + [f"- {x}" for x in res["limitations"]] + [""]
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())
