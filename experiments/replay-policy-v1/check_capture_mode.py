#!/usr/bin/env python3
"""Check ``run_replay_policy_v1.py --capture`` on the 22 Sep rollout, end to end through the development converter.

The script builds a development-format fixture capture of the 22 Sep rollout from the stored evidence:

1. ``context/observations.jsonl``: the 396 original API lines, rebuilt byte-exactly (CRLF) from the stored
   pilot-002 evidence, at their original line numbers. The SHA-256 of every line is checked against
   ``_source_record_sha256``, as the converter's self-test does. The other lines of the original file (not stored)
   are left blank, and the converter skips blank lines.
2. ``raw/trace-export.stdout``: one OTLP envelope per original export line, rebuilt from the 727 stored span records.
   The span content is identical; the envelope bytes are not the original ones.
3. ``capture.json``: development field names, taking the receipts from data/raw/rollout-telemetry/pilot-001/
   capture.json (``rollout-patch`` / ``rollout-wait`` become ``change-patch`` / ``change-wait``; the missing
   ``apply-collector`` receipt becomes the capture start, which only affects the configuration row). Also
   ``incident.json`` (a plan-style entry with change.service) and ``rollout-patch.json``.

It then runs the converter CLI (``phase3/convert_capture.py --capture <fixture>``), then
``run_replay_policy_v1.py --capture <fixture>``, and compares <fixture>/replay/results.json with the default run's
experiments/replay-policy-v1/results.json.

    PYTHONDONTWRITEBYTECODE=1 python3 experiments/replay-policy-v1/check_capture_mode.py [--workdir DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PILOT = ROOT / "data/raw/rollout-telemetry/pilot-001"
STORED = ROOT / "results/evidence-index-pilot-002/accepted_evidence.jsonl"
REQUIRED = ("complete", "delayed_api_30s")
COMPARED = ("correct", "wrong", "abstain", "harmful", "coverage", "confirmed", "fallback", "wrong_confirmed",
            "wrong_fallback", "tie_breaks", "flips", "flip_to_other", "flip_to_abstain", "resolved_later",
            "answers_using_withdrawn_version", "wrong_events", "abstain_events", "answers", "statuses")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build_fixture(target: Path) -> dict:
    stored = [json.loads(line) for line in STORED.read_text(encoding="utf-8").splitlines() if line.strip()]
    protocol = json.loads((PILOT / "protocol.json").read_text(encoding="utf-8"))
    pilot = json.loads((PILOT / "capture.json").read_text(encoding="utf-8"))
    receipts = {r["id"]: r for r in pilot["command_receipts"]}
    (target / "context").mkdir(parents=True)
    (target / "raw").mkdir()
    # 1. API lines in original order, byte-exact.
    apis = sorted((e["record"] for e in stored if e["record"]["kind"] == "api_observation"),
                  key=lambda r: int(r["source_ref"].rsplit("#L", 1)[1]))
    by_number = {int(r["source_ref"].rsplit("#L", 1)[1]): r for r in apis}
    assert len(by_number) == len(apis), "two API records claim one source line"
    with (target / "context/observations.jsonl").open("wb") as handle:
        for number in range(1, max(by_number) + 1):
            record = by_number.get(number)
            if record is None:  # a non-API line of the original file (not stored); blank keeps the numbering
                handle.write(b"\r\n")
                continue
            original = {k: v for k, v in record["payload"].items() if not k.startswith("_source")}
            raw = (json.dumps(original, sort_keys=True) + "\r\n").encode()
            assert sha(raw) == record["payload"]["_source_record_sha256"], "API line bytes not reproduced"
            handle.write(raw)
    # 2. One envelope per original export line (span content identical; envelope bytes rebuilt).
    by_line = defaultdict(list)
    for e in stored:
        if e["record"]["kind"] == "span_claim":
            by_line[e["record"]["payload"]["source_locator"]["line"]].append(e["record"])
    with (target / "raw/trace-export.stdout").open("wb") as handle:
        for line in range(1, max(by_line) + 1):
            records = by_line.get(line)
            if not records:
                handle.write(b"\n")  # keeps the original line numbers; blank lines are skipped by the converter
                continue
            envelope = {"resourceSpans": []}
            for record in sorted(records, key=lambda r: tuple(r["payload"]["source_locator"][k]
                                                              for k in ("resourceSpans", "scopeSpans", "spans"))):
                loc, p = record["payload"]["source_locator"], record["payload"]
                while len(envelope["resourceSpans"]) <= loc["resourceSpans"]:
                    envelope["resourceSpans"].append({"resource": None, "scopeSpans": []})
                rs = envelope["resourceSpans"][loc["resourceSpans"]]
                rs["resource"] = p["resource"]
                while len(rs["scopeSpans"]) <= loc["scopeSpans"]:
                    rs["scopeSpans"].append({"scope": None, "spans": []})
                rs["scopeSpans"][loc["scopeSpans"]]["scope"] = p["scope"]
                rs["scopeSpans"][loc["scopeSpans"]]["spans"].append(p["span"])
            handle.write((json.dumps(envelope) + "\n").encode())
    # 3. Phase 3-shaped capture.json, incident.json and the change patch.
    command_receipts = [
        {"id": "apply-collector", "collector_available_at": pilot["started_at"],
         "fixture_note": "pilot-001 has no apply receipt; the capture start is used (configuration row only)"},
        receipts["trace-export"],
        dict(receipts["rollout-patch"], id="change-patch"),
        dict(receipts["rollout-wait"], id="change-wait"),
    ]
    doc = {"capture_id": "R22SEP-001", "incident_id": "R22SEP", "namespace": protocol["namespace"],
           "cluster_incarnation_id": protocol["cluster_incarnation_id"], "started_at": pilot["started_at"],
           "finished_at": pilot["finished_at"], "change": {"service": protocol["replacement_service"]},
           "protocol": {"request_trigger_index": protocol["request_trigger_index"]},
           "command_receipts": command_receipts,
           "fixture": "22 Sep 2026 rollout (pilot-001) rebuilt by experiments/replay-policy-v1/check_capture_mode.py"}
    (target / "capture.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    incident = {"incident": {"id": "R22SEP", "label": "22 Sep 2026 rollout (pilot-001), fixture",
                             "change": {"service": protocol["replacement_service"], "kind": "rollout", "at": "T0"},
                             "fault": None, "ground_truth": {"fault_present": False, "root_cause_service": None,
                                                             "change_services": [protocol["replacement_service"]]}},
                "fixture": True}
    (target / "incident.json").write_text(json.dumps(incident, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(PILOT / "rollout-patch.json", target / "rollout-patch.json")
    return {"api_lines": len(apis), "observation_file_lines": max(by_number),
            "span_records": sum(len(v) for v in by_line.values()), "export_lines": max(by_line)}


def run(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable] + args, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def compare(fixture: Path) -> dict:
    default = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    mine = json.loads((fixture / "replay/results.json").read_text(encoding="utf-8"))
    key = lambda c: (c["policy"], c["perturbation"], c["delta"])
    a, b = {key(c): c for c in default["cells"]}, {key(c): c for c in mine["cells"]}
    per_stream = {}
    for pert in dict.fromkeys(p for _, p, _ in a):
        keys = [k for k in a if k[1] == pert]
        present = [k for k in keys if k in b]
        diffs = [{"cell": list(k), "fields": [f for f in COMPARED if a[k][f] != b[k][f]]}
                 for k in present if any(a[k][f] != b[k][f] for f in COMPARED)]
        per_stream[pert] = {"cells": len(keys), "present_in_capture_run": len(present), "differing": diffs}
    manifests_a = {p["name"]: p["manifest"] for p in default["perturbations"]}
    manifests_b = {p["name"]: p["manifest"] for p in mine["perturbations"]}
    same_manifests = sorted(n for n in manifests_a if manifests_b.get(n) == manifests_a[n])
    records_a = [(r["record_id"], r["subject"], r["value"], r["observed_at"], r["available_at"])
                 for r in default["evidence"]["records"]]
    records_b = [(r["record_id"], r["subject"], r["value"], r["observed_at"], r["available_at"])
                 for r in mine["evidence"]["records"]]
    truth_b = {r["event"]: (r["request"], r["truth"]) for r in mine["evidence"]["requests"]}
    required_equal = all(per_stream[p]["present_in_capture_run"] == per_stream[p]["cells"] and
                         not per_stream[p]["differing"] for p in REQUIRED)
    return {"required_streams": list(REQUIRED), "required_streams_equal": required_equal,
            "all_streams_equal": all(v["present_in_capture_run"] == v["cells"] and not v["differing"]
                                     for v in per_stream.values()),
            "streams": {p: {"cells": v["cells"], "equal": v["present_in_capture_run"] == v["cells"] and not v["differing"],
                            "differing": v["differing"]} for p, v in per_stream.items()},
            "perturbation_manifests_identical": same_manifests,
            "pod_state_records_identical": records_a == records_b,
            "requests_in_index_order": all(truth_b[i][0] == str(i) for i in truth_b) and len(truth_b) == 120,
            "truth_split": {lab: sum(1 for _, t in truth_b.values() if t == lab) for lab in ("old", "new")},
            "service_source": mine["capture"]["service_source"],
            "capture_cross_checks": {k: (v.get("skipped") if "skipped" in v else
                                         f"{v['agreements']}/{v.get('decisions', v.get('queries'))}")
                                     for k, v in mine["cross_checks"].items()}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workdir", type=Path, help="keep the fixture here (must not exist); default: temporary")
    args = parser.parse_args(argv)
    holder = None
    if args.workdir is None:
        holder = tempfile.TemporaryDirectory()
        workdir = Path(holder.name) / "work"
    else:
        workdir = args.workdir.resolve()
        if workdir.exists():
            raise SystemExit(f"--workdir must not exist: {workdir}")
    try:
        fixture = workdir / "R22SEP-001"
        built = build_fixture(fixture)
        converted = run(["phase3/convert_capture.py", "--capture", str(fixture)])
        if converted.returncode:
            raise SystemExit("converter failed:\n" + converted.stdout + converted.stderr)
        replayed = run(["experiments/replay-policy-v1/run_replay_policy_v1.py", "--capture", str(fixture)])
        if replayed.returncode:
            raise SystemExit("replay --capture failed:\n" + replayed.stdout + replayed.stderr)
        result = {"fixture": str(fixture), "built": built,
                  "converter_report": json.loads(converted.stdout), "comparison": compare(fixture)}
        print(json.dumps(result, indent=1))
        return 0 if result["comparison"]["required_streams_equal"] else 1
    finally:
        if holder is not None:
            holder.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
