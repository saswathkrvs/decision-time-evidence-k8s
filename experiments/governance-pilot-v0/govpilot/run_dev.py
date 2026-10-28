#!/usr/bin/env python3
"""Governance pilot v0: the development rollback pilot.

    python3 experiments/governance-pilot-v0/govpilot/run_dev.py                    # synthetic fixtures end to end
    python3 experiments/governance-pilot-v0/govpilot/run_dev.py --dry-run-inputs   # the nine captures, coverage only
    python3 experiments/governance-pilot-v0/govpilot/run_dev.py --captures         # the capture run
    python3 experiments/governance-pilot-v0/govpilot/run_dev.py --rerun-check [--captures]   # two interpreters

Default: runs the synthetic fixtures (``govpilot.fixtures``) through every causal view, stream and Delta, the
hindsight sensitivity, the outcome evaluator, the reconstruction checks and the side-channel test, and writes
``fixtures_results/``: results.json, SUMMARY.md (rendered from results.json), the index decision_log_index.json and
one decision log per fixture capture in decision_logs/.

``--dry-run-inputs`` loads the nine development captures through the guarded decision reader (only
evidence/accepted_evidence.jsonl and evidence/protocol.json) and writes ``dry_run_inputs/input_coverage.json`` and
``.md``: field presence and counts only. Outside the reader it also checks each capture's raw/kubectl-version.stdout
against the kubectl pin (``environment.py``).

``--captures`` is the capture run on the seven capture streams (S0, S30, S150, S180, S300, S1200, Snever; Scorr is a
software fixture only), written to ``capture_results/``. Both runs share one pipeline per capture: verdicts into the
capture's own decision log, reconstruction checks 1-4 on that capture's contexts, the log streamed to
decision_logs/<capture>.jsonl.gz and dropped from memory; after the last capture the index is closed, and only then
does the evaluator read ground truth and the request rows back.

Deterministic: no wall clock, no randomness; outputs are byte-identical across interpreters (``--rerun-check``).
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

if __package__ in (None, ""):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "govpilot"

from govpilot import ADAPTER_VERSION  # noqa: E402
from govpilot import fixtures as FX  # noqa: E402
from govpilot.checks import (check_append_only, check_earlier_cutoff, check_engines, check_provenance,  # noqa: E402
                             gate_v1_vs_live, side_channel)
from govpilot.common import PILOT_DIR, ROOT, R, rel, sha256_file, sha256_text, ts_us  # noqa: E402
from govpilot.engine import DELTAS, DecisionLog, LogIndex, run_hindsight, run_q2, stream_context  # noqa: E402
from govpilot.environment import KUBECTL_VERSION_FILE, kubectl_pin_check  # noqa: E402
from govpilot.inputs import CAPTURE_STREAMS, STREAM_BY_NAME, STREAMS, input_coverage, read_capture  # noqa: E402
from govpilot.outcomes import (Labeller, cells, collapsed_cells, compare, ground_truth_from_doc,  # noqa: E402
                               load_ground_truth)
from govpilot.rollout import KUBECTL_REFERENCE  # noqa: E402
from govpilot.views import (CAUSAL_VIEWS, MATCHED_PAIRS, OPERATIONAL_PAIRS, capture_model,  # noqa: E402
                            evaluate_hindsight, hindsight_view)

FIXTURES_OUT = PILOT_DIR / "fixtures_results"
DRY_RUN_OUT = PILOT_DIR / "dry_run_inputs"
CAPTURES_OUT = PILOT_DIR / "capture_results"
LOGS_DIR = "decision_logs"
INDEX_FILE = "decision_log_index.json"
ALL_STREAMS = tuple(s.name for s in STREAMS)                    # fixture plan: Scorr included (a software fixture)
SECONDARY_STREAMS = ("S0", "S30", "S150", "Snever", "Scorr")   # fixture plan: full grid on 'fault' only
Q2_VIEWS = tuple(CAUSAL_VIEWS)
SENSITIVITY_VIEWS = ("T@F600", "L@F600", "T+p@F600", "L+p@F600", "T@Eopen", "L@Eopen", "T+p@Eopen", "L+p@Eopen")
FIXTURE_PAIRS = MATCHED_PAIRS + OPERATIONAL_PAIRS + (("T@F600", "L@F600"), ("T+p@F600", "L+p@F600"))
CAPTURES = (   # roles; labels come from ground-truth fields, roles only name the rows
    {"id": "I1-001", "role": "benign change"},
    {"id": "I2-002", "role": "relevant fault + rollout"},
    {"id": "I6-002", "role": "relevant fault + rollout"},
    {"id": "I2-003", "role": "same design, effect not established"},
    {"id": "I6-003", "role": "relevant fault + rollout"},
    {"id": "I4-002", "role": "unrelated change 20 s before the fault", "catalog_disruption_u": True},
    {"id": "I4-003", "role": "unrelated change 20 s before the fault", "catalog_disruption_u": True},
    {"id": "I7-001", "role": "unrelated change, settled"},
    {"id": "I3-004", "role": "fault without change (A never posed)"},
)
CAPTURES_ROOT = ROOT / "phase3/captures"
INPUT_FILES = ("evidence/accepted_evidence.jsonl", "evidence/protocol.json")   # the decision reader's only inputs
HINDSIGHT_HEADING = "hindsight, not a live read"
T4_FIELDS = ("posed", "first_verdicts", "dispositions", "executions_by_label", "gt1p_executions",
             "missed_opportunities", "waiting_seconds")
CHECK1_CAPTURE_NOTE = ("Reconstruction check 1 (append-only corrections): no capture stream carries a correction, because Scorr "
                       "is a labelled software fixture only; on "
                       "captures the check is therefore reported with n = 0 and is exercised on the fixtures.")


def _iso(us):
    return R.iso(us)


# ---------------------------------------------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------------------------------------------
def fixture_plan(quick: bool = False) -> list[dict]:
    """Which scenario runs with which views, streams and Deltas (the sensitivities and c-hind on 'fault' only)."""
    if quick:
        sc = dataclasses.replace(FX.STANDARD["fault"], requests=tuple(range(20, 100, 4)))
        return [{"scenario": sc, "views": ("T", "L", "T+p", "d", "a"), "streams": ("S0", "S30", "Snever", "Scorr"),
                 "deltas": (0, 30), "hindsight_streams": ("S0",), "x1": None}]
    plan = []
    for key, sc in FX.STANDARD.items():
        main = key == "fault"
        plan.append({"scenario": sc, "views": Q2_VIEWS + (SENSITIVITY_VIEWS if main else ()),
                     "streams": ALL_STREAMS if main else SECONDARY_STREAMS, "deltas": DELTAS,
                     "hindsight_streams": ALL_STREAMS if main else (), "x1": None})
    for kind in ("intime", "X1a", "X1b"):
        sc = dataclasses.replace(FX.STANDARD["fault"], name=f"fault-{kind}")
        plan.append({"scenario": sc, "views": ("T", "L", "a"), "streams": ("S0",), "deltas": (0,),
                     "hindsight_streams": (), "x1": kind})
    return plan


# ---------------------------------------------------------------------------------------------------------------
# The shared per-capture pipeline
# ---------------------------------------------------------------------------------------------------------------
def verdict_phase(model, index: LogIndex, *, views, streams, deltas, hindsight_streams,
                  cutoff_streams=None) -> dict:
    """One capture's verdicts into its own decision log; reconstruction checks 1-4 on its stream contexts (software checks that
    read the log, never ground truth); then the log is streamed to its gzip through the index and dropped. Returns
    the reconstruction-check results, the engine counts, the index entry and each stream's records (for the evaluator)."""
    log = DecisionLog(meta=dict(index.meta, capture=model.capture_id))
    contexts = run_q2(model, log, views=views, streams=streams, deltas=deltas)
    if hindsight_streams and model.action is not None:
        run_hindsight(model, log, hindsight=True, views=("c-hind",), streams=hindsight_streams, deltas=deltas,
                      contexts=contexts)
    q1 = {"append_only_corrections": [], "provenance": [], "earlier_cutoff_invariance": []}
    try:
        if model.action is not None:
            for name, sctx in sorted(contexts.items()):
                base = {"capture": model.capture_id, "stream": name}
                q1["append_only_corrections"].append({**base, **check_append_only(log, sctx)})
                q1["provenance"].append({**base, **check_provenance(log, sctx)})
                if cutoff_streams is None or name in cutoff_streams:
                    q1["earlier_cutoff_invariance"].append({**base, **check_earlier_cutoff(log, sctx)})
        engines = check_engines(list(contexts.values()))
    finally:
        for sctx in contexts.values():
            sctx.close()
    entry = index.write(log, model.capture_id)
    return {"q1": q1, "engines": engines, "log": entry,
            "stream_records": {name: sctx.records for name, sctx in contexts.items()}}


def merge_q1(phases: list[dict]) -> dict:
    q1 = {"append_only_corrections": [], "earlier_cutoff_invariance": [], "provenance": []}
    totals = {"n": 0, "x": 0, "disagreements": 0}
    for phase in phases:
        for name in q1:
            q1[name] += phase["q1"][name]
        for key in totals:
            totals[key] += phase["engines"][key]
    q1["graph_sqlite_agreement"] = totals
    return q1


def evaluate_logs(index: LogIndex, items: list[dict], pairs) -> dict:
    """The evaluator over a sealed index, one capture at a time: T1/T4 cells, T2 comparisons, collapsed cells.

    ``items``: one dict per capture with its ``capture`` ID, ``labeller``, ``stream_records`` (stream -> records)
    and horizon ``H``."""
    cell_rows, comparisons, collapsed = [], {f"{a} vs {b}": [] for a, b in pairs}, []
    for item in sorted(items, key=lambda i: i["capture"]):
        rows = index.read_requests(item["capture"])
        records = {(item["capture"], name): recs for name, recs in item["stream_records"].items()}
        cell_rows += cells(rows, {item["capture"]: item["labeller"]}, records)
        for a, b in pairs:
            comparisons[f"{a} vs {b}"] += compare(rows, a, b)
        collapsed += collapsed_cells(rows, records, {item["capture"]: item["H"]})
    t1, t4 = split_tables(cell_rows)
    return {"T1_cells": t1, "T4_sensitivities": t4, "T2_comparisons": comparisons, "T1_collapsed_cells": collapsed}


def decision_logs_block(index: LogIndex) -> dict:
    return {"directory": LOGS_DIR, "index_file": INDEX_FILE,
            "per_capture": [{k: v for k, v in index.entries[c].items() if "sha256" not in k}
                            for c in sorted(index.entries)], "totals": index.totals()}


def _clear_logs(out_dir: Path) -> None:
    """Remove a previous fixture run's decision logs (and the single-file log of earlier adapter versions)."""
    legacy = out_dir / "decision_log.jsonl.gz"
    if legacy.exists():
        legacy.unlink()
    logs = out_dir / LOGS_DIR
    if logs.is_dir():
        for path in logs.glob("*.jsonl.gz"):
            path.unlink()


# ---------------------------------------------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------------------------------------------
def split_tables(cell_rows: list[dict]) -> tuple[list[dict], dict]:
    """T1 keeps the primary cells (the causal views at F = 30 s and E = 120 s; (a) at its own 600 s). T4 puts each
    sensitivity cell beside its primary cell: F = 600 s and E open until H beside the same view, and (c-hind),
    defined "as (L)" except for its future sightings, beside (L) under the heading "hindsight, not a live read"."""
    primary = {(c["capture"], c["view"], c["stream"], c["delta_s"]): c for c in cell_rows if c["view"] in Q2_VIEWS}
    t1 = [c for c in cell_rows if c["view"] in Q2_VIEWS]
    t4 = {"F600": [], "Eopen": [], "c-hind": {"heading": HINDSIGHT_HEADING, "rows": []}}
    for c in cell_rows:
        if c["view"] in Q2_VIEWS:
            continue
        if c["view"] == "c-hind":
            base, block = "L", t4["c-hind"]["rows"]
        elif "@" in c["view"] and c["view"].split("@", 1)[1] in ("F600", "Eopen"):
            base, suffix = c["view"].split("@", 1)
            block = t4[suffix]
        else:
            raise ValueError(f"cell for an unknown view {c['view']!r}")
        ref = primary.get((c["capture"], base, c["stream"], c["delta_s"]))
        block.append({"capture": c["capture"], "stream": c["stream"], "delta_s": c["delta_s"], "view": c["view"],
                      "primary_view": base, "primary": {k: ref[k] for k in T4_FIELDS} if ref else None,
                      "sensitivity": {k: c[k] for k in T4_FIELDS}})
    return t1, t4


# ---------------------------------------------------------------------------------------------------------------
# Fixture run
# ---------------------------------------------------------------------------------------------------------------
def write_fixture_outputs(out_dir: Path, quick: bool = False) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _clear_logs(out_dir)
    (out_dir / LOGS_DIR).mkdir(exist_ok=True)
    index = LogIndex(out_dir / LOGS_DIR, meta={
        "kind": "governance pilot v0 development decision log (synthetic fixtures only)", "adapter": ADAPTER_VERSION})
    runs = []
    for item in fixture_plan(quick):
        sc = item["scenario"]
        extra = FX.x1_records(item["x1"], sc) if item["x1"] else ()
        ci = FX.scenario_inputs(sc, extra_records=extra)
        model = capture_model(ci.capture_id, ci.records, ci.requests)
        phase = verdict_phase(model, index, views=item["views"], streams=item["streams"], deltas=item["deltas"],
                              hindsight_streams=item["hindsight_streams"],
                              cutoff_streams=None if quick else ("S0", "Scorr"))
        runs.append({"item": item, "inputs": ci, "model": model, "phase": phase})
    index.seal()                                   # every verdict exists: the evaluator may now read ground truth
    index.write_index(out_dir / INDEX_FILE)
    labellers, scenarios, items = {}, [], []
    for run in runs:
        sc, model, ci = run["item"]["scenario"], run["model"], run["inputs"]
        gt = ground_truth_from_doc(FX.scenario_ground_truth(sc))
        freezes = tuple(r for r in model.records if r.kind == "freeze_declaration")
        labellers[model.capture_id] = Labeller(gt, model.binding, model.records, freezes, posing_P=model.P)
        items.append({"capture": model.capture_id, "labeller": labellers[model.capture_id],
                      "stream_records": run["phase"]["stream_records"], "H": model.H})
        scenarios.append({"capture": model.capture_id, "scenario": dataclasses.asdict(sc) | {
            "deployment_overrides": len(sc.deployment_overrides)},
            "requests": len(ci.requests),
            "rows_by_kind": ci.notes["rows_by_kind"],
            "binding": model.binding.to_dict() if model.binding else None,
            "P": _iso(model.P), "H": _iso(model.H), "ground_truth": gt.to_dict(),
            "labels": labellers[model.capture_id].to_dict(),
            "views": list(run["item"]["views"]), "streams": list(run["item"]["streams"]),
            "deltas": list(run["item"]["deltas"]), "hindsight_streams": list(run["item"]["hindsight_streams"]),
            "x1": run["item"]["x1"]})
    tables = evaluate_logs(index, items, FIXTURE_PAIRS)
    q1 = merge_q1([run["phase"] for run in runs])
    q1["deterministic_replay"] = {"how": "run_dev.py --rerun-check (two interpreters, PYTHONHASHSEED 1 and 2); "
                                         "result in rerun_check.txt"}
    side, live = [], []
    with tempfile.TemporaryDirectory(prefix="govpilot-fixture-captures-") as tmp:
        for run in runs:
            sc, model = run["item"]["scenario"], run["model"]
            if run["item"]["x1"]:
                continue
            directory = FX.write_capture(sc, Path(tmp) / model.capture_id)
            side.append({"capture": model.capture_id, **side_channel(model, directory)})
            if model.binding is not None:
                live.append({"capture": model.capture_id, **gate_v1_vs_live(directory, model)})
    x1 = []
    cv = hindsight_view("CV", hindsight=True)
    for run in runs:
        if not run["item"]["x1"]:
            continue
        sctx = stream_context(run["model"], STREAM_BY_NAME["S0"])
        verdicts = Counter()
        try:
            for row in index.read_requests(run["model"].capture_id).requests:
                if row.get("disposition") == "ALLOW":
                    entry = evaluate_hindsight(cv, sctx, ts_us(row["disposition_at"]), hindsight=True)
                    verdicts[f"{row['view']}: CV {entry['verdict']}"] += 1
        finally:
            sctx.close()
        x1.append({"capture": run["model"].capture_id, "fixture": run["item"]["x1"],
                   "executions_by_corrected_view_verdict": dict(sorted(verdicts.items()))})
    results = {
        "kind": "governance pilot v0: development run on synthetic fixtures (no capture verdict)",
        "adapter": ADAPTER_VERSION,
        "python": "{}.{}".format(*sys.version_info[:2]),
        "parameters": {"F_seconds": 30.0, "F_gate_v1_seconds": 600.0, "E_seconds": 120.0, "N_seconds": 30.0,
                       "S_seconds": 300.0, "replica_floor": 1, "blast_radius_k": 3, "deltas_seconds": list(DELTAS),
                       "streams": [s.to_dict() for s in STREAMS], "capture_streams": list(CAPTURE_STREAMS),
                       "kubectl": KUBECTL_REFERENCE},
        "decision_logs": decision_logs_block(index),
        "scenarios": scenarios,
        "side_channel": side,
        "gate_v1_store_vs_live_audit": live,
        **tables,
        "T3_q1_checks": q1,
        "x1_fixtures": x1,
        "notes": ["Synthetic fixtures only: no capture was evaluated. Counts describe invented scenarios and are not "
                  "results.", "Sensitivity views (@F600, @Eopen), c-hind (hindsight, not a live read) and the streams "
                  "S180, S300 and S1200 appear only for the 'fault' scenario; the other scenarios run S0, S30, S150, "
                  "Snever and Scorr.", "Scorr is a labelled software fixture: it runs here and never in the capture "
                  "run, whose streams are " + ", ".join(CAPTURE_STREAMS) + ".", "Earlier-cutoff invariance (reconstruction "
                  "check 2) is run over every logged causal evaluation of the S0 and Scorr streams (it rebuilds a "
                  "store per arrival prefix).", "ALLOW dispositions are split by R7's reason at the disposition "
                  "instant: allowed with no visible change, and allowed after rollout_complete"
                  "; view (a) has no R7 and is not split."],
    }
    text = json.dumps(results, indent=1, ensure_ascii=False, sort_keys=True) + "\n"
    with open(out_dir / "results.json", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    with open(out_dir / "SUMMARY.md", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_summary(json.loads(text)))
    return [out_dir / n for n in output_files(out_dir)]


def output_files(directory: Path, *, summary: bool = True) -> list[str]:
    """The run's published files, relative to its output folder (what the rerun check compares)."""
    directory = Path(directory)
    names = ["results.json", INDEX_FILE] + (["SUMMARY.md"] if summary else [])
    logs = directory / LOGS_DIR
    if logs.is_dir():
        names += sorted(f"{LOGS_DIR}/{p.name}" for p in logs.glob("*.jsonl.gz"))
    return names


# ---------------------------------------------------------------------------------------------------------------
# SUMMARY.md (rendered from results.json only)
# ---------------------------------------------------------------------------------------------------------------
def disposition_text(block: dict) -> str:
    split = block.get("allow_split") or {}
    parts = []
    for key, value in block["counts"].items():
        text = f"{key} {value}"
        if key == "ALLOW" and "allowed_with_no_visible_change" in split:
            text += (f" (no visible change {split['allowed_with_no_visible_change']}, after rollout_complete "
                     f"{split['allowed_after_rollout_complete']})")
        parts.append(text)
    return ", ".join(parts) or "-"


def render_summary(res: dict) -> str:
    logs = res["decision_logs"]
    largest = max(logs["per_capture"], key=lambda e: (e["text_bytes"], e["capture"]))
    L = ["# Governance pilot v0: development run on synthetic fixtures", "",
         "**No capture was evaluated. Every scenario below is invented (`govpilot/fixtures.py`); counts describe "
         "the fixtures only and support no claim.** Rendered from `results.json`.", "",
         f"- Decision logs: `{logs['directory']}/`, one per fixture capture (files: {len(logs['per_capture'])}; "
         f"index `{logs['index_file']}`): "
         f"{logs['totals']['evaluations']} evaluations, {logs['totals']['requests']} request rows, "
         f"{logs['totals']['facts']} referenced fact versions; largest `{largest['file']}`: "
         f"{largest['text_bytes']} bytes uncompressed, {largest['gzip_bytes']} gzipped", ""]
    L += ["## Reconstruction checks (x of n)", ""]
    q1 = res["T3_q1_checks"]
    for name in ("append_only_corrections", "provenance"):
        n = sum(c["n"] for c in q1[name])
        x = sum(c["x"] for c in q1[name])
        L.append(f"- {name.replace('_', ' ')}: {x} of {n}")
    n = sum(c["n"] for c in q1["earlier_cutoff_invariance"])
    xt = sum(c["x_truncated"] for c in q1["earlier_cutoff_invariance"])
    xf = sum(c["x_full_stream"] for c in q1["earlier_cutoff_invariance"])
    streams = sorted({c["stream"] for c in q1["earlier_cutoff_invariance"]})
    L.append(f"- earlier-cutoff invariance (streams {', '.join(streams)}): truncated {xt} of {n}; "
             f"fresh full stream {xf} of {n}")
    g = q1["graph_sqlite_agreement"]
    L.append(f"- graph/SQLite agreement: {g['x']} of {g['n']} store queries")
    L.append(f"- deterministic replay: {q1['deterministic_replay']['how']}")
    L += ["", "## Section 3A side-channel test and (a)'s store", ""]
    for s in res["side_channel"]:
        L.append(f"- `{s['capture']}`: per-stream availability "
                 f"{sum(v['ok'] for v in s['per_stream'].values())} of {len(s['per_stream'])} streams; "
                 f"Snever = rows deleted {s['snever_equals_receipt_rows_deleted']}; "
                 f"binding S0 = Snever {s['binding_equal_S0_Snever']}; "
                 f"capture.json deletion byte-identical {s['capture_json_deletion_byte_identical']}")
    for s in res["gate_v1_store_vs_live_audit"]:
        L.append(f"- `{s['capture']}`: (a)'s S0 store equals the live audit's store: {s['equal']} "
                 f"({s['facts_adapter']} / {s['facts_live_audit']} fact versions)")
    collapsed = res["T1_collapsed_cells"]
    groups = [g for c in collapsed for part in ("first_verdicts", "dispositions") for g in c[part]]
    L += ["", "## Collapsed cells", "",
          f"- {len(collapsed)} capture x view x Delta cells have streams whose inputs are identical by construction "
          f"({len(groups)} groups); groups whose logged outcomes differ: "
          f"{sum(not g['outcomes_identical'] for g in groups)}. Listed per cell in `results.json` "
          "`T1_collapsed_cells`."]
    L += ["", "## T1: dispositions at Delta = 0 (counts of posed requests; primary cells)", "",
          "ALLOW is split by R7's reason at the disposition instant: allowed with no visible change, and after "
          "rollout_complete (view (a) has no R7 and is not split).", "",
          "| Capture | View | Stream | Posed | First verdicts | Dispositions | Executions by label | GT-1p exec. | "
          "Missed GT-2 |", "| --- | --- | --- | ---: | --- | --- | --- | ---: | ---: |"]
    for c in res["T1_cells"]:
        if c["delta_s"] != 0 or c["posed"] == 0:
            continue
        ex = ", ".join(f"{k} {v}" for k, v in c["executions_by_label"]["counts"].items() if v) or "-"
        L.append(f"| `{c['capture']}` | {c['view']} | {c['stream']} | {c['posed']} | "
                 + ", ".join(f"{k} {v}" for k, v in c["first_verdicts"]["counts"].items()) + " | "
                 + disposition_text(c["dispositions"]) + f" | {ex} | "
                 f"{c['gt1p_executions']['count']} | {c['missed_opportunities']['total']} of "
                 f"{c['missed_opportunities']['of_requests_labelled_GT2_at_d']} |")

    def counts(block):
        return ", ".join(f"{k} {v}" for k, v in block["counts"].items() if v) or "-"

    def t2_total(rows, field):
        kinds = Counter()
        for r in rows:
            kinds.update(r[field]["block_allow_by_direction"])
            kinds.update(r[field]["severity_only_by_type"])
        detail = ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()))
        return f"{sum(r[field]['differing_requests'] for r in rows)}" + (f" ({detail})" if detail else "")
    L += ["", "## T2: request-level differences between two views", "",
          "Sums over the capture x stream x Delta cells in which both views ran; one row per cell in `results.json` "
          "`T2_comparisons`.", "",
          "| Comparison | Cells | Posed | First verdicts differing | Dispositions differing |",
          "| --- | ---: | ---: | --- | --- |"]
    for name, rows in res["T2_comparisons"].items():
        L.append(f"| {name} | {len(rows)} | {sum(r['posed'] for r in rows)} | {t2_total(rows, 'first_verdict')} | "
                 f"{t2_total(rows, 'disposition')} |")

    def t4_rows(rows):
        out = ["| Capture | Sensitivity | Stream | Beside | Dispositions (primary) | Dispositions (sensitivity) | "
               "Executions (primary) | Executions (sensitivity) |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for r in rows:
            if r["delta_s"] != 0 or r["sensitivity"]["posed"] == 0:
                continue
            p, s = r["primary"], r["sensitivity"]
            out.append(f"| `{r['capture']}` | {r['view']} | {r['stream']} | {r['primary_view']} | "
                       f"{disposition_text(p['dispositions']) if p else 'not run'} | "
                       f"{disposition_text(s['dispositions'])} | "
                       f"{counts(p['executions_by_label']) if p else 'not run'} | {counts(s['executions_by_label'])} |")
        return out
    t4 = res["T4_sensitivities"]
    L += ["", "## T4: sensitivities beside their primary cells (Delta = 0)", "",
          "### F = 600 s and E open until H", ""] + t4_rows(t4["F600"] + t4["Eopen"])
    L += ["", f"### (c-hind) beside (L): {t4['c-hind']['heading']}", ""] + t4_rows(t4["c-hind"]["rows"])
    L += ["", "## X1 fixtures (constructed freezes; CV = corrected view, hindsight)", ""]
    for x in res["x1_fixtures"]:
        L.append(f"- `{x['capture']}` ({x['fixture']}): " + (", ".join(
            f"{k}: {v}" for k, v in x["executions_by_corrected_view_verdict"].items()) or "no execution"))
    L += ["", "## Notes", ""] + [f"- {n}" for n in res["notes"]] + [""]
    return "\n".join(L)


# ---------------------------------------------------------------------------------------------------------------
# Dry run over the nine captures: coverage only
# ---------------------------------------------------------------------------------------------------------------
def dry_run_inputs(out_dir: Path, *, captures_root: Path = CAPTURES_ROOT, captures=CAPTURES) -> list[Path]:
    """The input dry run (defaults: the nine development captures; tests pass fixture captures). Each capture is read
    through the guarded decision reader; its raw/kubectl-version.stdout is read afterwards, outside the reader."""
    out_dir = Path(out_dir)
    rows = []
    for spec in captures:
        directory = Path(captures_root) / spec["id"]
        ci = read_capture(directory)
        rows.append(dict(input_coverage(ci), role=spec["role"], kubectl_version=kubectl_pin_check(directory)))
    report = {"kind": "governance pilot v0 input dry run: field presence and counts only; no binding, no posing, "
                      "no rule evaluated, no verdict",
              "reader": "govpilot.inputs.read_capture (guarded: only evidence/accepted_evidence.jsonl and "
                        "evidence/protocol.json are opened)",
              "kubectl_pin": {"reference": KUBECTL_REFERENCE, "file": KUBECTL_VERSION_FILE,
                              "read_by": "govpilot.environment (outside the decision reader; not a decision input)",
                              "captures_matching": sum(r["kubectl_version"]["matches_pin"] for r in rows),
                              "of_captures": len(rows)},
              "captures": rows}
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "input_coverage.json", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(report, indent=1, sort_keys=True) + "\n")
    pin = report["kubectl_pin"]
    L = ["# Governance pilot v0: input dry run (coverage only)", "",
         "Rendered from `input_coverage.json`. Field presence and counts from the nine development captures, read "
         "through the guarded decision reader. No binding, no posing, no rule and no verdict.", "",
         f"kubectl pin: {KUBECTL_REFERENCE['pin']}. `{KUBECTL_VERSION_FILE}` (read outside the decision reader) "
         f"matches it in {pin['captures_matching']} of {pin['of_captures']} captures.", "",
         "| Capture | Role | Target-block requests | Planned service mapped | Deployment rows (planned) | "
         "spec.replicas | observedGeneration | updatedReplicas | replicas | availableReplicas | revision | "
         "conditions | Patch row | Wait row (exit code, timeout arg) | api available_ns = payload | "
         "kubectl client / server |",
         "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | --- |"]
    for r in rows:
        d = r["deployment_rows_planned_service"]
        patch, wait = r["change_records"]["change_patch"], r["change_records"]["change_wait"]
        wait_text = (f"{wait['rows']} ({'yes' if wait.get('wait_exit_code_present') else 'no'}, "
                     f"{'yes' if wait.get('timeout_arg_present') else 'no'})") if wait["rows"] else "0"
        mismatch = r["api_available_ns_vs_payload_mismatch"]
        k = r["kubectl_version"]
        L.append(f"| `{r['capture']}` | {r['role']} | {r['requests_target_block']} | "
                 f"{r['configuration']['service_mapped_to_deployment']} | {d['rows']} | {d['spec.replicas']} | "
                 f"{d['status.observedGeneration']} | {d['status.updatedReplicas']} | {d['status.replicas']} | "
                 f"{d['status.availableReplicas']} | {d['revision_annotation']} | {d['status.conditions']} | "
                 f"{patch['rows']} | {wait_text} | {r['rows_by_kind'].get('api_observation', 0) - mismatch} of "
                 f"{r['rows_by_kind'].get('api_observation', 0)} | {k['client_gitVersion']} / "
                 f"{k['server_gitVersion']} |")
    L.append("")
    with open(out_dir / "input_coverage.md", "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(L))
    return [out_dir / "input_coverage.json", out_dir / "input_coverage.md"]


# ---------------------------------------------------------------------------------------------------------------
# The capture run
# ---------------------------------------------------------------------------------------------------------------
class Refused(SystemExit):
    pass


def run_captures(out_dir: Path, *, captures_root: Path = CAPTURES_ROOT, captures=CAPTURES,
                 views=Q2_VIEWS + SENSITIVITY_VIEWS, streams=CAPTURE_STREAMS, deltas=DELTAS,
                 hindsight_streams=CAPTURE_STREAMS, expected_requests: int | None = 120) -> list[Path]:
    """The Stage-1 capture run on the nine development captures; the keyword arguments exist so that the test
    suite can run this exact path on fixture capture directories with a small grid. Captures are processed one at a time: abort checks, verdicts, reconstruction checks 1-4, the capture's decision
    log written and dropped; then the index is sealed and the evaluator runs."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / LOGS_DIR).mkdir()
    index = LogIndex(out_dir / LOGS_DIR, meta={
        "kind": "governance pilot Stage 1 capture run (development; labelled)", "adapter": ADAPTER_VERSION})
    side_streams = [STREAM_BY_NAME[name] for name in CAPTURE_STREAMS]
    runs = []
    for spec in captures:
        directory = Path(captures_root) / spec["id"]
        ci = read_capture(directory)
        if expected_requests is not None and [k for k, _ in ci.requests] != list(range(1, expected_requests + 1)):
            raise SystemExit(f"abort: {spec['id']} target block is not requests 1..{expected_requests}")
        model = capture_model(ci.capture_id, ci.records, ci.requests)
        side = side_channel(model, directory, streams=side_streams)
        if not side["ok"]:
            raise SystemExit(f"abort: side-channel test failed on {spec['id']}: {side}")
        live = gate_v1_vs_live(directory, model) if model.binding else None
        if live is not None and not live["equal"]:
            raise SystemExit(f"abort: (a)'s S0 store differs from the live audit's on {spec['id']}")
        phase = verdict_phase(model, index, views=views, streams=streams, deltas=deltas,
                              hindsight_streams=hindsight_streams)
        if phase["engines"]["disagreements"]:
            raise SystemExit(f"abort: graph and SQLite disagreed on {spec['id']}")
        runs.append({"spec": spec, "dir": directory, "model": model, "side": side, "live": live, "phase": phase})
    index.seal()                                   # every verdict exists: the evaluator may now read ground truth
    index.write_index(out_dir / INDEX_FILE)
    labellers, truths, items = {}, {}, []
    for run in runs:
        capture_id = run["model"].capture_id
        truths[capture_id] = load_ground_truth(run["dir"], index,
                                               catalog_disruption=bool(run["spec"].get("catalog_disruption_u")))
        labellers[capture_id] = Labeller(truths[capture_id], run["model"].binding, run["model"].records,
                                         posing_P=run["model"].P)
        items.append({"capture": capture_id, "labeller": labellers[capture_id],
                      "stream_records": run["phase"]["stream_records"], "H": run["model"].H})
    tables = evaluate_logs(index, items, MATCHED_PAIRS + OPERATIONAL_PAIRS)
    q1 = merge_q1([run["phase"] for run in runs])
    q1["check_1_note"] = CHECK1_CAPTURE_NOTE
    q1["deterministic_replay"] = {"how": "run_dev.py --rerun-check --captures (two interpreters, PYTHONHASHSEED 1 "
                                         "and 2, compared with this run); result in rerun_check.txt"}
    results = {"kind": "governance pilot Stage 1 capture run (development; labelled; no claim)",
               "adapter": ADAPTER_VERSION, "python": "{}.{}".format(*sys.version_info[:2]),
               "grid": {"views": list(views), "streams": list(streams), "deltas_seconds": list(deltas),
                        "hindsight_streams": list(hindsight_streams), "side_channel_streams": list(CAPTURE_STREAMS)},
               "parameters": {"F_seconds": 30.0, "F_gate_v1_seconds": 600.0, "E_seconds": 120.0, "N_seconds": 30.0,
                              "S_seconds": 300.0, "replica_floor": 1, "blast_radius_k": 3,
                              "kubectl": KUBECTL_REFERENCE},
               "decision_logs": decision_logs_block(index),
               "captures": [{"capture": r["spec"]["id"], "role": r["spec"]["role"],
                             "P": _iso(r["model"].P), "H": _iso(r["model"].H),
                             "binding": r["model"].binding.to_dict() if r["model"].binding else None,
                             "ground_truth": truths[r["model"].capture_id].to_dict(),
                             "labels": labellers[r["model"].capture_id].to_dict()} for r in runs],
               **tables,
               "T3_q1_checks": q1,
               "side_channel": [{"capture": r["spec"]["id"], **r["side"]} for r in runs],
               "gate_v1_store_vs_live_audit": [{"capture": r["spec"]["id"], **r["live"]} for r in runs if r["live"]]}
    with open(out_dir / "results.json", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(results, indent=1, sort_keys=True) + "\n")
    return [out_dir / n for n in output_files(out_dir, summary=False)]


# ---------------------------------------------------------------------------------------------------------------
# Reconstruction check 5: deterministic replay in two interpreters
# ---------------------------------------------------------------------------------------------------------------
def rerun_check(quick: bool = False, published: Path | None = FIXTURES_OUT, *,
                captures: bool = False) -> tuple[bool, str]:
    """Reconstruction check 5: the fixture run (default) or, with ``captures=True``, the capture run, executed twice in
    separate interpreters and compared file by file with each other and with ``published``."""
    published = Path(published) if published is not None else None
    if captures:
        if published is None or not all((published / n).exists() for n in ("results.json", INDEX_FILE)):
            raise Refused(f"refused: no published capture run in {published}; run --captures first, then this check "
                          "compares two fresh runs with it")
        extra = ["--captures"]
    else:
        extra = ["--quick"] if quick else []
    runs = {}
    with tempfile.TemporaryDirectory(prefix="govpilot-rerun-") as tmp:
        for label, seed in (("run_a", "1"), ("run_b", "2")):
            out = Path(tmp) / label
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE="1")
            cmd = [sys.executable, str(Path(__file__).resolve()), *extra, "--output", str(out)]
            proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True)
            if proc.returncode != 0:
                raise SystemExit(f"{label} failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
            runs[label] = {n: sha256_file(out / n) for n in output_files(out, summary=not captures)}
    identical = runs["run_a"] == runs["run_b"]
    lines = ["governance pilot v0: rerun check (reconstruction check 5)",
             "Two separate interpreter runs (PYTHONHASHSEED=1 and 2) of govpilot/run_dev.py"
             + "".join(f" {a}" for a in extra[:1]) + " --output <tmp>, compared byte for byte.", ""]
    current = None
    if published is not None and not quick:
        current = {n: sha256_file(published / n) if (published / n).exists() else None
                   for n in output_files(published, summary=not captures)}
    names = sorted(set(runs["run_a"]) | set(runs["run_b"]) | set(current or {}))
    for n in names:
        lines += [n, f"  run_a {runs['run_a'].get(n)}", f"  run_b {runs['run_b'].get(n)}"]
        if current is not None:
            lines.append(f"  published {current.get(n)}")
    lines += ["", f"run_a == run_b: {str(identical).lower()}"]
    matches = None if current is None else runs["run_a"] == current
    if matches is not None:
        lines.append(f"run_a == published: {str(matches).lower()}")
    return identical and matches in (None, True), "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--dry-run-inputs", action="store_true", help="coverage report over the nine captures")
    parser.add_argument("--captures", action="store_true", help="the capture run on the development captures")
    parser.add_argument("--rerun-check", action="store_true", help="two interpreters, byte-identical outputs")
    parser.add_argument("--quick", action="store_true", help="the small fixture plan (tests)")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.rerun_check:                           # with --captures: reconstruction check 5 of the capture run
        out = args.output or (CAPTURES_OUT if args.captures else FIXTURES_OUT)
        ok, text = rerun_check(quick=args.quick, published=out, captures=args.captures)
        if not args.quick:
            out.mkdir(parents=True, exist_ok=True)
            (out / "rerun_check.txt").write_text(text, encoding="utf-8")
        print(text)
        return 0 if ok else 1
    if args.captures:
        for path in run_captures(args.output or CAPTURES_OUT):
            print(rel(path))
        return 0
    if args.dry_run_inputs:
        for path in dry_run_inputs(args.output or DRY_RUN_OUT):
            print(rel(path))
        return 0
    for path in write_fixture_outputs(args.output or FIXTURES_OUT, quick=args.quick):
        print(rel(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
