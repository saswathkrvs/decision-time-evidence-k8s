"""Reconstruction checks and the input abort checks of the development rollback pilot.

Each reconstruction check is reported as x of n over the logged evaluations it covers:

1. append-only corrections: with every correction appended, re-evaluating at a logged cutoff before the
   correction's availability gives the identical verdict, rule trace and record IDs as the stream without it
   (capture streams carry no correction, since Scorr is a software fixture, so on captures n = 0, reported as such);
2. earlier-cutoff invariance: the same after truncating the stream's model inputs at the cutoff, and from a freshly
   built full stream;
3. exact provenance: every evaluation lists per-rule record IDs and the configuration hash; every listed record was
   available and not withdrawn at the cutoff (causal views); every fact the resolver handed out is listed;
4. graph/SQLite agreement on every store query (the dual engine asks both);
5. deterministic replay: two interpreters with different PYTHONHASHSEED produce byte-identical outputs
   (``run_dev.py --rerun-check``; ``--rerun-check --captures`` for the capture run).

Checks 1-4 run on one capture's stream contexts right after its verdicts, before its decision log is written and
dropped (they read the log; they never need ground truth).

Abort checks: the side-channel test (four parts), A's binding under S0 and Snever, and view (a)'s S0 fact store equal
to the live audit's store fact for fact (receipt record IDs renamed, see ``gate_v1_vs_live``). These checks are not the
decision reader: the last one reads evidence/capture.json, as the live audit did, only to compare stores; nothing it
reads reaches a view.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from .common import R, canonical, ts_us
from .inputs import CHANGE_KINDS, STREAMS, bind, bound_change_records, perturb, read_capture
from .mapping import ModelInputs, build_model_inputs, live_module
from .views import GATE_V1, StreamContext, causal_view, evaluate_causal, inputs_behind, records_behind


def _trace(entry: dict, sctx: StreamContext) -> str:
    """Verdict, per-rule trace (verdict, reason, detail, IDs) and the record IDs behind it (via the store)."""
    ids = [x for r in entry["rules"] for x in r["ids"]]
    return canonical({"verdict": entry["verdict"], "rules": entry["rules"],
                      "records": records_behind(sctx.store(entry["store"]), ids)})


def _fresh(sctx: StreamContext, model: ModelInputs | None = None, label: str | None = None,
           cache: dict | None = None) -> StreamContext:
    ctx = StreamContext.__new__(StreamContext)
    ctx.capture, ctx.stream, ctx.records, ctx.manifest = sctx.capture, label or sctx.stream, sctx.records, {}
    ctx.model = model if model is not None else build_model_inputs(sctx.records, sctx.capture.binding)
    ctx._stores, ctx.memo, ctx.fact_cache = {}, {}, cache
    return ctx


def truncate_model(model: ModelInputs, tau: int) -> ModelInputs:
    """The model inputs a reader would hold at cutoff tau: everything available (or withdrawn) by tau."""
    keep_obs = tuple(o for o in model.observations if R.to_us(o.available_at) <= tau)
    keep_ids = {o.record_id for o in keep_obs}
    return ModelInputs(
        keep_obs, tuple(f for f in model.identity_facts if R.to_us(f.available_at) <= tau),
        {k: v for k, v in model.withdrawals.items() if v <= tau and k in keep_ids},
        {k: v for k, v in model.provenance.items() if k in keep_ids},
        frozenset(x for x in model.receipt_observations if x in keep_ids),
        frozenset(x for x in model.cluster_observations if x in keep_ids),
        tuple(c for c in model.completion_receipts if c.available_at <= tau),
        {k: v for k, v in model.completion_withdrawals.items() if v <= tau},
        tuple(f for f in model.freezes if f.available_at <= tau),
        {k: v for k, v in model.freeze_withdrawals.items() if v <= tau},
        {k: v for k, v in model.availability.items() if v <= tau})


def _logged(log, capture_id: str, stream: str, *, causal_only: bool = True) -> list[dict]:
    out = []
    for entry in log.evaluations.values():
        if entry["capture"] != capture_id or entry["stream"] != stream:
            continue
        if causal_only and "hindsight" in entry:
            continue
        out.append(entry)
    return sorted(out, key=lambda e: (e["view"], e["instant_us"]))


def check_append_only(log, sctx: StreamContext) -> dict:
    """Check 1 on one stream that contains corrections."""
    corrections = [r for r in sctx.records if r.corrects is not None]
    if not corrections:
        return {"n": 0, "x": 0, "failures": [], "note": "no correction in this stream"}
    first = min(c.available_at for c in corrections)
    base_records = tuple(r for r in sctx.records if r.corrects is None)
    base = StreamContext(sctx.capture, sctx.stream + "/without-corrections", base_records)
    n = x = 0
    failures = []
    try:
        for entry in _logged(log, sctx.capture.capture_id, sctx.stream):
            if entry["instant_us"] >= first:
                continue
            n += 1
            again = evaluate_causal(causal_view(entry["view"]), base, entry["instant_us"])
            if _trace(again, base) == _trace(entry, sctx):
                x += 1
            else:
                failures.append(entry["eval_id"])
    finally:
        base.close()
    return {"n": n, "x": x, "failures": failures[:20],
            "first_correction_available_at": R.iso(first), "corrections": sorted(c.id for c in corrections)}


def check_earlier_cutoff(log, sctx: StreamContext) -> dict:
    """Check 2: (a) model inputs truncated at the cutoff, (b) a freshly built full stream."""
    entries = sorted(_logged(log, sctx.capture.capture_id, sctx.stream), key=lambda e: (e["instant_us"], e["view"]))
    fresh = _fresh(sctx)
    truncated_cache: dict[int, StreamContext] = {}
    group_cache: dict = {}          # per-group facts, derived independently from each truncated group
    n = x_trunc = x_full = 0
    failures = []
    arrivals = sorted({*sctx.model.availability.values()})
    try:
        for entry in entries:
            tau = entry["instant_us"]
            spec = causal_view(entry["view"])
            # the truncated model depends only on the last arrival <= tau
            index = max((a for a in arrivals if a <= tau), default=None)
            if index not in truncated_cache:
                for ctx in truncated_cache.values():
                    ctx.close()
                truncated_cache = {index: _fresh(sctx, truncate_model(sctx.model, tau), sctx.stream, group_cache)}
            n += 1
            truncated = truncated_cache[index]
            if _trace(evaluate_causal(spec, truncated, tau), truncated) == _trace(entry, sctx):
                x_trunc += 1
            else:
                failures.append(("truncated", entry["eval_id"]))
            if _trace(evaluate_causal(spec, fresh, tau), fresh) == _trace(entry, sctx):
                x_full += 1
            else:
                failures.append(("full", entry["eval_id"]))
    finally:
        fresh.close()
        for ctx in truncated_cache.values():
            ctx.close()
    return {"n": n, "x_truncated": x_trunc, "x_full_stream": x_full, "failures": failures[:20]}


def check_provenance(log, sctx: StreamContext) -> dict:
    """Check 3 over the stream's logged causal evaluations, from the log alone: per-rule IDs and the configuration
    hash are present; the record IDs behind every listed fact (the log's fact table) and every listed record were
    available, and not withdrawn, at the cutoff; every fact the resolver handed out is listed."""
    withdrawn_at = {}
    m = sctx.model
    for table in (m.withdrawals, m.completion_withdrawals, m.freeze_withdrawals):
        withdrawn_at.update(table)
    capture_id = sctx.capture.capture_id
    n = x = 0
    failures = []
    for entry in _logged(log, capture_id, sctx.stream):
        n += 1
        tau = entry["instant_us"]
        ok = bool(entry.get("config_sha256")) and all("ids" in r for r in entry["rules"])
        records = set()
        for r in entry["rules"]:
            for identifier in r["ids"]:
                if identifier.startswith(("freeze:", "input:")):
                    records.add(identifier.split(":", 1)[1])
                    continue
                fact = log.facts.get((capture_id, sctx.stream, entry["store"], identifier))
                if fact is None:
                    ok = False
                    continue
                if ts_us(fact["available_at"]) > tau:
                    ok = False
                if fact["superseded_at"] is not None and ts_us(fact["superseded_at"]) <= tau:
                    ok = False
                records.update(fact["support"])
        for rid in records | set(inputs_behind(m, records)):
            available = m.availability.get(rid)
            if available is None or available > tau or (rid in withdrawn_at and withdrawn_at[rid] <= tau):
                ok = False
        if entry["provenance_unlisted_fact_ids"]:
            ok = False
        if ok:
            x += 1
        else:
            failures.append(entry["eval_id"])
    return {"n": n, "x": x, "failures": failures[:20]}


def check_engines(contexts) -> dict:
    """Check 4: every store query answered by both engines; counts per store."""
    queries = disagreements = 0
    for sctx in contexts:
        for store in sctx._stores.values():
            queries += store.dual.queries
            disagreements += len(store.dual.disagreements)
    return {"n": queries, "x": queries - disagreements, "disagreements": disagreements}


# ---------------------------------------------------------------------------------------------------------------
# Section 3A side-channel test and the binding check
# ---------------------------------------------------------------------------------------------------------------
def side_channel(capture, capture_dir: Path | None = None, streams=STREAMS) -> dict:
    """The four side-channel checks on one capture (fixtures; abort check on captures)."""
    out = {"per_stream": {}}
    ok_all = True
    for spec in streams:
        records, _ = perturb(capture.records, spec)
        records = bound_change_records(records, capture.binding)
        model = build_model_inputs(records, capture.binding)
        rows = {r.id: r.available_at for r in records if r.kind in CHANGE_KINDS}
        problems = []
        for rid in model.receipt_observations:
            source = model.provenance[rid][0]
            if source not in rows or model.availability[rid] != rows[source]:
                problems.append(f"{rid} not at its row's availability")
        for c in model.completion_receipts:
            if c.record_id not in rows or c.available_at != rows[c.record_id]:
                problems.append(f"{c.record_id} not at its row's availability")
        if spec.drop and (model.receipt_observations or model.completion_receipts):
            problems.append("receipt-derived records exist under Snever")
        out["per_stream"][spec.name] = {"ok": not problems, "problems": problems,
                                        "receipt_derived_records": len(model.receipt_observations)
                                        + len(model.completion_receipts)}
        ok_all &= not problems
    never, _ = perturb(capture.records, next(s for s in streams if s.drop))
    deleted = tuple(r for r in capture.records if r.kind not in CHANGE_KINDS)
    equal_deleted = (canonical(build_model_inputs(bound_change_records(never, capture.binding),
                                                  capture.binding).serialize())
                     == canonical(build_model_inputs(deleted, capture.binding).serialize()))
    out["snever_equals_receipt_rows_deleted"] = equal_deleted
    binding_s0 = bind(capture.records, capture.P) if capture.binding else None
    binding_never = bind(never, capture.P) if capture.binding else None
    out["binding_equal_S0_Snever"] = binding_s0 == binding_never
    out["capture_json_deletion_byte_identical"] = None
    if capture_dir is not None:
        out["capture_json_deletion_byte_identical"] = capture_json_deletion(Path(capture_dir))
    out["ok"] = bool(ok_all and equal_deleted and out["binding_equal_S0_Snever"]
                     and out["capture_json_deletion_byte_identical"] in (None, True))
    return out


def capture_json_deletion(capture_dir: Path) -> bool:
    """Section 3A check 3: the reader's inputs are byte-identical with evidence/capture.json deleted."""
    original = read_capture(capture_dir).serialize()
    with tempfile.TemporaryDirectory(prefix="govpilot-sidechannel-") as tmp:
        copy = Path(tmp) / capture_dir.name
        (copy / "evidence").mkdir(parents=True)
        for name in ("accepted_evidence.jsonl", "protocol.json"):
            shutil.copyfile(capture_dir / "evidence" / name, copy / "evidence" / name)
        assert not (copy / "evidence/capture.json").exists()
        again = read_capture(copy).serialize()
    return original == again


# ---------------------------------------------------------------------------------------------------------------
# View (a)'s S0 store against the live audit's store
# ---------------------------------------------------------------------------------------------------------------
def gate_v1_vs_live(capture_dir: Path, capture) -> dict:
    """(a)'s S0 fact store == the live audit's store, fact for fact.

    The live store is built the way run_policy_gate_live.build_store builds it: v1's load_sightings over the
    capture's accepted evidence and the patch side copy in evidence/capture.json. The only allowed difference is the
    receipt record IDs (``receipt:rollout-patch#...`` there, ``<patch evidence_id>#...`` here), mapped before the
    comparison."""
    live = live_module()
    pga = live.pga
    capture_dir = Path(capture_dir)
    evidence = capture_dir / "evidence"
    protocol = json.loads((evidence / "protocol.json").read_text(encoding="utf-8"))
    capture_doc = json.loads((evidence / "capture.json").read_text(encoding="utf-8"))
    previous = pga.INPUTS["api_sightings"]
    pga.INPUTS["api_sightings"] = evidence / "accepted_evidence.jsonl"   # in memory only; restored below
    try:
        sightings = pga.load_sightings(protocol)
    finally:
        pga.INPUTS["api_sightings"] = previous
    patch = pga.patch_receipt(capture_doc)
    live_store = live.build_store({"sightings": sightings, "patch": patch, "protocol": protocol})[0]
    sctx = StreamContext(capture, "S0", capture.records)
    mine = sctx.store(GATE_V1)
    patch_rows = [r.id for r in capture.records if r.kind == "change_patch"]
    rename = {}
    if patch_rows:
        for suffix in ("request_started_at", "response_received_at"):
            rename[f"{patch_rows[0]}#{suffix}"] = f"receipt:rollout-patch#{suffix}"

    def rows(facts, mapping):
        return sorted((f.fact_id, f.subject, f.predicate, f.object, R.iso(R.to_us(f.valid_from)) if f.valid_from
                       else None, R.iso(R.to_us(f.valid_to)) if f.valid_to else None, R.iso(R.to_us(f.available_at)),
                       R.iso(R.to_us(f.superseded_at)) if f.superseded_at else None,
                       mapping.get(f.source_id, f.source_id), f.known_open,
                       R.iso(R.to_us(f.confirmed_at)) if f.confirmed_at else None) for f in facts)

    a, b = rows(mine.facts, rename), rows(live_store.facts, {})
    live_store.close()
    sctx.close()
    differing = sorted(set(a) ^ set(b))
    return {"equal": a == b, "facts_adapter": len(a), "facts_live_audit": len(b), "differences": differing[:10],
            "renamed_record_ids": rename}
