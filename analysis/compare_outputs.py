"""Compare the outputs of a rerun with the published per-capture outputs in ``results/``.

    python -m analysis.compare_outputs adapter   <dir>   # <dir>/<capture>/results.json  vs results/stage2/adapter/
    python -m analysis.compare_outputs diagnosis <dir>   # <dir>/<capture>/results.json, <dir>/summary.json
                                                         #                                vs results/stage2/diagnosis/
    python -m analysis.compare_outputs bridge    <dir>   # <dir>/<capture>/results.json  vs results/development/diagnosis/
    python -m analysis.compare_outputs gate      <dir>   # <dir>/results.json            vs results/development/gate_audit.json
    python -m analysis.compare_outputs pilot     <dir>   # <dir>/results.json            vs results/development/rollback_pilot.json

Every key, string, integer and boolean must be equal; floats are compared with a relative tolerance of 1e-9 (the
published outputs were computed under Python 3.11 with the library versions they record). The interpreter and library
versions (``python``, ``environment``) are not compared. For the gate analysis and the rollback pilot, the published
files hold a subset of the top-level keys; only those are compared. Exit status 1 when anything differs.
Standard library only.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IGNORED = {"python", "environment"}


def diff(a, b, path=(), out=None):
    out = [] if out is None else out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k in IGNORED:
                continue
            if k not in a:
                out.append(("/".join(map(str, path + (k,))), "missing in the rerun"))
            elif k not in b:
                out.append(("/".join(map(str, path + (k,))), "not in the published file"))
            else:
                diff(a[k], b[k], path + (k,), out)
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(("/".join(map(str, path)), f"list length {len(a)} vs {len(b)}"))
            return out
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, path + (i,), out)
        return out
    if isinstance(a, float) or isinstance(b, float):
        if (isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool)
                and not isinstance(b, bool) and math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12)):
            return out
    if a != b:
        out.append(("/".join(map(str, path)), f"{str(a)[:120]!r} vs {str(b)[:120]!r}"))
    return out


def load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def pairs(kind: str, rerun: Path, results: Path):
    if kind in ("adapter", "diagnosis", "bridge"):
        published = {"adapter": results / "stage2/adapter", "diagnosis": results / "stage2/diagnosis",
                     "bridge": results / "development/diagnosis"}[kind]
        for d in sorted(p for p in rerun.iterdir() if (p / "results.json").exists()):
            yield d.name, load(d / "results.json"), published / (d.name + ".json")
        if kind == "diagnosis" and (rerun / "summary.json").exists():
            yield "summary", load(rerun / "summary.json"), published / "summary.json"
        return
    published = results / "development" / {"gate": "gate_audit.json", "pilot": "rollback_pilot.json"}[kind]
    doc = load(rerun / "results.json")
    keys = load(published).keys()
    yield published.stem, {k: doc[k] for k in keys if k in doc}, published


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("kind", choices=("adapter", "diagnosis", "bridge", "gate", "pilot"))
    parser.add_argument("rerun", type=Path, help="the rerun's output directory")
    parser.add_argument("--results", type=Path, default=ROOT / "results")
    args = parser.parse_args(argv)
    bad = n = 0
    for name, doc, published in pairs(args.kind, args.rerun, args.results):
        n += 1
        if not published.exists():
            print(f"{name}: no published file {published}")
            bad += 1
            continue
        found = diff(doc, load(published))
        print(f"{name}: " + ("identical" if not found else f"{len(found)} difference(s)"))
        for p, m in found[:10]:
            print(f"    {p}: {m}")
        bad += bool(found)
    if not n:
        print("nothing to compare")
        return 1
    print("all identical" if not bad else f"{bad} of {n} differ")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
