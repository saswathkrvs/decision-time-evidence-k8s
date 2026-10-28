#!/usr/bin/env python3
"""Governance adapter of the follow-up study: one converted capture -> decision logs, labels and T1-T4.

    python3 experiments/governance-stage2/run_stage2_adapter.py --capture <converted dir> \
        --plan phase3/stage2_plan.json --out <new dir> [--conditions T_p,L-kappa,R,T_w] [--cells primary|all] \
        [--raw <raw capture dir>] [--allow-excluded] [--measure] [--rerun-check]
    python3 experiments/governance-stage2/run_stage2_adapter.py --check [--write-expectation]
    python3 experiments/governance-stage2/run_stage2_adapter.py --build-synthetic <new dir>

- ``--capture``: a converter-v4 output directory (``<capture>/evidence``); the raw capture (capture.json,
  COMPLETE.txt, ground_truth/) is its parent unless ``--raw`` names it.
- ``--out``: written once and never overwritten: decision_logs/<capture>.<observer>.jsonl.gz (one per observer),
  decision_log_index.json, results.json, SUMMARY.md.
- ``--cells primary``: only the conditions, streams and actions of the arm's primary cells.
- ``--rerun-check``: after the run, a second interpreter (another PYTHONHASHSEED) runs the same arguments into
  ``<out>.rerun`` and every output file is compared byte for byte.
- ``--check``: rebuilds the tiny_g2 fixture in a temporary directory, runs it under the narrowed fixture plan and
  compares every count and label with govstage2/fixture_expectation.json (``--write-expectation`` rewrites that
  file).
- ``--build-synthetic``: writes converter v4's synthetic arm-G capture with spans (govstage2.fixtures.synthetic_arm_g)
  and prints the converted directory.

Exit status 0 on success, 1 when --check or --rerun-check finds a difference, 2 on a refusal or an input error.
Standard library only; Python 3.11 or newer (nine-digit timestamp fractions).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

if sys.version_info < (3, 11):
    sys.exit("run_stage2_adapter.py needs Python 3.11 or newer (nine-digit fractions in collector timestamps)")

from govstage2 import pipeline  # noqa: E402
from govstage2.common import DEFAULT_PLAN, EXPECTATION_FILE, AdapterError, Refused, json_dump, rel  # noqa: E402


def _progress(quiet: bool):
    if quiet:
        return None
    return lambda message: print(message, file=sys.stderr, flush=True)


def run(args) -> int:
    if not args.capture or not args.out:
        print("--capture and --out are required (or use --check / --build-synthetic)", file=sys.stderr)
        return 2
    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()] if args.conditions else None
    try:
        results = pipeline.run_capture(args.capture, args.plan, args.out, raw=args.raw, conditions=conditions,
                                       cells=args.cells, allow_excluded=args.allow_excluded,
                                       measure=args.measure_heap, progress=_progress(args.quiet))
    except Refused as refusal:
        print(str(refusal), file=sys.stderr)
        return 2
    except AdapterError as error:
        print(f"input error: {error}", file=sys.stderr)
        return 2
    out = Path(args.out)
    print(f"wrote {out / pipeline.RESULTS_FILE}, {out / pipeline.SUMMARY_FILE}, {out / pipeline.INDEX_FILE} and "
          f"{len(results['decision_logs']['per_observer'])} decision logs")
    runtime = results["_runtime_not_written"]
    if args.measure or args.measure_heap:
        try:
            import resource       # not on Windows
            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            runtime["peak_rss_mib"] = round(peak / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)
        except ImportError:
            runtime["peak_rss_mib"] = "not available on this platform (no resource module)"
        print(json.dumps({"runtime_not_written_to_outputs": runtime}, indent=1, sort_keys=True))
    if args.rerun_check:
        return rerun_check(args)
    return 0


def rerun_check(args) -> int:
    """The rerun check: the same arguments in a second interpreter into <out>.rerun, then a byte comparison."""
    second = Path(str(Path(args.out)) + ".rerun")
    if second.exists():
        print(f"refused: {second} exists", file=sys.stderr)
        return 2
    command = [sys.executable, str(Path(__file__).resolve()), "--capture", args.capture, "--plan", args.plan,
               "--out", str(second), "--cells", args.cells, "--quiet"]
    for flag, value in (("--raw", args.raw), ("--conditions", args.conditions)):
        if value:
            command += [flag, value]
    if args.allow_excluded:
        command.append("--allow-excluded")
    env = dict(os.environ, PYTHONHASHSEED="12345", PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run(command, env=env, capture_output=True, text=True)
    if done.returncode != 0:
        print(done.stdout + done.stderr, file=sys.stderr)
        return 2
    comparison = pipeline.compare_trees(args.out, second)
    print(json.dumps({"rerun_check_deterministic_replay": comparison}, indent=1, sort_keys=True))
    return 0 if comparison["identical"] else 1


def check(args) -> int:
    with tempfile.TemporaryDirectory(prefix="govstage2-check-") as tmp:
        results = pipeline.run_check_fixture(Path(tmp), progress=_progress(args.quiet))
        view = pipeline.expectation_view(results)
    if args.write_expectation:
        json_dump(EXPECTATION_FILE, view)
        print(f"wrote {rel(EXPECTATION_FILE)}")
        return 0
    if not EXPECTATION_FILE.is_file():
        print(f"{rel(EXPECTATION_FILE)} does not exist; run --check --write-expectation once", file=sys.stderr)
        return 2
    expected = json.loads(EXPECTATION_FILE.read_text(encoding="utf-8"))
    differences = pipeline.diff_docs(expected, view)
    if differences:
        print(f"--check: {len(differences)} difference(s) from {rel(EXPECTATION_FILE)}:")
        for line in differences[:50]:
            print("  " + line)
        return 1
    print(f"--check: the tiny_g2 fixture reproduces {rel(EXPECTATION_FILE)} exactly "
          f"({len(view['T1_cells'])} T1 cells, {len(view['T2_comparisons'])} T2 rows)")
    return 0


def build_synthetic(args) -> int:
    from govstage2.fixtures import synthetic_arm_g
    target = Path(args.build_synthetic)
    if target.exists():
        print(f"refused: {target} exists", file=sys.stderr)
        return 2
    target.mkdir(parents=True)
    built = synthetic_arm_g(target)
    print(built["converted"])
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--capture", help="converted capture directory (<capture>/evidence)")
    parser.add_argument("--plan", default=str(DEFAULT_PLAN), help="the capture plan (default %(default)s)")
    parser.add_argument("--out", help="output directory (must not exist)")
    parser.add_argument("--raw", help="raw capture directory (default: the converted directory's parent)")
    parser.add_argument("--conditions", help="comma-separated subset of the arm's conditions")
    parser.add_argument("--cells", choices=("primary", "all"), default="all")
    parser.add_argument("--allow-excluded", action="store_true",
                        help="analyse a capture its validity fields exclude (diagnostics only; marked in outputs)")
    parser.add_argument("--measure", action="store_true",
                        help="print wall time, seconds per observer and the peak resident memory (stdout only)")
    parser.add_argument("--measure-heap", action="store_true",
                        help="as --measure, plus the peak Python heap by tracemalloc (several times slower)")
    parser.add_argument("--rerun-check", action="store_true",
                        help="run again in a second interpreter and compare every output file byte for byte")
    parser.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    parser.add_argument("--check", action="store_true", help="run the fixture self-check")
    parser.add_argument("--write-expectation", action="store_true", help="with --check: rewrite the expectation")
    parser.add_argument("--build-synthetic", metavar="DIR", help="write the synthetic arm-G capture into DIR")
    args = parser.parse_args(argv)
    if args.check:
        return check(args)
    if args.build_synthetic:
        return build_synthetic(args)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
