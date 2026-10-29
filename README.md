# Decision-time evidence for Kubernetes diagnosis and remediation

Code, per-capture outputs and table scripts for the paper *When Does Decision-Time Evidence Matter? A Controlled
Replay Study of Kubernetes Diagnosis and Remediation*.

Kubernetes rollouts of two Online Boutique services were recorded on a single-node kind cluster. Every record keeps
two times: when the observed state held (valid time) and when the record reached the pipeline (availability time).
The recorded incidents are replayed offline through a fixed robust ranker (diagnosis) and a fixed rule-based
remediation gate; proposed actions are counterfactual and never executed. The raw captures are archived separately
(below); everything in `results/` can be recomputed from them with the code here.

## Contents

| Path | |
| --- | --- |
| `src/aiops_kg/` | evidence records and their validation (`evidence.py`), the replay engine (`replay.py`), the remediation gate with its graph and SQLite resolvers (`policy_gate.py`), the context bridge from records to the ranker (`context_bridge.py`), the ranker (`graph_rank.py`), the fault-control evaluators (`fault_control.py`, `fault_control_kill.py`) |
| `phase3/` | the converters from a raw capture to evidence rows (`convert_capture.py`: development captures; `convert_stage2.py`: follow-up captures), the follow-up capture plan (`stage2_plan.json`) and the capture formats (`CAPTURE_FORMAT.md`, `CAPTURE_FORMAT_STAGE2.md`) |
| `scripts/`, `infrastructure/` | the collectors that wrote the captures (API poller, watch collector, recheck loop, per-Pod probe, kubectl proxy, host-command receipts, clock probe) and two infrastructure files the analyses read |
| `experiments/context-bridge-v1/` | development diagnosis: context policies, request attribution and ranking, per capture |
| `experiments/policy-gate-live-v1/` | development gate analysis: label-free, over nine real rollouts |
| `experiments/governance-pilot-v0/` | development matched rollback pilot |
| `experiments/policy-gate-v1/`, `experiments/replay-policy-v1/`, `experiments/attribution-lag-v1/` | the analyses of the 22 Sep 2026 rollout that the development stage builds on; the outputs of the first two are kept in their folders (the gate analysis reads them) |
| `experiments/governance-stage2/` | follow-up governance adapter: decision logs, outcome labels, design check and comparisons, per capture; further replays of the arm-G restart decisions (`govstage2/replays.py`, `run_replays.py`): the views at the recheck's instants and with its lag, the valid-time and end-of-capture audit replays, the thinned and delayed poller, and the check of the labels against traffic and probes |
| `experiments/diagnosis-control-v1/` | follow-up diagnosis control (arm D) and the diagnosis stress test (`run_diagnosis_stress.py`) |
| `analysis/` | every table, number and figure of the paper, recomputed from `results/` (`paper_numbers.py`, `tables.py`, `figures.py`, `stats.py`), the summaries of the replay analyses (`capture_stats.py`, `replay_summary.py`, `by_delay.py`, `stress_summary.py`), and a comparison of rerun outputs with `results/` (`compare_outputs.py`) |
| `results/` | the per-capture outputs (below) |
| `tests/` | unit and end-to-end tests on constructed fixtures |

## Reproduce the paper's numbers (no captures needed)

```
python -m analysis.paper_numbers --check
python -m analysis.figures --out figures          # Figures 2-5; needs matplotlib
```

The first recomputes every number of the paper from `results/` and compares each with the published value; it needs
only the standard library. It includes the check of `analysis.tables`, which covers the captures, the observers, the
principal comparisons and the diagnosis (`python -m analysis.tables --check` runs it alone).

## The captures

The raw captures are archived at Zenodo, [doi:10.5281/zenodo.23756543](https://doi.org/10.5281/zenodo.23756543).
Unpack the archive at the repository root;
it adds

```
phase3/captures/<ID>/                                  15 development capture attempts (I1-001 ... I7-001)
phase3/captures_stage2/<ID>/                           28 follow-up capture attempts (D1-001 ... G4-003, two pilots)
results/evidence-index-pilot-002/accepted_evidence.jsonl,
data/raw/rollout-telemetry/pilot-001/                  the 22 Sep 2026 rollout
```

Each capture holds the collectors' records (`MANIFEST.json` lists every file with its size and SHA-256), the
sources that ran (`sources/`) and the evaluation-only ground truth (`ground_truth/`, never a model input). Local
file paths and the capture host's user name are not included; measured values, timestamps and identifiers are as
recorded, and this repository reproduces every published number from the archive, whose own README describes its
contents. The formats are described in `phase3/CAPTURE_FORMAT.md` and
`phase3/CAPTURE_FORMAT_STAGE2.md`. The analyses read a capture only after conversion, which writes
`<capture>/evidence/` and changes nothing else.

## Rerun the analyses

Python 3.11 or later, `pip install -r requirements.txt`, and the captures unpacked as above. Commands run from the
repository root; every output directory must not exist yet. The runs are deterministic.

**Follow-up stage (the governance adapter and the diagnosis control).**

```
python phase3/convert_stage2.py --capture phase3/captures_stage2/G1-001
python experiments/governance-stage2/run_stage2_adapter.py --capture phase3/captures_stage2/G1-001/evidence \
    --out rerun/adapter/G1-001
python experiments/diagnosis-control-v1/run_diagnosis_control_v1.py --out rerun/diagnosis --captures \
    phase3/captures_stage2/D1-001 phase3/captures_stage2/D1-002 phase3/captures_stage2/D1-003 \
    phase3/captures_stage2/D1-004 phase3/captures_stage2/D1-005 phase3/captures_stage2/D1-006 \
    phase3/captures_stage2/D2-001 phase3/captures_stage2/D2-002 phase3/captures_stage2/D2-003
python -m analysis.compare_outputs adapter rerun/adapter
python -m analysis.compare_outputs diagnosis rerun/diagnosis
```

Convert each capture once; the adapter runs on every included capture (`results/stage2/captures.json`). One core
takes about 2 minutes per arm-D capture and about 45 minutes per arm-G capture for the adapter, and about
2.5 minutes for the diagnosis control on the nine arm-D captures. The adapter also writes the decision logs
(`decision_logs/*.jsonl.gz`, one per observer) that its counts are computed from.

**Replay analyses of the follow-up captures.** `<follow-up>` is the folder holding the converted follow-up
captures (`<capture>/evidence`, for example `phase3/captures_stage2`) and `<development>` the converted development
captures (`phase3/captures`). Outputs go to `results/stage2/analyses/`.

```
python -m analysis.capture_stats                                                         # per_capture_stats.json
python experiments/governance-stage2/run_replays.py --captures-root <follow-up>              # replays/<capture>.json
python experiments/governance-stage2/run_replays.py --captures-root <follow-up> --latency    # latency/<capture>.json
python experiments/governance-stage2/run_replays.py --captures-root <follow-up> --surrogate  # surrogate/<capture>.json
python -m analysis.replay_summary                                                        # replays_summary.json
python -m analysis.by_delay                                                              # by_delay.json
python experiments/diagnosis-control-v1/run_diagnosis_stress.py --captures-root <follow-up> \
    --dev-captures-root <development>                                                    # diagnosis_stress.json
python -m analysis.stress_summary                                                        # diagnosis_stress_summary.json
```

The three `run_replays.py` passes skip a capture whose output exists, so an interrupted run continues where it
stopped; each checks that its replay of the published views reproduces the adapter's counts. One core takes about
1 to 3 minutes per capture for the replays, 1 to 2 minutes for the latency pass, under a minute for the label check
and about 2 minutes for the stress test on 13 captures; the summaries take about a second each.

**Development stage.**

```
python phase3/convert_capture.py --capture phase3/captures/I2-002                  # each of the nine captures below
python experiments/replay-policy-v1/run_replay_policy_v1.py --capture phase3/captures/I2-002   # each but I3-004
python experiments/context-bridge-v1/run_context_bridge_v1.py --capture phase3/captures/I2-002 --output rerun/bridge/I2-002
python experiments/policy-gate-live-v1/run_policy_gate_live.py --output rerun/gate
python experiments/governance-pilot-v0/govpilot/run_dev.py --captures --output rerun/pilot
python -m analysis.compare_outputs bridge rerun/bridge
python -m analysis.compare_outputs gate rerun/gate
python -m analysis.compare_outputs pilot rerun/pilot
```

The development analyses use I1-001, I2-002, I2-003, I3-004, I4-002, I4-003, I6-002, I6-003 and I7-001; the
diagnosis uses the five fault captures I2-002, I3-004, I6-002, I6-003 and I7-001. The replay (`<capture>/replay/`)
is what the gate analysis checks its own reading of each capture against. The diagnosis takes seconds per capture,
the gate analysis about half a minute, and the rollback pilot about an hour.

`analysis.compare_outputs` compares every key and value of a rerun's outputs with `results/` (floats within a
relative 1e-9) and ignores only the recorded interpreter and library versions.

**Tests.** `pip install pytest`, then `python -m pytest tests`. They build their own fixtures; without the archive,
the few that read the 22 Sep rollout or a converted capture are skipped.

## Results

| Path | |
| --- | --- |
| `results/stage2/captures.json` | every follow-up capture attempt: scenario, arm, slot, kind (study attempt or pilot), whether it is included and why not. The reasons come from the runner's validity record in each capture's `capture.json` (inclusion rules 1 and 2: a completed run, observer continuity) and, for arm D, from the diagnosis control (rule 3: the fault's effect and the change confirmed on both observers' inputs) |
| `results/stage2/capture_summaries.json` | per attempt, from its `capture.json`: status, validity, observer continuity, recheck read latency, clock band, fault-control summary |
| `results/stage2/adapter/<ID>.json` | the governance adapter's output per included capture: design check, decisions and their outcome labels per condition, cell and observer, the comparisons' sums, reconstruction checks, measured lags, decision-log line counts |
| `results/stage2/diagnosis/` | the diagnosis control per arm-D capture and its summary |
| `results/development/diagnosis/<ID>.json` | the development diagnosis of the five fault captures |
| `results/development/gate_audit.json`, `rollback_pilot.json` | the development gate analysis and the matched rollback pilot |
| `results/stage2/analyses/per_capture_stats.json` | the principal comparisons per capture and per scenario, with leave-one-capture-out and the comparison without scenario G3; every view's counts by dispatch delay and cutoff |
| `results/stage2/analyses/replays/<ID>.json` | per arm-G capture: the replayed views (two-clock and latest-snapshot gates at the recheck's instants, with the recheck's lag, thinned poller, valid-time replay), their decisions' counts per cell, agreement with the published views, the audit replays and the poll intervals |
| `results/stage2/analyses/latency/<ID>.json`, `surrogate/<ID>.json` | the gate with every poller record available 5 s and 30 s later; the label check (EndpointSlice, server spans, probes) at every execution instant |
| `results/stage2/analyses/replays_summary.json`, `by_delay.json` | the sums and paired comparisons of the replays; every view's posed decisions, executions, unsafe executions and missed opportunities by dispatch delay and cutoff |
| `results/stage2/analyses/diagnosis_stress.json`, `diagnosis_stress_summary.json` | the diagnosis stress test: every (capture, family, delay, cutoff, policy) cell and each capture's Pod-list intervals, and their summary |

These are the outputs the code here writes; for the gate analysis and the pilot, the published files keep the
analysis keys of the tools' `results.json`. All times are host times unless a field says otherwise.

## License

Code: MIT (`LICENSE`). Results in `results/`: CC BY 4.0. Online Boutique belongs to its authors and is not
included.
