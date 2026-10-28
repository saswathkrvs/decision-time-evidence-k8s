"""Governance adapter of the follow-up study: the remediation gate's conditions, decided on converted captures.

The conditions (T_p, L_p, T_w, L_w, L-kappa, R, c-hind, T@F600, L@F600), decisions dispatched delta after their
knowledge cutoff, K1 late corrections, the outcome labels (computed after the decision logs are written, never from
the gate rules R1-R7), the per-capture tables, the design check, the reconstruction checks and cross-observer
agreement. Research prototype: nothing is executed.

The development adapter (experiments/governance-pilot-v0/govpilot), src/aiops_kg/policy_gate.py, temporal.py,
fault_control_kill.py and experiments/policy-gate-v1/run_policy_gate_audit.py are imported read-only; new
behaviour lives in subclasses and wrappers here.

Modules:

- ``common``     paths, read-only imports, integer-microsecond time, canonical JSON, streaming gzip logs;
- ``forward``    posing with delta: subclasses of the resolvers and of policy_gate.OperationalView that lift only the
                 "observation <= cutoff" guard;
- ``capture``    the converted capture: decision inputs per observer (guarded reader), requests, spans, the plan,
                 floors, the clock band; the evaluation-side inputs (ground truth, kill receipt) behind a separate call;
- ``mapping2``   observer rows -> gate observations through gate v1's mapping with the creation-ceiling clamp, K1
                 point observations merged per observer, the (R) snapshot store;
- ``conditions`` condition specs, actions A and B, the gate configuration, one evaluation at (cutoff, dispatch);
- ``engine2``    schedules per (observer, stream, delta), posing, abstain-and-wait, (R) consumption, the streaming
                 per-capture-and-observer decision logs and their index;
- ``design``     record transitions, contested decisions, decisions reached by a late correction, measured lags;
- ``labels``     the outcome labels (V1, GT-2-A, V2, V-target, V-floor, GT-2-B, neutral, U), the EndpointSlice
                 cross-check and the clock band;
- ``checks2``    reconstruction checks 1 and 2 (checks 3 and 4 run in ``engine2`` on every evaluation) and
                 cross-observer agreement;
- ``tables``     T1-T4 and the per-capture primary-cell sums;
- ``pipeline``   one capture end to end (decision phase, index, evaluation phase, results.json);
- ``fixtures``   tiny hand-computed fixture captures and the synthetic arm-G capture.
"""

import sys as _sys
from pathlib import Path as _Path

ADAPTER_VERSION = "governance-stage2-adapter-v0.1-dev"

# The read-only code this package imports: src/ (aiops_kg) and Stage 1's adapter (govpilot). Set up here so that any
# submodule may be imported first.
_ROOT = _Path(__file__).resolve().parents[3]
for _path in (_ROOT / "src", _ROOT / "experiments/governance-pilot-v0"):
    if str(_path) not in _sys.path:
        _sys.path.insert(0, str(_path))
