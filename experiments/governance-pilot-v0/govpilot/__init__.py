"""Governance pilot adapter v0: the development rollback pilot (one action: roll back the newest change; one record
class: the change record). Research prototype: nothing is executed and no module here claims a decision-quality
result.

Modules:

- ``common``      shared time, hashing and path helpers;
- ``inputs``      immutable input records, the change-record mapping, the guarded decision reader, the delay grid
                  (``perturb``; ``CAPTURE_STREAMS``) and A's binding;
- ``rollout``     R7: kubectl's rollout-status logic with UID/revision binding (state and procedural clauses); the pin;
- ``environment`` the kubectl versions each capture recorded (input dry run only; never a decision input);
- ``mapping``     records -> gate observations and fact stores for each knowledge rule;
- ``views``       the knowledge views (causal views; hindsight views behind ``hindsight=True``);
- ``engine``      the execution model and the per-capture decision logs;
- ``outcomes``    the outcome evaluator (reads ground truth only after every verdict is logged);
- ``checks``      the reconstruction checks and the input abort checks;
- ``fixtures``    synthetic scenarios (records, development-format capture directories, ground truth);
- ``run_dev``     command line: fixtures end to end, the input dry run, and the capture run.
"""

ADAPTER_VERSION = "governance-pilot-v0-dev"
