# Phase 3 capture format

What the development capture runner (`phase3/run_incident.py`; its exact source is in every capture's `sources/`) writes, and the evidence rows the offline replay reads. Live collection only records. Everything else (delay, loss, correction, ranking) happens offline.

## 1. Pipeline

```
run_incident.py --incident I2   ->  phase3/captures/I2-001/          raw capture (its files are never changed)
convert_capture.py --capture …  ->  phase3/captures/I2-001/evidence/ accepted_evidence.jsonl + side files
replay (offline)                ->  reads evidence/ as model input; reads ground_truth/ only to score
```

Only captures with `COMPLETE.txt` are evaluated. INVALID and FAILED captures are kept, but neither the converter nor the replay checks the marker, so the caller chooses which captures to convert and score. The replay engine (`src/aiops_kg/replay.py`, `experiments/replay-policy-v1/run_replay_policy_v1.py --capture`) reads this layout.

## 2. Capture directory (`phase3/captures/<ID>-<NNN>/`)

| Path | Content |
| --- | --- |
| `COMPLETE.txt`, `INVALID.txt` or `FAILED.txt` | Status, error, file counts and `validity`. `finished` → `COMPLETE.txt`; `invalid` (files present, planned scenario did not happen) → `INVALID.txt`; `incomplete` / `failed` / `interrupted` → `FAILED.txt`. Only COMPLETE captures enter the evaluation; `validity` lists the reasons |
| `MANIFEST.json` | SHA-256 and size of every file, host environment (Python, OS, git HEAD), timeline, evaluation summary, `validity` |
| `capture.json` | Every kubectl command/stream receipt (`command_receipts`, same fields as the 22 Sep rollout capture), `timeline` (host UTC + monotonic ns per schedule boundary), `trigger`, `change`, `fault_target`, `validity`, `namespace`, `cluster_incarnation_id`, `kubectl_base`, `source_sha256`. `change` holds the patch/wait receipts plus the replacement proof: `pre_change_pod_uids` (Ready Pods before the patch, UID → name), `pre_change_other_pod_uids`, `replacement_pods` (Ready, non-terminating Pods listed after a successful rollout whose UID was absent before the patch), `valid` and `invalid_reasons`. Since plan v1.1, `change` also holds `at` and `thread_started_at` / `thread_started_monotonic_ns`. `at` is the plan's `change.at`: `T0`, which is also the meaning of a missing value, or `reference_end` (I7). The two `thread_started` fields say when the change thread began: right after T0, or right after `reference_end`. The plan's `change` dict, with `at` and `settle_seconds`, is also what the converter's configuration row carries. A `reference_end` change adds `change_settle` (`settle_seconds`, `returned`, `valid`, `waited_seconds`, `return_bound_seconds`) and the timeline mark `change_settled`. The probes, the gap and the target block start only at `change_settled`, `settle_seconds` after `change_rollout_returned`. A `change.at` other than `T0` or `reference_end` is refused when the plan loads. `fault_target` holds the Pod name/UID, `selected_by` (`replacement_uid` after a change on the faulted service, else `newest_ready_pod`) and `ready_pod_uids_at_selection`. `namespace_ownership` = `uid`, `owner_token`, `created_receipt_id` (`namespace-create`) and `verified_at` of the namespace this run created (absent if it never got that far). `teardown` = `namespace_owned`, `verification` (`[owned, reason]` from the teardown read-back, or null) and `actions` (the teardown commands issued); `teardown_refused` = the reason when an owned namespace failed that check, so nothing was scaled or deleted. Fault incidents: `observer_server` = the persistent observer (see section 4): Pod, `source_sha256`, `expected_original_source_sha256` and the `original_source_sha256` its ready line reported, `server_token`, `state` (`closed` normally; `failed` or `refused` after a fallback), `lifecycle` (its startup/ready/eof/finished/error records), `exchanges`, `sent_requests`, `received_responses` and `shutdown` (EOF/finished/exit-0 proof, `verified`); `observer_error` exists only if it was not ready, was refused or failed |
| `incident.json` | The plan entry and defaults used, namespace, probe product IDs |
| `manifests/namespace.json`, `manifests/collector.json`, `manifests/applications.json` | The existing rollout-telemetry manifests with only namespace, `aiops-project` label and cluster incarnation rewritten. The Namespace object is written **separately** to `namespace.json`, with the added annotation `aiops.project/owner-token` = `<capture id>:<16 random hex>`; it is created with `kubectl create -f` (fails if the namespace exists), never applied. `collector.json` is the rendered collector manifest **with its Namespace item removed**: exactly the file that `apply-collector` applied |
| `rollout-patch.json` | Copy of `infrastructure/rollout-telemetry/rollout-patch.json` (the change) |
| `sources/` | Exact bytes of every script or inline source sent to the cluster, plus `run_incident.py` and the plan. `fault_observer_server.py` is the observer source sent to the target container, built by `fault_observer_v2.py` (also copied) from `fault_control_remote.py` |
| `context/manifest.json`, `context/observations.jsonl` | Output of `scripts/collect_deployment_history.py`: 80 rounds of Pods, ReplicaSets, Deployments and the Node |
| `raw/<id>.stdout/.stderr` | Raw bytes of each command: `namespace-absent-check`, `namespace-create`, `namespace-read-back`, `apply-collector`, `pods-NNN`, `events-NNN`, `metrics-NNN`, `deploy-before/after-*`, `pods-after`, `events-final`, `change-pods-before`, `change-patch`, `change-wait`, `change-pods-after`, `trace-export`, `collector-logs`, `teardown-verify-namespace`, `teardown-scale` and, with `--delete-namespace`, `teardown-delete-namespace` (the two teardown commands only after a successful `teardown-verify-namespace`) |
| `raw/<stream>.arrivals.jsonl` | One line per streamed output line: `line_index`, `host_received_at`, `collector_available_at`, `host_monotonic_ns`, `line_sha256`. Streams: `client-reference`, `client-target`, `trace-tail`, `logs-<pod UID>` |
| `ground_truth/` | **Evaluation only, never model input.** `ground_truth.json`, `fault_control_evaluation.json`, `probe_rows.jsonl`, `raw/` (probe server, worker, `target-pods-NNN` target selection, `inspect-initial-001` and any one-shot inspect/observe/terminate outputs, and `observer-server.stdout` / `.stderr` / `.arrivals.jsonl`: every line of the persistent observer with its host arrival, same shape as `probe-server.*`) |

Files are written with `open(..., 'x')` and never overwritten. On Windows, text-mode JSONL lines end in CRLF. Hashes always cover the exact bytes; the 22 Sep `observations.jsonl` lines were CRLF as well (checked: 396/396).

## 3. Evidence rows (`evidence/accepted_evidence.jsonl`)

Same row shape and field names as `results/evidence-index-pilot-002/accepted_evidence.jsonl`, validated with `aiops_kg.evidence.Evidence` and `Accepted`:

```
{"available_ns": int, "logical_confirmation_ns": int,
 "record": {"evidence_id", "logical_id", "kind", "subject", "payload", "supports": [], "supersedes": [],
            "source_ref", "source_sha256", "acquired_at"}}
```

- `subject` = canonical JSON `[cluster_incarnation, api_group, Kind, namespace, uid]`. The group is `""` for Pod/Node and `"apps"` for ReplicaSet/Deployment; the namespace is `""` for Node. This is exactly the pilot-002 format.
- `acquired_at` is the host UTC time at which the record reached the capture pipeline.
- `available_ns` = `acquired_at` in ns, which is the **capture-era pipeline acceptance**. It differs from pilot-002, where `available_ns` was the offline import time (about 2.5 h later). The replay engine makes delayed/missing/corrected views by transforming `available_ns` (and adding `supersedes` rows for corrections), never by editing the capture.
- `logical_confirmation_ns` = `available_ns`. The converter leaves `supersedes` empty, and `supports` empty except on the rollout-wait `change_receipt` row, which supports the patch row.

| kind | Read by existing loaders | evidence_id | Observed (source) time in payload | Pipeline-receipt time (`acquired_at`) |
| --- | --- | --- | --- | --- |
| `configuration` (1) | pilot-002 importer | `configuration:<sha>` | — | when `apply-collector` returned |
| `api_observation` | **yes** (policy-gate `load_sightings`, attribution-lag) | `api:<collection_id>/<seq>` | `observed_at` = list response receipt | `available_at` = record write acceptance (monotone) |
| `span_claim` | **yes** (attribution-lag `load_requests`) | `span:<traceId>:<spanId>` | `span.startTimeUnixNano/endTimeUnixNano` (node clock); `collector_processed_at_raw` (collector clock) | host receipt of the identical line in the live `trace-tail` if found (`acquisition_basis: live_tail_line`), else the final `trace-export` receipt (`final_export_file`) |
| `change_receipt` (patch) | no (new) | `change:<capture>:<service>:patch` | patch receipt `request_started_at` / `response_received_at`; `deployment_uid` | patch `collector_available_at` |
| `change_receipt` (rollout wait; only if `change-wait` ran) | no (new) | `change:<capture>:<service>:rollout-wait`, `supports` = the patch row | wait receipt `request_started_at` / `response_received_at` (the rollout-status return), `wait_exit_code` | wait `collector_available_at` |
| `api_event` | no (new) | `event:<uid>:<resourceVersion>` | Event `eventTime/firstTimestamp/lastTimestamp` | first `events-NNN` receipt showing that version |
| `metric_sample` | no (new) | `metric:<snapshot>:<pod uid>` | kubelet `cpu.time`, `memory.time` | `metrics-NNN` receipt |
| `log_line` | no (new) | `log:<pod uid>:<line>` | kubelet timestamp prefix | per-line `collector_available_at` |
| `client_request` | no (new) | `client-reference:<i>` / `client-target:<i>` | client `started_at` / `finished_at` (Pod clock) | per-line `collector_available_at` |

The `configuration` payload holds only what an operator knows at deployment time: `deployment_manifests` (the rendered manifests in `manifests/`, keyed by file name: `namespace.json` with its owner token, a per-run nonce, and `collector.json` without its Namespace item, plus `applications.json`), `incident` = the plan entry reduced to `id`, `change` (the planned change request, e.g. the rollout of a service) and `runnable`, `rollout_patch`, `source_sha256` and `acquisition_semantics`. The fault specification (`fault`: service, offset), `ground_truth`, `label`, `repeat_of` and every other descriptive field of the plan entry are **not** in any evidence row. They are copied unchanged to `evidence/evaluation_only/incident_entry.json` (see the side files below).

The change patch and its rollout-wait outcome are **separate** `change_receipt` rows (converter `phase3-capture-to-evidence-v3`), each acquired at its own receipt, and each carries only receipts received at or before its own `acquired_at`. The rollout-wait row exists only if `change-wait` ran (the patch exited 0), and its payload is the wait receipt plus `wait_exit_code`.

Payloads of `api_observation` and `span_claim` are identical to pilot-002: the original record plus `_source_record_sha256` (exact line or envelope bytes) and `_source_record_hash_semantics`. Spans also carry `resource_attributes`, `span_attributes`, `source_locator`, `trace_export_receipt` and `_fragment_canonical_sha256` = SHA-256 of canonical `{resource, scope, span}`. Phase 3 spans add `acquisition_basis` and `trace_tail_arrival`.

Spans whose trace ID belongs to an evaluator probe (listed in `ground_truth/probe_rows.jsonl`) are **excluded** by default (`--include-probe-traffic` keeps them). The ordinary workload is `client-reference` (60 requests) plus `client-target` (120 requests), and its client root spans are `pilot.ListRecommendations` with `aiops.request.index`. The block of a trace is known from the `client_request` rows.

Side files for the existing loaders:

- `evidence/protocol.json`: `namespace`, `cluster_incarnation_id`, `replacement_service` (the changed service, or null), `request_trigger_index`, `incident_id`.
- `evidence/capture.json`: `command_receipts` holding the change patch renamed `rollout-patch`, which is what `run_policy_gate_audit.patch_receipt()` looks for. I3 has no change, so there is no receipt.
- `evidence/conversion_report.json`: row counts per kind, the SHA-256 of the evidence file and `configuration_incident_keys` (the plan-entry keys kept in the configuration row).
- `evidence/evaluation_only/`: **evaluation only, never a model input.** `incident_entry.json` is the full original plan entry (fault, ground-truth labels, label, repeat_of); `README.txt` states that nothing in the folder is accepted evidence. The replay reads only `accepted_evidence.jsonl`, `protocol.json` and `capture.json` from `evidence/`, so it never reads this folder. To choose the target service, `capture_service` in `src/aiops_kg/replay.py` takes `--service` if given, else the planned change's service from the capture's `incident.json` (`change.service`), else `replacement_service` in `evidence/protocol.json`. The choice never uses `fault.service` or the ground-truth labels, which are evaluator-only. A capture without a planned change (I3) therefore needs an explicit `--service`; without it the replay stops with an error.

The development loaders were written for the 22 Sep rollout (727 spans, 120 roots, two Pod UIDs); the replay engine takes the path, namespace and service from `protocol.json` and derives counts and UIDs from the rows.

## 4. Ground truth (`ground_truth/`, scoring only)

- `ground_truth.json`: planned labels (`root_cause_service`, `change_services`, `fault_present`), observed `trigger`, `change` receipts with the replacement proof, `fault_target` (Pod name/UID, `selected_by`), worker `started`/`finished` records (worker monotonic clock), `worker_exit_confirmed`, host timeline (T0, fault_launch, fault_ack, active_end, worker_exit_confirmed, drain_end, recovery_end), the evaluation summary and `validity`.
- `fault_control_evaluation.json`: the unchanged `evaluate_fault_control` result (`activation_verified`, `latency_effect_established`, `recovery_established`, `fault_control_passed`, per-block medians) plus `deviations_from_fault_control_v2` and `observer_transport` (persistent exchanges, one-shot calls, observer state and error).
- `probe_rows.jsonl`: one row per probe pair, with `block` (`nominal`, `pre_fault`, `active`, `recovery`), sequences, host issue/receive ns and the raw batch (two direct RPCs with their own trace IDs).

Blocks are defined as follows. **nominal** runs from the reference-block end to T0, before any change. For `change.at` = `reference_end` (I7) it runs from `change_settled` to T0, after the change. In both cases it starts at timeline `probe_nominal_start`, the first probe; the reference block itself never has probe traffic. **pre_fault** runs from T0 to F; it is kept but not evaluated. **active** runs from the worker `started` ack to ack + 20 s. An active probe counts only if an alive worker observation *finished* before it and another *started* after it. **recovery** is the 30 s that follow a 5 s drain after exit confirmation.

Observations: from F-6 s to the end of recovery, one persistent observer process in the target's `server` container (fault-control v2, `scripts/fault_observer_v2.py`, over `kubectl exec -i`) answers inspect, or observe while the worker lives, every 1.0 s; the exit check and the final inspect use it too. Each exchange's `start_sequence` / host monotonic ns are taken immediately before its request line is written and `end_sequence` / ns immediately after its response line arrives (`capture.json` `observer_server.exchanges`, with the response's line index and SHA-256 in `observer-server.stdout`). While it is not ready, or after it was refused or failed, observations are one-shot `kubectl exec` calls every 2.5 s with receipt sequences; each observation carries `transport` (`persistent` / `one_shot`).
