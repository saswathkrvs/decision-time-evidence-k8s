# Stage 2 capture format: watch, live recheck and clock-probe streams

The files that three observer scripts add to a follow-up capture:

- `scripts/kube_proxy_v1.py`: one `kubectl proxy` on loopback;
- `scripts/collect_watch_v1.py`: the watch-based collector, tag `watch-v1` (condition W);
- `scripts/recheck_loop_v1.py`: the live recheck loop, tag `recheck-v1` (condition R).

It also describes the clock-probe file (written with `infrastructure/stage2/smoke/clock_probe.py`) and how the converter (`phase3/convert_stage2.py`) maps these records to evidence rows.

Read it together with `phase3/CAPTURE_FORMAT.md`. That Phase-3 layout and its poller stream (`context/manifest.json`, `context/observations.jsonl`) are unchanged.

## Contents

1. [Files in a capture directory](#1-files-in-a-capture-directory)
2. [Clocks: where every time comes from](#2-clocks-where-every-time-comes-from)
3. [Common conventions and the record envelope](#3-common-conventions-and-the-record-envelope)
4. [Object projection (shared by the watch and the recheck)](#4-object-projection-shared-by-the-watch-and-the-recheck)
5. [`context/watch_events.jsonl`](#5-contextwatch_eventsjsonl)
6. [`context/watch_snapshots.jsonl`: `watch_cache_snapshot`](#6-contextwatch_snapshotsjsonl-watch_cache_snapshot)
7. [`context/watch_manifest.json`](#7-contextwatch_manifestjson)
8. [`context/recheck.jsonl`: `live_recheck`](#8-contextrecheckjsonl-live_recheck)
9. [`context/recheck_manifest.json`](#9-contextrecheck_manifestjson)
10. [Raw archives `context/*_raw.jsonl.gz`](#10-raw-archives-contextraw_jsonlgz)
11. [Clock probes `context/clock_probes.json`](#11-clock-probes-contextclock_probesjson)
12. [The kubectl proxy record](#12-the-kubectl-proxy-record)
13. [Converter mapping to evidence rows](#13-converter-mapping-to-evidence-rows)
14. [Observer continuity (inclusion rule 2)](#14-observer-continuity-inclusion-rule-2)

## 1. Files in a capture directory

| Path (inside `phase3/captures_stage2/<ID>-<NNN>/`) | Written by | Content |
| --- | --- | --- |
| `context/manifest.json`, `context/observations.jsonl` | poller v1 / v1.1 | Unchanged (`phase3/CAPTURE_FORMAT.md` §2) |
| `context/watch_events.jsonl` | `collect_watch_v1.py` | Lists, list objects, watch-stream lifecycle, every watch event, continuity gaps, `collection_end` (§5) |
| `context/watch_snapshots.jsonl` | `collect_watch_v1.py` | Cache snapshots (§6) |
| `context/watch_manifest.json` | `collect_watch_v1.py` | Written at start (`status: collecting`), replaced atomically at the end (§7) |
| `context/watch_raw.jsonl.gz` | `collect_watch_v1.py` | Exact raw bytes of LIST bodies and watch lines (§10; absent with `--no-raw`) |
| `context/recheck.jsonl` | `recheck_loop_v1.py` | One `live_recheck` record per scheduled tick, then `collection_end` (§8) |
| `context/recheck_manifest.json` | `recheck_loop_v1.py` | As the watch manifest (§9) |
| `context/recheck_raw.jsonl.gz` | `recheck_loop_v1.py` | Exact raw response bodies (§10; absent with `--no-raw`) |
| `context/clock_probes.json` | the runner, with `infrastructure/stage2/smoke/clock_probe.py` | §11 |

**Ordering constraint with the poller.** `scripts/collect_deployment_history.py` refuses an output directory that already exists ("Output directory already exists"). The two other observers create `context/` if it is missing, so the runner (`phase3/run_stage2.py`, in every capture's `sources/`) starts the poller first and the watch and the recheck only after `context/manifest.json` exists. Their file names are fixed, and `--output-dir` chooses the directory.

**Process control.**

- One shared proxy: `kube_proxy_v1.KubeProxy`, started by the runner. Its URL goes to both observers with `--proxy-url`, and its record is saved as `context/kube_proxy.json` (§12).
- Each observer gets a `--stop-file` that does not exist at start, e.g. `<capture>/control/watch.stop` and `<capture>/control/recheck.stop`. The runner creates the file to stop the observer. The observer then finishes its records and its manifest within about 0.2 s plus the current request.
- Each observer's stdout and stderr are kept, like the poller's `context.stdout` / `context.stderr`.
- On Windows, `Popen.terminate()` is `TerminateProcess`: no cleanup runs, so the manifest would stay at `collecting`. Use the stop file. SIGTERM (POSIX) and SIGBREAK (Windows, `CTRL_BREAK_EVENT` to a process started with `CREATE_NEW_PROCESS_GROUP`) are also graceful stops. Ctrl-C ends with `status: interrupted`.

## 2. Clocks: where every time comes from

| Clock | Read by | Fields | Notes |
| --- | --- | --- | --- |
| **Host wall clock, UTC** | `time.time_ns()` in the observer process on the Windows host | every `*_at` (ISO-8601, nine fractional digits, `Z`) and `*_at_ns` (int, ns since 1970-01-01T00:00:00Z) | Adjustable: it can step under w32time. Python ≥ 3.13 on Windows reads `GetSystemTimePreciseAsFileTime` (sub-µs). The manifests record the interpreter and `time.get_clock_info('time')`. The ISO strings are accepted by `aiops_kg.evidence.timestamp_ns` |
| **Host monotonic clock** | `time.monotonic_ns()` | every `*_monotonic_ns` | `QueryPerformanceCounter` on Windows, `CLOCK_MONOTONIC` on Linux. It is system-wide within one boot, so it is comparable between the observer processes and with the runner's `host_monotonic_ns`, but not across reboots. Use it for every interval: gaps, latencies, tick lateness and the §10 windows |
| **Kubelet (node) clock** | inside `resource_data` / `objects` | Pod `status.conditions[].lastTransitionTime`, container `state.running.startedAt`, `lastState.terminated.startedAt` / `finishedAt`, … | RFC 3339, whole seconds. It is the clock of the kind node container, inside Docker Desktop's VM, and is not calibrated against the host. The clock probes (§11) bound the offset; no timestamp is corrected |
| **API-server / controller clock** | inside objects | `metadata.creationTimestamp`, `metadata.deletionTimestamp`, Deployment and ReplicaSet `conditions[].lastUpdateTime` / `lastTransitionTime`, PDB `conditions[]` | Same single-node VM as the kubelet in this kind cluster |
| **resourceVersion** | API server (etcd revision) | `resource_version`, `list_resource_version`, `resourceVersion`, `last_resource_version` | Opaque by API contract. It is used only for equality and as the watch start point, never as a time |
| **Planned instants** | derived | recheck `scheduled_*` | `scheduled_monotonic_ns` = start + k × interval, exact. `scheduled_at(_ns)` = start wall time + the same monotonic offset (no wall reading is taken for a planned instant) |

What each named time means. All are host times; "the collector" is the observer process.

| Name | Meaning |
| --- | --- |
| `received_*` | Watch event and invalid line: taken immediately after the socket read that delivered the line's last byte (its `\n`). Lines completed by one read share it. It is measured after `kubectl proxy`, so any delay the proxy adds is included |
| `request_started_*` | Just before the request bytes were sent. For a recheck GET: the first attempt (§8) |
| `response_head_received_*` | Watch request: after the status line and headers were read |
| `response_received_*` | After the last byte of a response body was read (LIST; recheck GET). For a recheck tick: the last attempted GET's (= x_R, the instant at which a recheck verdict can act) |
| `accepted_*` | When the collector accepted the record: after parsing and projection, under the writer lock, immediately before the line was written. File order equals `accepted` order |
| `observed_at` | The poller envelope's observation time (ISO only): `received_at` for events, `response_received_at` for lists, list objects and recheck ticks, `snapshot_at` for snapshots, `gap_to_at` for closed gaps, the detection or head time for lifecycle records, `stop_requested_at` for final records, null for missed ticks |
| `available_at`, `available_at_ns` | The poller's monotone acceptance (`scripts/collect_deployment_history.py` `emit`): max(`accepted_at_ns`, the observed ns, the previous record's `available_at_ns`) within one collection. `clock_adjusted` is true when it differs from `accepted_at_ns`, i.e. the wall clock stepped back |
| `detected_*` | When the collector noticed a stream break (or a thread error) |
| `gap_from_*`, `gap_to_*` | Bounds of a continuity gap (§5.1) |
| `snapshot_*` | When the cache was materialised, under the writer lock |
| `stop_requested_*` | When the collector saw its stop condition |

## 3. Common conventions and the record envelope

- **Encoding.** JSON Lines: one object per line, keys sorted, compact separators (`,` and `:`), ASCII only (anything else is `\u`-escaped), and each line ends with **LF on every OS**. The files are written in binary mode. This differs from the Phase-3 poller, whose lines are CRLF on Windows. Each line is flushed when written. Data files are created with mode `x` and never overwritten.
- **Time triple.** `<name>_at` (ISO string), `<name>_at_ns` (int) and `<name>_monotonic_ns` (int) come from one reading; all three are null when the time does not exist.
- **Names.** `resource` is the plural used in API paths (`pods`, `deployments`, `replicasets`, `endpointslices`, `poddisruptionbudgets`); `kind` is the Kind (`Pod`, …).
- **Envelope.** Every record in `watch_events.jsonl`, `watch_snapshots.jsonl` and `recheck.jsonl` carries:

| Field | Type | Meaning |
| --- | --- | --- |
| `record_type` | string | See §5, §6, §8 |
| `sequence` | int ≥ 1 | One counter per collection across **all** its `.jsonl` files. Within a file, lines are in sequence order; merged by `sequence`, the two watch files give the collector's exact write order |
| `record_id` | string | `<collection_id>/<sequence>` (as the poller's) |
| `collection_id` | string | UUID4; equals the manifest's |
| `collector` | string | `watch-v1` or `recheck-v1` |
| `observed_at` | string \| null | §2 |
| `available_at`, `available_at_ns`, `clock_adjusted` | string, int, bool | §2 |
| `accepted_at`, `accepted_at_ns`, `accepted_monotonic_ns` | string, int, int | §2 |

## 4. Object projection (shared by the watch and the recheck)

One function, `collect_watch_v1.project_object(item, resource, namespace)`, produces every `resource_data` and `objects` entry. It imports the poller (`scripts/collect_deployment_history.py`, which has no import side effects) read-only.

| Kind | Kept |
| --- | --- |
| Pod | Exactly poller v1's `project_resource` (lines 88–126): `apiVersion`, `kind`; `metadata` = `uid`, `name`, `namespace`, `resourceVersion`, `generation`, `creationTimestamp`, `deletionTimestamp`, `labels`, `ownerReferences`, and only the `deployment.kubernetes.io/revision` annotation; `spec.nodeName`, `spec.containers[]` and `spec.initContainers[]` (`name`, `image`); `status.phase`, `status.startTime`; `status.containerStatuses[]` (`name`, `image`, `imageID`, `containerID`, `ready`, `restartCount`). **Added:** `status.conditions` (verbatim, when present) and each container status's `state` and `lastState` (verbatim, when present) |
| ReplicaSet, Deployment | Poller v1 (`spec.replicas`, `selector`, template labels and containers; `status.observedGeneration`, `replicas`, `updatedReplicas`, `readyReplicas`, `availableReplicas`, `unavailableReplicas`). **Added:** `status.conditions` |
| EndpointSlice (new) | v1's metadata projection (re-implemented as `_metadata`, the same rules), `addressType`, `endpoints[]` (`addresses`, `conditions`, `hostname`, `nodeName`, `targetRef`, `zone`), `ports` |
| PodDisruptionBudget (new) | v1's metadata projection, `spec` (`minAvailable`, `maxUnavailable`, `selector`, `unhealthyPodEvictionPolicy`), `status` (`observedGeneration`, `disruptionsAllowed`, `currentHealthy`, `desiredHealthy`, `expectedPods`, `disruptedPods`, `conditions`) |

- **Raw LIST items have no `kind` or `apiVersion`.** kubectl adds them only when it prints `-o json`; the API server's list items lack them. Before projecting, the collector sets them from the list (`PodList` gives `Pod`, and the list's `apiVersion`), so a projected object has the shape of poller v1's output. Watch-event objects carry both fields from the server.
- **Validation** is poller v1's: nonempty `uid`, `name` and `resourceVersion`; the namespace must match; owner references need `kind`, `name` and `uid`; a list must be complete (no `continue`) and free of duplicate UIDs. A failure makes the LIST fail (recorded and retried), breaks the watch stream (`invalid_watch_line`, then a gap and a relist), or gives a recheck GET the outcome `invalid_body`.
- **Alignment with poller v1.1** (`scripts/collect_deployment_history_v1_1.py`). It extends v1 by the same fields, and both projections give identical objects for Pods (with and without conditions and container statuses), ReplicaSets and Deployments. The poller and the watch therefore differ only in timing.

## 5. `context/watch_events.jsonl`

Per kind, the collector writes:

1. `continuity_gap` (`history_before_collection_unknown`), then `watch_list`, then one `watch_list_object` per object (a snapshot follows, in the other file).
2. `watch_stream_open`, then `api_watch_event`* (or `invalid_watch_line`), then `watch_stream_end`.
3. After a break: `continuity_gap` (`watch_interrupted`) **immediately followed by** the relist `watch_list` and its objects, then a new stream, and so on.
4. At the stop: `watch_stream_end` (`stopped`) for each open stream, the closing gaps of every kind, then one `collection_end`.

Failed LIST attempts are `watch_list` records with `ok: false`. A relist after a healthy stream (one that delivered a line or stayed open for 5 s) starts at once. A retry after a failed LIST, or a relist after an unhealthy stream, waits 0.25, 0.5, 1 and 2 s, then 2 s each time. Kinds run in parallel threads, so their records interleave.

**Defaults.**

- Kinds: all five, in the capture namespace, with **no label selector**, as the poller lists the whole namespace. `--label-selector RESOURCE=SELECTOR` is optional.
- LIST: `GET /api/v1/namespaces/<ns>/pods` (and the `apps/v1`, `discovery.k8s.io/v1` and `policy/v1` equivalents) with no `resourceVersion`, i.e. a consistent read.
- WATCH: `GET <same path>?watch=1&resourceVersion=<list rv>&allowWatchBookmarks=true&timeoutSeconds=1800`. The server-side timeout is longer than a capture, so that a normal timeout causes no relist inside one.
- Each request is HTTP/1.1 with `Connection: close` and `Accept: application/json`, over a raw loopback socket. A 0.2 s read timeout lets the thread check its stop flag. `http.client` was not usable here: its socket file refuses all reads after one timeout.

### 5.1 `continuity_gap`

| Field | Type | Meaning |
| --- | --- | --- |
| `resource`, `kind` | string | |
| `reason` | string | `history_before_collection_unknown` (before the kind's first successful list), `watch_interrupted` (a stream broke) or `history_after_collection_unknown` (after the stop) |
| `cause` | string \| null | `watch_interrupted` only: `eof_clean` (terminating chunk, e.g. the server timeout), `eof_unterminated` (connection closed mid-stream), `socket_error`, `bad_framing` (invalid chunking or a line over 16 MiB), `invalid_event` (unparseable line, unknown type, projection refused), `error_event` (an `ERROR` event, e.g. 410 Expired/Gone), `watch_http_status` (non-200 watch response, e.g. HTTP 410), `watch_request_failed` (connect or head failure) or `collector_error` (the kind's thread raised) |
| `gap_from_*` | time triple \| nulls | `watch_interrupted`: the `received_*` of the broken stream's **last good line**, meaning an `ADDED`, `MODIFIED`, `DELETED` or `BOOKMARK` event. Without one, the `response_received_*` of the list the stream started from. An `ERROR` or invalid line is not evidence of continuity. `history_after_collection_unknown`: the stop request if the kind's watch was open then; the open gap's `gap_from` if the kind was in a gap; null if the kind was never listed. `history_before_collection_unknown`: null |
| `gap_to_*` | time triple \| nulls | The `response_received_*` of the successful (re)list that ended the gap; null if the gap was still open at the stop, and for `history_after_collection_unknown` |
| `duration_seconds` | float \| null | (`gap_to_monotonic_ns` − `gap_from_monotonic_ns`) / 1e9 |
| `detected_*` | time triple | `watch_interrupted` only: when the break was noticed. The less conservative gap would be [`detected`, `gap_to`] |
| `open_at_stop` | bool | True for a `watch_interrupted` gap without a successful relist before the stop, and for a `history_before_collection_unknown` of a kind never listed |
| `failed_list_attempts` | int | Failed (re)list attempts inside this gap |
| `stream_id` | string | `watch_interrupted`: the broken stream (`<resource>/<n>`) |
| `relist_attempt` | int | Closed `watch_interrupted` gaps: the `list_attempt` of the closing relist. Its `watch_list` record is the **next** sequence and points back through `closes_gap_sequence` |
| `error`, `status_object`, `error_code`, `error_reason`, `http_status`, `line_index`, `line_sha256` | various | Present according to the cause: the error text; the Status object of an `ERROR` event or a non-200 response; its `code` and `reason`; the watch response's HTTP status; the invalid line's index and hash |
| `last_line_received_at` | string \| null | `history_after_collection_unknown` only: receipt of the kind's last line of any type |

### 5.2 `watch_list`

| Field | Type | Meaning |
| --- | --- | --- |
| `resource`, `kind`, `path` | string | `path` = request target with query |
| `list_attempt` | int | 1, 2, … per kind; counts every attempt, successful or not |
| `relist` | bool | False only for attempts before the kind's first success |
| `ok` | bool | HTTP 200 and a valid, complete list |
| `closes_gap_sequence` | int \| null | Sequence of the `continuity_gap` written just before; null when `ok` is false |
| `http_status`, `error` | int \| null, string \| null | |
| `body_bytes`, `body_sha256` | int, string | Exact response body (SHA-256 of b'' when there is no body) |
| `request_started_*`, `response_received_*` | time triples | |
| `list_resource_version`, `object_count`, `uids` | string, int, [string] | `ok` only; `uids` sorted |
| `cache_change` | object \| null | Successful relists only: `absent_uids` (in the cache before, missing now: deleted, or no longer selected, during the gap, time unknown), `absence_semantics`, `new_uids`, `changed_uids` (`resourceVersion` differs), `unchanged_count` |
| `status_object` | object \| null | `ok: false` only: a Status body, if any |

### 5.3 `watch_list_object`

One per object of a successful list, right after its `watch_list`: `resource`, `kind`, `list_sequence` (the list's `sequence`), `uid`, `name`, `namespace`, `resource_version`, `resource_data` (§4), `observation_basis: "watch_list"`, `response_received_*` (the list's), and `observed_at` = the list's response receipt.

### 5.4 `watch_stream_open`

`resource`, `kind`, `stream_id` (`<resource>/<n>`, n = 1, 2, … per kind), `path`, `resource_version` (the watch start = the list's RV), `ok`, `http_status`, `content_type`, `transfer_encoding`, `error`, `status_object` (non-200 only), `body_bytes` and `body_sha256` (non-200 only), `request_started_*`, `response_head_received_*` (nulls if no head arrived).

### 5.5 `api_watch_event`

| Field | Type | Meaning |
| --- | --- | --- |
| `resource`, `kind` | string | The watched kind |
| `event_type` | string | `ADDED`, `MODIFIED`, `DELETED`, `BOOKMARK` or `ERROR` |
| `object_kind` | string \| null | The event object's `kind` (`Status` for `ERROR`) |
| `stream_id`, `line_index` | string, int | `line_index` = 1-based line number within the stream (blank lines count) |
| `line_bytes`, `line_sha256` | int, string | Exact line bytes after de-chunking, **including the final `\n`** |
| `line_chunks` | int | Number of HTTP chunks the line's bytes came from (1 = one chunk; ≥ 2 = an event split across chunks) |
| `received_*` | time triple | §2 |
| `name`, `namespace`, `uid`, `resource_version` | string \| null | From the projected object; `BOOKMARK`: `resource_version` = the bookmark's, the others null; `ERROR`: all null |
| `resource_data` | object \| null | Projected object (§4) for `ADDED`, `MODIFIED`, `DELETED` (the object's final state); null otherwise |
| `status_object` | object \| null | `ERROR` only: the Status object verbatim |
| `bookmark_annotations` | object \| null | `BOOKMARK` only (present only on bookmarks) |
| `cache_effect` | string | `insert`, `update`, `delete`, `delete_absent` (`DELETED` of an object not in the cache) or `none` |
| `cache_previous_resource_version` | string \| null | The cache's version of the object before this event |
| `observation_basis` | string | `watch_event` |

The cache is a map from uid to the latest projected object of all five kinds. `ADDED` and `MODIFIED` insert or replace; `DELETED` removes. `BOOKMARK` and `ERROR` do not change it. An `ERROR` event ends the stream: the collector closes it at once and relists.

### 5.6 Other records

| `record_type` | Fields |
| --- | --- |
| `invalid_watch_line` | `resource`, `kind`, `stream_id`, `line_index`, `line_bytes`, `line_sha256`, `line_chunks`, `received_*`, `error`. The stream then ends with `invalid_event` |
| `watch_stream_end` | `resource`, `kind`, `stream_id`, `cause` (`stopped` or one of the §5.1 stream causes), `lines`, `events`, `blank_lines`, `bytes` (body bytes read, chunk framing included), `http_chunks`, `partial_line_bytes` (an unterminated line at the end), `error`, `last_line_received_at`, `detected_*`. A `stopped` stream opens no gap |
| `collector_error` | `resource`, `error`, `traceback` (last 4,000 characters), `detected_*`. The kind's state becomes `failed`; a gap opens if it was open |
| `collection_end` | `reason` (= the manifest's `stop_reason`), `events_by_type`, `snapshots_by_trigger`, `gaps` (number of `watch_interrupted` gaps), `resources_never_listed`, `thread_errors`, `unjoined_threads`, `stop_requested_*`. Always the last line |

## 6. `context/watch_snapshots.jsonl`: `watch_cache_snapshot`

| Field | Type | Meaning |
| --- | --- | --- |
| `snapshot_index` | int | 1, 2, … |
| `trigger` | string | `list`: after every successful (re)list. `event`: after every `ADDED`, `MODIFIED` or `DELETED`; `BOOKMARK` and `ERROR` change nothing and trigger nothing. `periodic`: every `--snapshot-interval-seconds` (default 1.0 s) on the schedule start + k × interval (monotonic), written only while at least one kind is `open`. Skipped ticks are counted in the manifest |
| `trigger_sequence` | int \| null | Sequence of the `watch_list` or `api_watch_event` that caused it; null for `periodic` |
| `snapshot_*` | time triple | When the cache was materialised; `observed_at` = `snapshot_at` |
| `namespace` | string | |
| `resources` | object | For each resource: `state` (`not_started`, `open`, `gap` or `failed`), `since_at` (`open`: the list receipt that began the current continuous interval; `gap` / `failed`: the gap's start), `last_resource_version` (last list, event or bookmark RV) |
| `object_count`, `objects` | int, list | The whole cache: one `{kind, name, uid, resourceVersion, ref}` per object, sorted by (`kind`, `uid`, `resourceVersion`) |
| `objects_sha256` | string | SHA-256 of the compact JSON `[[kind, uid, resourceVersion], …]` in that order. Equal hashes mean the same cache content |
| `observation_basis` | string | `watch_cache_snapshot` |

- **References, not copies.** `ref` is the `sequence` of the record in `watch_events.jsonl` that holds the full projected object at exactly that `resourceVersion`: a `watch_list_object`, or an `api_watch_event` with `resource_data`. A `ref` is always smaller than the snapshot's own `sequence`. To resolve, index `watch_events.jsonl` by `sequence`.
- **Why references.** They keep the size bounded. A full projected Pod is about 1.5–2 KB. With about 20 objects in an arm-G namespace and roughly 1,000 periodic plus a few hundred event snapshots per capture, full copies would come to about 30–40 MB, against about 5–8 MB with references.
- **Usability rule for consumers.** A snapshot's `resources[K].state` is only the collector's knowledge at that moment. A break is detected after it happened, and its gap is backdated to the last good line, so snapshots taken between that line and the detection still say `open`. The `continuity_gap` records are authoritative. A snapshot taken at t is usable for kind K only if t is:
  - not inside any K `watch_interrupted` gap (`gap_from` < t < `gap_to`, with a null `gap_to` meaning until the end);
  - not before the K `history_before_collection_unknown` `gap_to`;
  - not after the K `history_after_collection_unknown` `gap_from`.
- **Stale and absent objects.** Objects of a kind in a gap stay in the cache as their last known state. An object's absence from a snapshot means it was deleted (by an event) or was absent at the last relist; it never establishes the deletion time.

## 7. `context/watch_manifest.json`

| Field | Meaning |
| --- | --- |
| `schema_version` (1), `collector` (`watch-v1`), `collection_id`, `format` | |
| `status` | `collecting` (written at start), `finished` (normal stop, every kind listed at least once, no thread error, every thread joined), `partial` or `interrupted` (Ctrl-C). Exit code 0 only for `finished`; 1 for a setup failure (options, existing outputs, proxy not started); 2 otherwise |
| `stop_reason` | `seconds`, `stop_file`, `stop_event` (programmatic), `signal:SIGTERM`, `signal:SIGBREAK`, `interrupted`, `proxy_exited` (own proxy only) or `all_watchers_ended` |
| `namespace`, `resources`, `kinds`, `label_selectors` | Selectors: null = none |
| `per_resource` | For each resource: `kind`, `label_selector`, `path`, `first_list_received_at`, `first_event_received_at`, `last_event_received_at`, `events`, `final_state`, `max_gap_seconds` (closed `watch_interrupted` gaps only) |
| `proxy` | `base_url`, `started_by_collector`, `record` (§12; with `--start-proxy` only) |
| `options` | `seconds`, `stop_file`, `snapshot_interval_seconds`, `watch_timeout_seconds`, `request_timeout_seconds`, `poll_seconds`, `raw_archive` |
| `started_at`, `started_monotonic_ns`, `stop_requested_at`, `finished_at`, `elapsed_seconds` | `elapsed_seconds` is monotonic |
| `first_event_received_at`, `last_event_received_at`, `first_snapshot_at`, `last_snapshot_at` | Over all kinds |
| `counts` | `records`; `lines_by_file`; `events_by_type`; `events_by_resource`; `snapshots_by_trigger`; `raw_archive_entries`; `initial_lists`; `relists`; `list_failures`; `watch_streams_opened` / `_refused` / `_ended`; `gaps_opened`; `invalid_lines`; `periodic_snapshots_skipped_no_open_watch`; `periodic_ticks_skipped_late`; `writes_after_close`. Zero counts may be absent |
| `continuity_gaps` | Every `watch_interrupted` gap: `resource`, `cause`, `gap_from_at`, `gap_to_at`, `duration_seconds`, `sequence` and, if still open at the stop, `open_at_stop: true` |
| `thread_errors`, `unjoined_threads` | |
| `files` | For `watch_events.jsonl`, `watch_snapshots.jsonl` and `watch_raw.jsonl.gz`: `sha256`, `bytes`, `lines` (null for `.gz`) |
| `sources` | SHA-256 of `collect_watch_v1.py`, `kube_proxy_v1.py` and the read-only poller v1 |
| `host` | `python`, `platform`, `clock` (`time.get_clock_info` for `time` and `monotonic`) |
| `temporal_semantics` | One-sentence statement of the informer trust model |

## 8. `context/recheck.jsonl`: `live_recheck`

**Schedule.**

- Tick k is scheduled at start + k × `--interval-seconds` (default 1.0) on the monotonic clock, k = 0, 1, 2, ….
- The loop waits until the instant, checking for a stop every 50 ms. It then runs **five GETs in this order: Deployments, ReplicaSets, Pods, EndpointSlices, PodDisruptionBudgets**, one after another, on one keep-alive HTTP/1.1 connection to the proxy.
- After a tick, each scheduled instant that passed while the tick was in flight becomes a **missed** tick with its own record. Exceptions: no missed tick is recorded once a stop has been requested, or at or after the `--seconds` deadline.
- The loop never interprets a response.

**Selectors (server-side, defaults; `--label-selector RESOURCE=SELECTOR` overrides):**

| Resource | Selector |
| --- | --- |
| Deployments, ReplicaSets, Pods, PodDisruptionBudgets | `app in (recommendationservice,productcatalogservice)`. The manifests put `app` on the Deployments, the Pod templates (so on ReplicaSets and Pods) and the PDBs (`infrastructure/stage2/applications_multi.json`) |
| EndpointSlices | `kubernetes.io/service-name in (recommendationservice,productcatalogservice)` (set by the EndpointSlice controller) |

`--services` changes the two names.

**Tick record:**

| Field | Type | Meaning |
| --- | --- | --- |
| `tick` | int | 0, 1, 2, …, consecutive: one record per scheduled instant |
| `status`, `answered` | string, bool | `answered` (all five GETs: HTTP 200 and a valid complete list), `failed` (attempted, some GET not ok) or `missed` (not attempted: the previous tick was in flight) |
| `missed_reason`, `blocking_tick` | string \| null, int \| null | Missed ticks only: `previous_tick_in_flight` and the tick that was in flight |
| `scheduled_*` | time triple | The planned instant (§2) |
| `request_started_*` | time triple \| nulls | Start of the first GET's first attempt. It is never later than any of the five reads |
| `response_received_*` | time triple \| nulls | Receipt of the last attempted GET's body: **x_R** |
| `observed_at` | string \| null | = `response_received_at`; null when missed |
| `read_latency_ms`, `start_lateness_ms` | float \| null | (`response_received` − `request_started`) and (`request_started` − `scheduled`), monotonic |
| `gets` | list | Five entries in GET order (empty when missed), below |
| `object_count`, `objects` | int, list | Projected objects (§4) of **every GET whose outcome is `ok`**, sorted by Pod, Deployment, ReplicaSet, EndpointSlice, PodDisruptionBudget, then `name`, then `uid`. Complete only when `answered` |
| `namespace`, `services` | string, list | |
| `observation_basis` | string | `live_recheck` |

**Per GET (`gets[]`):**

| Field | Meaning |
| --- | --- |
| `resource`, `kind`, `path` | `path` = request target with the selector |
| `attempts` | 0 (skipped), 1, or 2: one retry on a fresh connection after a stale keep-alive failure (`RemoteDisconnected`, `BadStatusLine`, connection reset, aborted or broken pipe) |
| `connection_reused` | Whether the final attempt used a kept-alive connection |
| `outcome` | `ok`, `http_error`, `transport_error` (connect, timeout or reset; the remaining GETs of the tick are then `skipped_after_transport_error`), `invalid_body` or `skipped_after_transport_error` |
| `http_status`, `error` | |
| `body_bytes`, `body_sha256` | The final attempt's exact response body; null if none |
| `list_resource_version`, `object_count`, `uids` | `ok` only (`uids` sorted) |
| `request_started_*` | The first attempt's start |
| `response_received_*` | The final attempt's receipt |

**How condition (R) uses it.** For a dispatch instant x:

1. Take the first record with `status: answered` and `request_started_at` ≥ x. Compare on the host wall clock, or on `request_started_monotonic_ns` if x is expressed on that clock.
2. Compute the verdict on its `objects`.
3. An ALLOW executes at its `response_received_at` (x_R). An ABSTAIN waits for the next answered record.

The objects were read between `request_started` and `response_received`, in GET order; each GET's own interval is in `gets[]`.

`collection_end` closes the file: `reason`, `ticks` (counts by status), `stop_requested_*`.

## 9. `context/recheck_manifest.json`

`schema_version`, `collector` (`recheck-v1`), `collection_id`, `status` (as §7; `finished` also needs at least one answered tick), `stop_reason` (as §7 without `all_watchers_ended`), `namespace`, `services`, `resources` (GET order), `label_selectors`, `targets` (exact request targets), `interval_seconds`, `request_timeout_seconds` (socket timeout of each GET), `proxy`, `options`, `started_at`, `started_monotonic_ns`, `stop_requested_at`, `finished_at`, `elapsed_seconds`, **`ticks`** (`total`, `answered`, `failed`, `missed`, `answered_fraction` = answered / total over the whole run), `first_tick_scheduled_at`, `last_tick_scheduled_at`, `first_answered_response_at`, `last_answered_response_at`, `read_latency_ms` and `start_lateness_ms` (`n`, `min`, `median`, `max` over attempted ticks), `http_status_counts` (`"None"` = transport error), `get_outcomes`, `records`, `raw_archive_entries`, `files` (`recheck.jsonl`, `recheck_raw.jsonl.gz`), `sources`, `host`, `semantics`, `format`.

## 10. Raw archives `context/*_raw.jsonl.gz`

- **Format.** gzip (no file name, mtime 0) of JSON lines `{kind, sequence, sha256, bytes, encoding, data, …}`. `sequence` names the record that carries the bytes' SHA-256.
- **`kind` values.** `list_body` (a `watch_list`), `event_line` (an `api_watch_event`), `invalid_line`, `watch_error_body` (a non-200 `watch_stream_open`) and `recheck_body` (a `live_recheck`, with `tick` and `resource`). The watch entries also carry `resource`.
- **Exact bytes.** `data.encode('utf-8')` when `encoding` is `utf-8` (the bytes were strictly UTF-8; JSON string escaping round-trips exactly), or `base64.b64decode(data)` when it is `base64`. `collect_watch_v1.read_raw_archive(path)` returns `[(entry, bytes)]`, against which every SHA-256 can be checked.
- **Flushing.** The watch flushes the gzip stream (`Z_SYNC_FLUSH`) every snapshot interval, the recheck after every tick. A hard kill loses at most the unflushed tail; the `.jsonl` files, flushed per line, are the primary record.
- **Expected size: an estimate.** The recheck keeps every body, about 80 KB raw per tick with `managedFields`, so about 10 MB gzipped per 1,000 ticks. The watch archive is small.

## 11. Clock probes `context/clock_probes.json`

Every capture takes ten paired readings of the node clock at its start and at its end, bracketed by host times. One probe set is one JSON document as `infrastructure/stage2/smoke/clock_probe.py` writes it.

**Capture file.** `context/clock_probes.json` = a JSON **array of two such documents**, label `start` then label `end`. The runner writes it with `clock_probe.probe()` and `clock_probe.summarise()`, with the script's own serialisation: indent 2, sorted keys, LF, mode `x`. `src/aiops_kg/fault_control_kill.clock_readings` reads such an array, a single document, and also an older spelling (below).

**Document fields:**

| Field | Meaning |
| --- | --- |
| `capture_id`, `test`, `script`, `script_sha256`, `written_by` and the other top-level strings | Identification |
| `label` | `start` or `end` (a free label in the script) |
| `started_at` | Host wall clock, ISO with **microseconds** (truncated; `smoke_common.iso_from_ns`) |
| `host_clock` | `time.get_clock_info('time')` (`implementation`, `resolution_seconds`, `monotonic`, `adjustable`) plus `python` and `platform` |
| `node`, `command` | The node container (`aiops-context-pilot-control-plane`) and the argv, `<docker prefix> exec <node> date +%s.%N` |
| `pairs` | One entry per reading (below) |
| `summary` | Below |
| `versions` | Optional: kubectl client and server versions and the node image, against the pins |

**Per pair (`pairs[]`):**

| Field | Clock | Meaning |
| --- | --- | --- |
| `index` | — | 1 … n |
| `send_ns`, `send_at` | host wall (`time.time_ns`); ISO in µs | Just before `docker exec` was started |
| `receive_ns`, `receive_at` | host wall | Just after it returned |
| `round_trip_seconds` | host monotonic | Receive − send |
| `exit_code`, `node_output`, `stderr`, `error` | — | A non-null `error` makes the pair unusable |
| `node_ns`, `node_at` | **node clock** (`date +%s.%N` in the node container) | Usable pairs only |
| `offset_low_ns`, `offset_high_ns` (and `_seconds`) | derived | θ = host − node lies in [`send_ns` − `node_ns`, `receive_ns` − `node_ns`] |

**Summary (`summary`).**

- `pairs`, `pairs_ok`, `offset_definition`.
- `intersection_seconds`: [max low, min high], or null with `intersection_note` when the intervals do not overlap.
- `union_seconds`, `midpoint_median_seconds`.
- `widest_abs_bound_seconds`: the largest of \|low\| and \|high\| over the usable pairs.
- `clock_band_candidate_seconds` = 1 s + `widest_abs_bound_seconds`: the clock band b_c. `clock_band_rule` states the rule.
- `round_trip_seconds` (`min`, `median`, `max`).
- `verdict`, only when no pair is usable.

**Differences from the other files of this document.**

- Per-pair times are `<name>_ns` and `<name>_at` only, with no monotonic reading per instant.
- The ISO strings have six fractional digits.
- The names are `send_ns`, `receive_ns` and `node_ns`.

**Older spelling.** An earlier version used `{"sets": [{"phase", "probes": [{"host_send_at_ns", "node_time_ns", "host_receive_at_ns", "offset_lower_ns", "offset_upper_ns", …}]}]}`. The captures use `clock_probe.py`'s format above; `fault_control_kill.clock_readings` also reads the older one.

## 12. The kubectl proxy record

`kube_proxy_v1.KubeProxy.record`. It appears in an observer's manifest (`proxy.record`) when that observer started its own proxy. The runner saves its shared proxy's record as `context/kube_proxy.json`, and `python scripts/kube_proxy_v1.py --record FILE` writes the same object. The times here are nested objects `{at, at_ns, monotonic_ns}`, not flattened triples.

| Field | Meaning |
| --- | --- |
| `tag` | `kube-proxy-v1` |
| `argv` | Exact argv, by default `<kubectl> [--kubeconfig K] [--context C] [--server S] proxy --port=0 --address=127.0.0.1 --reject-methods=^POST$,^PUT$,^PATCH$,^DELETE$` |
| `read_only` | Whether the reject-methods flag is present |
| `pid`, `base_url`, `port`, `serve_line` | `serve_line` is the "Starting to serve on 127.0.0.1:NNNNN" line the port was read from |
| `stdout_before_serve`, `stdout_after_serve` | Other stdout lines, each `{line, at}`; expected empty |
| `stderr_tail` | Last 200 stderr lines, each `{line, at}` |
| `started` | Before `Popen` |
| `serving` | When the serve line was read |
| `stop_requested`, `stopped` | |
| `stop_method`, `return_code` | `stop_method`: `terminate`, `kill` (terminate did not end it within the stop timeout), `kill_unconfirmed` or `already_exited` |
| `start_error` | |
| `clock` | Host clock info |
| `gets`, `cli_stop_reason` | CLI only |

The proxy is started in its own process group on Windows (`CREATE_NEW_PROCESS_GROUP`) or its own session on POSIX. A Ctrl-C therefore reaches only the Python process, whose `stop()` (or context-manager exit) terminates the proxy.

## 13. Converter mapping to evidence rows

Row shape as in `phase3/CAPTURE_FORMAT.md` §3: `{available_ns, logical_confirmation_ns, record: {evidence_id, logical_id, kind, subject, payload, supports, supersedes, source_ref, source_sha256, acquired_at}}`. `acquired_at` is the source record's `available_at`, and `available_ns = logical_confirmation_ns = timestamp_ns(acquired_at)`. `subject` = canonical `[cluster_incarnation, api_group, Kind, namespace, uid]`, with the group `""` for Pod, `apps` for Deployment and ReplicaSet, `discovery.k8s.io` for EndpointSlice and `policy` for PodDisruptionBudget. `convert_capture.py`'s `API_GROUPS` lacks the last two, so converter v4 passes the group explicitly.

| Source | Evidence `kind` | `observation_basis` | `evidence_id` | Observation time in the payload | `acquired_at` |
| --- | --- | --- | --- | --- | --- |
| `api_watch_event` with `ADDED`, `MODIFIED` or `DELETED` | `api_watch_event` | `watch_event` | `watch:<collection_id>/<sequence>` | `received_at` | `available_at` |
| `watch_cache_snapshot` × each object of a kind that is usable at `snapshot_at` (§6 rule), kept only inside the decision window ± 60 s | `api_observation` | `watch_cache_snapshot` | `watchsnap:<collection_id>/<snapshot sequence>/<uid>` | `snapshot_at` | the snapshot's `available_at` |
| `live_recheck` with `status: answered` | `live_recheck` | `live_recheck` | `recheck:<collection_id>/<tick>` | `request_started_at` and `response_received_at` (x_R) | `available_at` (≥ x_R) |
| `context/clock_probes.json`, one row per document (set) | `clock_probe` | — | `clock:<capture>:<label>` | the pairs and the summary | the set's last `receive_at` |

- **Snapshot row payload.** It has the shape of the poller's `resource_observation`, so that the Stage-2 adapter can map both alike: `record_type: "resource_observation"`, `observation_basis: "watch_cache_snapshot"`, `resource`, `resource_data` (resolved through `ref`), `observed_at` = `snapshot_at`, `available_at` = the snapshot's, `snapshot_id` = the snapshot's `record_id`, `collection_id`, `collector: "watch-v1"`, `source_record` = the `record_id` of the `ref`, `_source_record_sha256` (snapshot line) and `_object_source_sha256` (carrier line).
- **Recheck row.** `subject` = `[cluster, "aiops.project", "LiveRecheck", namespace, collection_id]`; the payload is the tick record plus `_source_record_sha256`. `failed` and `missed` ticks are not evidence; they count in §14.
- **Not evidence rows.** `BOOKMARK` and `ERROR` events, invalid lines, stream lifecycle records and gaps. They go to a side file (`evidence/stage2/observer_continuity.json`) with the §14 quantities.
- **Development loaders.** Gate v1's `load_sightings` refuses every basis but `snapshot_receipt`. These rows are for the Stage-2 adapter and the diagnosis control, and are **never relabelled `snapshot_receipt`**.

## 14. Observer continuity (inclusion rule 2)

Window W = [T0 − 10 s, end of recovery] on the host monotonic clock, from the runner's timeline (`host_monotonic_ns`, the same clock within one boot). The thresholds are 15 s, 5 s and 90 %; each capture's `capture.json` records them with the measured values (`section10.rule_2`).

- **Poller:** unchanged. From `observations.jsonl`, the receipts of consecutive Pod snapshots, at most 15 s apart inside W.
- **Watch:** for each kind, the longest overlap with W of any `continuity_gap` interval, using `gap_from_monotonic_ns` and `gap_to_monotonic_ns`; a null bound is the start or the end of the collection. That includes `history_before_collection_unknown` and `history_after_collection_unknown`. The overlap must be at most 5 s. The rule takes the maximum over the five watched kinds (the Pods' value is recorded too). A less conservative variant starts gaps at `detected_*`; it is recorded but is not the rule.
- **Recheck:** among `live_recheck` records with `scheduled_monotonic_ns` in W, `answered` / all must be at least 0.90. Missed and failed ticks count as not answered.
