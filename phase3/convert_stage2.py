#!/usr/bin/env python3
"""Converter v4: one raw follow-up capture -> the development-format evidence rows, plus the follow-up row kinds.

    python phase3/convert_stage2.py --capture phase3/captures_stage2/G2-001          # writes <capture>/evidence/
    python phase3/convert_stage2.py --capture <capture> --out <dir> [--window-margin-seconds 60] [--window-all]
    python phase3/convert_stage2.py --self-test                                      # synthetic capture, no cluster

The poller's rows are written by the development converter (phase3/convert_capture.py ``convert()``), imported and
called unchanged. Added here: the watch's events (``api_watch_event``) and cache snapshots (``api_observation``,
``observation_basis: watch_cache_snapshot``), the live recheck's ticks (``live_recheck``), the clock probes
(``clock_probe``), the host-command receipts and the per-Pod probe rows (evaluation only), and one K1-ready Pod file
per observer. Every Pod object keeps the kubelet's own stamps (Ready ``lastTransitionTime``,
``lastState.terminated.finishedAt`` with ``restartCount``, ``state.running.startedAt``); every snapshot row names the
record its object was resolved from; no stamp is changed or inferred. Snapshot rows are kept for the decision window
plus a margin (60 s by default). Watch data is never written as ``snapshot_receipt`` (the poller's basis).

The output layout is described in phase3/CAPTURE_FORMAT_STAGE2.md. ``--self-test`` builds a synthetic capture by
driving the collectors' own code with fake clocks and a scripted API, converts it and checks the result.
Standard library only; Python 3.10+.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import math
import os
import shutil
import sys
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))
from aiops_kg.evidence import Accepted, Evidence, canonical, timestamp_ns  # noqa: E402


def import_readonly(path, name):
    """Import a script by path without writing bytecode (the file is only read)."""
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError('cannot import ' + str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


CC = import_readonly(HERE / 'convert_capture.py', 'convert_capture_readonly_for_convert_stage2')

CONVERTER_VERSION = 'phase3-stage2-capture-to-evidence-v4'
MANIFEST_NAME = 'stage2_manifest.json'
WATCH_TAG, RECHECK_TAG = 'watch-v1', 'recheck-v1'
OBSERVERS = ('poller', 'watch', 'recheck')
# resource (plural, as in API paths and the collectors' records) -> (Kind, API group) (CAPTURE_FORMAT_STAGE2.md
# section 13: convert_capture.API_GROUPS lacks the last two kinds, so the group is always passed explicitly)
RESOURCES = {'pods': ('Pod', ''), 'deployments': ('Deployment', 'apps'), 'replicasets': ('ReplicaSet', 'apps'),
             'endpointslices': ('EndpointSlice', 'discovery.k8s.io'),
             'poddisruptionbudgets': ('PodDisruptionBudget', 'policy')}
GROUP_OF_KIND = dict(RESOURCES.values())
OBJECT_EVENT_TYPES = ('ADDED', 'MODIFIED', 'DELETED')
WATCH_EVENT_FILE_TYPES = ('continuity_gap', 'watch_list', 'watch_list_object', 'watch_stream_open', 'api_watch_event',
                          'watch_stream_end', 'invalid_watch_line', 'collector_error', 'collection_end')
PER_POD_PROBE_SCHEMA = 'per-pod-probe-row-v1'
PROBE_ROW_FILES = ('ground_truth/probe_rows.jsonl', 'ground_truth/per_pod_probe_rows.jsonl')
RECEIPT_FOLDERS = ('raw', 'ground_truth/raw')
OUT = {'list_objects': 'stage2/api_watch_list_object.jsonl',
       'events': 'stage2/api_watch_event.jsonl',
       'snapshots': 'stage2/api_observation.watch_cache_snapshot.jsonl',
       'recheck': 'stage2/live_recheck.jsonl',
       'gaps': 'stage2/continuity_gap.jsonl',
       'clock': 'stage2/clock_probe.jsonl',
       'host_commands': 'evaluation_only/stage2/host_command.jsonl',
       'probes': 'evaluation_only/stage2/per_pod_probe.jsonl'}
K1_FILES = {observer: 'stage2/k1_pod_records.{}.jsonl'.format(observer) for observer in OBSERVERS}
CONTINUITY_FILE = 'stage2/observer_continuity.json'
EVAL_README = 'evaluation_only/stage2/README.txt'
LINE_SEMANTICS = CC.LINE_SEMANTICS        # 'Exact original JSONL line bytes, including line ending if present'
SNAPSHOT_LINE_SEMANTICS = 'Exact original JSONL line bytes of the whole cache snapshot, including line ending'
CARRIER_LINE_SEMANTICS = 'Exact original JSONL line bytes of source_record (the ref), including line ending'
CLOCK_SOURCE_SEMANTICS = ('SHA-256 of the whole clock-probe file; the document is element _source_index of its JSON '
                          'array (index 0 for a single document)')
# Collector-manifest keys that hold host paths (kubeconfig, stop file, the proxy argv); dropped from
# stage2/observer_continuity.json because converted evidence may be committed while raw captures are not.
MANIFEST_PATH_KEYS = {'poller': (('kubeconfig',),),
                      'watch': (('options', 'stop_file'), ('proxy', 'record')),
                      'recheck': (('options', 'stop_file'), ('proxy', 'record'))}
EVALUATION_ONLY_README = (
    'EVALUATION ONLY -- NEVER A MODEL INPUT.\n'
    'Written by phase3/convert_stage2.py (converter v4). host_command.jsonl holds the host-command receipts of the\n'
    'capture (the F2 kill, its container lookups and any other docker exec the runner made);\n'
    'per_pod_probe.jsonl holds the evaluator probe rows addressed to a Pod IP. Both are\n'
    'fault, effect and label evidence; no replay, ranking, policy or gate may read\n'
    'them as input. The model-side Stage-2 rows are under ../../stage2/.\n')
ROW_SEMANTICS = {
    'available_ns': 'capture-era acceptance of the source record by its observer (available_at), never an offline '
                    'import time; logical_confirmation_ns = available_ns',
    'api_watch_list_object': 'one object of a successful watch LIST; observed_at = the LIST response receipt',
    'api_watch_event': 'one ADDED / MODIFIED / DELETED watch event; observed_at = its line receipt (received_at); '
                       'BOOKMARK and ERROR events are lifecycle records in stage2/observer_continuity.json',
    'api_observation (watch_cache_snapshot)': 'one object of one cache snapshot, resolved through its ref; '
                                              'observed_at = snapshot_at; only kinds usable at snapshot_at under '
                                              'CAPTURE_FORMAT_STAGE2.md section 6 and only inside the window',
    'live_recheck': 'one answered recheck tick (all five GETs HTTP 200 with a valid list); observed_at = x_R = '
                    'the last GET\'s receipt; failed and missed ticks are continuity_gap rows',
    'continuity_gap': 'poller and watch: the collector\'s own gap records; recheck: one row per failed or missed '
                      'tick (reason recheck_tick_failed / recheck_tick_missed, objects omitted)',
    'clock_probe': 'one clock-probe document (ten paired node-clock readings); acquired at its last host receipt',
    'host_command': 'EVALUATION ONLY: one host-command receipt (scripts/host_command_receipt_v1.py)',
    'per_pod_probe': 'EVALUATION ONLY: one per-Pod probe row (scripts/per_pod_probe_v1.py, schema '
                     'per-pod-probe-row-v1)',
    'k1_pod_records': 'not evidence rows: one Pod object with its observer receipt (observed_at) and acceptance '
                      '(available_at) per line, record_id = the evidence_id of the row carrying it (recheck: '
                      '<evidence_id>#<pod uid>), for src/aiops_kg/fault_control_kill.k1_extract, per observer'}


class WindowError(ValueError):
    """The decision window cannot be placed (a timeline mark is missing or the bounds are inverted)."""


# ---------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------
def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def iso_ns(epoch_ns: int) -> str:
    """UTC ISO-8601 with nine fractional digits and 'Z' (as the Stage-2 collectors write; timestamp_ns reads it)."""
    seconds, fraction = divmod(int(epoch_ns), 10 ** 9)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(seconds)) + '.{:09d}Z'.format(fraction)


def jsonl_lines(data: bytes):
    """(line number, exact bytes) of every nonblank line, numbered as convert_capture.lines_with_bytes numbers them
    (split on b'\\n' only; blank lines count but are skipped)."""
    for number, raw in enumerate(io.BytesIO(data), start=1):
        if raw.strip():
            yield number, raw


def relative_dir(value: str) -> str:
    """A relative directory inside the capture ('context'); no absolute path, drive or '..'."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError('directory must be a nonempty relative path')
    for pure in (PurePosixPath(value), PureWindowsPath(value)):
        if pure.is_absolute() or pure.drive or '..' in pure.parts:
            raise ValueError('directory must stay inside the capture: ' + repr(value))
    return value.replace('\\', '/').strip('/')


def drop_path(mapping, path):
    """A copy of a nested dict without the key at `path` (a tuple of keys), if present."""
    if not isinstance(mapping, dict) or not path:
        return mapping
    head, rest = path[0], path[1:]
    if head not in mapping:
        return mapping
    copy = dict(mapping)
    if rest:
        copy[head] = drop_path(copy[head], rest)
    else:
        del copy[head]
    return copy


def write_bytes_exclusive(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'xb') as handle:
        handle.write(data)


def json_document(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


@dataclass(frozen=True)
class WindowSpec:
    """Which snapshot rows are kept: those whose snapshot instant lies in [timeline[start_mark]
    - margin, timeline[end_mark] + margin] (inclusive), or all of them with keep_all."""
    start_mark: str = 'reference_start'
    end_mark: str = 'recovery_end'
    margin_seconds: float = 60.0
    keep_all: bool = False

    def __post_init__(self):
        for name in ('start_mark', 'end_mark'):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(name + ' must be a nonempty timeline mark name')
        margin = self.margin_seconds
        if isinstance(margin, bool) or not isinstance(margin, (int, float)) or not math.isfinite(margin) or margin < 0:
            raise ValueError('margin_seconds must be a finite number >= 0')


DEFAULT_WINDOW = WindowSpec()


class Window:
    """The resolved decision window. The comparison uses the host monotonic clock when both timeline marks carry
    host_monotonic_ns (runner timeline marks and the watch's snapshot_monotonic_ns are one system-wide clock within a
    boot, CAPTURE_FORMAT_STAGE2.md section 2), else the host wall clock (host_utc vs snapshot_at_ns)."""

    def __init__(self, spec: WindowSpec, timeline):
        self.spec, self.key, self.low, self.high = spec, None, None, None
        self.record = {'definition': ('decision window = [timeline[start_mark], timeline[end_mark]] of the runner\'s '
                                      'capture.json, widened by margin_seconds on both sides: '
                                      '"keep snapshot rows for the decision window +- 60 s only"'),
                       'applies_to': ('stage2/api_observation.watch_cache_snapshot.jsonl only; every other row '
                                      'kind is complete'),
                       'start_mark': spec.start_mark, 'end_mark': spec.end_mark,
                       'margin_seconds': float(spec.margin_seconds), 'keep_all': spec.keep_all}
        if spec.keep_all:
            self.record.update(mode='all_snapshots_kept', clock=None, bounds=None)
            return
        marks = timeline if isinstance(timeline, dict) else {}
        start, end = marks.get(spec.start_mark), marks.get(spec.end_mark)
        missing = [name for name, mark in ((spec.start_mark, start), (spec.end_mark, end))
                   if not isinstance(mark, dict) or not isinstance(mark.get('host_utc'), str)]
        if missing:
            raise WindowError('capture.json timeline has no mark {} (marks present: {}); the decision window cannot be '
                              'placed: name other marks with --window-start-mark / --window-end-mark, or keep every '
                              'snapshot with --window-all'.format(', '.join(repr(m) for m in missing),
                                                                 ', '.join(sorted(marks)) or 'none'))
        margin_ns = int(round(spec.margin_seconds * 1e9))
        start_wall, end_wall = timestamp_ns(start['host_utc']), timestamp_ns(end['host_utc'])
        monotonic = all(type(mark.get('host_monotonic_ns')) is int for mark in (start, end))
        if monotonic:
            self.key = 'snapshot_monotonic_ns'
            self.low, self.high = start['host_monotonic_ns'] - margin_ns, end['host_monotonic_ns'] + margin_ns
        else:
            self.key = 'snapshot_at_ns'
            self.low, self.high = start_wall - margin_ns, end_wall + margin_ns
        if self.high < self.low:
            raise WindowError('the decision window ends before it starts ({} after {})'.format(spec.start_mark,
                                                                                            spec.end_mark))
        self.record.update(mode='decision_window', clock='host_monotonic' if monotonic else 'host_wall_clock',
                           start_mark_at=start['host_utc'], end_mark_at=end['host_utc'],
                           start_mark_monotonic_ns=start.get('host_monotonic_ns'),
                           end_mark_monotonic_ns=end.get('host_monotonic_ns'),
                           bounds={'field': self.key, 'from': self.low, 'to': self.high, 'inclusive': True},
                           bounds_wall_clock={'from_at': iso_ns(start_wall - margin_ns),
                                              'to_at': iso_ns(end_wall + margin_ns)})

    def position(self, record) -> str:
        """'inside', 'before' or 'after' the window for one snapshot record."""
        if self.key is None:
            return 'inside'
        value = record.get(self.key)
        if type(value) is not int:
            raise ValueError('snapshot record {} has no integer {}'.format(record.get('record_id'), self.key))
        return 'before' if value < self.low else 'after' if value > self.high else 'inside'


class GapIndex:
    """The watch's continuity gaps per resource, for the snapshot usability rule of CAPTURE_FORMAT_STAGE2.md
    section 6: a snapshot taken at t is usable for kind K only if t is not inside any K watch_interrupted gap
    (gap_from < t < gap_to; a null gap_to means until the end), not before the K history_before_collection_unknown
    gap_to and not after the K history_after_collection_unknown gap_from. Compared on the host monotonic clock (one
    collector process). A kind without its history_after record (a collector killed before it closed its files)
    has no upper bound; that is reported in the manifest."""
    MISSING = object()

    def __init__(self):
        self.before, self.after, self.interrupted = {}, {}, defaultdict(list)
        self.duplicates = []

    def add(self, record):
        resource, reason = record.get('resource'), record.get('reason')
        start, end = record.get('gap_from_monotonic_ns'), record.get('gap_to_monotonic_ns')
        if reason == 'history_before_collection_unknown':
            if resource in self.before:
                self.duplicates.append(record.get('record_id'))
            self.before[resource] = end
        elif reason == 'history_after_collection_unknown':
            if resource in self.after:
                self.duplicates.append(record.get('record_id'))
            self.after[resource] = start
        elif reason == 'watch_interrupted':
            self.interrupted[resource].append((start, end))
        else:
            raise ValueError('unknown watch continuity_gap reason {!r} in {}'.format(reason, record.get('record_id')))

    def usable(self, resource, instant):
        """(True, None) or (False, reason)."""
        if resource not in self.before:
            return False, 'no_history_before_collection_record'
        first = self.before[resource]
        if first is None or instant < first:
            return False, 'before_first_successful_list'
        for start, end in self.interrupted.get(resource, ()):
            if (start is None or start < instant) and (end is None or instant < end):
                return False, 'inside_watch_interrupted_gap'
        if resource in self.after:
            last = self.after[resource]
            if last is None or instant > last:
                return False, 'after_collection_stop'
        return True, None


# ---------------------------------------------------------------------------------------------------------------
# The conversion
# ---------------------------------------------------------------------------------------------------------------
class Stage2Conversion:
    """Everything converter v4 adds to the Phase-3 converter's output, written into `out` (the staging
directory)."""

    def __init__(self, capture: Path, out: Path, *, window: WindowSpec, observer_dir: str, include_probe_traffic: bool,
                 verify_raw: bool):
        self.capture, self.out, self.window_spec = capture, out, window
        self.observer_dir = relative_dir(observer_dir)
        self.include_probe_traffic, self.verify_raw = include_probe_traffic, verify_raw
        self.doc = json.loads((capture / 'capture.json').read_text(encoding='utf-8'))
        self.cluster = self.doc.get('cluster_incarnation_id') or 'unknown-cluster'     # as convert_capture
        self.namespace = self.doc['namespace']
        self.rel = capture.name                                                       # as convert_capture
        self.rows = {key: [] for key in OUT}          # key -> [(available_ns, evidence_id, canonical line, basis)]
        self.k1 = {observer: [] for observer in OBSERVERS}
        self.inputs, self.observers, self.integrity = {}, {}, {}
        self.problems, self.notes = [], []
        self.window_record, self.snapshot_stats = None, None
        self.watch_by_sequence, self.recheck_by_sequence = {}, {}

    # -- inputs ------------------------------------------------------------------------------------------------
    def observer_file(self, name):
        return '{}/{}'.format(self.observer_dir, name)

    def read_input(self, relative):
        """Exact bytes of a capture file (recorded with its SHA-256 among the manifest's inputs), or None."""
        path = self.capture / relative
        if not path.is_file():
            return None
        data = path.read_bytes()
        self.inputs[relative] = {'sha256': sha(data), 'bytes': len(data)}
        return data

    def read_json_input(self, relative):
        data = self.read_input(relative)
        return None if data is None else json.loads(data)

    def parse_jsonl(self, data, relative):
        """[(line number, exact bytes, record)]. A final line without its newline that is not JSON (a writer killed
        mid-line) is skipped and reported; any other unparseable line refuses the capture."""
        lines = list(jsonl_lines(data))
        parsed = []
        for index, (number, raw) in enumerate(lines):
            try:
                record = json.loads(raw)
            except ValueError:
                if index == len(lines) - 1 and not raw.endswith(b'\n'):
                    self.problems.append({'source': relative, 'line': number, 'problem': 'truncated_final_line',
                                          'bytes': len(raw)})
                    continue
                raise ValueError('{}:{} is not a JSON line'.format(relative, number)) from None
            if not isinstance(record, dict):
                raise ValueError('{}:{} is not a JSON object'.format(relative, number))
            parsed.append((number, raw, record))
        return parsed

    # -- rows -------------------------------------------------------------------------------------------------
    def object_subject(self, kind, namespace, uid):
        return CC.subject(self.cluster, kind, namespace, uid, GROUP_OF_KIND.get(kind, ''))

    def project_subject(self, kind, key):
        return canonical([self.cluster, 'aiops.project', kind, self.namespace, key])

    def add_row(self, key, evidence_id, kind, subject, payload, source_ref, source_sha256, acquired_at, basis=None):
        """Validate one row as convert_capture.row does (Evidence, Accepted) and keep its canonical line."""
        available = timestamp_ns(acquired_at)
        evidence = Evidence.from_dict({'evidence_id': evidence_id, 'logical_id': evidence_id, 'kind': kind,
                                       'subject': subject, 'payload': payload, 'supports': [], 'supersedes': [],
                                       'source_ref': source_ref, 'source_sha256': source_sha256,
                                       'acquired_at': acquired_at})
        Accepted(evidence, available)                 # acquisition must not follow acceptance
        record = {'evidence_id': evidence_id, 'logical_id': evidence_id, 'kind': kind, 'subject': subject,
                  'payload': payload, 'supports': [], 'supersedes': [], 'source_ref': source_ref,
                  'source_sha256': source_sha256, 'acquired_at': acquired_at}
        line = canonical({'available_ns': available, 'logical_confirmation_ns': available, 'record': record})
        self.rows[key].append((available, evidence_id, line, basis))

    def k1_row(self, observer, record_id, record, observed_at, observed_ns, available_at, available_ns, pod, source_ref,
               **extra):
        """One K1-ready Pod row (fault_control_kill.pod_records reads record_id, observer, observed_at(_ns),
        available_at(_ns) and the object under 'pod')."""
        meta = pod.get('metadata') or {}
        row = {'record_id': record_id, 'observer': observer, 'collector': record.get('collector'),
               'collection_id': record.get('collection_id'), 'observation_basis': record.get('observation_basis'),
               'event_type': None, 'observed_at': observed_at, 'observed_at_ns': observed_ns,
               'available_at': available_at, 'available_at_ns': available_ns, 'pod_uid': meta.get('uid'),
               'pod_name': meta.get('name'), 'pod': pod, 'source_record': record.get('record_id'),
               'source_ref': source_ref}
        row.update(extra)
        self.k1[observer].append(row)

    # -- poller (context/observations.jsonl; its api_observation rows come from the Phase-3 converter) ----------
    def convert_poller(self):
        relative = 'context/observations.jsonl'
        data = self.read_input(relative)
        info = {'present': data is not None, 'file': relative}
        self.observers['poller'] = info
        if data is None:
            self.notes.append('poller: context/observations.jsonl absent')
            return
        manifest = self.read_json_input('context/manifest.json')
        file_sha = sha(data)
        types, collections, collectors, gap_rows = Counter(), set(), set(), 0
        for number, raw, rec in self.parse_jsonl(data, relative):
            rtype = rec.get('record_type')
            types[str(rtype)] += 1
            if rec.get('collection_id'):
                collections.add(rec['collection_id'])
            collectors.add(rec.get('collector'))
            ref = '{}/{}#L{}'.format(self.rel, relative, number)
            if rtype == 'continuity_gap':
                payload = dict(rec, observer='poller', _source_record_hash_semantics=LINE_SEMANTICS,
                               _source_record_sha256=sha(raw))
                self.add_row('gaps', 'gap:poller:' + rec['record_id'], 'continuity_gap',
                             self.project_subject('ObserverContinuity', 'poller:' + rec['collection_id']), payload,
                             ref, file_sha, rec['available_at'])
                gap_rows += 1
            elif rtype == 'resource_observation' and (rec.get('resource_data') or {}).get('kind') == 'Pod':
                self.k1_row('poller', 'api:' + rec['record_id'], rec, rec['observed_at'],
                            timestamp_ns(rec['observed_at']), rec['available_at'], timestamp_ns(rec['available_at']),
                            rec['resource_data'], ref)
        if len(collections) > 1:
            raise ValueError('context/observations.jsonl spans several collections: {}'.format(sorted(collections)))
        tags = sorted(tag for tag in collectors if tag)
        info.update(collection_id=next(iter(collections), None), collector_tags=tags,
                    collector_version='1.1' if 'collect_deployment_history_v1_1' in tags else '1 (untagged)',
                    record_types=dict(sorted(types.items())), continuity_gap_rows=gap_rows,
                    k1_pod_rows=len(self.k1['poller']),
                    manifest=self.trimmed_manifest('poller', manifest))

    def trimmed_manifest(self, observer, manifest):
        if manifest is None:
            return None
        for path in MANIFEST_PATH_KEYS.get(observer, ()):
            manifest = drop_path(manifest, path)
        return manifest

    def check_envelope(self, record, collection_id, tag, relative):
        sequence = record.get('sequence')
        if type(sequence) is not int or sequence < 1:
            raise ValueError('{}: a record without a positive integer sequence'.format(relative))
        if record.get('collection_id') != collection_id or record.get('collector') != tag:
            raise ValueError('{}: record {} is not of collection {} ({})'.format(relative, sequence, collection_id,
                                                                                tag))
        if record.get('record_id') != '{}/{}'.format(collection_id, sequence):
            raise ValueError('{}: record {} has record_id {!r}'.format(relative, sequence, record.get('record_id')))
        if not isinstance(record.get('available_at'), str) or timestamp_ns(record['available_at']) != \
                record.get('available_at_ns'):
            raise ValueError('{}: record {} has inconsistent available_at / available_at_ns'.format(relative, sequence))

    # -- watch ------------------------------------------------------------------------------------------------
    def convert_watch(self):
        events_rel, snaps_rel = self.observer_file('watch_events.jsonl'), self.observer_file('watch_snapshots.jsonl')
        events_data, snaps_data = self.read_input(events_rel), self.read_input(snaps_rel)
        manifest = self.read_json_input(self.observer_file('watch_manifest.json'))
        info = {'present': events_data is not None, 'files': [events_rel, snaps_rel]}
        self.observers['watch'] = info
        if events_data is None:
            if snaps_data is not None:
                raise ValueError(snaps_rel + ' exists without ' + events_rel)
            self.notes.append('watch: {} absent'.format(events_rel))
            return
        events = self.parse_jsonl(events_data, events_rel)
        snapshots = self.parse_jsonl(snaps_data, snaps_rel) if snaps_data is not None else []
        if not events:
            raise ValueError(events_rel + ' has no record')
        collection_id = (manifest or {}).get('collection_id') or events[0][2].get('collection_id')
        by_sequence = self.watch_by_sequence
        for relative, items in ((events_rel, events), (snaps_rel, snapshots)):
            for number, raw, rec in items:
                self.check_envelope(rec, collection_id, WATCH_TAG, relative)
                if rec['sequence'] in by_sequence:
                    raise ValueError('{}: sequence {} appears twice'.format(relative, rec['sequence']))
                by_sequence[rec['sequence']] = (relative, number, raw, rec)
        events_sha = sha(events_data)
        gaps, lifecycle, line_hash = GapIndex(), [], {}
        counts = Counter()
        for number, raw, rec in events:
            rtype = rec.get('record_type')
            if rtype not in WATCH_EVENT_FILE_TYPES:
                raise ValueError('{}:{}: unknown record_type {!r}'.format(events_rel, number, rtype))
            ref = '{}/{}#L{}'.format(self.rel, events_rel, number)
            counts[rtype] += 1
            if rtype in ('watch_list_object', 'api_watch_event') and isinstance(rec.get('resource_data'), dict) \
                    and (rtype == 'watch_list_object' or rec.get('event_type') in OBJECT_EVENT_TYPES):
                kind, _ = RESOURCES[rec['resource']]
                data = rec['resource_data']
                meta = data['metadata']
                if data.get('kind') != kind or meta.get('uid') != rec.get('uid'):
                    raise ValueError('{}:{}: object does not match its record'.format(events_rel, number))
                line_hash[rec['sequence']] = sha(raw)
                payload = dict(rec, _source_record_hash_semantics=LINE_SEMANTICS,
                               _source_record_sha256=line_hash[rec['sequence']])
                is_list = rtype == 'watch_list_object'
                prefix, out_key = ('watchlist:', 'list_objects') if is_list else ('watch:', 'events')
                evidence_kind = 'api_watch_list_object' if is_list else 'api_watch_event'
                self.add_row(out_key, prefix + rec['record_id'], evidence_kind,
                             self.object_subject(kind, meta.get('namespace'), meta['uid']), payload, ref, events_sha,
                             rec['available_at'], basis=rec.get('observation_basis'))
                if kind == 'Pod':
                    observed_ns = rec['response_received_at_ns'] if is_list else rec['received_at_ns']
                    self.k1_row('watch', prefix + rec['record_id'], rec, rec['observed_at'], observed_ns,
                                rec['available_at'], rec['available_at_ns'], data, ref,
                                event_type=rec.get('event_type'))
            elif rtype == 'continuity_gap':
                gaps.add(rec)
                payload = dict(rec, observer='watch', _source_record_hash_semantics=LINE_SEMANTICS,
                               _source_record_sha256=sha(raw))
                self.add_row('gaps', 'gap:watch:' + rec['record_id'], 'continuity_gap',
                             self.project_subject('ObserverContinuity', 'watch:' + collection_id), payload, ref,
                             events_sha, rec['available_at'])
            else:
                if rtype == 'api_watch_event' and rec.get('event_type') in OBJECT_EVENT_TYPES:
                    self.problems.append({'source': events_rel, 'line': number,
                                          'problem': 'object_event_without_resource_data'})
                lifecycle.append(rec)
        if gaps.duplicates:
            self.problems.append({'source': events_rel, 'problem': 'duplicate_history_gap_records',
                                  'records': gaps.duplicates})
        listed = sorted(set(gaps.before))
        unbounded = sorted(resource for resource in gaps.before if resource not in gaps.after)
        if unbounded:
            self.notes.append('watch: no history_after_collection_unknown record for {} (collection not closed); their '
                              'snapshots have no upper usability bound'.format(', '.join(unbounded)))
        self.convert_snapshots(snapshots, snaps_rel, snaps_data, gaps, line_hash)
        info.update(collection_id=collection_id, record_types=dict(sorted(counts.items())),
                    snapshot_records=len(snapshots), resources_with_history_record=listed,
                    resources_without_closing_record=unbounded, lifecycle_records=lifecycle,
                    manifest=self.trimmed_manifest('watch', manifest),
                    continuity_gap_rows=sum(1 for _, number, raw, rec in by_sequence.values()
                                            if rec.get('record_type') == 'continuity_gap'),
                    k1_pod_rows=len(self.k1['watch']))
        if manifest is not None and manifest.get('status') != 'finished':
            self.notes.append('watch: manifest status {!r} (stop_reason {!r})'.format(manifest.get('status'),
                                                                                    manifest.get('stop_reason')))

    def convert_snapshots(self, snapshots, snaps_rel, snaps_data, gaps, carrier_hash):
        stats = {'snapshots_total': len(snapshots), 'snapshots_by_trigger': Counter(), 'inside_window': Counter(),
                 'before_window': 0, 'after_window': 0, 'objects_inside_window': 0, 'rows_written': 0,
                 'objects_omitted_unusable': Counter(), 'objects_omitted_by_resource': Counter()}
        self.snapshot_stats = stats
        if not snapshots:
            self.window_record = dict(Window(WindowSpec(keep_all=True), None).record, mode='not_applied',
                                      note='no watch cache snapshot in the capture')
            return
        window = Window(self.window_spec, self.doc.get('timeline'))
        self.window_record = window.record
        snaps_sha = sha(snaps_data)
        for number, raw, snap in snapshots:
            if snap.get('record_type') != 'watch_cache_snapshot':
                raise ValueError('{}:{}: not a watch_cache_snapshot record'.format(snaps_rel, number))
            stats['snapshots_by_trigger'][snap['trigger']] += 1
            where = window.position(snap)
            if where != 'inside':
                stats[where + '_window'] += 1
                continue
            stats['inside_window'][snap['trigger']] += 1
            if snap.get('observed_at') != snap.get('snapshot_at'):
                self.problems.append({'source': snaps_rel, 'line': number, 'problem': 'observed_at_is_not_snapshot_at'})
            instant = snap['snapshot_monotonic_ns']
            snapshot_sha = sha(raw)
            ref_text = '{}/{}#L{}'.format(self.rel, snaps_rel, number)
            for entry in snap['objects']:
                stats['objects_inside_window'] += 1
                carrier = self.watch_by_sequence.get(entry['ref'])
                if carrier is None or entry['ref'] >= snap['sequence']:
                    raise ValueError('{}:{}: unresolvable ref {} of {}'.format(snaps_rel, number, entry['ref'],
                                                                               entry['uid']))
                _, _, carrier_raw, carrier_rec = carrier
                data = carrier_rec.get('resource_data')
                if carrier_rec.get('record_type') not in ('watch_list_object', 'api_watch_event') \
                        or not isinstance(data, dict) or carrier_rec.get('uid') != entry['uid'] \
                        or carrier_rec.get('resource_version') != entry['resourceVersion'] \
                        or data.get('kind') != entry['kind'] \
                        or data['metadata'].get('resourceVersion') != entry['resourceVersion']:
                    raise ValueError('{}:{}: ref {} does not carry {} {} at resourceVersion {}'.format(
                        snaps_rel, number, entry['ref'], entry['kind'], entry['uid'], entry['resourceVersion']))
                resource = carrier_rec['resource']
                usable, reason = gaps.usable(resource, instant)
                if not usable:
                    stats['objects_omitted_unusable'][reason] += 1
                    stats['objects_omitted_by_resource'][resource] += 1
                    continue
                if entry['ref'] not in carrier_hash:
                    carrier_hash[entry['ref']] = sha(carrier_raw)
                payload = {
                    'record_type': 'resource_observation', 'observation_basis': 'watch_cache_snapshot',
                    'collector': WATCH_TAG, 'collection_id': snap['collection_id'], 'snapshot_id': snap['record_id'],
                    'snapshot_sequence': snap['sequence'], 'snapshot_index': snap['snapshot_index'],
                    'snapshot_trigger': snap['trigger'], 'trigger_sequence': snap['trigger_sequence'],
                    'snapshot_at': snap['snapshot_at'], 'snapshot_at_ns': snap['snapshot_at_ns'],
                    'snapshot_monotonic_ns': instant, 'observed_at': snap['observed_at'],
                    'available_at': snap['available_at'], 'available_at_ns': snap['available_at_ns'],
                    'clock_adjusted': snap['clock_adjusted'], 'resource': resource,
                    'resource_state': snap['resources'].get(resource), 'resource_data': data,
                    'source_record': carrier_rec['record_id'], 'source_record_type': carrier_rec['record_type'],
                    'source_record_sequence': entry['ref'],
                    '_source_record_hash_semantics': SNAPSHOT_LINE_SEMANTICS, '_source_record_sha256': snapshot_sha,
                    '_object_source_hash_semantics': CARRIER_LINE_SEMANTICS,
                    '_object_source_sha256': carrier_hash[entry['ref']]}
                meta = data['metadata']
                self.add_row('snapshots', 'watchsnap:{}/{}'.format(snap['record_id'], entry['uid']), 'api_observation',
                             self.object_subject(entry['kind'], meta.get('namespace'), entry['uid']), payload,
                             ref_text, snaps_sha, snap['available_at'], basis='watch_cache_snapshot')
                stats['rows_written'] += 1

    # -- recheck ----------------------------------------------------------------------------------------------
    def convert_recheck(self):
        relative = self.observer_file('recheck.jsonl')
        data = self.read_input(relative)
        manifest = self.read_json_input(self.observer_file('recheck_manifest.json'))
        info = {'present': data is not None, 'file': relative}
        self.observers['recheck'] = info
        if data is None:
            self.notes.append('recheck: {} absent'.format(relative))
            return
        records = self.parse_jsonl(data, relative)
        if not records:
            raise ValueError(relative + ' has no record')
        collection_id = (manifest or {}).get('collection_id') or records[0][2].get('collection_id')
        file_sha = sha(data)
        ticks, statuses, lifecycle = [], Counter(), []
        for number, raw, rec in records:
            self.check_envelope(rec, collection_id, RECHECK_TAG, relative)
            if rec['sequence'] in self.recheck_by_sequence:
                raise ValueError('{}: sequence {} appears twice'.format(relative, rec['sequence']))
            self.recheck_by_sequence[rec['sequence']] = (relative, number, raw, rec)
            ref = '{}/{}#L{}'.format(self.rel, relative, number)
            rtype = rec.get('record_type')
            if rtype == 'collection_end':
                lifecycle.append(rec)
                continue
            if rtype != 'live_recheck':
                raise ValueError('{}:{}: unknown record_type {!r}'.format(relative, number, rtype))
            status = rec.get('status')
            statuses[str(status)] += 1
            ticks.append(rec['tick'])
            if status == 'answered':
                if rec.get('answered') is not True or any(get.get('outcome') != 'ok' for get in rec['gets']):
                    raise ValueError('{}:{}: tick {} is answered without five ok GETs'.format(relative, number,
                                                                                            rec['tick']))
                payload = dict(rec, _source_record_hash_semantics=LINE_SEMANTICS, _source_record_sha256=sha(raw))
                evidence_id = 'recheck:{}/{}'.format(collection_id, rec['tick'])
                self.add_row('recheck', evidence_id, 'live_recheck',
                             self.project_subject('LiveRecheck', collection_id), payload, ref, file_sha,
                             rec['available_at'], basis=rec.get('observation_basis'))
                pods_get = next((get for get in rec['gets'] if get.get('resource') == 'pods'), {})
                for obj in rec['objects']:
                    if obj.get('kind') == 'Pod':
                        self.k1_row('recheck', '{}#{}'.format(evidence_id, obj['metadata']['uid']), rec,
                                    rec['observed_at'], rec['response_received_at_ns'], rec['available_at'],
                                    rec['available_at_ns'], obj, ref, tick=rec['tick'],
                                    pods_get_response_received_at=pods_get.get('response_received_at'))
            elif status in ('failed', 'missed'):
                tick_record = {key: value for key, value in rec.items() if key != 'objects'}
                payload = {'record_type': 'continuity_gap', 'observer': 'recheck',
                           'reason': 'recheck_tick_' + status, 'collector': RECHECK_TAG,
                           'collection_id': collection_id, 'source_record': rec['record_id'], 'tick': rec['tick'],
                           'scheduled_at': rec.get('scheduled_at'),
                           'scheduled_monotonic_ns': rec.get('scheduled_monotonic_ns'),
                           'observed_at': rec.get('observed_at'), 'available_at': rec['available_at'],
                           'available_at_ns': rec['available_at_ns'],
                           'objects_omitted': len(rec.get('objects') or []), 'tick_record': tick_record,
                           'semantics': ('a scheduled recheck tick that was not answered; condition (R) never '
                                         'consumes it and it counts against the answered fraction of inclusion '
                                         'rule 2 (CAPTURE_FORMAT_STAGE2.md); the objects of '
                                         'GETs that did answer in a failed tick are omitted here'),
                           '_source_record_hash_semantics': LINE_SEMANTICS, '_source_record_sha256': sha(raw)}
                self.add_row('gaps', 'gap:recheck:{}/tick/{}'.format(collection_id, rec['tick']), 'continuity_gap',
                             self.project_subject('ObserverContinuity', 'recheck:' + collection_id), payload, ref,
                             file_sha, rec['available_at'])
            else:
                raise ValueError('{}:{}: unknown tick status {!r}'.format(relative, number, status))
        if ticks != list(range(len(ticks))):
            self.problems.append({'source': relative, 'problem': 'ticks_not_consecutive_from_0'})
        info.update(collection_id=collection_id, ticks=dict(sorted(statuses.items())), tick_records=len(ticks),
                    lifecycle_records=lifecycle, manifest=self.trimmed_manifest('recheck', manifest),
                    k1_pod_rows=len(self.k1['recheck']))
        if manifest is not None and manifest.get('status') != 'finished':
            self.notes.append('recheck: manifest status {!r} (stop_reason {!r})'.format(manifest.get('status'),
                                                                                      manifest.get('stop_reason')))

    # -- clock probes -------------------------------------------------------------------------------------------
    def convert_clock_probes(self):
        relative = self.observer_file('clock_probes.json')
        data = self.read_input(relative)
        if data is None:
            self.notes.append('clock probes: {} absent'.format(relative))
            return
        value = json.loads(data)
        if isinstance(value, list):
            documents = value
        elif isinstance(value, dict) and isinstance(value.get('sets'), list):      # the superseded first draft
            documents = [dict(item, label=item.get('label', item.get('phase'))) for item in value['sets']]
        elif isinstance(value, dict):
            documents = [value]
        else:
            raise ValueError(relative + ' is neither a clock-probe document nor a list of them')
        file_sha, seen = sha(data), Counter()
        for index, document in enumerate(documents):
            if not isinstance(document, dict):
                raise ValueError('{}: element {} is not a document'.format(relative, index))
            readings = document.get('pairs') if isinstance(document.get('pairs'), list) else document.get('probes')
            receipts = [reading.get('receive_ns', reading.get('host_receive_at_ns')) for reading in readings or []
                        if isinstance(reading, dict)]
            receipts = [value for value in receipts if type(value) is int]
            if not receipts:
                self.problems.append({'source': relative, 'index': index, 'problem': 'clock_probe_without_receipts'})
                continue
            label = str(document.get('label') or 'set{}'.format(index + 1))
            seen[label] += 1
            evidence_id = 'clock:{}:{}'.format(self.rel, label)
            if seen[label] > 1:
                evidence_id += '#{}'.format(seen[label])
            payload = dict(document, _source_index=index, _source_hash_semantics=CLOCK_SOURCE_SEMANTICS,
                           _source_file_sha256=file_sha, _document_canonical_sha256=sha(canonical(document).encode()))
            self.add_row('clock', evidence_id, 'clock_probe',
                         self.project_subject('ClockProbe', '{}:{}'.format(self.rel, label)), payload,
                         '{}/{}#{}'.format(self.rel, relative, index), file_sha, iso_ns(max(receipts)))

    # -- host commands (evaluation only) -------------------------------------------------------------------------
    def convert_host_commands(self):
        found = {}
        capture_sha = self.inputs.get('capture.json', {}).get('sha256') or sha((self.capture / 'capture.json')
                                                                              .read_bytes())
        for receipt in self.doc.get('command_receipts') or []:
            if isinstance(receipt, dict) and receipt.get('kind') == 'host_command':
                found[receipt['id']] = {'receipt': receipt, 'source': 'capture.json#command_receipts',
                                        'source_sha256': capture_sha}
        files = set()
        for folder in RECEIPT_FOLDERS:                  # recursively: runner v2 keeps its clock receipts in raw/clock/
            directory = self.capture / folder
            if directory.is_dir():
                files.update(path.relative_to(self.capture).as_posix() for path in directory.rglob('*.receipt.json'))
        for entry in found.values():                    # and wherever a receipt says its file is
            named = entry['receipt'].get('receipt_file')
            if isinstance(named, str) and named and (self.capture / named).is_file():
                files.add(relative_dir(named))
        for relative in sorted(files):                  # a receipt file is the source of its own receipt
            data = self.read_input(relative)
            receipt = json.loads(data)
            if not isinstance(receipt, dict) or receipt.get('kind') != 'host_command':
                continue
            known = found.get(receipt.get('id'))
            if known is not None and known['receipt'] != receipt:
                self.problems.append({'source': relative, 'problem': 'receipt_file_differs_from_capture_json',
                                      'id': receipt.get('id')})
            found[receipt['id']] = {'receipt': receipt, 'source': relative, 'source_sha256': sha(data)}
        verification = Counter()
        for identifier in sorted(found):
            entry = found[identifier]
            receipt = entry['receipt']
            checks = {}
            for stream in ('stdout', 'stderr'):
                checks[stream] = self.verify_output(receipt, stream)
                verification[checks[stream]] += 1
                if checks[stream] == 'mismatch':
                    self.problems.append({'source': receipt.get(stream + '_file'), 'problem': 'output_hash_mismatch',
                                          'id': identifier})
            acquired = receipt.get('collector_available_at') or receipt.get('response_received_at')
            payload = dict(receipt, _receipt_source=entry['source'], _output_files_verified=checks)
            self.add_row('host_commands', 'host:{}:{}'.format(self.rel, identifier), 'host_command',
                         self.project_subject('HostCommand', identifier), payload,
                         '{}/{}'.format(self.rel, entry['source']), entry['source_sha256'], acquired)
        self.integrity['host_command_output_files'] = dict(sorted(verification.items()))

    def verify_output(self, receipt, stream):
        relative = receipt.get(stream + '_file')
        if not relative:
            return 'no_file'
        data = self.read_input(relative)
        if data is None:
            return 'missing'
        if receipt.get(stream + '_truncated'):
            return 'truncated_as_recorded' if len(data) == receipt.get(stream + '_file_bytes') else 'mismatch'
        return 'match' if sha(data) == receipt.get(stream + '_sha256') else 'mismatch'

    # -- per-Pod probe rows (evaluation only) --------------------------------------------------------------------
    def convert_probes(self):
        traces, other_rows = set(), Counter()
        for relative in PROBE_ROW_FILES:
            data = self.read_input(relative)
            if data is None:
                continue
            file_sha = sha(data)
            for number, raw, row in self.parse_jsonl(data, relative):
                if row.get('schema') != PER_POD_PROBE_SCHEMA:
                    other_rows[relative] += 1
                    continue
                for call in (row.get('batch') or {}).get('calls') or []:
                    if isinstance(call, dict) and call.get('trace_id'):
                        traces.add(call['trace_id'])
                acquired = iso_ns(row['host_received_wall_ns']) if type(row.get('host_received_wall_ns')) is int \
                    else row['host_received_at']
                if row.get('target_pod_uid') and row.get('target_service'):
                    subject = self.object_subject('Pod', self.namespace, row['target_pod_uid'])
                else:
                    subject = self.project_subject('ProbePair', row['probe_id'])
                payload = dict(row, _source_record_hash_semantics=LINE_SEMANTICS, _source_record_sha256=sha(raw))
                self.add_row('probes', 'probe:{}:{}'.format(self.rel, row['probe_id']), 'per_pod_probe', subject,
                             payload, '{}/{}#L{}'.format(self.rel, relative, number), file_sha, acquired)
        if other_rows:
            self.notes.append('probe rows without schema {} (Phase-3 rows through the Services) are not converted: '
                              '{}'.format(PER_POD_PROBE_SCHEMA, dict(sorted(other_rows.items()))))
        if traces and not self.include_probe_traffic:
            leaked = sorted(self.span_traces() & traces)
            if leaked:
                raise ValueError('{} trace(s) of per-Pod probe rows reached accepted_evidence.jsonl as span_claim rows '
                                 '(the Phase-3 converter excludes only the traces listed in ground_truth/'
                                 'probe_rows.jsonl): {}'.format(len(leaked), leaked[:5]))

    def span_traces(self):
        traces = set()
        with open(self.out / 'accepted_evidence.jsonl', 'rb') as handle:
            for line in handle:
                record = json.loads(line)['record']
                if record['kind'] == 'span_claim':
                    traces.add(record['payload'].get('trace_id'))
        return traces

    # -- raw archives ----------------------------------------------------------------------------------------------
    def verify_archives(self):
        expected_fields = {'list_body': ('watch_list', 'body_sha256'), 'event_line': ('api_watch_event', 'line_sha256'),
                           'invalid_line': ('invalid_watch_line', 'line_sha256'),
                           'watch_error_body': ('watch_stream_open', 'body_sha256')}
        for name, relative, records in (('watch', self.observer_file('watch_raw.jsonl.gz'), self.watch_by_sequence),
                                         ('recheck', self.observer_file('recheck_raw.jsonl.gz'),
                                          self.recheck_by_sequence)):
            if not records:
                continue
            path = self.capture / relative
            if not self.verify_raw:
                self.integrity[name + '_raw_archive'] = {'checked': False, 'present': path.is_file()}
                continue
            if not path.is_file():
                self.integrity[name + '_raw_archive'] = {'checked': True, 'present': False}
                continue
            data = self.read_input(relative)
            result = Counter()
            covered = set()
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as handle:
                    for line in handle:
                        entry = json.loads(line)
                        raw = entry['data'].encode('utf-8') if entry['encoding'] == 'utf-8' \
                            else base64.b64decode(entry['data'])
                        result['entries'] += 1
                        if sha(raw) != entry['sha256'] or len(raw) != entry['bytes']:
                            result['entry_hash_mismatch'] += 1
                            continue
                        expected = self.archive_expectation(entry, records, expected_fields)
                        if expected is None:
                            result['unreferenced'] += 1
                        elif expected == entry['sha256']:
                            result['verified'] += 1
                            covered.add((entry['sequence'], entry.get('resource')))
                        else:
                            result['record_hash_mismatch'] += 1
            except (EOFError, OSError, zlib.error, ValueError, KeyError) as error:
                result['truncated_or_unreadable'] += 1
                self.problems.append({'source': relative, 'problem': 'raw_archive_unreadable_tail',
                                      'error': '{}: {}'.format(type(error).__name__, error)[:300]})
            missing = sum(1 for key in self.archive_expected_keys(name, records) if key not in covered)
            result['records_without_entry'] = missing
            for problem in ('entry_hash_mismatch', 'record_hash_mismatch'):
                if result[problem]:
                    self.problems.append({'source': relative, 'problem': 'raw_archive_' + problem,
                                          'count': result[problem]})
            self.integrity[name + '_raw_archive'] = dict(sorted(result.items()), checked=True, present=True)

    @staticmethod
    def archive_expectation(entry, records, expected_fields):
        carrier = records.get(entry.get('sequence'))
        if carrier is None:
            return None
        rec = carrier[3]
        if entry.get('kind') == 'recheck_body':
            get = next((g for g in rec.get('gets') or [] if g.get('resource') == entry.get('resource')), None)
            return None if get is None else get.get('body_sha256')
        record_type, field = expected_fields.get(entry.get('kind'), (None, None))
        return rec.get(field) if rec.get('record_type') == record_type else None

    @staticmethod
    def archive_expected_keys(name, records):
        """(sequence, resource) of every record whose exact bytes the collector archives."""
        keys = []
        for _, _, _, rec in records.values():
            rtype = rec.get('record_type')
            if name == 'recheck':
                if rtype == 'live_recheck':
                    keys.extend((rec['sequence'], get['resource']) for get in rec.get('gets') or []
                                if get.get('body_sha256'))
            elif rtype in ('api_watch_event', 'invalid_watch_line') or (
                    rtype == 'watch_list' and rec.get('body_bytes')) or (
                    rtype == 'watch_stream_open' and not rec.get('ok') and rec.get('body_bytes')):
                keys.append((rec['sequence'], rec.get('resource')))
        return keys

    # -- writing ----------------------------------------------------------------------------------------------------
    def run(self):
        self.read_input('capture.json')
        self.convert_poller()
        self.convert_watch()
        if self.window_record is None:
            self.window_record = dict(Window(WindowSpec(keep_all=True), None).record, mode='not_applied',
                                      note='no watch collection in the capture')
        self.convert_recheck()
        self.convert_clock_probes()
        self.convert_host_commands()
        self.convert_probes()
        self.verify_archives()
        return self.write()

    def write(self):
        base_ids, base_kinds, base_basis = set(), Counter(), Counter()
        with open(self.out / 'accepted_evidence.jsonl', 'rb') as handle:
            for line in handle:
                record = json.loads(line)['record']
                base_ids.add(record['evidence_id'])
                base_kinds[record['kind']] += 1
                if record['kind'] == 'api_observation':
                    base_basis[str(record['payload'].get('observation_basis'))] += 1
        seen = set(base_ids)
        rows_by_file = {'accepted_evidence.jsonl': sum(base_kinds.values())}
        kinds = Counter(base_kinds)
        basis_by_file = {'accepted_evidence.jsonl (api_observation rows)': dict(sorted(base_basis.items()))}
        for key, relative in OUT.items():
            rows = sorted(self.rows[key], key=lambda item: (item[0], item[1]))
            for _, evidence_id, _, _ in rows:
                if evidence_id in seen:
                    raise ValueError('duplicate evidence ID ' + evidence_id)
                seen.add(evidence_id)
            write_bytes_exclusive(self.out / relative, b''.join(line.encode('utf-8') + b'\n' for _, _, line, _ in rows))
            rows_by_file[relative] = len(rows)
            kind = {'list_objects': 'api_watch_list_object', 'events': 'api_watch_event',
                    'snapshots': 'api_observation (watch_cache_snapshot)', 'recheck': 'live_recheck',
                    'gaps': 'continuity_gap', 'clock': 'clock_probe', 'host_commands': 'host_command',
                    'probes': 'per_pod_probe'}[key]
            kinds[kind] += len(rows)
            bases = Counter(str(basis) for _, _, _, basis in rows if basis is not None)
            if bases:
                basis_by_file[relative] = dict(sorted(bases.items()))
        k1_counts = {}
        for observer, relative in K1_FILES.items():
            rows = self.k1[observer]
            ids = [row['record_id'] for row in rows]
            if len(ids) != len(set(ids)):
                raise ValueError('duplicate K1 record_id in the {} rows'.format(observer))
            write_bytes_exclusive(self.out / relative, b''.join(canonical(row).encode('utf-8') + b'\n' for row in rows))
            k1_counts[observer] = len(rows)
        write_bytes_exclusive(self.out / EVAL_README, EVALUATION_ONLY_README.encode('utf-8'))
        continuity = {'schema': 'stage2-observer-continuity-v1', 'converter': CONVERTER_VERSION,
                      'semantics': ('what each observer recorded about itself: its manifest (keys holding host paths '
                                    'dropped), record counts and lifecycle records (watch: list summaries, stream '
                                    'opens and ends, BOOKMARK and ERROR events, invalid lines, collector errors and '
                                    'collection_end; recheck: collection_end). The gaps themselves are rows of '
                                    'continuity_gap.jsonl. No validity verdict is computed here (the inclusion '
                                    'rules are applied by the validity check).'),
                      'observers': {name: self.observers.get(name, {'present': False}) for name in OBSERVERS}}
        write_bytes_exclusive(self.out / CONTINUITY_FILE, json_document(continuity))
        files = {}
        for path in sorted(p for p in self.out.rglob('*') if p.is_file()):
            relative = path.relative_to(self.out).as_posix()
            if relative == MANIFEST_NAME:
                continue
            data = path.read_bytes()
            files[relative] = {'sha256': sha(data), 'bytes': len(data),
                               'lines': data.count(b'\n') if relative.endswith('.jsonl') else None}
        stats = self.snapshot_stats or {}
        snapshots = {key: (dict(sorted(value.items())) if isinstance(value, Counter) else value)
                     for key, value in stats.items()}
        manifest = {
            'converter': CONVERTER_VERSION, 'phase3_converter': CC.CONVERTER_VERSION,
            'capture_id': self.doc.get('capture_id'), 'capture_dir': self.rel, 'namespace': self.namespace,
            'cluster_incarnation_id': self.cluster,
            'options': {'observer_dir': self.observer_dir, 'include_probe_traffic': self.include_probe_traffic,
                        'verify_raw_archives': self.verify_raw,
                        'window': {'start_mark': self.window_spec.start_mark, 'end_mark': self.window_spec.end_mark,
                                   'margin_seconds': float(self.window_spec.margin_seconds),
                                   'keep_all': self.window_spec.keep_all}},
            'window': self.window_record, 'watch_cache_snapshots': snapshots,
            'counts_by_kind': dict(sorted(kinds.items())), 'rows_by_file': dict(sorted(rows_by_file.items())),
            'k1_pod_records': k1_counts, 'observation_basis_by_file': dict(sorted(basis_by_file.items())),
            'evaluation_only': ['evaluation_only/incident_entry.json (Phase-3 converter)', OUT['host_commands'],
                                OUT['probes']],
            'integrity': dict(sorted(self.integrity.items())), 'problems': self.problems, 'notes': self.notes,
            'inputs': dict(sorted(self.inputs.items())), 'files': files, 'row_semantics': ROW_SEMANTICS,
            'format': 'phase3/CAPTURE_FORMAT_STAGE2.md'}
        write_bytes_exclusive(self.out / MANIFEST_NAME, json_document(manifest))
        return manifest


def convert(capture, output, *, window: WindowSpec = DEFAULT_WINDOW, observer_dir='context',
            include_probe_traffic=False, verify_raw=True):
    """Convert one capture into `output` (which must not exist); returns the stage2 manifest.

    The Phase-3 converter writes its files first, into a hidden sibling staging directory; the Stage-2 rows
    follow; the directory is renamed to `output` only when everything was written. On any error the staging
    directory is removed and nothing is left at `output`."""
    capture, output = Path(capture).resolve(), Path(output).resolve()
    if output.exists():
        raise SystemExit('Output exists; choose a new directory: ' + str(output))
    if not (capture / 'capture.json').is_file():
        raise SystemExit('Not a capture directory (no capture.json): ' + str(capture))
    staging = output.parent / ('.' + output.name + '.converting')
    if staging.exists():
        raise SystemExit('A staging directory exists (an interrupted conversion?); remove it first: ' + str(staging))
    created = False
    try:
        CC.convert(capture, staging, include_probe_traffic)
        created = True
        manifest = Stage2Conversion(capture, staging, window=window, observer_dir=observer_dir,
                                    include_probe_traffic=include_probe_traffic, verify_raw=verify_raw).run()
        os.rename(staging, output)
    except BaseException:
        if created or staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


# ---------------------------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------------------------
def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument('--capture', type=Path, help='a capture directory, e.g. phase3/captures/G2-001')
    result.add_argument('--out', '--output', dest='out', type=Path,
                        help='output directory (default <capture>/evidence, where aiops_kg.replay.load_capture_task '
                             'reads; it must not exist)')
    result.add_argument('--observer-dir', default='context',
                        help='directory of the watch, recheck and clock-probe files inside the capture (default '
                             'context; CAPTURE_FORMAT_STAGE2.md)')
    result.add_argument('--window-start-mark', default=DEFAULT_WINDOW.start_mark,
                        help='capture.json timeline mark that starts the decision window (default reference_start)')
    result.add_argument('--window-end-mark', default=DEFAULT_WINDOW.end_mark,
                        help='timeline mark that ends it (default recovery_end)')
    result.add_argument('--window-margin-seconds', type=float, default=DEFAULT_WINDOW.margin_seconds,
                        help='margin on both sides of the decision window for snapshot rows (default 60)')
    result.add_argument('--window-all', action='store_true', help='keep every cache snapshot (no window)')
    result.add_argument('--include-probe-traffic', action='store_true',
                        help='passed to the Phase-3 converter: keep spans of evaluator probes (not recommended)')
    result.add_argument('--no-verify-raw', action='store_true',
                        help='skip the SHA-256 check of the watch and recheck raw archives (*.jsonl.gz)')
    result.add_argument('--self-test', action='store_true',
                        help='build a synthetic Stage-2 capture with the collectors\' own code (fake clocks, no '
                             'cluster or network) and the 22 Sep fixture, convert them and check the results')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.capture:
        parser().error('--capture or --self-test is required')
    capture = args.capture.resolve()
    try:
        window = WindowSpec(args.window_start_mark, args.window_end_mark, args.window_margin_seconds, args.window_all)
        manifest = convert(capture, (args.out or capture / 'evidence').resolve(), window=window,
                           observer_dir=args.observer_dir, include_probe_traffic=args.include_probe_traffic,
                           verify_raw=not args.no_verify_raw)
    except ValueError as error:
        raise SystemExit('Conversion refused: {}: {}'.format(type(error).__name__, error)) from error
    print(json.dumps({key: manifest[key] for key in ('converter', 'capture_id', 'counts_by_kind', 'k1_pod_records',
                                                     'window', 'problems', 'notes')}, indent=2))
    return 2 if manifest['problems'] else 0


# ---------------------------------------------------------------------------------------------------------------
# A synthetic Stage-2 capture (--self-test and tests/test_stage2_converter.py). Every observer file is written by the
# collectors' own code: the watch collector's WatchCollector and the recheck loop's RecheckLoop (fake host clocks;
# the recheck's HTTP connection answered from a scripted namespace), the poller v1.1 (or the v1) collect()
# with injected kubectl, clock and UUID (as tests/test_stage2_poller_v1_1.py injects them), the smoke kit's
# clock_probe.probe/summarise, scripts/host_command_receipt_v1.run_host_command and scripts/per_pod_probe_v1's
# PerPodProbeLoop. The scenario is an arm-G G2 capture compressed to one namespace: a 3-replica recommendationservice
# rollout at T0 = 60 s with a container kill of a new-revision replica at T0 + 15 s, a 2-replica catalog, their
# EndpointSlices and PodDisruptionBudgets; a watch ERROR 410 at the start and a pods watch break (gap 97.5-100.63 s);
# one slow recheck GET (two missed ticks) and one HTTP 500 (a failed tick).
# ---------------------------------------------------------------------------------------------------------------
SYNTHETIC_CAPTURE_ID = 'SYNTH-G2-001'
SYNTHETIC_NAMESPACE = 'aiops-s2-synth-g2-001-c0de'
SYNTHETIC_START_NS = timestamp_ns('2026-10-19T10:00:00Z')
SYNTHETIC_MONOTONIC0_NS = 7_000 * 10 ** 9
SYNTHETIC_COLLECTIONS = {'poller': '5e7a0003-0000-4000-8000-000000000003',
                         'watch': '5e7a0001-0000-4000-8000-000000000001',
                         'recheck': '5e7a0002-0000-4000-8000-000000000002'}
SYNTHETIC_TIMELINE = {'deployed': -20.0, 'context_collector_started': 0.1, 'reference_start': 9.0,
                      'reference_end': 39.0, 'probe_nominal_start': 39.0, 'target_start': 49.0, 'T0_trigger': 60.0,
                      'change_patch_start': 60.05, 'fault_launch': 75.0, 'pre_fault_end': 75.0, 'fault_ack': 75.3,
                      'active_start': 75.3, 'change_rollout_returned': 82.5, 'active_end': 95.3, 'drain_start': 95.3,
                      'drain_end': 100.3, 'recovery_end': 130.3, 'probes_closed': 130.5, 'target_end': 185.0,
                      'export_done': 200.0}
SYNTHETIC_WATCH_STREAMS = {   # resource: [(list request, stream open, stream end or None, end cause)]
    'pods': [(0.40, 0.44, 99.20, 'eof_unterminated'), (100.60, 100.65, None, None)],
    'deployments': [(0.42, 0.46, 0.70, 'error_event'), (1.10, 1.15, None, None)],
    'replicasets': [(0.44, 0.48, None, None)],
    'endpointslices': [(0.46, 0.50, None, None)],
    'poddisruptionbudgets': [(0.48, 0.52, None, None)]}
SYNTHETIC_BOOKMARKS = ((90.00, 'poddisruptionbudgets'), (97.50, 'pods'))
SYNTHETIC_WATCH_STOP, SYNTHETIC_RECHECK = 220.0, (30.0, 101)  # recheck: first tick and tick count (T0 - 30 s ... 130 s)
SYNTHETIC_KILL = {'target': 'rec-d', 'lookup': (74.60, 74.85), 'kill': (75.00, 75.30)}
SYNTHETIC_NODE_SKEW_NS = -250_000_000                             # node clock 0.25 s behind the host
API_VERSIONS = {'pods': 'v1', 'deployments': 'apps/v1', 'replicasets': 'apps/v1',
                'endpointslices': 'discovery.k8s.io/v1', 'poddisruptionbudgets': 'policy/v1'}
SYNTHETIC_IMAGES = {'recommendationservice': 'us-central1-docker.pkg.dev/google-samples/microservices-demo/'
                                             'recommendationservice:v0.10.6',
                    'productcatalogservice': 'us-central1-docker.pkg.dev/google-samples/microservices-demo/'
                                            'productcatalogservice:v0.10.6'}
SYNTHETIC_PORTS = {'recommendationservice': 8080, 'productcatalogservice': 3550}
STATUS_410 = {'kind': 'Status', 'apiVersion': 'v1', 'metadata': {}, 'status': 'Failure',
              'message': 'too old resource version: 1001 (1050)', 'reason': 'Expired', 'code': 410}


def _ns(seconds):
    return int(round(seconds * 1e9))


def synthetic_uid(name):
    """Deterministic UUID of a synthetic object (uuid5 of its key)."""
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'https://example.invalid/aiops-stage2-synthetic/' + name))


def synthetic_container_id(name):
    return sha(('synthetic-container/' + name).encode())


class _FakeHostClock:
    """Wall clock (ns since the epoch) and monotonic clock (ns) of one fake host process. at() moves to an absolute
    instant (seconds after the synthetic start; never backwards); every reading advances both clocks by step_ns."""

    def __init__(self, at_seconds=0.0, step_ns=1_000):
        self.wall, self.step = SYNTHETIC_START_NS + _ns(at_seconds), step_ns

    @property
    def mono(self):
        return SYNTHETIC_MONOTONIC0_NS + (self.wall - SYNTHETIC_START_NS)

    def seconds(self):
        return (self.wall - SYNTHETIC_START_NS) / 1e9

    def at(self, seconds):
        self.wall = max(self.wall, SYNTHETIC_START_NS + _ns(seconds))

    def advance(self, seconds):
        self.wall += _ns(seconds)

    def read(self):
        self.wall += self.step
        return {'at': iso_ns(self.wall), 'at_ns': self.wall, 'monotonic_ns': self.mono}

    def wall_ns(self):
        self.wall += self.step
        return self.wall

    def mono_ns(self):
        self.wall += self.step
        return self.mono


def synthetic_stamp(seconds):
    """Kubelet / API-server stamp: RFC 3339, whole seconds (truncated), of the synthetic instant."""
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime((SYNTHETIC_START_NS + _ns(seconds)) // 10 ** 9))


def synthetic_iso_us(seconds):
    """Host receipt as Phase 3's runner writes it: ISO with microseconds and 'Z'."""
    ns = SYNTHETIC_START_NS + _ns(seconds)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ns // 10 ** 9)) + '.{:06d}Z'.format(ns % 10 ** 9 // 1000)


class SyntheticWorld:
    """The namespace over time: every change is (t, event type, resource, key, typed object); the state at t is
    the latest version of every object changed at or before t and not deleted."""

    def __init__(self):
        self.ns, self.params, self.changes, self.deleted, self.rv = SYNTHETIC_NAMESPACE, {}, [], set(), 1000

    # -- objects ------------------------------------------------------------------------------------------------
    def meta(self, p, rv, labels, owners=None, annotations=None, generation=None):
        meta = {'name': p['name'], 'namespace': self.ns, 'uid': p['uid'], 'resourceVersion': rv,
                'creationTimestamp': synthetic_stamp(p['created']), 'labels': labels,
                'annotations': dict({'kubectl.kubernetes.io/last-applied-configuration': '{}'}, **(annotations or {})),
                'managedFields': [{'manager': 'kube-controller-manager', 'operation': 'Update'}]}
        if generation is not None:
            meta['generation'] = generation
        if owners:
            meta['ownerReferences'] = owners
        if p.get('deleting') is not None:
            meta['deletionTimestamp'] = synthetic_stamp(p['deleting'])
            meta['deletionGracePeriodSeconds'] = 30
        return meta

    def build(self, resource, p, rv):
        kind = RESOURCES[resource][0]
        builder = getattr(self, '_' + resource)
        return dict({'kind': kind, 'apiVersion': API_VERSIONS[resource]}, **builder(p, rv))

    def _pods(self, p, rv):
        owners = [{'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'name': p['rs'], 'uid': p['rs_uid'],
                   'controller': True, 'blockOwnerDeletion': True}]
        meta = self.meta(p, rv, {'app': p['app'], 'pod-template-hash': p['hash']}, owners)
        container = {'name': 'server', 'image': SYNTHETIC_IMAGES[p['app']],
                     'imageID': SYNTHETIC_IMAGES[p['app']] + '@sha256:' + sha(p['app'].encode()),
                     'ready': p['ready'], 'restartCount': p['restarts'],
                     'started': p['phase'] == 'Running' and p.get('terminated') is None}
        if p.get('container_id'):
            container['containerID'] = 'containerd://' + p['container_id']
        if p['phase'] == 'Pending':
            container['state'] = {'waiting': {'reason': 'ContainerCreating'}}
        elif p.get('terminated') is not None:
            container['state'] = {'terminated': {'exitCode': 137, 'reason': 'Error',
                                                 'startedAt': synthetic_stamp(p['started']),
                                                 'finishedAt': synthetic_stamp(p['terminated']),
                                                 'containerID': 'containerd://' + p['container_id']}}
        else:
            container['state'] = {'running': {'startedAt': synthetic_stamp(p['started'])}}
        container['lastState'] = {'terminated': dict(p['last'])} if p.get('last') else {}
        ready = 'True' if p['ready'] else 'False'
        conditions = [{'type': 'PodReadyToStartContainers', 'status': 'True' if p['phase'] == 'Running' else 'False',
                       'lastProbeTime': None, 'lastTransitionTime': synthetic_stamp(p['started'] or p['created'])},
                      {'type': 'Initialized', 'status': 'True', 'lastProbeTime': None,
                       'lastTransitionTime': synthetic_stamp(p['created'])},
                      {'type': 'Ready', 'status': ready, 'lastProbeTime': None,
                       'lastTransitionTime': synthetic_stamp(p['ready_since'])},
                      {'type': 'ContainersReady', 'status': ready, 'lastProbeTime': None,
                       'lastTransitionTime': synthetic_stamp(p['ready_since'])},
                      {'type': 'PodScheduled', 'status': 'True', 'lastProbeTime': None,
                       'lastTransitionTime': synthetic_stamp(p['created'])}]
        status = {'phase': p['phase'], 'conditions': conditions, 'hostIP': '172.18.0.2', 'qosClass': 'Burstable',
                  'startTime': synthetic_stamp(p['created']), 'containerStatuses': [container]}
        if p.get('ip'):
            status.update(podIP=p['ip'], podIPs=[{'ip': p['ip']}])
        spec = {'nodeName': 'aiops-context-pilot-control-plane', 'restartPolicy': 'Always',
                'serviceAccountName': 'default',
                'containers': [{'name': 'server', 'image': SYNTHETIC_IMAGES[p['app']],
                                'ports': [{'containerPort': SYNTHETIC_PORTS[p['app']]}],
                                'env': [{'name': 'PORT', 'value': str(SYNTHETIC_PORTS[p['app']])}]}]}
        return {'metadata': meta, 'spec': spec, 'status': status}

    def _deployments(self, p, rv):
        meta = self.meta(p, rv, {'app': p['name']}, annotations={'deployment.kubernetes.io/revision': p['revision']},
                         generation=p['generation'])
        progressing = {'type': 'Progressing', 'status': 'True', 'reason': p['progressing'],
                       'lastUpdateTime': synthetic_stamp(p['progressing_since']),
                       'lastTransitionTime': synthetic_stamp(p['created'])}
        available = {'type': 'Available', 'status': 'True', 'reason': 'MinimumReplicasAvailable',
                     'lastUpdateTime': synthetic_stamp(p['created'] + 5),
                     'lastTransitionTime': synthetic_stamp(p['created'] + 5)}
        status = {'observedGeneration': p['observed'], 'replicas': p['status_replicas'],
                  'updatedReplicas': p['updated'], 'readyReplicas': p['ready'], 'availableReplicas': p['available'],
                  'conditions': [available, progressing]}
        if p['unavailable']:
            status['unavailableReplicas'] = p['unavailable']
        spec = {'replicas': p['replicas'], 'selector': {'matchLabels': {'app': p['name']}},
                'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': 1, 'maxUnavailable': 0}},
                'template': {'metadata': {'labels': {'app': p['name']},
                                          'annotations': {'aiops.project/revision': p['template_revision']}},
                             'spec': {'containers': [{'name': 'server', 'image': SYNTHETIC_IMAGES[p['name']]}]}}}
        return {'metadata': meta, 'spec': spec, 'status': status}

    def _replicasets(self, p, rv):
        owners = [{'apiVersion': 'apps/v1', 'kind': 'Deployment', 'name': p['app'], 'uid': p['dep_uid'],
                   'controller': True, 'blockOwnerDeletion': True}]
        meta = self.meta(p, rv, {'app': p['app'], 'pod-template-hash': p['hash']}, owners,
                         {'deployment.kubernetes.io/revision': p['revision']}, generation=p['generation'])
        selector = {'matchLabels': {'app': p['app'], 'pod-template-hash': p['hash']}}
        spec = {'replicas': p['replicas'], 'selector': selector,
                'template': {'metadata': {'labels': {'app': p['app'], 'pod-template-hash': p['hash']}},
                             'spec': {'containers': [{'name': 'server', 'image': SYNTHETIC_IMAGES[p['app']]}]}}}
        status = {'replicas': p['replicas'], 'fullyLabeledReplicas': p['replicas'], 'readyReplicas': p['ready'],
                  'availableReplicas': p['ready'], 'observedGeneration': p['generation']}
        return {'metadata': meta, 'spec': spec, 'status': status}

    def _endpointslices(self, p, rv):
        owners = [{'apiVersion': 'v1', 'kind': 'Service', 'name': p['service'],
                   'uid': synthetic_uid('svc-' + p['service']), 'controller': True, 'blockOwnerDeletion': True}]
        meta = self.meta(p, rv, {'kubernetes.io/service-name': p['service'],
                                 'endpointslice.kubernetes.io/managed-by': 'endpointslice-controller.k8s.io'}, owners)
        return {'metadata': meta, 'addressType': 'IPv4', 'endpoints': [dict(e) for e in p['endpoints']],
                'ports': [{'name': 'grpc', 'port': SYNTHETIC_PORTS[p['service']], 'protocol': 'TCP'}]}

    def _poddisruptionbudgets(self, p, rv):
        meta = self.meta(p, rv, {'app': p['app']}, generation=1)
        condition = {'type': 'DisruptionAllowed', 'status': 'True' if p['allowed'] else 'False',
                     'reason': 'SufficientPods' if p['allowed'] else 'InsufficientPods',
                     'lastTransitionTime': synthetic_stamp(p['since']), 'observedGeneration': 1}
        return {'metadata': meta, 'spec': {'maxUnavailable': 1, 'selector': {'matchLabels': {'app': p['app']}}},
                'status': {'observedGeneration': 1, 'disruptionsAllowed': p['allowed'], 'currentHealthy': p['healthy'],
                           'desiredHealthy': p['desired'], 'expectedPods': p['expected'], 'disruptedPods': {},
                           'conditions': [condition]}}

    # -- changes and state ----------------------------------------------------------------------------------------
    def put(self, t, resource, key, **changes):
        known = key in self.params
        params = dict(self.params[key][1]) if known else {}
        params.update(changes)
        self.params[key] = (resource, params)
        self.rv += 1
        self.changes.append((t, 'MODIFIED' if known else 'ADDED', resource, key,
                             self.build(resource, params, str(self.rv))))

    def delete(self, t, key):
        resource, params = self.params[key]
        self.rv += 1
        self.deleted.add(key)
        self.changes.append((t, 'DELETED', resource, key, self.build(resource, params, str(self.rv))))

    def state(self, resource, t):
        current = {}
        for when, event, kind, key, obj in self.changes:
            if when > t:
                break
            if kind != resource:
                continue
            if event == 'DELETED':
                current.pop(key, None)
            else:
                current[key] = obj
        return sorted(current.values(), key=lambda obj: obj['metadata']['name'])

    def version(self, t):
        return str(max([int(obj['metadata']['resourceVersion']) for when, _, _, _, obj in self.changes if when <= t]
                       or [1000]))

    def api_list(self, resource, t, selector=None):
        """A raw API LIST body (items without kind and apiVersion, as the API server sends them)."""
        items = []
        for obj in self.state(resource, t):
            labels = obj['metadata'].get('labels') or {}
            if selector is not None:
                key, values = selector
                if labels.get(key) not in values:
                    continue
            items.append({k: v for k, v in obj.items() if k not in ('kind', 'apiVersion')})
        return json.dumps({'kind': RESOURCES[resource][0] + 'List', 'apiVersion': API_VERSIONS[resource],
                           'metadata': {'resourceVersion': self.version(t)}, 'items': items}).encode('utf-8')

    def kubectl_list(self, resource, t):
        """`kubectl get <resource> -o json` output: a generic List of typed items (the poller's input)."""
        if resource == 'nodes':
            items = [{'apiVersion': 'v1', 'kind': 'Node',
                      'metadata': {'name': 'aiops-context-pilot-control-plane', 'uid': synthetic_uid('node'),
                                   'resourceVersion': '900', 'creationTimestamp': synthetic_stamp(-3600)},
                      'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}]
        else:
            items = self.state(resource, t)
        return json.dumps({'apiVersion': 'v1', 'kind': 'List', 'metadata': {'resourceVersion': ''},
                           'items': items}, indent=4)

    # -- the scenario ---------------------------------------------------------------------------------------------
    def pods_of(self, service):
        return sorted((key, p) for key, (resource, p) in self.params.items()
                      if resource == 'pods' and p['app'] == service and key not in self.deleted)

    def refresh_service(self, t, service):
        """EndpointSlice and PodDisruptionBudget of a service from its Pods (as the controllers would)."""
        pods = self.pods_of(service)
        endpoints = [{'addresses': [p['ip']], 'conditions': {'ready': p['ready'] and p.get('deleting') is None,
                                                               'serving': p['ready'],
                                                               'terminating': p.get('deleting') is not None},
                      'targetRef': {'kind': 'Pod', 'namespace': self.ns, 'name': p['name'], 'uid': p['uid']},
                      'nodeName': 'aiops-context-pilot-control-plane'} for _, p in pods if p.get('ip')]
        self.put(t, 'endpointslices', 'eps-' + service, endpoints=endpoints)
        expected = 3 if service == 'recommendationservice' else 2
        healthy = sum(1 for _, p in pods if p['ready'] and p.get('deleting') is None)
        allowed = max(0, healthy - (expected - 1))
        previous = self.params['pdb-' + service][1]
        if (previous['healthy'], previous['allowed']) != (healthy, allowed):
            since = previous['since'] if (previous['allowed'] > 0) == (allowed > 0) else t
            self.put(t + 0.05, 'poddisruptionbudgets', 'pdb-' + service, healthy=healthy, allowed=allowed, since=since)

    def new_pod(self, t, key, service, rs_key, ip, *, created=None, running=None, ready=None):
        rs = self.params[rs_key][1]
        params = {'name': '{}-{}'.format(rs['name'], key.split('-')[-1] * 5), 'uid': synthetic_uid(key),
                  'app': service, 'rs': rs['name'], 'rs_uid': rs['uid'], 'hash': rs['hash'],
                  'created': t if created is None else created, 'phase': 'Pending', 'ip': None, 'ready': False,
                  'ready_since': t if created is None else created, 'restarts': 0, 'started': None,
                  'container_id': None, 'deleting': None, 'terminated': None, 'last': None}
        if running is not None:
            params.update(phase='Running', ip=ip, started=running, container_id=synthetic_container_id(key + '/0'),
                          ready=ready is not None, ready_since=ready if ready is not None else running)
        self.put(t, 'pods', key, **params)

    def scenario(self):
        """The G2 timeline (seconds after 10:00:00Z); every API change the kubelet and controllers would make."""
        dep = {'recommendationservice': synthetic_uid('dep-rec'), 'productcatalogservice': synthetic_uid('dep-cat')}
        for service, replicas, created in (('recommendationservice', 3, -500.0), ('productcatalogservice', 2, -500.0)):
            self.put(-400.0, 'deployments', 'dep-' + service, name=service, uid=dep[service], created=created,
                     generation=1, revision='1', template_revision='1', replicas=replicas, observed=1,
                     status_replicas=replicas, updated=replicas, ready=replicas, available=replicas, unavailable=0,
                     progressing='NewReplicaSetAvailable', progressing_since=created + 5)
        for key, service, template_hash, replicas in (('rs-rec-1', 'recommendationservice', '5c8859fcbf', 3),
                                                      ('rs-cat-1', 'productcatalogservice', '7cd5497c86', 2)):
            self.put(-400.0, 'replicasets', key, name='{}-{}'.format(service, template_hash), uid=synthetic_uid(key),
                     app=service, hash=template_hash, dep_uid=dep[service], created=-500.0, generation=1,
                     revision='1', replicas=replicas, ready=replicas)
        for service, expected in (('recommendationservice', 3), ('productcatalogservice', 2)):
            self.put(-400.0, 'poddisruptionbudgets', 'pdb-' + service, name=service,
                     uid=synthetic_uid('pdb-' + service), app=service, created=-500.0, healthy=expected,
                     desired=expected - 1, expected=expected, allowed=1, since=-495.0)
            self.put(-400.0, 'endpointslices', 'eps-' + service,
                     name=service + ('-xk2p9' if service == 'recommendationservice' else '-m7d4q'),
                     uid=synthetic_uid('eps-' + service), service=service, created=-500.0, endpoints=[])
        for key, service, rs_key, ip in (('rec-a', 'recommendationservice', 'rs-rec-1', '10.244.0.11'),
                                         ('rec-b', 'recommendationservice', 'rs-rec-1', '10.244.0.12'),
                                         ('rec-c', 'recommendationservice', 'rs-rec-1', '10.244.0.13'),
                                         ('cat-a', 'productcatalogservice', 'rs-cat-1', '10.244.0.31'),
                                         ('cat-b', 'productcatalogservice', 'rs-cat-1', '10.244.0.32')):
            self.new_pod(-400.0, key, service, rs_key, ip, created=-499.0, running=-498.0, ready=-494.0)
        self.refresh_service(-399.0, 'recommendationservice')
        self.refresh_service(-399.0, 'productcatalogservice')
        rec = 'dep-recommendationservice'
        # T0 = 60 s: the rollout patch (revision 2); maxSurge 1, maxUnavailable 0: three replacement steps
        self.put(60.30, 'deployments', rec, generation=2, revision='2', template_revision='2')
        self.put(60.35, 'deployments', rec, observed=2, status_replicas=4, updated=0, unavailable=1,
                 progressing='ReplicaSetUpdated', progressing_since=60.35)
        self.put(60.40, 'replicasets', 'rs-rec-2', name='recommendationservice-7d9f6c4b8d',
                 uid=synthetic_uid('rs-rec-2'), app='recommendationservice', hash='7d9f6c4b8d',
                 dep_uid=dep['recommendationservice'], created=60.40, generation=1, revision='2', replicas=1, ready=0)
        steps = (('rec-d', '10.244.0.21', 60.45, 'rec-a'), ('rec-e', '10.244.0.22', 66.50, 'rec-b'),
                 ('rec-f', '10.244.0.23', 72.70, 'rec-c'))
        for number, (key, ip, start, old) in enumerate(steps, start=1):
            self.new_pod(start, key, 'recommendationservice', 'rs-rec-2', ip)
            self.put(start + 0.15, 'pods', key, ip=ip)
            self.put(start + 1.25, 'pods', key, phase='Running', started=start + 1.25,
                     container_id=synthetic_container_id(key + '/0'))
            if key != 'rec-f':
                self.put(start + 5.75, 'pods', key, ready=True, ready_since=start + 5.75)
                self.refresh_service(start + 5.80, 'recommendationservice')
                self.put(start + 5.85, 'replicasets', 'rs-rec-2', ready=number)
                self.put(start + 5.90, 'replicasets', 'rs-rec-1', replicas=3 - number, ready=3 - number)
                self.put(start + 5.91, 'replicasets', 'rs-rec-2', replicas=min(3, number + 1))
                self.put(start + 5.95, 'pods', old, deleting=start + 5.95, ready=False, ready_since=start + 5.95)
                self.refresh_service(start + 6.00, 'recommendationservice')
                self.delete(start + 8.35, old)
                self.refresh_service(start + 8.40, 'recommendationservice')
        # T0 + 15 s: the kill of rec-d (Ready since 66.2 s); the kubelet reports at 75.4 s and restarts it at 76.5 s
        killed = self.params['rec-d'][1]
        old_id, new_id = killed['container_id'], synthetic_container_id('rec-d/1')
        self.put(75.40, 'pods', 'rec-d', ready=False, ready_since=75.0, terminated=75.0)
        self.refresh_service(75.45, 'recommendationservice')
        self.put(75.47, 'replicasets', 'rs-rec-2', ready=1)
        last = {'exitCode': 137, 'reason': 'Error', 'startedAt': synthetic_stamp(killed['started']),
                'finishedAt': synthetic_stamp(75.0), 'containerID': 'containerd://' + old_id}
        self.put(76.50, 'pods', 'rec-d', terminated=None, restarts=1, last=last, started=76.50, container_id=new_id)
        # the rollout's last step continues: rec-f Ready at 79.3 s, rec-c leaves, rec-d Ready again at 81.3 s
        self.put(79.30, 'pods', 'rec-f', ready=True, ready_since=79.30)
        self.refresh_service(79.35, 'recommendationservice')
        self.put(79.40, 'replicasets', 'rs-rec-2', ready=2)
        self.put(79.50, 'pods', 'rec-c', deleting=79.50, ready=False, ready_since=79.50)
        self.put(79.55, 'replicasets', 'rs-rec-1', replicas=0, ready=0)
        self.refresh_service(79.60, 'recommendationservice')
        self.put(81.30, 'pods', 'rec-d', ready=True, ready_since=81.30)
        self.refresh_service(81.35, 'recommendationservice')
        self.put(81.45, 'replicasets', 'rs-rec-2', ready=3)
        self.delete(81.90, 'rec-c')
        self.refresh_service(82.00, 'recommendationservice')
        self.put(82.20, 'deployments', rec, status_replicas=3, updated=3, ready=3, available=3, unavailable=0,
                 progressing='NewReplicaSetAvailable', progressing_since=82.20)
        # inside the pods watch break (97.5-100.63 s): a status update the stream never delivers (seen at the relist)
        self.put(99.60, 'pods', 'rec-e', ip='10.244.0.22')
        self.put(150.00, 'pods', 'cat-b', ip='10.244.0.32')
        self.changes.sort(key=lambda change: change[0])
        return {'kill_target_uid': killed['uid'], 'kill_target_name': killed['name'], 'kill_target_ip': killed['ip'],
                'killed_container_id': old_id, 'restarted_container_id': new_id}


class _FakeAPIConnection:
    """http.client.HTTPConnection for the recheck loop: each GET is answered from the synthetic namespace at the fake
    clock's instant (selectors applied); scripted: a slow pods GET at 70 s and an HTTP 500 for replicasets at 100 s."""

    def __init__(self, world, clock):
        self.world, self.clock, self.sock, self.target = world, clock, None, None

    def request(self, method, target, headers=None):
        self.sock, self.target = self.sock or object(), target
        self.clock.advance(0.002)

    def getresponse(self):
        from urllib.parse import parse_qs, unquote, urlsplit
        parts = urlsplit(self.target)
        resource = parts.path.rstrip('/').rsplit('/', 1)[-1]
        selector = unquote(parse_qs(parts.query).get('labelSelector', [''])[0])
        key, _, values = selector.partition(' in ')
        values = tuple(v.strip() for v in values.strip('()').split(','))
        now = self.clock.seconds()
        slow = resource == 'pods' and 70.0 <= now < 70.5
        state_time = now + 0.001
        self.clock.advance(2.3 if slow else 0.011)
        if resource == 'replicasets' and 100.0 <= now < 100.5:
            body = json.dumps({'kind': 'Status', 'apiVersion': 'v1', 'metadata': {}, 'status': 'Failure',
                               'message': 'injected', 'reason': 'InternalError', 'code': 500}).encode()
            return _FakeResponse(500, body)
        return _FakeResponse(200, self.world.api_list(resource, state_time, (key.strip(), values)))

    def close(self):
        self.sock = None


class _FakeResponse:
    def __init__(self, status, body):
        self.status, self.body, self.will_close = status, body, False

    def read(self):
        return self.body


def _script_modules():
    """The collectors and helpers, imported from the repository (read-only; no bytecode written)."""
    sys.dont_write_bytecode = True
    for directory in (ROOT / 'scripts', ROOT / 'infrastructure' / 'stage2' / 'smoke'):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    import clock_probe                              # noqa: F401  (infrastructure/stage2/smoke)
    import collect_deployment_history               # noqa: F401  (poller v1)
    import collect_deployment_history_v1_1          # noqa: F401
    import collect_watch_v1
    import host_command_receipt_v1
    import per_pod_probe_v1
    import recheck_loop_v1
    from aiops_kg import fault_control_kill
    return {'clock_probe': clock_probe, 'poller_v1': collect_deployment_history,
            'poller_v1_1': collect_deployment_history_v1_1, 'watch': collect_watch_v1,
            'host_command': host_command_receipt_v1, 'per_pod_probe': per_pod_probe_v1, 'recheck': recheck_loop_v1,
            'kill': fault_control_kill}


def _drive_poller(module, world, output):
    """Poller v1.1 (or v1) collect() with an injected kubectl, clock, monotonic clock, sleep and UUID."""
    import subprocess
    import uuid
    from datetime import datetime, timedelta, timezone
    from unittest import mock
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    clock = _FakeHostClock(0.20)

    def utc_now():
        clock.advance(0.0005)
        return epoch + timedelta(microseconds=clock.wall // 1000)

    def run(argv, **kwargs):
        if 'config' in argv:
            clock.advance(0.05)
            config = {'contexts': [{'name': 'kind-aiops-context-pilot',
                                    'context': {'cluster': 'kind-aiops-context-pilot'}}],
                      'clusters': [{'name': 'kind-aiops-context-pilot',
                                    'cluster': {'server': 'https://127.0.0.1:6443'}}]}
            return subprocess.CompletedProcess(argv, 0, json.dumps(config), '')
        resource = argv[argv.index('get') + 1]
        state_time = clock.seconds() + 0.10
        clock.advance(0.25)
        return subprocess.CompletedProcess(argv, 0, world.kubectl_list(resource, state_time), '')

    args = argparse.Namespace(context='kind-aiops-context-pilot', namespace=SYNTHETIC_NAMESPACE, kubeconfig=None,
                              output=str(output), kubectl='kubectl', kinds=['pods', 'replicasets', 'deployments'],
                              include_nodes=True, allow_server_host=None, samples=70, interval_seconds=2,
                              duration_seconds=240, request_timeout_seconds=10)
    with mock.patch('uuid.uuid4', return_value=uuid.UUID(SYNTHETIC_COLLECTIONS['poller'])):
        return module.collect(args, run=run, clock=utc_now, monotonic=lambda: clock.mono / 1e9,
                              sleep=lambda seconds: clock.advance(seconds))


def _drive_watch(watch, world, context):
    """The watch collector's own WatchCollector, driven through the scripted streams with a fake host clock."""
    from types import SimpleNamespace
    from unittest import mock
    clock = _FakeHostClock(0.30)
    args = watch.parser().parse_args(['--namespace', SYNTHETIC_NAMESPACE, '--output-dir', str(context),
                                      '--proxy-url', 'http://127.0.0.1:1', '--seconds', str(SYNTHETIC_WATCH_STOP)])
    paths = watch.prepare_output(context, watch.FILES)
    actions = []
    for resource, streams in SYNTHETIC_WATCH_STREAMS.items():
        for listed, opened, ended, cause in streams:
            actions.append((listed, 0, 'list', resource, None))
            actions.append((opened, 1, 'open', resource, None))
            if ended is not None:
                actions.append((ended, 3, cause, resource, None))
            for when, event, kind, _, obj in world.changes:
                receipt = when + 0.02
                if kind == resource and when > listed + 0.005 and (ended is None or receipt < ended):
                    actions.append((max(receipt, opened + 0.001), 2, 'event', resource, (event, obj)))
    for when, resource in SYNTHETIC_BOOKMARKS:
        actions.append((when, 2, 'bookmark', resource, None))
    tick = 1
    while 0.30 + tick < SYNTHETIC_WATCH_STOP:
        actions.append((0.30 + tick, 5, 'periodic', None, None))
        tick += 1
    actions.sort(key=lambda action: (action[0], action[1], str(action[3])))
    stub = SimpleNamespace(decoder=SimpleNamespace(chunks=0), pending=b'')
    with mock.patch.object(watch, 'host_time', clock.read):
        collector = watch.WatchCollector(args, {}, paths, 'http://127.0.0.1:1', '127.0.0.1', 1)
        collector.collection_id = SYNTHETIC_COLLECTIONS['watch']
        collector.handles = {'events': open(paths['events'], 'xb'), 'snapshots': open(paths['snapshots'], 'xb')}
        collector.archive = watch.RawArchive(paths['raw'])
        try:
            clock.at(0.30)
            collector.start = clock.read()
            watch.write_manifest(paths['manifest'], collector.manifest('collecting', None, None, []), first=True)
            attempts, streams, versions = Counter(), {}, {}
            for when, _, action, resource, data in actions:
                clock.at(when)
                if action == 'list':
                    attempts[resource] += 1
                    started = clock.read()
                    body = world.api_list(resource, when + 0.005)
                    clock.at(when + 0.03)
                    received = clock.read()
                    version, objects = watch.parse_list(json.loads(body), resource, SYNTHETIC_NAMESPACE)
                    versions[resource] = version
                    collector.apply_list(resource, attempts[resource], watch.request_target(resource,
                                                                                            SYNTHETIC_NAMESPACE),
                                         started, received, body, version, objects)
                elif action == 'open':
                    number = streams[resource]['number'] + 1 if resource in streams else 1
                    stream_id = '{}/{}'.format(resource, number)
                    started = clock.read()
                    clock.at(when + 0.004)
                    head = clock.read()
                    query = {'watch': '1', 'resourceVersion': versions[resource], 'allowWatchBookmarks': 'true',
                             'timeoutSeconds': '1800'}
                    collector.record_stream_open(resource, {
                        'stream_id': stream_id, 'path': watch.request_target(resource, SYNTHETIC_NAMESPACE, query),
                        'resource_version': versions[resource], 'content_type': 'application/json',
                        'transfer_encoding': 'chunked', 'ok': True, 'http_status': 200}, started, head)
                    streams[resource] = {'number': number, 'id': stream_id, 'stats': Counter(), 'open': True}
                elif action in ('event', 'bookmark', 'error_event'):
                    stream = streams[resource]
                    if action == 'event':
                        event, obj = data
                    elif action == 'bookmark':
                        event, obj = 'BOOKMARK', {'kind': RESOURCES[resource][0], 'apiVersion': API_VERSIONS[resource],
                                                  'metadata': {'resourceVersion': world.version(when)}}
                    else:
                        event, obj = 'ERROR', dict(STATUS_410)
                    line = json.dumps({'type': event, 'object': obj}, separators=(',', ':')).encode('utf-8') + b'\n'
                    stats = stream['stats']
                    stats['lines'] += 1
                    stats['events'] += 1
                    stats['bytes'] += len(line) + 10
                    info = {'stream_id': stream['id'], 'line_index': stats['lines'], 'line_bytes': len(line),
                            'line_sha256': sha(line), 'line_chunks': 1 + len(line) // 4096}
                    received = clock.read()
                    projected = watch.project_object(obj, resource, SYNTHETIC_NAMESPACE) \
                        if event in OBJECT_EVENT_TYPES else None
                    collector.apply_event(resource, event, obj, projected, info, received, line)
                    if action == 'error_event':
                        detected = clock.read()
                        details = {'status_object': obj, 'error_code': 410, 'error_reason': 'Expired'}
                        collector.record_stream_end(resource, stream['id'], 'error_event', stats, stub, stub, details,
                                                    detected)
                        collector.open_gap(resource, 'error_event', dict(details, stream_id=stream['id'],
                                                                         detected=detected))
                        stream['open'] = False
                elif action == 'eof_unterminated':
                    stream = streams[resource]
                    detected = clock.read()
                    collector.record_stream_end(resource, stream['id'], action, stream['stats'], stub, stub, {},
                                                detected)
                    collector.open_gap(resource, action, {'stream_id': stream['id'], 'detected': detected})
                    stream['open'] = False
                elif action == 'periodic':
                    with collector.lock:
                        if any(state['state'] == 'open' for state in collector.states.values()):
                            collector.snapshot('periodic', None)
                        else:
                            collector.counts['periodic_snapshots_skipped_no_open_watch'] += 1
                        collector.archive.flush()
            clock.at(SYNTHETIC_WATCH_STOP)
            stop = clock.read()
            for resource in sorted(streams):
                if streams[resource]['open']:
                    collector.record_stream_end(resource, streams[resource]['id'], 'stopped',
                                                streams[resource]['stats'], stub, stub, {}, clock.read())
            return collector.finish('stop_file', stop, [])
        finally:
            for handle in collector.handles.values():
                if not handle.closed:
                    handle.close()
            if collector.archive is not None:
                collector.archive.close()


def _drive_recheck(recheck, watch, world, context):
    """The recheck loop's own RecheckLoop (tick, missed, emit, manifest) with a fake clock and API connection."""
    from unittest import mock
    first, count = SYNTHETIC_RECHECK
    clock = _FakeHostClock(first - 0.5)
    args = recheck.parser().parse_args(['--namespace', SYNTHETIC_NAMESPACE, '--output-dir', str(context),
                                        '--proxy-url', 'http://127.0.0.1:1', '--seconds', str(count + 1.0)])
    paths = watch.prepare_output(context, recheck.FILES)
    with mock.patch.object(recheck, 'host_time', clock.read):
        loop = recheck.RecheckLoop(args, {}, paths, 'http://127.0.0.1:1', '127.0.0.1', 1)
        loop.collection_id = SYNTHETIC_COLLECTIONS['recheck']
        loop.handle = open(paths['records'], 'xb')
        loop.archive = watch.RawArchive(paths['raw'])
        loop.connection = _FakeAPIConnection(world, clock)
        try:
            clock.at(first)
            loop.start = clock.read()
            watch.write_manifest(paths['manifest'], loop.manifest('collecting', None, None), first=True)
            interval = loop.interval_ns
            number = 0
            while number < count:                       # the schedule of RecheckLoop.run, on the fake clock
                scheduled = loop.start['monotonic_ns'] + number * interval
                clock.at(first + number + 0.002)
                loop.tick(number, scheduled)
                blocking, number = number, number + 1
                now = clock.mono
                while number < count:
                    instant = loop.start['monotonic_ns'] + number * interval
                    if instant >= now:
                        break
                    loop.missed(number, instant, blocking)
                    number += 1
            clock.at(first + count)
            stop = clock.read()
            end = {'record_type': 'collection_end', 'reason': 'stop_file', 'ticks': dict(loop.status_counts)}
            recheck.put_time(end, 'stop_requested', stop)
            loop.emit(end, stop)
        finally:
            loop.handle.close()
            loop.archive.close()
        manifest = loop.manifest('finished', 'stop_file', stop)
        watch.write_manifest(paths['manifest'], manifest)
    return manifest


def _clock_documents(clock_probe, label, at_seconds):
    """Ten paired node-clock readings with the smoke kit's own probe() and summarise() (node 0.25 s behind)."""
    clock = _FakeHostClock(at_seconds, step_ns=1)

    class Done:
        def __init__(self, out):
            self.stdout, self.stderr, self.returncode = out, b'', 0

    def runner(argv, **kwargs):
        clock.advance(0.04)
        node = clock.wall + SYNTHETIC_NODE_SKEW_NS
        clock.advance(0.06)
        return Done('{}.{:09d}\n'.format(node // 10 ** 9, node % 10 ** 9).encode())

    command, pairs = clock_probe.probe(['docker', '--context', 'desktop-linux'], 'aiops-context-pilot-control-plane',
                                       10, runner=runner, wall_ns=clock.wall_ns, mono_ns=clock.mono_ns,
                                       pause=lambda seconds: clock.advance(seconds))
    return {'test': 'Stage-2 capture clock probe',
            'script': 'infrastructure/stage2/smoke/clock_probe.py', 'script_sha256': sha(Path(clock_probe.__file__)
                                                                                         .read_bytes()),
            'written_by': 'phase3/convert_stage2.py synthetic capture', 'label': label,
            'started_at': synthetic_iso_us(at_seconds),
            'host_clock': {'implementation': 'synthetic', 'resolution_seconds': 1e-09, 'monotonic': False,
                           'adjustable': True, 'python': 'synthetic', 'platform': 'synthetic'},
            'node': 'aiops-context-pilot-control-plane', 'command': command, 'pairs': pairs,
            'summary': clock_probe.summarise(pairs)}


def _host_commands(host_command, kill, capture, info):
    """The F2 lookup and kill receipts, written by run_host_command into ground_truth/raw/."""
    import subprocess
    target = info['kill_target_name']
    listing = {'containers': [{'id': info['killed_container_id'], 'podSandboxId': sha(b'sandbox-rec-d'),
                               'metadata': {'name': 'server', 'attempt': 0}, 'state': 'CONTAINER_RUNNING',
                               'labels': {kill.POD_NAME_LABEL: target, kill.POD_NAMESPACE_LABEL: SYNTHETIC_NAMESPACE,
                                          kill.CONTAINER_NAME_LABEL: 'server',
                                          kill.POD_UID_LABEL: info['kill_target_uid']}}]}
    receipts = []
    for identifier, argv, (start, end), stdout in (
            ('kill-lookup-001', kill.list_containers_argv(kill.DOCKER_ARGV, kill.NODE), SYNTHETIC_KILL['lookup'],
             json.dumps(listing, indent=2).encode()),
            ('kill-target-001', kill.kill_argv(kill.DOCKER_ARGV, kill.NODE, info['killed_container_id']),
             SYNTHETIC_KILL['kill'], (info['killed_container_id'] + '\n').encode())):
        clock = _FakeHostClock(start)

        def runner(command, **kwargs):
            clock.at(end)
            return subprocess.CompletedProcess(command, 0, stdout, b'')

        _, _, receipt = host_command.run_host_command(identifier, argv, capture_dir=capture, folder='ground_truth/raw',
                                                      runner=runner, wall_ns=clock.wall_ns,
                                                      monotonic_ns=clock.mono_ns)
        receipts.append(receipt)
    return receipts


def _probe_rows(per_pod_probe, info):
    """Per-Pod probe rows from PerPodProbeLoop: nominal and pre_fault through the Services, active and recovery to the
    killed Pod's IP; the probe server is replaced by an exchange that fails while the target is down."""
    clock = _FakeHostClock(SYNTHETIC_TIMELINE['probe_nominal_start'])
    marks = {'probe_start': SYNTHETIC_TIMELINE['probe_nominal_start'], 'T0_trigger': SYNTHETIC_TIMELINE['T0_trigger'],
             'pre_fault_end': SYNTHETIC_TIMELINE['pre_fault_end'], 'active_start': SYNTHETIC_TIMELINE['active_start'],
             'active_end': SYNTHETIC_TIMELINE['active_end'], 'drain_end': SYNTHETIC_TIMELINE['drain_end'],
             'recovery_end': SYNTHETIC_TIMELINE['recovery_end']}
    target_address = '{}:{}'.format(info['kill_target_ip'], SYNTHETIC_PORTS['recommendationservice'])
    lines = {'n': 0}

    def exchange(request):
        lines['n'] += 1
        calls = []
        for service, field in (('recommendationservice', 'recommendation_address'),
                               ('productcatalogservice', 'catalog_address')):
            address = request[field]
            start = clock.mono
            down = address == target_address and 75.0 <= clock.seconds() < 81.3
            clock.advance(0.002 if down else 0.012)
            end = clock.mono
            calls.append({'record_type': 'fault_effect_rpc', 'probe_id': '{}/{}'.format(request['probe_id'], service),
                          'batch_probe_id': request['probe_id'], 'phase': request['phase'], 'service': service,
                          'address': address, 'outcome': 'rpc_error' if down else 'ok', 'functional_ok': not down,
                          'error': 'StatusCode.UNAVAILABLE: connection refused' if down else None,
                          'grpc_status': 'UNAVAILABLE' if down else 'OK', 'client_start_monotonic_ns': start,
                          'client_end_monotonic_ns': end, 'elapsed_ns': end - start,
                          'latency_ns': None if down else end - start,
                          'trace_id': sha('{}/{}'.format(request['probe_id'], service).encode())[:32]})
        return {'calls': calls}, {'line_index': lines['n'], 'host_received_at': iso_ns(clock.wall)}

    target = per_pod_probe.make_target('recommendationservice', info['kill_target_name'], info['kill_target_uid'],
                                       info['kill_target_ip'])
    def reached():
        return {name for name, at in marks.items() if clock.seconds() >= at}

    loop = per_pod_probe.PerPodProbeLoop(exchange, reached, per_pod_probe.CATALOGUE_IDS, target=target, id_prefix='s2',
                                         monotonic=lambda: clock.mono / 1e9, monotonic_ns=clock.mono_ns,
                                         wall_ns=clock.wall_ns, sleep=lambda seconds: clock.advance(seconds))
    return loop.run()


def build_synthetic_capture(target, *, poller='v1.1'):
    """Write the synthetic capture into `target` (must not exist); returns facts the checks use. poller='v1' writes
    the same capture with the poller v1 (the twin of the identity check)."""
    target = Path(target)
    if target.exists():
        raise ValueError('synthetic capture target exists: ' + str(target))
    modules = _script_modules()
    world = SyntheticWorld()
    facts = world.scenario()
    target.mkdir(parents=True)
    _drive_poller(modules['poller_v1_1' if poller == 'v1.1' else 'poller_v1'], world, target / 'context')
    _drive_watch(modules['watch'], world, target / 'context')
    _drive_recheck(modules['recheck'], modules['watch'], world, target / 'context')
    documents = [_clock_documents(modules['clock_probe'], 'start', -4.0),
                 _clock_documents(modules['clock_probe'], 'end', 222.0)]
    write_bytes_exclusive(target / 'context' / 'clock_probes.json',
                          (json.dumps(documents, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    host_receipts = _host_commands(modules['host_command'], modules['kill'], target, facts)
    rows = _probe_rows(modules['per_pod_probe'], facts)
    write_bytes_exclusive(target / 'ground_truth' / 'probe_rows.jsonl',
                          b''.join((json.dumps(row) + '\n').encode('utf-8') for row in rows))
    # the Phase-3 skeleton the Phase-3 converter reads (capture.json, incident.json, manifests/, rollout-patch.json)
    service = 'recommendationservice'
    deployment = next(obj for _, _, _, key, obj in world.changes if key == 'dep-' + service)
    write_bytes_exclusive(target / 'raw' / 'deploy-before-{}.stdout'.format(service),
                          json.dumps(deployment, indent=4).encode())
    receipts = [{'id': 'apply-collector', 'args': ['apply', '-f', 'manifests/collector.json'], 'argv_prefix': 'scoped',
                 'request_started_at': synthetic_iso_us(-25.0), 'response_received_at': synthetic_iso_us(-24.5),
                 'collector_available_at': synthetic_iso_us(-24.499), 'exit_code': 0}]
    for identifier, args, (start, end), stdout in (
            ('change-patch', ['patch', 'deployment', service, '--type=merge', '--patch-file', 'rollout-patch.json',
                              '-o', 'json'], (60.05, 60.60), json.dumps(deployment).encode()),
            ('change-wait', ['rollout', 'status', 'deployment/' + service, '--timeout=120s'], (60.61, 82.50),
             b'deployment "recommendationservice" successfully rolled out\n')):
        write_bytes_exclusive(target / 'raw' / (identifier + '.stdout'), stdout)
        write_bytes_exclusive(target / 'raw' / (identifier + '.stderr'), b'')
        receipts.append({'id': identifier, 'args': args, 'argv_prefix': 'scoped',
                         'request_started_at': synthetic_iso_us(start), 'response_received_at': synthetic_iso_us(end),
                         'collector_available_at': synthetic_iso_us(end + 0.001),
                         'host_monotonic_start_ns': SYNTHETIC_MONOTONIC0_NS + _ns(start),
                         'host_monotonic_end_ns': SYNTHETIC_MONOTONIC0_NS + _ns(end), 'exit_code': 0,
                         'stdout_file': 'raw/{}.stdout'.format(identifier),
                         'stderr_file': 'raw/{}.stderr'.format(identifier), 'stdout_sha256': sha(stdout),
                         'stderr_sha256': sha(b'')})
    receipts.extend(host_receipts)
    timeline = {mark: {'host_utc': synthetic_iso_us(at), 'host_monotonic_ns': SYNTHETIC_MONOTONIC0_NS + _ns(at)}
                for mark, at in sorted(SYNTHETIC_TIMELINE.items(), key=lambda item: item[1])}
    doc = {'capture_id': SYNTHETIC_CAPTURE_ID, 'incident_id': 'G2', 'namespace': SYNTHETIC_NAMESPACE,
           'cluster_incarnation_id': 'synthetic-stage2-cluster', 'started_at': synthetic_iso_us(-30.0),
           'finished_at': synthetic_iso_us(225.0), 'status': 'finished', 'timeline': timeline,
           'change': {'service': service, 'at': 'T0'}, 'protocol': {'request_trigger_index': 30},
           'command_receipts': receipts, 'validity': {'valid': True, 'reasons': []},
           'synthetic': 'phase3/convert_stage2.py build_synthetic_capture (no cluster)'}
    write_bytes_exclusive(target / 'capture.json', (json.dumps(doc, indent=2) + '\n').encode())
    incident = {'incident': {'id': 'G2', 'arm': 'G', 'runnable': True,
                             'change': {'service': service, 'kind': 'rollout', 'at': 'T0'},
                             'fault': {'type': 'F2', 'service': service,
                                       'start': {'after': 'T0', 'offset_seconds': 15}},
                             'label': 'synthetic G2 capture', 'ground_truth': {'fault_present': True}},
                'namespace': SYNTHETIC_NAMESPACE}
    write_bytes_exclusive(target / 'incident.json', (json.dumps(incident, indent=2) + '\n').encode())
    for name, value in (('namespace.json', {'apiVersion': 'v1', 'kind': 'Namespace',
                                            'metadata': {'name': SYNTHETIC_NAMESPACE}}),
                        ('collector.json', {'apiVersion': 'v1', 'kind': 'List', 'items': []}),
                        ('applications.json', {'apiVersion': 'v1', 'kind': 'List', 'items': []})):
        write_bytes_exclusive(target / 'manifests' / name, (json.dumps(value, indent=2) + '\n').encode())
    write_bytes_exclusive(target / 'rollout-patch.json',
                          (ROOT / 'infrastructure' / 'rollout-telemetry' / 'rollout-patch.json').read_bytes())
    write_bytes_exclusive(target / 'COMPLETE.txt', b'status=finished\nsynthetic=true\n')
    return dict(facts, capture=target, world=world, timeline=dict(SYNTHETIC_TIMELINE),
                collections=dict(SYNTHETIC_COLLECTIONS), probe_rows=len(rows), host_receipts=host_receipts,
                pods_gap=(97.50, 100.63), deployments_gap=(0.45, 1.13))


# ---------------------------------------------------------------------------------------------------------------
# --self-test
# ---------------------------------------------------------------------------------------------------------------
PHASE3_FILES = ('accepted_evidence.jsonl', 'protocol.json', 'capture.json', 'conversion_report.json',
                'evaluation_only/README.txt', 'evaluation_only/incident_entry.json')


def _rows(path):
    with open(path, 'rb') as handle:
        return [json.loads(line) for line in handle]


def self_test():
    """Converts the 22 Sep fixture and the synthetic capture and checks the converter's contract."""
    checks, details = {}, {}

    def check(name, condition):
        checks[name] = bool(condition)

    gate = import_readonly(ROOT / 'experiments/policy-gate-v1/run_policy_gate_audit.py',
                           'policy_gate_audit_readonly_for_convert_stage2_self_test')
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        # 1. the 22 Sep rollout as a Phase-3 capture (experiments/replay-policy-v1/check_capture_mode.py): the
        #    Phase-3 layout byte for byte, and gate v1's load_sightings on it
        builder = ROOT / 'experiments/replay-policy-v1/check_capture_mode.py'
        if builder.exists() and (ROOT / 'results/evidence-index-pilot-002/accepted_evidence.jsonl').exists():
            fixture = temp / 'R22SEP-001'
            import_readonly(builder, 'check_capture_mode_readonly_for_convert_stage2').build_fixture(fixture)
            CC.convert(fixture, temp / 'r22-phase3')
            convert(fixture, temp / 'r22-stage2')
            check('22sep_phase3_layout_byte_identical', all((temp / 'r22-phase3' / name).read_bytes() ==
                                                            (temp / 'r22-stage2' / name).read_bytes()
                                                            for name in PHASE3_FILES))
            protocol = json.loads((temp / 'r22-stage2' / 'protocol.json').read_text(encoding='utf-8'))
            previous = gate.INPUTS['api_sightings']
            try:
                gate.INPUTS['api_sightings'] = temp / 'r22-stage2' / 'accepted_evidence.jsonl'
                check('22sep_load_sightings_accepts_poller_rows', len(gate.load_sightings(protocol)) == 396)
            finally:
                gate.INPUTS['api_sightings'] = previous
        else:
            details['22sep'] = 'skipped: the 22 Sep fixture data are not in this working copy'
        # 2. the synthetic Stage-2 capture, converted twice
        info = build_synthetic_capture(temp / SYNTHETIC_CAPTURE_ID)
        capture = info['capture']
        CC.convert(capture, temp / 'phase3')
        first = convert(capture, temp / 'a')
        convert(capture, temp / 'b')
        check('phase3_layout_byte_identical', all((temp / 'phase3' / name).read_bytes() ==
                                                  (temp / 'a' / name).read_bytes() for name in PHASE3_FILES))
        names = sorted(first['files']) + [MANIFEST_NAME]
        check('deterministic_two_runs', all((temp / 'a' / name).read_bytes() == (temp / 'b' / name).read_bytes()
                                            for name in names))
        check('manifest_hashes_every_file', all(sha((temp / 'a' / name).read_bytes()) == entry['sha256']
                                                for name, entry in first['files'].items()))
        counts = first['counts_by_kind']
        for kind in ('api_watch_list_object', 'api_watch_event', 'api_observation (watch_cache_snapshot)',
                     'live_recheck', 'continuity_gap', 'clock_probe', 'host_command', 'per_pod_probe'):
            check('rows_present:' + kind, counts.get(kind, 0) > 0)
        check('no_problems', not first['problems'])
        bases = first['observation_basis_by_file']
        check('observation_basis_values', bases == {
            'accepted_evidence.jsonl (api_observation rows)': {'snapshot_receipt': counts['api_observation']},
            OUT['list_objects']: {'watch_list': counts['api_watch_list_object']},
            OUT['events']: {'watch_event': counts['api_watch_event']},
            OUT['snapshots']: {'watch_cache_snapshot': counts['api_observation (watch_cache_snapshot)']},
            OUT['recheck']: {'live_recheck': counts['live_recheck']}})
        # snapshot rows: resolved through their refs, inside the window, never during a gap of their kind
        carriers = {}
        for name in (OUT['list_objects'], OUT['events']):
            for row in _rows(temp / 'a' / name):
                carriers[row['record']['payload']['record_id']] = row['record']['payload']['resource_data']
        snapshot_rows = _rows(temp / 'a' / OUT['snapshots'])
        window = first['window']['bounds']
        check('snapshot_rows_resolve_to_their_carriers', all(
            row['record']['payload']['resource_data'] == carriers[row['record']['payload']['source_record']]
            for row in snapshot_rows))
        check('snapshot_rows_inside_window', all(window['from'] <= row['record']['payload']['snapshot_monotonic_ns']
                                                 <= window['to'] for row in snapshot_rows))
        start, end = info['pods_gap']
        check('no_pod_snapshot_inside_the_pods_gap', not [
            row for row in snapshot_rows if row['record']['payload']['resource'] == 'pods'
            and SYNTHETIC_MONOTONIC0_NS + _ns(start) < row['record']['payload']['snapshot_monotonic_ns']
            < SYNTHETIC_MONOTONIC0_NS + _ns(end)])
        pruned = first['watch_cache_snapshots']['after_window']
        check('window_prunes_late_snapshots', pruned > 0 and first['window']['margin_seconds'] == 60.0)
        # the Phase-3 loader: poller rows accepted, watch snapshot rows refused (no false snapshot_receipt)
        protocol = json.loads((temp / 'a' / 'protocol.json').read_text(encoding='utf-8'))
        previous = gate.INPUTS['api_sightings']
        try:
            gate.INPUTS['api_sightings'] = temp / 'a' / 'accepted_evidence.jsonl'
            check('load_sightings_accepts_poller_rows', len(gate.load_sightings(protocol)) == counts['api_observation'])
            gate.INPUTS['api_sightings'] = temp / 'a' / OUT['snapshots']
            try:
                gate.load_sightings(protocol)
                check('load_sightings_refuses_watch_rows', False)
            except SystemExit as refusal:
                check('load_sightings_refuses_watch_rows', 'unexpected observation basis' in str(refusal))
        finally:
            gate.INPUTS['api_sightings'] = previous
        # K1: every observer's rows feed fault_control_kill.k1_extract; the kill's termination is found in each
        kill = _script_modules()['kill']
        for observer in OBSERVERS:
            extraction = kill.k1_extract(_rows(temp / 'a' / K1_FILES[observer]))
            found = [o for o in extraction['observations'] if o['pod_uid'] == info['kill_target_uid']
                     and o['source_field'].endswith('lastState.terminated.finishedAt')]
            check('k1_kill_termination_found:' + observer, len(found) == 1
                  and found[0]['stamp'] == synthetic_stamp(75.0))
            details['k1_' + observer] = extraction['counts']
        # the F2 evaluator reads the converted kill receipt, watch K1 rows, per-Pod probe rows and clock probes
        receipt = next(row['record']['payload'] for row in _rows(temp / 'a' / OUT['host_commands'])
                       if row['record']['payload']['id'] == 'kill-target-001')
        documents = [row['record']['payload'] for row in _rows(temp / 'a' / OUT['clock'])]
        evaluation = kill.evaluate_kill({
            'target': {'service': 'recommendationservice', 'pod_uid': info['kill_target_uid'],
                       'pod_name': info['kill_target_name'], 'pod_ip': info['kill_target_ip']},
            'kill_receipt': receipt, 'pod_records': _rows(temp / 'a' / K1_FILES['watch']),
            'probe_rows': [row['record']['payload'] for row in _rows(temp / 'a' / OUT['probes'])],
            'clock_band': kill.clock_band(documents), 'docker_argv': list(kill.DOCKER_ARGV), 'node': kill.NODE})
        check('f2_evaluator_activation_from_converted_rows', evaluation['activation_verified'])
        check('f2_evaluator_passes_on_converted_rows', evaluation['fault_control_passed'])
        details['synthetic_counts_by_kind'] = counts
        details['synthetic_bytes'] = {name: entry['bytes'] for name, entry in first['files'].items()}
    ok = all(checks.values())
    print(json.dumps({'self_test_passed': ok, 'converter': CONVERTER_VERSION, 'checks': checks, 'details': details},
                     indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
