#!/usr/bin/env python3
"""Watch-based collector (collector tag watch-v1): an informer-style LIST + WATCH per kind through one ``kubectl
proxy``, with every event kept at its host receipt, a continuity gap and a relist on any break, and cache snapshots at
every event and every 1.0 s while the watch is open.

The object projection is the poller's ``project_resource`` (scripts/collect_deployment_history.py), imported, not
copied, extended by status.conditions and by container state / lastState; EndpointSlices and PodDisruptionBudgets get
the same identity projection plus their own fields. Record format: phase3/CAPTURE_FORMAT_STAGE2.md. Python 3.10+
standard library only; importing this module contacts no cluster and starts nothing.

    python scripts/collect_watch_v1.py --namespace <ns> --out <dir> \
        --context kind-aiops-context-pilot --kubeconfig .runtime/context-pilot/kubeconfig --seconds 120
"""
from __future__ import annotations

import argparse
import base64
import copy
import gzip
import json
import os
import platform
import re
import signal
import socket
import sys
import threading
import time
import traceback
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlencode

sys.dont_write_bytecode = True       # no .pyc next to the poller (as phase3/run_incident.py)
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import collect_deployment_history as poller_v1  # noqa: E402  poller v1, read-only; no import side effects
from kube_proxy_v1 import (KubeProxy, ProxyError, clock_info, host_time, iso_ns, loopback_base_url,  # noqa: E402
                           put_time, sha256, sha256_file)

COLLECTOR_TAG = 'watch-v1'
SCHEMA_VERSION = 1
# resource (plural, as in the API path) -> (Kind, API path prefix, API group)
RESOURCES = {
    'pods': ('Pod', '/api/v1', ''),
    'deployments': ('Deployment', '/apis/apps/v1', 'apps'),
    'replicasets': ('ReplicaSet', '/apis/apps/v1', 'apps'),
    'endpointslices': ('EndpointSlice', '/apis/discovery.k8s.io/v1', 'discovery.k8s.io'),
    'poddisruptionbudgets': ('PodDisruptionBudget', '/apis/policy/v1', 'policy'),
}
DEFAULT_RESOURCES = tuple(RESOURCES)
POLLER_V1_RESOURCES = ('pods', 'replicasets', 'deployments')      # accepted by the project_resource
KIND_ORDER = {RESOURCES[name][0]: index for index, name in enumerate(RESOURCES)}
ENDPOINT_KEYS = ('addresses', 'conditions', 'hostname', 'nodeName', 'targetRef', 'zone')
PDB_SPEC_KEYS = ('minAvailable', 'maxUnavailable', 'selector', 'unhealthyPodEvictionPolicy')
PDB_STATUS_KEYS = ('observedGeneration', 'disruptionsAllowed', 'currentHealthy', 'desiredHealthy', 'expectedPods',
                   'disruptedPods', 'conditions')
FILES = {'events': 'watch_events.jsonl', 'snapshots': 'watch_snapshots.jsonl', 'manifest': 'watch_manifest.json',
         'raw': 'watch_raw.jsonl.gz'}
EVENT_TYPES = ('ADDED', 'MODIFIED', 'DELETED', 'BOOKMARK', 'ERROR')
NORMAL_STOPS = ('seconds', 'stop_file', 'stop_event')
RECV_SIZE = 65536
MAX_HEAD_BYTES = 64 * 1024
MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_BODY_BYTES = 64 * 1024 * 1024
USER_AGENT = 'aiops-stage2-' + COLLECTOR_TAG
MAX_SECONDS = 7200.0


# ----------------------------------------------------------------------------------------------
# Projection (shared with scripts/recheck_loop_v1.py)
# ----------------------------------------------------------------------------------------------
def validate_namespace(namespace):
    """The poller's namespace rule (scripts/collect_deployment_history.py lines 42-45)."""
    if not isinstance(namespace, str) or not re.fullmatch(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?', namespace):
        raise ValueError('An explicit DNS-label namespace is required')
    if namespace in {'default', 'kube-system', 'kube-public', 'kube-node-lease'}:
        raise ValueError('Use a dedicated research namespace')
    return namespace


def _metadata(item, kind, namespace):
    """The identity projection of poller v1's project_resource (scripts/collect_deployment_history.py lines 90-108),
    re-implemented for the kinds that v1 does not accept (EndpointSlice, PodDisruptionBudget)."""
    if not isinstance(item, dict) or item.get('kind') != kind:
        raise ValueError('Unexpected resource kind; expected ' + kind)
    metadata = item.get('metadata', {})
    for key in ('uid', 'name', 'resourceVersion'):
        poller_v1.nonempty(metadata.get(key), key)
    if metadata.get('namespace') != namespace:
        raise ValueError('Snapshot contains an object outside the requested namespace')
    owners = metadata.get('ownerReferences', [])
    if not isinstance(owners, list):
        raise ValueError('ownerReferences must be a list')
    for owner in owners:
        for key in ('kind', 'name', 'uid'):
            poller_v1.nonempty(owner.get(key), 'ownerReferences.' + key)
    projected = {key: metadata[key] for key in ('uid', 'name', 'namespace', 'resourceVersion', 'generation',
                                                 'creationTimestamp', 'deletionTimestamp', 'labels') if key in metadata}
    projected['ownerReferences'] = owners
    revision = metadata.get('annotations', {}).get(poller_v1.REVISION)
    if revision is not None:
        projected['annotations'] = {poller_v1.REVISION: revision}
    return projected


def project_object(item, resource, namespace):
    """Project one API object ("through the same projection and mapping as the poller").

    pods / replicasets / deployments: exactly poller v1's project_resource, plus status.conditions (verbatim, when
    present) and, for Pods, each containerStatuses entry's state and lastState (verbatim, when present; restartCount
    is already in v1). Nothing v1 keeps is changed or dropped.
    endpointslices: v1's identity projection, addressType, endpoints (addresses, conditions, hostname, nodeName,
    targetRef, zone) and ports.
    poddisruptionbudgets: v1's identity projection, spec (minAvailable, maxUnavailable, selector,
    unhealthyPodEvictionPolicy) and status (observedGeneration, disruptionsAllowed, currentHealthy, desiredHealthy,
    expectedPods, disruptedPods, conditions).
    The item must carry kind (raw LIST items do not: parse_list sets it from the list)."""
    if resource not in RESOURCES:
        raise ValueError('Unsupported resource ' + repr(resource))
    kind = RESOURCES[resource][0]
    if resource in POLLER_V1_RESOURCES:
        result = poller_v1.project_resource(item, resource, namespace)
        status = item.get('status') or {}
        if 'conditions' in status:
            result['status']['conditions'] = copy.deepcopy(status['conditions'])
        if resource == 'pods':           # v1 maps containerStatuses one to one, in order: equal lengths
            for projected, original in zip(result['status']['containerStatuses'],
                                           status.get('containerStatuses') or [], strict=True):
                for key in ('state', 'lastState'):
                    if key in original:
                        projected[key] = copy.deepcopy(original[key])
        return result
    result = {'apiVersion': item.get('apiVersion') if isinstance(item, dict) else None, 'kind': kind,
              'metadata': _metadata(item, kind, namespace)}
    if resource == 'endpointslices':
        result['addressType'] = item.get('addressType')
        result['endpoints'] = [{key: copy.deepcopy(endpoint[key]) for key in ENDPOINT_KEYS if key in endpoint}
                               for endpoint in item.get('endpoints') or []]
        result['ports'] = copy.deepcopy(item.get('ports') or [])
    else:
        spec, status = item.get('spec') or {}, item.get('status') or {}
        result['spec'] = {key: copy.deepcopy(spec[key]) for key in PDB_SPEC_KEYS if key in spec}
        result['status'] = {key: copy.deepcopy(status[key]) for key in PDB_STATUS_KEYS if key in status}
    return result


def parse_list(payload, resource, namespace):
    """(list resourceVersion, [projected objects]) of a raw API LIST body. A raw LIST's items carry no kind or
    apiVersion (kubectl adds them only when it prints -o json), so both are set from the list before projection.
    Pagination, a missing list resourceVersion and duplicate UIDs are refused, as in poller v1's parse_snapshot."""
    kind = RESOURCES[resource][0]
    if not isinstance(payload, dict) or payload.get('kind') != kind + 'List':
        raise ValueError('Expected a {}List'.format(kind))
    metadata = payload.get('metadata') or {}
    if metadata.get('continue'):
        raise ValueError('Incomplete paginated list; no complete snapshot accepted')
    version = poller_v1.nonempty(metadata.get('resourceVersion'), 'list resourceVersion')
    items = payload.get('items')
    items = [] if items is None else items
    if not isinstance(items, list):
        raise ValueError('Expected list items')
    if len(items) > 10000:
        raise ValueError('Research snapshot exceeds 10000 objects')
    objects = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('List item is not an object')
        filled = dict(item)
        filled.setdefault('kind', kind)
        filled.setdefault('apiVersion', payload.get('apiVersion'))
        objects.append(project_object(filled, resource, namespace))
    uids = [obj['metadata']['uid'] for obj in objects]
    if len(uids) != len(set(uids)):
        raise ValueError('Duplicate UID in list')
    return version, objects


def collection_path(resource, namespace):
    return '{}/namespaces/{}/{}'.format(RESOURCES[resource][1], namespace, resource)


def request_target(resource, namespace, query=None):
    """Path plus query string (percent-encoded, spaces as %20) of a namespaced collection request."""
    target = collection_path(resource, namespace)
    if query:
        target += '?' + urlencode(list(query.items()), quote_via=quote, safe='')
    return target


def parse_selectors(values):
    """['pods=app in (a,b)', 'poddisruptionbudgets='] -> {'pods': 'app in (a,b)', 'poddisruptionbudgets': None}."""
    result = {}
    for value in values or []:
        resource, sep, selector = value.partition('=')
        if not sep or resource not in RESOURCES:
            raise ValueError('label selector must be RESOURCE=SELECTOR with RESOURCE in {}: {!r}'.format(
                ', '.join(RESOURCES), value))
        if any(ord(char) < 32 for char in selector) or selector != selector.strip():
            raise ValueError('label selector must be one line without outer whitespace: {!r}'.format(value))
        result[resource] = selector or None
    return result


def sort_objects(objects):
    return sorted(objects, key=lambda obj: (KIND_ORDER.get(obj['kind'], 99), obj['metadata']['name'],
                                            obj['metadata']['uid']))


# ----------------------------------------------------------------------------------------------
# HTTP/1.1 over a raw loopback socket, decoded incrementally
# ----------------------------------------------------------------------------------------------
class StopRequested(Exception):
    """The collection is stopping; the current request was abandoned."""


class ChunkedDecoder:
    """Incremental decoder of an HTTP/1.1 chunked body (RFC 9112 section 7.1). feed() returns (data, chunk number)
    pieces, chunk numbers starting at 1; chunk extensions and trailer fields are ignored."""

    def __init__(self):
        self.state, self.buffer, self.left, self.chunks = 'size', bytearray(), 0, 0
        self.complete, self.trailing_bytes = False, 0

    def feed(self, data):
        self.buffer += data
        out = []
        while True:
            if self.state == 'size':
                end = self.buffer.find(b'\r\n')
                if end < 0:
                    if len(self.buffer) > 1024:
                        raise ValueError('chunk-size line too long')
                    return out
                line = bytes(self.buffer[:end])
                del self.buffer[:end + 2]
                text = line.split(b';', 1)[0].strip()
                if not re.fullmatch(rb'[0-9a-fA-F]{1,16}', text):
                    raise ValueError('invalid chunk-size line {!r}'.format(line[:40]))
                size = int(text, 16)
                if size == 0:
                    self.state = 'trailer'
                else:
                    self.left, self.chunks, self.state = size, self.chunks + 1, 'data'
            elif self.state == 'data':
                if not self.buffer:
                    return out
                take = min(self.left, len(self.buffer))
                out.append((bytes(self.buffer[:take]), self.chunks))
                del self.buffer[:take]
                self.left -= take
                if not self.left:
                    self.state = 'data_end'
            elif self.state == 'data_end':
                if len(self.buffer) < 2:
                    return out
                if self.buffer[:2] != b'\r\n':
                    raise ValueError('chunk data is not followed by CRLF')
                del self.buffer[:2]
                self.state = 'size'
            elif self.state == 'trailer':
                end = self.buffer.find(b'\r\n')
                if end < 0:
                    if len(self.buffer) > MAX_HEAD_BYTES:
                        raise ValueError('chunked trailer too long')
                    return out
                line = bytes(self.buffer[:end])
                del self.buffer[:end + 2]
                if not line:
                    self.state, self.complete = 'done', True
            else:
                self.trailing_bytes += len(self.buffer)
                self.buffer.clear()
                return out


class LengthDecoder:
    """A body with Content-Length."""

    def __init__(self, length):
        if length < 0:
            raise ValueError('negative Content-Length')
        self.left, self.chunks, self.complete, self.trailing_bytes = length, 0, length == 0, 0

    def feed(self, data):
        take = data[:self.left]
        self.left -= len(take)
        self.trailing_bytes += len(data) - len(take)
        self.complete = self.left == 0
        return [(take, 0)] if take else []


class CloseDecoder:
    """A body delimited by the end of the connection."""

    def __init__(self):
        self.chunks, self.complete, self.trailing_bytes = 0, False, 0

    def feed(self, data):
        return [(data, 0)] if data else []


class LineAssembler:
    """Newline-terminated lines across chunk and read boundaries; reports how many HTTP chunks each line spans."""

    def __init__(self, limit=MAX_LINE_BYTES):
        self.parts, self.size, self.first_chunk, self.limit = [], 0, None, limit

    def feed(self, data, chunk):
        lines, start = [], 0
        while start < len(data):
            end = data.find(b'\n', start)
            if end < 0:
                if not self.parts:
                    self.first_chunk = chunk
                self.parts.append(data[start:])
                self.size += len(data) - start
                if self.size > self.limit:
                    raise ValueError('watch line exceeds {} bytes'.format(self.limit))
                break
            first = self.first_chunk if self.parts else chunk
            lines.append((b''.join(self.parts) + data[start:end + 1], chunk - first + 1))
            self.parts, self.size, self.first_chunk = [], 0, None
            start = end + 1
        return lines

    @property
    def pending(self):
        return b''.join(self.parts)


class RawConnection:
    """One HTTP/1.1 GET (Connection: close) over a loopback TCP socket with a short read timeout, so that the reading
    thread can check its stop flag between reads. A timeout loses no bytes: this class keeps its own buffer.
    (http.client cannot be used for the watch: its buffered socket file refuses every read after one timeout.)"""

    def __init__(self, host, port, target, *, connect_timeout=10.0, poll_seconds=0.2):
        self.target = target
        self.sock = socket.create_connection((host, port), timeout=connect_timeout)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.sock.settimeout(poll_seconds)
        host_header = '[{}]'.format(host) if ':' in host else host
        request = ('GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nUser-Agent: {}\r\n'
                   'Connection: close\r\n\r\n').format(target, host_header, port, USER_AGENT)
        self.sock.sendall(request.encode('ascii'))
        self.buffer, self.initial, self.eof = bytearray(), b'', False
        self.status, self.reason, self.headers, self.decoder = None, '', {}, None

    def recv(self):
        """One read: the bytes received, b'' at the end of the stream, or None when the poll timeout passed."""
        if self.eof:
            return b''
        try:
            data = self.sock.recv(RECV_SIZE)
        except socket.timeout:
            return None
        if not data:
            self.eof = True
        return data

    def read_head(self, deadline, stop=None):
        """Read and parse the status line and headers before time.monotonic() passes deadline; returns the host time
        of the read that completed the head. Body bytes that came with the head are kept in self.initial."""
        while True:
            end = self.buffer.find(b'\r\n\r\n')
            if end >= 0:
                break
            if len(self.buffer) > MAX_HEAD_BYTES:
                raise ValueError('response head too long')
            if stop is not None and stop.is_set():
                raise StopRequested()
            if time.monotonic() > deadline:
                raise TimeoutError('no complete response head before the deadline')
            data = self.recv()
            if data is None:
                continue
            if not data:
                raise ConnectionError('connection closed before the response head')
            self.buffer += data
        at = host_time()
        head = bytes(self.buffer[:end]).decode('iso-8859-1')
        self.initial = bytes(self.buffer[end + 4:])
        self.buffer = bytearray()
        lines = head.split('\r\n')
        parts = lines[0].split(' ', 2)
        if len(parts) < 2 or not parts[0].startswith('HTTP/1.') or not parts[1].isdigit():
            raise ValueError('bad HTTP status line {!r}'.format(lines[0][:80]))
        self.status, self.reason = int(parts[1]), parts[2] if len(parts) > 2 else ''
        for line in lines[1:]:
            name, sep, value = line.partition(':')
            if not sep:
                raise ValueError('bad HTTP header line {!r}'.format(line[:80]))
            key, value = name.strip().lower(), value.strip()
            self.headers[key] = self.headers[key] + ', ' + value if key in self.headers else value
        if 'chunked' in self.headers.get('transfer-encoding', '').lower():
            self.decoder = ChunkedDecoder()
        elif 'content-length' in self.headers:
            self.decoder = LengthDecoder(int(self.headers['content-length']))
        else:
            self.decoder = CloseDecoder()
        return at

    def read_body(self, deadline, stop=None, limit=MAX_BODY_BYTES):
        """The whole body, decoded (for LIST responses and non-200 watch responses)."""
        parts, size = [], 0
        data, self.initial = self.initial, b''
        while True:
            for piece, _ in self.decoder.feed(data):
                parts.append(piece)
                size += len(piece)
            if size > limit:
                raise ValueError('response body exceeds {} bytes'.format(limit))
            if self.decoder.complete:
                return b''.join(parts)
            if stop is not None and stop.is_set():
                raise StopRequested()
            if time.monotonic() > deadline:
                raise TimeoutError('response body incomplete at the deadline')
            data = self.recv()
            if data is None:
                data = b''
                continue
            if not data:
                if isinstance(self.decoder, CloseDecoder):
                    return b''.join(parts)
                raise ConnectionError('connection closed before the end of the response body')

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def parse_status_object(body):
    """A Kubernetes Status object from an error body, or None."""
    try:
        value = json.loads(body)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) and value.get('kind') == 'Status' else None


def error_text(error):
    return '{}: {}'.format(type(error).__name__, error)[:2000]


# ----------------------------------------------------------------------------------------------
# Raw bytes archive (gzip JSONL)
# ----------------------------------------------------------------------------------------------
class RawArchive:
    """Exact raw bytes (LIST bodies, watch lines, recheck bodies) as gzip-compressed JSON lines. Each line names the
    record (by sequence) that carries the bytes' SHA-256; UTF-8 bodies are kept as JSON strings (exact round trip
    through .encode('utf-8')), anything else as base64. The gzip header has no name and mtime 0."""

    def __init__(self, path):
        self.handle = open(path, 'xb')
        self.gzip = gzip.GzipFile(filename='', mode='wb', fileobj=self.handle, mtime=0)
        self.count = 0

    def write(self, kind, sequence, data, extra=None):
        try:
            text, encoding = data.decode('utf-8'), 'utf-8'
        except UnicodeDecodeError:
            text, encoding = base64.b64encode(data).decode('ascii'), 'base64'
        record = {'kind': kind, 'sequence': sequence, 'sha256': sha256(data), 'bytes': len(data),
                  'encoding': encoding, 'data': text}
        record.update(extra or {})
        self.gzip.write((json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))
        self.count += 1

    def flush(self):
        self.gzip.flush()
        self.handle.flush()

    def close(self):
        if not self.handle.closed:
            self.gzip.close()
            self.handle.close()


def read_raw_archive(path):
    """[(record, exact bytes)] of a RawArchive file (for tests and the converter)."""
    result = []
    with gzip.open(path, 'rb') as handle:
        for line in handle:
            record = json.loads(line)
            data = (record['data'].encode('utf-8') if record['encoding'] == 'utf-8'
                    else base64.b64decode(record['data']))
            result.append((record, data))
    return result


# ----------------------------------------------------------------------------------------------
# Shared CLI pieces (also used by scripts/recheck_loop_v1.py)
# ----------------------------------------------------------------------------------------------
def add_common_arguments(result):
    result.add_argument('--namespace', required=True, help='the capture namespace (DNS label; never a system one)')
    result.add_argument('--output-dir', required=True,
                        help='directory for the output files (created if missing; the files themselves must not '
                             'exist and are never overwritten)')
    group = result.add_mutually_exclusive_group(required=True)
    group.add_argument('--proxy-url', help='an already running kubectl proxy, http://127.0.0.1:<port>')
    group.add_argument('--start-proxy', action='store_true',
                       help='start an own kubectl proxy with scripts/kube_proxy_v1.py (smoke tests, standalone use)')
    result.add_argument('--kubectl', help='with --start-proxy: kubectl executable (default: shutil.which)')
    result.add_argument('--context', help='with --start-proxy: kubeconfig context')
    result.add_argument('--kubeconfig', help='with --start-proxy: kubeconfig file')
    result.add_argument('--server', help='with --start-proxy: explicit API server URL')
    result.add_argument('--label-selector', action='append', default=[], metavar='RESOURCE=SELECTOR',
                        help='server-side label selector for one resource (repeatable); RESOURCE= clears it')
    result.add_argument('--seconds', type=float, help='stop after this many seconds')
    result.add_argument('--stop-file', help='stop when this file appears (checked every 0.1 s); it must not exist '
                                            'at start')
    result.add_argument('--no-raw', action='store_true', help='do not keep the raw bytes archive (*.jsonl.gz)')
    return result


def validate_common(args):
    validate_namespace(args.namespace)
    if args.seconds is None and not args.stop_file:
        raise ValueError('give --seconds, --stop-file or both')
    if args.seconds is not None and not 0 < args.seconds <= MAX_SECONDS:
        raise ValueError('--seconds must be in (0, {}]'.format(MAX_SECONDS))
    if args.stop_file and Path(args.stop_file).exists():
        raise ValueError('--stop-file already exists; the collector would stop at once: ' + args.stop_file)
    if not args.start_proxy and any(getattr(args, name) for name in ('kubectl', 'context', 'kubeconfig', 'server')):
        raise ValueError('--kubectl, --context, --kubeconfig and --server apply only with --start-proxy')
    if args.proxy_url:
        loopback_base_url(args.proxy_url)
    return parse_selectors(args.label_selector)


def prepare_output(directory, names):
    """Create the output directory if needed; refuse if any output file exists. Returns {key: path}."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = {key: directory / name for key, name in names.items()}
    existing = [str(path) for path in paths.values() if path.exists()]
    if existing:
        raise ValueError('output files exist; choose a new directory: ' + ', '.join(existing))
    return paths


def connect_proxy(args):
    """(base_url, host, port, own KubeProxy or None) from --proxy-url or --start-proxy."""
    if args.proxy_url:
        base, host, port = loopback_base_url(args.proxy_url)
        return base, host, port, None
    proxy = KubeProxy(args.kubectl, context=args.context, kubeconfig=args.kubeconfig, server=args.server)
    proxy.start()
    base, host, port = loopback_base_url(proxy.base_url)
    return base, host, port, proxy


def install_stop_signals(callback):
    """SIGTERM (POSIX) and SIGBREAK (Windows, CTRL_BREAK_EVENT to a process group) request a graceful stop.
    Popen.terminate() on Windows is TerminateProcess: no handler runs, so a runner should use --stop-file."""
    for name in ('SIGTERM', 'SIGBREAK'):
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(number, lambda signum, frame, name=name: callback('signal:' + name))
        except (ValueError, OSError):
            pass


def write_manifest(path, manifest, first=False):
    """The manifest is written at start ('x') and replaced atomically at the end."""
    data = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8')
    if first:
        with open(path, 'xb') as handle:
            handle.write(data)
        return
    temporary = Path(str(path) + '.tmp')
    with open(temporary, 'wb') as handle:
        handle.write(data)
    for attempt in range(10):          # Windows: a scanner or indexer may hold the old file for a moment
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.2)


def file_entry(path):
    path = Path(path)
    if not path.exists():
        return None
    raw_lines = None
    if path.suffix == '.jsonl':
        with open(path, 'rb') as handle:
            raw_lines = sum(1 for _ in handle)
    return {'sha256': sha256_file(path), 'bytes': path.stat().st_size, 'lines': raw_lines}


# ----------------------------------------------------------------------------------------------
# Watch threads
# ----------------------------------------------------------------------------------------------
class ResourceWatcher(threading.Thread):
    """LIST then WATCH for one resource, relisting after every break, until the collection stops."""

    def __init__(self, collector, resource):
        super().__init__(daemon=True, name='watch-' + resource)
        self.c, self.resource, self.kind = collector, resource, RESOURCES[resource][0]
        self.list_attempt, self.watch_index, self.failures = 0, 0, 0

    def run(self):
        try:
            self.loop()
        except BaseException as error:        # a bug must never end the collection silently
            self.c.thread_error(self.resource, error)

    def loop(self):
        stop = self.c.stop_event
        while not stop.is_set():
            if self.failures and stop.wait(min(0.25 * 2 ** (self.failures - 1), 2.0)):
                break
            version = self.list_once()
            if version is None:
                self.failures += 1
                continue
            if stop.is_set():
                break
            outcome = self.watch_once(version)
            if outcome is None:
                break
            cause, details, healthy = outcome
            self.c.open_gap(self.resource, cause, details)
            self.failures = 0 if healthy else self.failures + 1

    def list_once(self):
        c = self.c
        self.list_attempt += 1
        target = request_target(self.resource, c.namespace, c.selector_query(self.resource))
        started, received, status, body = host_time(), None, None, b''
        try:
            connection = RawConnection(c.host, c.port, target, connect_timeout=c.request_timeout,
                                       poll_seconds=c.poll_seconds)
            try:
                deadline = time.monotonic() + c.request_timeout
                connection.read_head(deadline, c.stop_event)
                status = connection.status
                body = connection.read_body(deadline, c.stop_event)
                received = host_time()               # the last body byte has arrived
            finally:
                connection.close()
            if status != 200:
                raise ValueError('HTTP {}'.format(status))
            version, objects = parse_list(json.loads(body), self.resource, c.namespace)
        except StopRequested:
            return None
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            c.record_list_failure(self.resource, self.list_attempt, target, started, received or host_time(), status,
                                  body, error_text(error))
            return None
        c.apply_list(self.resource, self.list_attempt, target, started, received, body, version, objects)
        return version

    def watch_once(self, version):
        """Open and read one watch stream. None when stopped; else (cause, details, healthy)."""
        c = self.c
        self.watch_index += 1
        stream_id = '{}/{}'.format(self.resource, self.watch_index)
        query = dict(c.selector_query(self.resource))
        query.update(watch='1', resourceVersion=version, allowWatchBookmarks='true',
                     timeoutSeconds=str(c.watch_timeout))
        target = request_target(self.resource, c.namespace, query)
        started = host_time()
        base = {'stream_id': stream_id, 'path': target, 'resource_version': version}
        try:
            connection = RawConnection(c.host, c.port, target, connect_timeout=c.request_timeout,
                                       poll_seconds=c.poll_seconds)
        except OSError as error:
            c.record_stream_open(self.resource, dict(base, ok=False, error=error_text(error)), started, None)
            return 'watch_request_failed', {'stream_id': stream_id, 'error': error_text(error)}, False
        try:
            try:
                head_at = connection.read_head(time.monotonic() + c.request_timeout, c.stop_event)
            except StopRequested:
                return None
            except (OSError, ValueError) as error:
                c.record_stream_open(self.resource, dict(base, ok=False, error=error_text(error)), started, None)
                return 'watch_request_failed', {'stream_id': stream_id, 'error': error_text(error)}, False
            headers = {'content_type': connection.headers.get('content-type'),
                       'transfer_encoding': connection.headers.get('transfer-encoding')}
            if connection.status != 200:
                body, error = b'', None
                try:
                    body = connection.read_body(time.monotonic() + c.request_timeout, c.stop_event, 1 << 20)
                except StopRequested:
                    return None
                except (OSError, ValueError) as failure:
                    error = error_text(failure)
                status_object = parse_status_object(body)
                c.record_stream_open(self.resource, dict(base, **headers, ok=False, http_status=connection.status,
                                                         error=error, status_object=status_object,
                                                         body_bytes=len(body), body_sha256=sha256(body)),
                                     started, head_at, body)
                return 'watch_http_status', {'stream_id': stream_id, 'http_status': connection.status,
                                             'status_object': status_object, 'error': error}, False
            c.record_stream_open(self.resource, dict(base, **headers, ok=True, http_status=200), started, head_at)
            return self.read_stream(connection, stream_id, head_at)
        finally:
            connection.close()

    def read_stream(self, connection, stream_id, head_at):
        c = self.c
        lines = LineAssembler()
        stats = Counter()
        outcome = self.consume(connection, connection.initial, head_at, lines, stream_id, stats)
        connection.initial = b''
        while outcome is None:
            if c.stop_event.is_set():
                c.record_stream_end(self.resource, stream_id, 'stopped', stats, connection, lines, {}, host_time())
                return None
            try:
                data = connection.recv()
            except OSError as error:
                outcome = 'socket_error', {'error': error_text(error)}
                break
            if data is None:
                continue
            received = host_time()
            if not data:
                outcome = ('eof_clean' if connection.decoder.complete else 'eof_unterminated'), {}
                break
            outcome = self.consume(connection, data, received, lines, stream_id, stats)
            if outcome is None and connection.decoder.complete:
                outcome = 'eof_clean', {}
        cause, details = outcome
        detected = host_time()
        c.record_stream_end(self.resource, stream_id, cause, stats, connection, lines, details, detected)
        healthy = stats['lines'] > 0 or detected['monotonic_ns'] - head_at['monotonic_ns'] >= 5 * 10 ** 9
        return cause, dict(details, stream_id=stream_id, detected=detected), healthy

    def consume(self, connection, data, received, lines, stream_id, stats):
        if not data:
            return None
        stats['bytes'] += len(data)
        try:
            complete_lines = []
            for piece, chunk in connection.decoder.feed(data):
                complete_lines.extend(lines.feed(piece, chunk))
        except ValueError as error:
            return 'bad_framing', {'error': error_text(error)}
        for line, chunks in complete_lines:
            outcome = self.handle_line(line, chunks, received, stream_id, stats)
            if outcome is not None:
                return outcome
        return None

    def handle_line(self, line, chunks, received, stream_id, stats):
        c = self.c
        stats['lines'] += 1
        info = {'stream_id': stream_id, 'line_index': stats['lines'], 'line_bytes': len(line),
                'line_sha256': sha256(line), 'line_chunks': chunks}
        if not line.strip():
            stats['blank_lines'] += 1
            return None
        try:
            event = json.loads(line)
            event_type, obj = event['type'], event['object']
            if event_type not in EVENT_TYPES or not isinstance(obj, dict):
                raise ValueError('unknown watch event type {!r}'.format(event_type)[:80])
            projected = None
            if event_type in ('ADDED', 'MODIFIED', 'DELETED'):
                projected = project_object(obj, self.resource, c.namespace)
            elif event_type == 'BOOKMARK':
                poller_v1.nonempty((obj.get('metadata') or {}).get('resourceVersion'), 'bookmark resourceVersion')
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            c.record_invalid_line(self.resource, info, received, line, error_text(error))
            return 'invalid_event', {'error': error_text(error), 'line_index': info['line_index'],
                                     'line_sha256': info['line_sha256']}
        stats['events'] += 1
        c.apply_event(self.resource, event_type, obj, projected, info, received, line)
        if event_type == 'ERROR':
            return 'error_event', {'status_object': obj, 'error_code': obj.get('code'),
                                   'error_reason': obj.get('reason')}
        return None


# ----------------------------------------------------------------------------------------------
# The collector: state, cache, writer
# ----------------------------------------------------------------------------------------------
class WatchCollector:
    """Shared state of one watch collection. Every write, cache change and snapshot happens under self.lock, so the
    file order equals the order of sequence numbers and of accepted_at."""

    def __init__(self, args, selectors, paths, base_url, host, port, proxy=None, stop_event=None):
        self.args, self.paths, self.proxy = args, paths, proxy
        self.namespace = args.namespace
        self.resources = list(args.resources)
        self.selectors = {resource: selectors.get(resource) for resource in self.resources}
        self.base_url, self.host, self.port = base_url, host, port
        self.snapshot_interval_ns = int(round(args.snapshot_interval_seconds * 1e9))
        self.watch_timeout = int(args.watch_timeout_seconds)
        self.request_timeout = float(args.request_timeout_seconds)
        self.poll_seconds = float(args.poll_seconds)
        self.stop_file = Path(args.stop_file) if args.stop_file else None
        self.stop_event = stop_event or threading.Event()
        self.external_reason = None
        self.lock = threading.RLock()
        self.collection_id = str(uuid.uuid4())
        self.sequence, self.last_available_ns, self.snapshot_index = 0, 0, 0
        self.handles, self.lines, self.archive, self.closed = {}, Counter(), None, False
        self.cache = {}       # uid -> {'resource', 'kind', 'name', 'uid', 'rv', 'ref'}
        self.states = {resource: {'kind': RESOURCES[resource][0], 'state': 'not_started', 'since': None,
                                  'stream_id': None, 'list_resource_version': None, 'last_resource_version': None,
                                  'last_evidence': None, 'last_line': None, 'gap': None,
                                  'initial_failed_list_attempts': 0, 'first_event': None, 'last_event': None,
                                  'first_list': None}
                       for resource in self.resources}
        self.counts = Counter()
        self.events_by_type = Counter()
        self.events_by_resource = Counter()
        self.snapshots_by_trigger = Counter()
        self.gaps, self.thread_errors = [], []
        self.first_snapshot = self.last_snapshot = None
        self.start = None

    # -- writer -------------------------------------------------------------------------------
    def emit(self, stream, record, observed):
        """(Caller holds self.lock.) Number, stamp and write one record; returns its sequence number. accepted_at is
        read here, after parsing and projection; available_at is the poller's monotone acceptance (it never moves
        back when the wall clock does; clock_adjusted marks such a record). After finish() closed the files (a
        thread that did not join in time) nothing is written and None is returned."""
        if self.closed:
            self.counts['writes_after_close'] += 1
            return None
        accepted = host_time()
        self.sequence += 1
        logical = max(accepted['at_ns'], observed['at_ns'] if observed else 0, self.last_available_ns)
        record.update(sequence=self.sequence, record_id='{}/{}'.format(self.collection_id, self.sequence),
                      collection_id=self.collection_id, collector=COLLECTOR_TAG,
                      observed_at=observed['at'] if observed else None, available_at=iso_ns(logical),
                      available_at_ns=logical, clock_adjusted=logical != accepted['at_ns'])
        put_time(record, 'accepted', accepted)
        self.last_available_ns = logical
        data = (json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        handle = self.handles[stream]
        handle.write(data)
        handle.flush()
        self.lines[stream] += 1
        return self.sequence

    def raw(self, kind, sequence, data, extra=None):
        if self.archive is not None and data is not None and not self.closed:
            self.archive.write(kind, sequence, data, extra)

    def selector_query(self, resource):
        selector = self.selectors.get(resource)
        return {'labelSelector': selector} if selector else {}

    def state_view(self, resource):
        state = self.states[resource]
        return {'state': state['state'], 'since_at': state['since']['at'] if state['since'] else None,
                'last_resource_version': state['last_resource_version']}

    def snapshot(self, trigger, trigger_sequence):
        """(Caller holds self.lock.) The cache as one watch_cache_snapshot record. Objects are referenced by the
        sequence number of the record that carries their full projection (a watch_list_object or api_watch_event
        record of watch_events.jsonl), never repeated."""
        at = host_time()
        objects = sorted(({'kind': entry['kind'], 'name': entry['name'], 'uid': uid, 'resourceVersion': entry['rv'],
                           'ref': entry['ref']} for uid, entry in self.cache.items()),
                         key=lambda item: (item['kind'], item['uid'], item['resourceVersion']))
        identity = [[item['kind'], item['uid'], item['resourceVersion']] for item in objects]
        self.snapshot_index += 1
        record = {'record_type': 'watch_cache_snapshot', 'observation_basis': 'watch_cache_snapshot',
                  'snapshot_index': self.snapshot_index, 'trigger': trigger, 'trigger_sequence': trigger_sequence,
                  'namespace': self.namespace, 'resources': {name: self.state_view(name) for name in self.resources},
                  'object_count': len(objects), 'objects': objects,
                  'objects_sha256': sha256(json.dumps(identity, separators=(',', ':')).encode('ascii'))}
        put_time(record, 'snapshot', at)
        self.emit('snapshots', record, at)
        self.snapshots_by_trigger[trigger] += 1
        self.first_snapshot = self.first_snapshot or at
        self.last_snapshot = at

    def gap_record(self, resource, reason, gap_from, gap_to, **fields):
        record = {'record_type': 'continuity_gap', 'resource': resource, 'kind': RESOURCES[resource][0],
                  'reason': reason}
        put_time(record, 'gap_from', gap_from)
        put_time(record, 'gap_to', gap_to)
        record['duration_seconds'] = ((gap_to['monotonic_ns'] - gap_from['monotonic_ns']) / 1e9
                                      if gap_from and gap_to else None)
        record.update(fields)
        return record

    # -- list -----------------------------------------------------------------------------------
    def apply_list(self, resource, attempt, target, started, received, body, version, objects):
        kind = RESOURCES[resource][0]
        with self.lock:
            state = self.states[resource]
            relist = state['state'] != 'not_started'
            gap_sequence = None
            if not relist:
                record = self.gap_record(resource, 'history_before_collection_unknown', None, received, cause=None,
                                         open_at_stop=False,
                                         failed_list_attempts=state['initial_failed_list_attempts'])
                gap_sequence = self.emit('events', record, received)
            elif state['gap'] is not None:
                gap = state['gap']
                record = self.gap_record(resource, 'watch_interrupted', gap['gap_from'], received, cause=gap['cause'],
                                         stream_id=gap['stream_id'], open_at_stop=False,
                                         failed_list_attempts=gap['failed_list_attempts'],
                                         relist_attempt=attempt, **gap['details'])
                put_time(record, 'detected', gap['detected'])
                gap_sequence = self.emit('events', record, received)
                self.gaps.append({'resource': resource, 'cause': gap['cause'], 'gap_from_at': record['gap_from_at'],
                                  'gap_to_at': record['gap_to_at'], 'duration_seconds': record['duration_seconds'],
                                  'sequence': gap_sequence})
            before = {uid: entry for uid, entry in self.cache.items() if entry['resource'] == resource}
            now = {obj['metadata']['uid']: obj for obj in objects}
            record = {'record_type': 'watch_list', 'resource': resource, 'kind': kind, 'list_attempt': attempt,
                      'relist': relist, 'ok': True, 'closes_gap_sequence': gap_sequence, 'path': target,
                      'http_status': 200, 'error': None, 'body_bytes': len(body), 'body_sha256': sha256(body),
                      'list_resource_version': version, 'object_count': len(objects), 'uids': sorted(now),
                      'cache_change': None}
            if relist:
                record['cache_change'] = {
                    'absent_uids': sorted(set(before) - set(now)),
                    'absence_semantics': 'in the cache before this relist, not in it: deleted (or no longer '
                                         'selected) during the gap; the deletion time is unknown',
                    'new_uids': sorted(set(now) - set(before)),
                    'changed_uids': sorted(uid for uid in set(now) & set(before)
                                           if now[uid]['metadata']['resourceVersion'] != before[uid]['rv']),
                    'unchanged_count': sum(1 for uid in set(now) & set(before)
                                           if now[uid]['metadata']['resourceVersion'] == before[uid]['rv'])}
            put_time(record, 'request_started', started)
            put_time(record, 'response_received', received)
            list_sequence = self.emit('events', record, received)
            self.raw('list_body', list_sequence, body, {'resource': resource})
            for uid in before:
                if uid not in now:
                    del self.cache[uid]
            for obj in objects:
                meta = obj['metadata']
                item = {'record_type': 'watch_list_object', 'observation_basis': 'watch_list', 'resource': resource,
                        'kind': kind, 'list_sequence': list_sequence, 'uid': meta['uid'], 'name': meta['name'],
                        'namespace': meta.get('namespace'), 'resource_version': meta['resourceVersion'],
                        'resource_data': obj}
                put_time(item, 'response_received', received)
                sequence = self.emit('events', item, received)
                self.cache[meta['uid']] = {'resource': resource, 'kind': kind, 'name': meta['name'],
                                           'uid': meta['uid'], 'rv': meta['resourceVersion'], 'ref': sequence}
            state.update(state='open', since=received, gap=None, list_resource_version=version,
                         last_resource_version=version, last_evidence=received)
            state['first_list'] = state['first_list'] or received
            self.counts['relists' if relist else 'initial_lists'] += 1
            self.snapshot('list', list_sequence)

    def record_list_failure(self, resource, attempt, target, started, received, status, body, error):
        with self.lock:
            state = self.states[resource]
            record = {'record_type': 'watch_list', 'resource': resource, 'kind': RESOURCES[resource][0],
                      'list_attempt': attempt, 'relist': state['state'] != 'not_started', 'ok': False,
                      'closes_gap_sequence': None, 'path': target, 'http_status': status, 'error': error,
                      'body_bytes': len(body), 'body_sha256': sha256(body),
                      'status_object': parse_status_object(body) if body else None}
            put_time(record, 'request_started', started)
            put_time(record, 'response_received', received)
            sequence = self.emit('events', record, received)
            if body:
                self.raw('list_body', sequence, body, {'resource': resource})
            if state['gap'] is not None:
                state['gap']['failed_list_attempts'] += 1
            elif state['state'] == 'not_started':
                state['initial_failed_list_attempts'] += 1
            self.counts['list_failures'] += 1

    # -- watch streams ----------------------------------------------------------------------------
    def record_stream_open(self, resource, fields, started, head_at, body=None):
        with self.lock:
            record = {'record_type': 'watch_stream_open', 'resource': resource, 'kind': RESOURCES[resource][0],
                      'http_status': None, 'error': None, 'status_object': None, 'content_type': None,
                      'transfer_encoding': None}
            record.update(fields)
            put_time(record, 'request_started', started)
            put_time(record, 'response_head_received', head_at)
            sequence = self.emit('events', record, head_at or host_time())
            if body:
                self.raw('watch_error_body', sequence, body, {'resource': resource})
            if record['ok']:
                self.states[resource]['stream_id'] = fields['stream_id']
                self.counts['watch_streams_opened'] += 1
            else:
                self.counts['watch_streams_refused'] += 1

    def record_stream_end(self, resource, stream_id, cause, stats, connection, lines, details, detected):
        with self.lock:
            state = self.states[resource]
            record = {'record_type': 'watch_stream_end', 'resource': resource, 'kind': RESOURCES[resource][0],
                      'stream_id': stream_id, 'cause': cause, 'lines': stats['lines'], 'events': stats['events'],
                      'blank_lines': stats['blank_lines'], 'bytes': stats['bytes'],
                      'http_chunks': connection.decoder.chunks if connection.decoder else None,
                      'partial_line_bytes': len(lines.pending), 'error': details.get('error'),
                      'last_line_received_at': state['last_line']['at'] if state['last_line'] else None}
            put_time(record, 'detected', detected)
            self.emit('events', record, detected)
            self.counts['watch_streams_ended'] += 1

    def apply_event(self, resource, event_type, obj, projected, info, received, line):
        kind = RESOURCES[resource][0]
        with self.lock:
            state = self.states[resource]
            record = {'record_type': 'api_watch_event', 'observation_basis': 'watch_event', 'resource': resource,
                      'kind': kind, 'event_type': event_type, 'object_kind': obj.get('kind'), 'name': None,
                      'namespace': None, 'uid': None, 'resource_version': None, 'resource_data': None,
                      'status_object': None, 'cache_effect': 'none', 'cache_previous_resource_version': None}
            record.update(info)
            put_time(record, 'received', received)
            uid = rv = None
            if projected is not None:
                meta = projected['metadata']
                uid, rv = meta['uid'], meta['resourceVersion']
                previous = self.cache.get(uid)
                record.update(name=meta['name'], namespace=meta.get('namespace'), uid=uid, resource_version=rv,
                              resource_data=projected,
                              cache_previous_resource_version=previous['rv'] if previous else None,
                              cache_effect=(('delete' if previous else 'delete_absent') if event_type == 'DELETED'
                                            else ('update' if previous else 'insert')))
            elif event_type == 'BOOKMARK':
                meta = obj.get('metadata') or {}
                record.update(resource_version=meta.get('resourceVersion'),
                              bookmark_annotations=meta.get('annotations'))
            else:
                record['status_object'] = obj
            sequence = self.emit('events', record, received)
            self.raw('event_line', sequence, line, {'resource': resource})
            if projected is not None:
                if event_type == 'DELETED':
                    self.cache.pop(uid, None)
                else:
                    self.cache[uid] = {'resource': resource, 'kind': kind, 'name': record['name'], 'uid': uid,
                                       'rv': rv, 'ref': sequence}
            if event_type != 'ERROR':
                state['last_evidence'] = received
                state['last_resource_version'] = record['resource_version'] or state['last_resource_version']
            state['last_line'] = received
            state['first_event'] = state['first_event'] or received
            state['last_event'] = received
            self.events_by_type[event_type] += 1
            self.events_by_resource[resource] += 1
            if projected is not None:
                self.snapshot('event', sequence)

    def record_invalid_line(self, resource, info, received, line, error):
        with self.lock:
            record = {'record_type': 'invalid_watch_line', 'resource': resource, 'kind': RESOURCES[resource][0],
                      'error': error}
            record.update(info)
            put_time(record, 'received', received)
            sequence = self.emit('events', record, received)
            self.raw('invalid_line', sequence, line, {'resource': resource})
            self.states[resource]['last_line'] = received
            self.counts['invalid_lines'] += 1

    def open_gap(self, resource, cause, details):
        """A stream broke: the gap starts at the receipt of the stream's last good line (ADDED, MODIFIED, DELETED or
        BOOKMARK) or, without one, of the list; an ERROR or invalid line is not evidence of continuity."""
        with self.lock:
            state = self.states[resource]
            if state['gap'] is not None or state['state'] not in ('open', 'gap'):
                return
            details = dict(details)
            detected = details.pop('detected', None) or host_time()
            stream_id = details.pop('stream_id', None)
            state['gap'] = {'cause': cause, 'details': details, 'gap_from': state['last_evidence'],
                            'detected': detected, 'failed_list_attempts': 0, 'stream_id': stream_id}
            state.update(state='gap', since=state['last_evidence'], stream_id=None)
            self.counts['gaps_opened'] += 1

    def thread_error(self, resource, error):
        with self.lock:
            detected = host_time()
            text = error_text(error)
            self.thread_errors.append({'resource': resource, 'error': text})
            record = {'record_type': 'collector_error', 'resource': resource, 'error': text,
                      'traceback': traceback.format_exc()[-4000:]}
            put_time(record, 'detected', detected)
            self.emit('events', record, detected)
            state = self.states[resource]
            if state['gap'] is None and state['state'] == 'open':
                state['gap'] = {'cause': 'collector_error', 'details': {'error': text},
                                'gap_from': state['last_evidence'], 'detected': detected, 'failed_list_attempts': 0,
                                'stream_id': state['stream_id']}
                state['since'] = state['last_evidence']
            state.update(state='failed', stream_id=None)

    # -- periodic snapshots -------------------------------------------------------------------------
    def ticker(self):
        interval = self.snapshot_interval_ns
        tick = 1
        while not self.stop_event.is_set():
            delay = (self.start['monotonic_ns'] + tick * interval - time.monotonic_ns()) / 1e9
            if delay > 0 and self.stop_event.wait(delay):
                return
            if self.stop_event.is_set():
                return
            with self.lock:
                if self.closed:
                    return
                if any(state['state'] == 'open' for state in self.states.values()):
                    self.snapshot('periodic', None)
                else:
                    self.counts['periodic_snapshots_skipped_no_open_watch'] += 1
                if self.archive is not None:
                    self.archive.flush()
            tick += 1
            due = (time.monotonic_ns() - self.start['monotonic_ns']) // interval
            if due > tick:
                self.counts['periodic_ticks_skipped_late'] += due - tick
                tick = due

    # -- run --------------------------------------------------------------------------------------
    def request_stop(self, reason):
        self.external_reason = self.external_reason or reason
        self.stop_event.set()

    def stop_reason(self, deadline, watchers):
        if self.external_reason:
            return self.external_reason
        if self.stop_event.is_set():
            return 'stop_event'
        if self.stop_file is not None and self.stop_file.exists():
            return 'stop_file'
        if deadline is not None and time.monotonic() >= deadline:
            return 'seconds'
        if self.proxy is not None and not self.proxy.alive():
            return 'proxy_exited'
        if not any(thread.is_alive() for thread in watchers):
            return 'all_watchers_ended'
        return None

    def run(self):
        self.handles = {'events': open(self.paths['events'], 'xb'), 'snapshots': open(self.paths['snapshots'], 'xb')}
        if not self.args.no_raw:
            self.archive = RawArchive(self.paths['raw'])
        self.start = host_time()
        write_manifest(self.paths['manifest'], self.manifest('collecting', None, None, []), first=True)
        deadline = None if self.args.seconds is None else time.monotonic() + self.args.seconds
        watchers = [ResourceWatcher(self, resource) for resource in self.resources]
        ticker = threading.Thread(target=self.ticker, daemon=True, name='watch-snapshots')
        for thread in watchers + [ticker]:
            thread.start()
        reason = None
        try:
            while reason is None:
                reason = self.stop_reason(deadline, watchers)
                if reason is None:
                    self.stop_event.wait(0.1)
        except KeyboardInterrupt:
            reason = 'interrupted'
        stop_at = host_time()
        self.stop_event.set()
        for thread in watchers + [ticker]:
            thread.join(timeout=self.poll_seconds * 5 + self.request_timeout + 5)
        unjoined = [thread.name for thread in watchers + [ticker] if thread.is_alive()]
        return self.finish(reason, stop_at, unjoined)

    def finish(self, reason, stop_at, unjoined):
        with self.lock:
            for resource in self.resources:
                state = self.states[resource]
                if state['gap'] is not None:
                    gap = state['gap']
                    record = self.gap_record(resource, 'watch_interrupted', gap['gap_from'], None, cause=gap['cause'],
                                             stream_id=gap['stream_id'], open_at_stop=True,
                                             failed_list_attempts=gap['failed_list_attempts'], **gap['details'])
                    put_time(record, 'detected', gap['detected'])
                    sequence = self.emit('events', record, stop_at)
                    self.gaps.append({'resource': resource, 'cause': gap['cause'],
                                      'gap_from_at': record['gap_from_at'], 'gap_to_at': None,
                                      'duration_seconds': None, 'open_at_stop': True, 'sequence': sequence})
                    final_from = gap['gap_from']
                elif state['first_list'] is None:          # never listed (also: a thread that failed before)
                    self.emit('events', self.gap_record(
                        resource, 'history_before_collection_unknown', None, None, cause=None, open_at_stop=True,
                        failed_list_attempts=state['initial_failed_list_attempts']), stop_at)
                    final_from = None
                else:
                    final_from = stop_at
                self.emit('events', self.gap_record(
                    resource, 'history_after_collection_unknown', final_from, None, cause=None, open_at_stop=False,
                    last_line_received_at=state['last_line']['at'] if state['last_line'] else None), stop_at)
            listed = [resource for resource in self.resources if self.states[resource]['first_list'] is not None]
            end = {'record_type': 'collection_end', 'reason': reason, 'events_by_type': dict(self.events_by_type),
                   'snapshots_by_trigger': dict(self.snapshots_by_trigger), 'gaps': len(self.gaps),
                   'resources_never_listed': [name for name in self.resources if name not in listed],
                   'thread_errors': len(self.thread_errors), 'unjoined_threads': unjoined}
            put_time(end, 'stop_requested', stop_at)
            self.emit('events', end, stop_at)
            self.closed = True
            for handle in self.handles.values():
                handle.close()
            if self.archive is not None:
                self.archive.close()
        proxy_record = self.proxy.stop() if self.proxy is not None else None
        normal = reason in NORMAL_STOPS or str(reason).startswith('signal:')
        complete = len(listed) == len(self.resources) and not self.thread_errors and not unjoined
        status = ('finished' if normal and complete else
                  'interrupted' if reason == 'interrupted' else 'partial')
        manifest = self.manifest(status, reason, stop_at, unjoined, proxy_record)
        write_manifest(self.paths['manifest'], manifest)
        return manifest

    def manifest(self, status, reason, stop_at, unjoined, proxy_record=None):
        args = self.args
        finished = host_time() if status != 'collecting' else None
        per_resource = {}
        for resource in self.resources:
            state = self.states[resource]
            per_resource[resource] = {
                'kind': RESOURCES[resource][0], 'label_selector': self.selectors.get(resource),
                'path': collection_path(resource, self.namespace),
                'first_list_received_at': state['first_list']['at'] if state['first_list'] else None,
                'first_event_received_at': state['first_event']['at'] if state['first_event'] else None,
                'last_event_received_at': state['last_event']['at'] if state['last_event'] else None,
                'events': self.events_by_resource[resource], 'final_state': state['state'],
                'max_gap_seconds': max((gap['duration_seconds'] or 0 for gap in self.gaps
                                        if gap['resource'] == resource), default=0.0)}
        firsts = [state['first_event'] for state in self.states.values() if state['first_event']]
        lasts = [state['last_event'] for state in self.states.values() if state['last_event']]
        files = {}
        if status != 'collecting':
            for key in ('events', 'snapshots', 'raw'):
                entry = file_entry(self.paths[key])
                if entry is not None:
                    files[self.paths[key].name] = entry
        return {
            'schema_version': SCHEMA_VERSION, 'collector': COLLECTOR_TAG, 'collection_id': self.collection_id,
            'status': status, 'stop_reason': reason, 'namespace': self.namespace, 'resources': self.resources,
            'kinds': {resource: RESOURCES[resource][0] for resource in self.resources},
            'label_selectors': self.selectors, 'per_resource': per_resource,
            'proxy': {'base_url': self.base_url, 'started_by_collector': self.proxy is not None,
                      'record': proxy_record},
            'options': {'seconds': args.seconds, 'stop_file': args.stop_file,
                        'snapshot_interval_seconds': args.snapshot_interval_seconds,
                        'watch_timeout_seconds': self.watch_timeout,
                        'request_timeout_seconds': self.request_timeout, 'poll_seconds': self.poll_seconds,
                        'raw_archive': not args.no_raw},
            'started_at': self.start['at'] if self.start else None,
            'started_monotonic_ns': self.start['monotonic_ns'] if self.start else None,
            'stop_requested_at': stop_at['at'] if stop_at else None,
            'finished_at': finished['at'] if finished else None,
            'elapsed_seconds': ((finished['monotonic_ns'] - self.start['monotonic_ns']) / 1e9
                                if finished and self.start else None),
            'first_event_received_at': min(firsts, key=lambda t: t['monotonic_ns'])['at'] if firsts else None,
            'last_event_received_at': max(lasts, key=lambda t: t['monotonic_ns'])['at'] if lasts else None,
            'first_snapshot_at': self.first_snapshot['at'] if self.first_snapshot else None,
            'last_snapshot_at': self.last_snapshot['at'] if self.last_snapshot else None,
            'counts': {'records': self.sequence, 'lines_by_file': {FILES[key]: self.lines[key] for key in self.handles},
                       'events_by_type': dict(self.events_by_type), 'events_by_resource': dict(self.events_by_resource),
                       'snapshots_by_trigger': dict(self.snapshots_by_trigger),
                       'raw_archive_entries': self.archive.count if self.archive else 0, **dict(self.counts)},
            'continuity_gaps': self.gaps, 'thread_errors': self.thread_errors, 'unjoined_threads': unjoined,
            'files': files,
            'sources': {'collect_watch_v1.py': sha256_file(__file__),
                        'kube_proxy_v1.py': sha256_file(SCRIPTS / 'kube_proxy_v1.py'),
                        'collect_deployment_history.py (projection, read-only)': sha256_file(poller_v1.__file__)},
            'host': {'python': sys.version, 'platform': platform.platform(), 'clock': clock_info()},
            'temporal_semantics': ('informer trust model: while a kind\'s watch is open, no event means no change; '
                                   'a kind is continuous from its list receipt until the receipt of the last good '
                                   'line of a stream that broke (continuity_gap records are authoritative); '
                                   'object timestamps are kubelet / API-server clocks, receipts are host clocks'),
            'format': 'phase3/CAPTURE_FORMAT_STAGE2.md'}


# ----------------------------------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------------------------------
def collect(args, stop_event=None, install_signals=False):
    """Run one watch collection (blocking) and return the final manifest."""
    selectors = validate_common(args)
    if not args.resources or len(set(args.resources)) != len(args.resources):
        raise ValueError('--resources must be unique members of ' + ', '.join(RESOURCES))
    for name, low, high in (('snapshot_interval_seconds', 0.05, 60), ('watch_timeout_seconds', 10, 86400),
                            ('request_timeout_seconds', 0.5, 120), ('poll_seconds', 0.01, 5)):
        value = getattr(args, name)
        if not low <= value <= high:
            raise ValueError('--{} must be in [{}, {}]'.format(name.replace('_', '-'), low, high))
    paths = prepare_output(args.output_dir, FILES)
    base, host, port, proxy = connect_proxy(args)
    collector = WatchCollector(args, selectors, paths, base, host, port, proxy=proxy, stop_event=stop_event)
    if install_signals:
        install_stop_signals(collector.request_stop)
    try:
        return collector.run()
    except BaseException:
        if proxy is not None:
            proxy.stop()
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_arguments(result)
    result.add_argument('--resources', nargs='+', choices=list(RESOURCES), default=list(DEFAULT_RESOURCES),
                        help='kinds to watch (default: all five)')
    result.add_argument('--snapshot-interval-seconds', type=float, default=1.0,
                        help='periodic cache snapshot interval while a watch is open (1 s)')
    result.add_argument('--watch-timeout-seconds', type=int, default=1800,
                        help='server-side timeoutSeconds of each watch request; longer than a capture, so that a '
                             'normal server timeout does not cause a relist inside one')
    result.add_argument('--request-timeout-seconds', type=float, default=10.0,
                        help='connect, LIST and watch-head timeout')
    result.add_argument('--poll-seconds', type=float, default=0.2,
                        help='socket read timeout between stop checks (no bytes are lost on a timeout)')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        manifest = collect(args, install_signals=True)
    except (ValueError, OSError, ProxyError) as error:
        raise SystemExit('Watch collection failed: ' + error_text(error)) from error
    print(json.dumps({key: manifest[key] for key in ('collector', 'collection_id', 'status', 'stop_reason',
                                                      'counts', 'continuity_gaps', 'files')}, indent=2))
    return 0 if manifest['status'] == 'finished' else 2


if __name__ == '__main__':
    raise SystemExit(main())
