"""Shared helpers of the capture smoke kit (infrastructure/stage2/smoke/). Not a script; importing it contacts nothing.

Conventions shared by every smoke script:
  * host receipt times are recorded twice: ``time.time_ns()`` (integer ns since the epoch, host wall clock) and the
    same instant as ISO-8601 UTC with microseconds and a trailing Z; plus ``time.monotonic_ns()`` for intervals;
  * outputs are opened in exclusive mode ('x'): an existing file is never overwritten;
  * the project's cluster is reached with the project kubeconfig and context, never the user's current context;
  * scripts that change something (a patch, a container kill) accept only a scratch namespace aiops-s2-smoke-*.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]                                   # infrastructure/stage2/smoke -> repository root
KUBECONFIG = ROOT / '.runtime' / 'context-pilot' / 'kubeconfig'
OWNER_FILE = ROOT / '.runtime' / 'context-pilot' / 'cluster-owner.json'
CONTEXT = 'kind-aiops-context-pilot'
NODE = 'aiops-context-pilot-control-plane'
DEFAULT_DOCKER = 'docker'          # the laptop's other scripts use "docker --context desktop-linux" (pass it via --docker)
SCRATCH_PREFIX = 'aiops-s2-smoke-'
SYSTEM_NAMESPACES = {'default', 'kube-system', 'kube-public', 'kube-node-lease', 'local-path-storage'}
WRITTEN_BY = 'infrastructure/stage2/smoke'
NEW_GROUP = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)   # Windows: Ctrl-C reaches only this script
DNS_LABEL = re.compile(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?')
RFC3339 = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$')


# ---------------------------------------------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------------------------------------------
def iso_from_ns(ns: int) -> str:
    """Host wall-clock ns -> '2026-10-19T14:00:00.123456Z' (microseconds, truncated; the ns value is kept apart)."""
    seconds, rest = divmod(int(ns), 1_000_000_000)
    return '{}.{:06d}Z'.format(datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'),
                               rest // 1000)


def host_now() -> dict:
    """One host instant: wall-clock ns, its ISO form and the monotonic ns."""
    wall, mono = time.time_ns(), time.monotonic_ns()
    return {'ns': wall, 'at': iso_from_ns(wall), 'monotonic_ns': mono}


def parse_rfc3339_ns(text):
    """A Kubernetes timestamp ('2026-10-19T14:00:00Z', optional fraction or offset) -> ns since the epoch, or None."""
    if not isinstance(text, str):
        return None
    match = RFC3339.match(text)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    moment = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc)
    ns = int(moment.timestamp()) * 1_000_000_000 + (int((fraction or '').ljust(9, '0')) if fraction else 0)
    if zone != 'Z':
        sign = 1 if zone[0] == '+' else -1
        ns -= sign * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60) * 1_000_000_000
    return ns


def clock_info() -> dict:
    """What the host clock can resolve (recorded so that a reader knows the receipt-time resolution)."""
    info = time.get_clock_info('time')
    return {'implementation': info.implementation, 'resolution_seconds': info.resolution,
            'monotonic': info.monotonic, 'adjustable': info.adjustable,
            'python': sys.version.split()[0], 'platform': sys.platform}


# ---------------------------------------------------------------------------------------------------------------
# Command lines
# ---------------------------------------------------------------------------------------------------------------
def split_argv(text: str) -> list:
    """Split a command prefix such as 'docker --context desktop-linux' or '"C:\\Program Files\\Docker\\docker.exe"'
    into argv. Whitespace separates words; double quotes group (and are removed); backslashes are literal (Windows
    paths). No other shell syntax."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError('empty command prefix')
    words, current, quoted, started = [], [], False, False
    for char in text:
        if char == '"':
            quoted, started = not quoted, True
        elif char.isspace() and not quoted:
            if started:
                words.append(''.join(current))
                current, started = [], False
        else:
            current.append(char)
            started = True
    if quoted:
        raise ValueError('unbalanced double quote in ' + repr(text))
    if started:
        words.append(''.join(current))
    return words


def resolve_executable(argv: list, which=shutil.which) -> list:
    """argv with argv[0] replaced by the full path that PATH (and PATHEXT on Windows, e.g. kubectl.exe) gives."""
    found = which(argv[0])
    if not found:
        raise FileNotFoundError('{} not found on PATH (on Windows: is {}.exe installed and on PATH?)'.format(
            argv[0], argv[0]))
    return [found] + list(argv[1:])


def kubectl_base(kubectl: str, kubeconfig, context: str, which=shutil.which) -> list:
    """kubectl with the project kubeconfig and context (never the user's current context)."""
    return resolve_executable([kubectl], which) + ['--kubeconfig', str(kubeconfig), '--context', context]


def docker_base(docker: str, which=shutil.which) -> list:
    return resolve_executable(split_argv(docker), which)


def check_namespace(namespace: str, scratch_only: bool) -> str:
    """A DNS-label namespace outside the system namespaces; for changing scripts also inside aiops-s2-smoke-*."""
    if not isinstance(namespace, str) or not DNS_LABEL.fullmatch(namespace):
        raise ValueError('namespace must be a DNS label, got {!r}'.format(namespace))
    if namespace in SYSTEM_NAMESPACES:
        raise ValueError('refusing a system namespace: ' + namespace)
    if scratch_only and not namespace.startswith(SCRATCH_PREFIX):
        raise ValueError('this script changes the cluster and accepts only a scratch namespace {}*, got {}'.format(
            SCRATCH_PREFIX, namespace))
    return namespace


def run_timed(argv: list, timeout: float, runner=subprocess.run) -> dict:
    """Run one command; never raises for a failing command. Host times bracket the call."""
    before = host_now()
    try:
        done = runner(argv, capture_output=True, timeout=timeout)
        out, err, code = done.stdout or b'', done.stderr or b'', done.returncode
    except subprocess.TimeoutExpired as error:
        out, err, code = error.stdout or b'', error.stderr or b'', 124
    except OSError as error:
        out, err, code = b'', repr(error).encode('utf-8'), 127
    after = host_now()
    return {'argv': [str(value) for value in argv], 'exit_code': code, 'stdout': out, 'stderr': err,
            'request_started_ns': before['ns'], 'request_started_at': before['at'],
            'response_received_ns': after['ns'], 'response_received_at': after['at'],
            'elapsed_seconds': round((after['monotonic_ns'] - before['monotonic_ns']) / 1e9, 6)}


def receipt_fields(result: dict) -> dict:
    """The JSON-safe part of a run_timed result (stdout/stderr summarised, not inlined)."""
    return {key: result[key] for key in ('argv', 'exit_code', 'request_started_ns', 'request_started_at',
                                         'response_received_ns', 'response_received_at', 'elapsed_seconds')} | {
        'stdout_bytes': len(result['stdout']), 'stdout_sha256': hashlib.sha256(result['stdout']).hexdigest(),
        'stderr_text': result['stderr'].decode('utf-8', 'replace')[-2000:]}


def stop_process(process, grace_seconds: float = 5.0) -> dict:
    """terminate(), wait, then kill() if still alive. On Windows both are TerminateProcess."""
    if process is None:
        return {'method': 'not_started'}
    if process.poll() is not None:
        return {'method': 'already_exited', 'exit_code': process.returncode}
    process.terminate()
    try:
        process.wait(timeout=grace_seconds)
        return {'method': 'terminate', 'exit_code': process.returncode}
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            return {'method': 'kill_unconfirmed', 'exit_code': None}
        return {'method': 'kill', 'exit_code': process.returncode}


def popen_group_kwargs() -> dict:
    """Start a long-lived child in its own process group, so the console's Ctrl-C reaches only this script, which
    then stops the child itself (Windows: CREATE_NEW_PROCESS_GROUP; POSIX: a new session)."""
    return {'creationflags': NEW_GROUP} if os.name == 'nt' else {'start_new_session': True}


# ---------------------------------------------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------------------------------------------
class JsonlWriter:
    """Thread-safe JSON-lines writer; exclusive create; one flush per line."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open('x', encoding='utf-8', newline='\n')
        self.lock = threading.Lock()
        self.count = 0

    def write(self, record: dict):
        line = json.dumps(record, sort_keys=True) + '\n'
        with self.lock:
            self.handle.write(line)
            self.handle.flush()
            self.count += 1

    def close(self) -> str:
        with self.lock:
            if not self.handle.closed:
                self.handle.close()
        return file_sha256(self.path)


def write_json_exclusive(path, value) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
    return file_sha256(path)


def file_sha256(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _flat(value) -> bool:
    return not isinstance(value, (dict, list, tuple)) or (
        isinstance(value, (list, tuple)) and all(not isinstance(item, (dict, list, tuple)) for item in value))


def compact_json(value, indent: int = 0) -> str:
    """JSON for pasting: one key per line, keys sorted, None values left out, lists of scalars (and short lists of
    short lists) on one line. Still valid JSON."""
    if isinstance(value, dict):
        entries = [(key, item) for key, item in sorted(value.items()) if item is not None]
        if not entries:
            return '{}'
        if all(not isinstance(item, (dict, list, tuple)) for _, item in entries):
            text = json.dumps(dict(entries), sort_keys=True, default=str)
            if len(text) <= 90:
                return text
        inner = ',\n'.join('{}{}: {}'.format(' ' * (indent + 1), json.dumps(str(key)), compact_json(item, indent + 1))
                           for key, item in entries)
        return '{\n' + inner + '\n' + ' ' * indent + '}'
    if isinstance(value, (list, tuple)):
        text = json.dumps(value, sort_keys=True, default=str)
        scalars_only = all(not isinstance(item, (dict, list, tuple)) for item in value)
        if scalars_only or (all(_flat(item) for item in value) and len(text) <= 110):
            return text
        inner = ',\n'.join(' ' * (indent + 1) + compact_json(item, indent + 1) for item in value)
        return '[\n' + inner + '\n' + ' ' * indent + ']'
    return json.dumps(value, default=str)


def print_summary(title: str, summary: dict):
    """Print a titled summary block of the run."""
    print('=== SUMMARY: {} ==='.format(title))
    print(compact_json(summary))
    print('=== END ===', flush=True)


def say(message: str):
    print(time.strftime('%H:%M:%S'), message, flush=True)


def median(values):
    ordered = sorted(value for value in values if value is not None)
    if not ordered:
        return None
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


if __name__ == '__main__':
    print('smoke_common.py is the shared helper module of the Stage-2 smoke kit; it has no command line of its own.\n'
          'Run the scripts next to it (each has --help and --self-test).')
