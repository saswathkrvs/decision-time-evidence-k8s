#!/usr/bin/env python3
"""Host-command receipt v1: run one host argv (the capture runner's ``docker exec <node> crictl ...`` and ``docker exec
<node> date +%s.%N`` commands) and keep a receipt in the layout of the development kubectl receipts, with
``kind: host_command``.

The F2 container kill runs the argv built by src/aiops_kg/fault_control_kill.py through this helper, and so do the
clock probes. The capture runner calls ``run_host_command`` with its own receipt sequence and appends the returned
receipt to capture.json ``command_receipts``; the evaluator reads the kill receipt's times and argv. The command
itself causes the physical event; the receipt only records that it ran. Python 3.10+ standard library only.

Receipt layout: one JSON object per command, written to ``<capture>/<folder>/<id>.receipt.json`` (folder default
``raw``) and returned to the caller, with every field of a development kubectl receipt (phase3/CAPTURE_FORMAT.md,
``command_receipts``) present with the same meaning.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

SCHEMA = 'host-command-receipt-v1'
KIND = 'host_command'
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_OUTPUT_BYTES = 1024 * 1024
INLINE_BYTES = 4096
TIMEOUT_EXIT_CODE = 124            # phase3/run_incident.py Recorder.command
START_FAILURE_EXIT_CODE = 127      # idem
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')


def iso_from_ns(ns):
    """Host wall-clock ns -> '2026-10-19T10:01:00.300000Z' (microseconds, truncated)."""
    seconds, rest = divmod(int(ns), 1_000_000_000)
    return '{}.{:06d}Z'.format(datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'),
                               rest // 1000)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_identifier(identifier):
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise ValueError('command ID must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}, got ' + repr(identifier))
    return identifier


def check_argv(argv):
    if not isinstance(argv, (list, tuple)) or not argv or not all(
            isinstance(value, str) and value != '' and '\0' not in value for value in argv):
        raise ValueError('argv must be a nonempty list of nonempty strings without NUL')
    return list(argv)


def check_folder(folder):
    """A relative folder inside the capture ('raw', 'ground_truth/raw'): no absolute path, drive or '..'."""
    if not isinstance(folder, str) or not folder:
        raise ValueError('folder must be a nonempty relative path')
    for pure in (PurePosixPath(folder), PureWindowsPath(folder)):
        if pure.is_absolute() or pure.drive or '..' in pure.parts:
            raise ValueError('folder must stay inside the capture directory, got ' + repr(folder))
    return folder.replace('\\', '/').strip('/')


def _text(data, limit):
    return data[:limit].decode('utf-8', 'replace')


def run_host_command(identifier, argv, *, capture_dir=None, folder='raw', timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
                     dry_run=False, sequence=None, runner=subprocess.run, wall_ns=time.time_ns,
                     monotonic_ns=time.monotonic_ns, max_output_bytes=MAX_OUTPUT_BYTES, inline_bytes=INLINE_BYTES,
                     creationflags=0, printer=print):
    """Run `argv` once (no shell) and return (stdout bytes, exit code, receipt); see the module docstring.

    `sequence`: optional zero-argument callable (the runner's `Recorder.seq`) read before and after. `runner`,
    `wall_ns`, `monotonic_ns` and `printer` are injectable for tests. `creationflags` is passed to subprocess.run
    only when non-zero (Windows: CREATE_NEW_PROCESS_GROUP shields a teardown command from a second Ctrl-C). A
    command that cannot start or times out still yields a receipt (exit 127 / 124), as in `Recorder.command`.
    """
    check_identifier(identifier)
    argv = check_argv(argv)
    folder = check_folder(folder)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 600:
        raise ValueError('timeout_seconds must be in (0, 600]')
    for name, value in (('max_output_bytes', max_output_bytes), ('inline_bytes', inline_bytes)):
        if type(value) is not int or value < 0:
            raise ValueError(name + ' must be a nonnegative integer')
    paths = {}
    if capture_dir is not None:
        base = Path(capture_dir) / folder
        paths = {suffix: base / '{}.{}'.format(identifier, suffix) for suffix in ('stdout', 'stderr', 'receipt.json')}
        existing = [str(path) for path in paths.values() if path.exists()]
        if existing:
            raise FileExistsError('refusing to run {}: {} already exist(s); a capture is never overwritten'.format(
                identifier, ', '.join(existing)))
        base.mkdir(parents=True, exist_ok=True)
    start_sequence = sequence() if sequence is not None else None
    wall_start, mono_start = wall_ns(), monotonic_ns()
    out = err = b''
    code, error, timed_out = None, None, False
    if dry_run:
        printer('[dry-run] {} would run: {}'.format(identifier, json.dumps(argv)))
        printer('[dry-run] command line: ' + subprocess.list2cmdline(argv))
        wall_end, mono_end = wall_start, mono_start
    else:
        kwargs = {'capture_output': True, 'timeout': timeout_seconds}
        if creationflags:
            kwargs['creationflags'] = creationflags
        try:
            done = runner(argv, **kwargs)
            out, err, code = done.stdout or b'', done.stderr or b'', done.returncode
        except subprocess.TimeoutExpired as exc:
            out, err, code = exc.stdout or b'', exc.stderr or b'', TIMEOUT_EXIT_CODE
            error, timed_out = repr(exc), True
        except OSError as exc:
            out, err, code = b'', repr(exc).encode('utf-8'), START_FAILURE_EXIT_CODE
            error = repr(exc)
        wall_end, mono_end = wall_ns(), monotonic_ns()
    end_sequence = sequence() if sequence is not None else None
    if isinstance(out, str):          # a runner in text mode: keep bytes semantics
        out = out.encode('utf-8')
    if isinstance(err, str):
        err = err.encode('utf-8')
    files = {'stdout_file': None, 'stderr_file': None, 'receipt_file': None}
    written = {'stdout': 0, 'stderr': 0}
    if paths and not dry_run:
        for name, data in (('stdout', out), ('stderr', err)):
            with paths[name].open('xb') as handle:
                handle.write(data[:max_output_bytes])
            written[name] = min(len(data), max_output_bytes)
            files[name + '_file'] = '{}/{}.{}'.format(folder, identifier, name)
    if paths:
        files['receipt_file'] = '{}/{}.receipt.json'.format(folder, identifier)
    receipt = {
        'kind': KIND, 'schema': SCHEMA, 'id': identifier, 'args': argv, 'argv_prefix': 'none',
        'command_line': subprocess.list2cmdline(argv), 'executed': not dry_run,
        'request_started_at': iso_from_ns(wall_start), 'response_received_at': iso_from_ns(wall_end),
        'collector_available_at': iso_from_ns(wall_ns()),
        'host_wall_start_ns': wall_start, 'host_wall_end_ns': wall_end,
        'host_monotonic_start_ns': mono_start, 'host_monotonic_end_ns': mono_end,
        'start_sequence': start_sequence, 'end_sequence': end_sequence,
        'timeout_seconds': timeout_seconds, 'timed_out': timed_out, 'exit_code': code, 'error': error,
        'stdout_file': files['stdout_file'], 'stderr_file': files['stderr_file'],
        'stdout_sha256': sha256(out), 'stderr_sha256': sha256(err),
        'stdout_bytes': len(out), 'stderr_bytes': len(err),
        'stdout_file_bytes': written['stdout'], 'stderr_file_bytes': written['stderr'],
        'stdout_truncated': bool(paths) and not dry_run and len(out) > max_output_bytes,
        'stderr_truncated': bool(paths) and not dry_run and len(err) > max_output_bytes,
        'stdout_text': _text(out, inline_bytes), 'stderr_text': _text(err, inline_bytes),
        'receipt_file': files['receipt_file'], 'python': platform.python_version(), 'platform': sys.platform,
    }
    if paths:
        with paths['receipt.json'].open('xb') as handle:
            handle.write((json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    return out, code, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--id', required=True, help='command ID, unique in the capture')
    parser.add_argument('--capture', type=Path, help='capture directory (files go to <capture>/<folder>/)')
    parser.add_argument('--folder', default='raw')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument('--dry-run', action='store_true', help='print the argv and write a receipt; run nothing')
    parser.add_argument('command', nargs=argparse.REMAINDER, help='-- followed by the argv to run')
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('give the command after --')
    out, code, receipt = run_host_command(args.id, command, capture_dir=args.capture, folder=args.folder,
                                          timeout_seconds=args.timeout, dry_run=args.dry_run)
    summary = {key: receipt[key] for key in ('id', 'executed', 'exit_code', 'timed_out', 'request_started_at',
                                             'response_received_at', 'stdout_sha256', 'stdout_bytes', 'receipt_file')}
    summary['stdout_text'] = receipt['stdout_text'][:500]
    summary['stderr_text'] = receipt['stderr_text'][-500:]
    print(json.dumps(summary, indent=1, sort_keys=True))
    if args.dry_run:
        return 0
    return code if isinstance(code, int) and 0 <= code < 256 else 1


if __name__ == '__main__':
    sys.exit(main())
