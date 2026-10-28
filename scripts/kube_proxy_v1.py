#!/usr/bin/env python3
"""Start, read through and stop one ``kubectl proxy`` on loopback (collector tag kube-proxy-v1).

The watch collector and the live recheck read the API through one proxy on loopback, so that no kubectl process is
spawned per read. Python 3.10+ standard library only; importing this module starts nothing and contacts no cluster.

What it does:
  * starts ``kubectl [--kubeconfig K] [--context C] [--server S] proxy --port=0 --address=127.0.0.1
    --reject-methods=^POST$,^PUT$,^PATCH$,^DELETE$`` (read-only by default; the whole argv is configurable);
  * reads the bound port from the proxy's stdout line "Starting to serve on 127.0.0.1:NNNNN";
  * exposes base_url, get(path) (urllib with a timeout and with no system or environment HTTP proxy) and stop();
  * drains the proxy's stdout and stderr in threads, and records its own start, serving and stop host times.

    python scripts/kube_proxy_v1.py --kubeconfig .runtime/context-pilot/kubeconfig --get /version --seconds 10 \
        --record proxy.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

PROXY_TAG = 'kube-proxy-v1'
# kubectl's proxy command prints exactly this line once its listener is bound (with --port=0 the real port).
SERVE_LINE = re.compile(r'^Starting to serve on (?P<host>127\.0\.0\.1|localhost|\[::1\]):(?P<port>[0-9]{1,5})$')
# kubectl proxy's --reject-methods takes comma-separated regular expressions; the observers only ever GET.
READ_ONLY_REJECT_METHODS = '^POST$,^PUT$,^PATCH$,^DELETE$'
NEW_GROUP = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)   # Windows: Ctrl-C is not delivered to the proxy
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost', '::1')
TAIL_LINES = 200


class ProxyError(RuntimeError):
    """kubectl proxy could not be started, or is not serving."""


# ----------------------------------------------------------------------------------------------
# Host clock helpers (shared by collect_watch_v1.py and recheck_loop_v1.py)
# ----------------------------------------------------------------------------------------------
def iso_ns(epoch_ns: int) -> str:
    """UTC ISO-8601 with nine fractional digits and 'Z' (accepted by aiops_kg.evidence.timestamp_ns)."""
    seconds, fraction = divmod(int(epoch_ns), 10 ** 9)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(seconds)) + '.{:09d}Z'.format(fraction)


def host_time() -> dict:
    """One host reading: wall clock (time.time_ns, UTC) and monotonic clock (time.monotonic_ns), back to back."""
    wall = time.time_ns()
    mono = time.monotonic_ns()
    return {'at': iso_ns(wall), 'at_ns': wall, 'monotonic_ns': mono}


def put_time(record: dict, name: str, value) -> dict:
    """Write one host reading as <name>_at (ISO), <name>_at_ns (epoch ns) and <name>_monotonic_ns; None -> nulls."""
    record[name + '_at'] = value['at'] if value else None
    record[name + '_at_ns'] = value['at_ns'] if value else None
    record[name + '_monotonic_ns'] = value['monotonic_ns'] if value else None
    return record


def clock_info() -> dict:
    """What the host clocks are (implementation and resolution), for the manifests."""
    result = {}
    for name in ('time', 'monotonic'):
        info = time.get_clock_info(name)
        result[name] = {'implementation': info.implementation, 'resolution': info.resolution,
                        'monotonic': info.monotonic, 'adjustable': info.adjustable}
    return result


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


# ----------------------------------------------------------------------------------------------
# Proxy URL and plain GET (no system proxy)
# ----------------------------------------------------------------------------------------------
def loopback_base_url(url: str) -> tuple:
    """(base_url, host, port) of an http://<loopback>:<port> proxy URL; anything else is a ValueError."""
    if not isinstance(url, str) or url != url.strip():
        raise ValueError('proxy URL must be a string without outer whitespace')
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname not in LOOPBACK_HOSTS or parts.port is None:
        raise ValueError('proxy URL must be http://127.0.0.1:<port> (loopback only), got ' + repr(url))
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('proxy URL must not carry credentials, a path, a query or a fragment: ' + repr(url))
    host = '[::1]' if parts.hostname == '::1' else parts.hostname
    return 'http://{}:{}'.format(host, parts.port), parts.hostname, parts.port


def direct_opener():
    """A urllib opener that never uses an HTTP proxy (environment variables or the Windows registry)."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_get(base_url: str, path: str, timeout: float = 10.0, opener=None) -> dict:
    """GET base_url + path with urllib. Returns status (None on a transport error), body bytes, its SHA-256 and the
    host times just before the request and just after the whole body arrived. Never raises for HTTP or socket errors."""
    if not isinstance(path, str) or not path.startswith('/') or any(c in path for c in '\r\n ') or '://' in path:
        raise ValueError('path must be an absolute API path such as /version: ' + repr(path))
    opener = opener or direct_opener()
    request = urllib.request.Request(base_url + path, headers={'Accept': 'application/json'}, method='GET')
    started = host_time()
    status, reason, headers, body, error = None, None, {}, b'', None
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read()
            status, reason, headers = response.status, response.reason, dict(response.headers.items())
    except urllib.error.HTTPError as failure:
        status, reason = failure.code, failure.reason
        headers = dict(failure.headers.items()) if failure.headers else {}
        try:
            body = failure.read()
        except OSError:
            body = b''
    except (urllib.error.URLError, OSError, ValueError) as failure:
        error = repr(failure)
    received = host_time()
    result = {'path': path, 'url': base_url + path, 'status': status, 'reason': reason, 'headers': headers,
              'body': body, 'body_bytes': len(body), 'body_sha256': sha256(body), 'error': error}
    put_time(result, 'request_started', started)
    put_time(result, 'response_received', received)
    return result


# ----------------------------------------------------------------------------------------------
# kubectl proxy process
# ----------------------------------------------------------------------------------------------
def resolve_kubectl(kubectl=None, which=None) -> str:
    """Full path of kubectl (kubectl.exe on Windows, through PATHEXT) or a FileNotFoundError."""
    name = kubectl or 'kubectl'
    found = (which or shutil.which)(name)
    if not found:
        raise FileNotFoundError('kubectl not found ({!r}); pass --kubectl with the full path of kubectl.exe'
                                .format(name))
    return found


def proxy_argv(kubectl: str, *, context=None, kubeconfig=None, server=None, read_only=True, extra_args=()) -> list:
    """The argv of `kubectl proxy` on loopback with a kernel-chosen port."""
    argv = [kubectl]
    if kubeconfig:
        argv += ['--kubeconfig', str(kubeconfig)]
    if context:
        argv += ['--context', context]
    if server:
        argv += ['--server', server]
    argv += ['proxy', '--port=0', '--address=127.0.0.1']
    if read_only:
        argv.append('--reject-methods=' + READ_ONLY_REJECT_METHODS)
    return argv + [str(value) for value in extra_args]


class KubeProxy:
    """One `kubectl proxy` child process on 127.0.0.1 with a kernel-chosen port (see the module docstring)."""

    def __init__(self, kubectl=None, *, context=None, kubeconfig=None, server=None, read_only=True, extra_args=(),
                 argv=None, start_timeout=20.0, stop_timeout=10.0, shield_from_ctrl_c=True, stderr_path=None,
                 popen=None, which=None):
        if argv is not None:
            self.argv = [str(value) for value in argv]
        else:
            self.argv = proxy_argv(resolve_kubectl(kubectl, which), context=context, kubeconfig=kubeconfig,
                                   server=server, read_only=read_only, extra_args=extra_args)
        self.start_timeout, self.stop_timeout = float(start_timeout), float(stop_timeout)
        self.shield = bool(shield_from_ctrl_c)
        self.stderr_path = Path(stderr_path) if stderr_path else None
        self._popen = popen if popen is not None else subprocess.Popen
        self.process = None
        self.base_url = None
        self.port = None
        self._serving = False
        self._lines = queue.Queue()
        self._stdout_tail = deque(maxlen=TAIL_LINES)
        self._stderr_tail = deque(maxlen=TAIL_LINES)
        self._threads = []
        self._stderr_file = None
        self._lock = threading.Lock()
        self._opener = direct_opener()
        self.record = {'tag': PROXY_TAG, 'argv': list(self.argv), 'read_only': READ_ONLY_REJECT_METHODS in ' '.join(
                           self.argv), 'pid': None, 'base_url': None, 'port': None, 'serve_line': None,
                       'stdout_before_serve': [], 'start_error': None, 'stop_method': None, 'return_code': None,
                       'started': None, 'serving': None, 'stop_requested': None, 'stopped': None,
                       'clock': clock_info()}

    # -- lifecycle ----------------------------------------------------------------------------
    def start(self):
        """Start the proxy and wait for its serve line; returns self. On any failure the process is stopped and a
        ProxyError carries the reason and the last stderr lines."""
        if self.process is not None:
            raise ProxyError('this KubeProxy was already started')
        kwargs = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}
        if self.shield:
            if os.name == 'nt':
                kwargs['creationflags'] = NEW_GROUP
            else:
                kwargs['start_new_session'] = True
        if self.stderr_path is not None:
            self._stderr_file = self.stderr_path.open('xb')
        self.record['started'] = host_time()
        try:
            self.process = self._popen(self.argv, **kwargs)
        except OSError as error:
            self.record['start_error'] = 'cannot start kubectl: {!r}'.format(error)
            self._close_files()
            raise ProxyError(self.record['start_error']) from error
        self.record['pid'] = getattr(self.process, 'pid', None)
        self._threads = [threading.Thread(target=self._read_stdout, daemon=True, name='kube-proxy-stdout'),
                         threading.Thread(target=self._read_stderr, daemon=True, name='kube-proxy-stderr')]
        for thread in self._threads:
            thread.start()
        deadline = time.monotonic() + self.start_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.record['start_error'] = 'no "Starting to serve on" line within {} s'.format(self.start_timeout)
                break
            try:
                item = self._lines.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            if item is None:      # stdout closed: the proxy exited (or closed stdout) before serving
                self.record['start_error'] = 'kubectl proxy closed stdout before serving'
                break
            text, at = item
            match = SERVE_LINE.match(text)
            if not match:
                self.record['stdout_before_serve'].append({'line': text, 'at': at['at']})
                continue
            port = int(match.group('port'))
            if not 0 < port < 65536:
                self.record['start_error'] = 'serve line names an invalid port: ' + text
                break
            self.port, self.base_url, self._serving = port, 'http://{}:{}'.format(match.group('host'), port), True
            self.record.update(base_url=self.base_url, port=port, serve_line=text, serving=at)
            return self
        reason = self.record['start_error']
        self.stop()
        tail = ' | '.join(line['line'] for line in list(self._stderr_tail)[-5:])
        raise ProxyError('{} (exit code {}); stderr: {}'.format(reason, self.record['return_code'], tail or '(none)'))

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout=None) -> dict:
        """Terminate the proxy, wait, kill if needed; idempotent. Returns the record (with stop times)."""
        timeout = self.stop_timeout if timeout is None else float(timeout)
        with self._lock:
            if self.process is None or self.record['stopped'] is not None:
                return self.record
            self.record['stop_requested'] = host_time()
            code, method = None, 'already_exited'
            if self.process.poll() is None:
                method = 'terminate'
                try:
                    self.process.terminate()
                except OSError:
                    pass
                try:
                    code = self.process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    method = 'kill'
                    try:
                        self.process.kill()
                    except OSError:
                        pass
                    try:
                        code = self.process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        method = 'kill_unconfirmed'
            else:
                code = self.process.returncode
            self.record.update(stopped=host_time(), return_code=code, stop_method=method)
            for thread in self._threads:
                thread.join(timeout=2.0)
            for stream in (getattr(self.process, 'stdout', None), getattr(self.process, 'stderr', None)):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass
            self._close_files()
            self.record['stdout_after_serve'] = list(self._stdout_tail)
            self.record['stderr_tail'] = list(self._stderr_tail)
            return self.record

    def __enter__(self):
        return self.start()

    def __exit__(self, kind, value, traceback):
        self.stop()
        return False

    # -- reads ----------------------------------------------------------------------------------
    def get(self, path: str, timeout: float = 10.0) -> dict:
        """GET base_url + path (urllib, no system proxy). See http_get."""
        if not self.base_url:
            raise ProxyError('the proxy is not serving')
        return http_get(self.base_url, path, timeout=timeout, opener=self._opener)

    def stderr_tail(self) -> list:
        return [line['line'] for line in self._stderr_tail]

    # -- pipe drains ----------------------------------------------------------------------------
    def _read_stdout(self):
        try:
            for raw in iter(self.process.stdout.readline, b''):
                at = host_time()
                text = raw.decode('utf-8', 'replace').rstrip('\r\n')
                if self._serving:
                    self._stdout_tail.append({'line': text, 'at': at['at']})
                else:
                    self._lines.put((text, at))
        except (OSError, ValueError, AttributeError):
            pass
        finally:
            self._lines.put(None)

    def _read_stderr(self):
        stream = getattr(self.process, 'stderr', None)
        if stream is None:
            return
        try:
            for raw in iter(stream.readline, b''):
                at = host_time()
                if self._stderr_file is not None:
                    try:
                        self._stderr_file.write(raw)
                        self._stderr_file.flush()
                    except (OSError, ValueError):
                        pass
                self._stderr_tail.append({'line': raw.decode('utf-8', 'replace').rstrip('\r\n'), 'at': at['at']})
        except (OSError, ValueError):
            pass

    def _close_files(self):
        if self._stderr_file is not None and not self._stderr_file.closed:
            self._stderr_file.close()


# ----------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------
def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument('--kubectl', help='kubectl executable or path (default: shutil.which("kubectl"))')
    result.add_argument('--context', help='kubeconfig context (default: kubectl\'s current context)')
    result.add_argument('--kubeconfig', help='kubeconfig file')
    result.add_argument('--server', help='explicit API server URL, as phase3/run_incident.py passes it')
    result.add_argument('--allow-write-methods', action='store_true',
                        help='do not pass --reject-methods (the default proxy is read-only)')
    result.add_argument('--start-timeout', type=float, default=20.0, help='seconds to wait for the serve line')
    result.add_argument('--get', action='append', default=[], metavar='PATH',
                        help='GET this API path through the proxy (repeatable), e.g. /version')
    result.add_argument('--get-timeout', type=float, default=10.0)
    result.add_argument('--print-body', action='store_true', help='print each GET body (UTF-8) in its JSON line')
    result.add_argument('--seconds', type=float, help='keep the proxy serving this long after the GETs')
    result.add_argument('--stop-file', help='keep the proxy serving until this file exists (checked every 0.2 s)')
    result.add_argument('--record', help='write the proxy record (start/stop times, argv, GETs) to this new file')
    result.add_argument('--stderr-log', help='copy the proxy stderr to this new file')
    return result


def _emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.seconds is not None and not 0 < args.seconds <= 86400:
        raise SystemExit('--seconds must be in (0, 86400]')
    if args.record and Path(args.record).exists():
        raise SystemExit('--record file exists; choose a new path: ' + args.record)
    try:
        proxy = KubeProxy(args.kubectl, context=args.context, kubeconfig=args.kubeconfig, server=args.server,
                          read_only=not args.allow_write_methods, start_timeout=args.start_timeout,
                          stderr_path=args.stderr_log)
    except FileNotFoundError as error:
        raise SystemExit(str(error)) from error
    gets, ok, reason = [], True, 'gets_done'
    try:
        proxy.start()
    except ProxyError as error:
        _emit({'event': 'start_failed', 'error': str(error), 'record': proxy.record})
        return 1
    try:
        _emit({'event': 'serving', 'tag': PROXY_TAG, 'base_url': proxy.base_url, 'pid': proxy.record['pid'],
               'serving_at': proxy.record['serving']['at']})
        for path in args.get:
            result = proxy.get(path, timeout=args.get_timeout)
            summary = {key: result[key] for key in ('path', 'status', 'reason', 'error', 'body_bytes', 'body_sha256',
                                                    'request_started_at', 'response_received_at')}
            summary['elapsed_ms'] = (result['response_received_monotonic_ns'] -
                                     result['request_started_monotonic_ns']) / 1e6
            if args.print_body:
                summary['body'] = result['body'].decode('utf-8', 'replace')
            gets.append(summary)
            ok = ok and result['status'] == 200
            _emit(dict(summary, event='get'))
        deadline = None if args.seconds is None else time.monotonic() + args.seconds
        while args.seconds is not None or args.stop_file:
            if args.stop_file and Path(args.stop_file).exists():
                reason = 'stop_file'
                break
            if deadline is not None and time.monotonic() >= deadline:
                reason = 'seconds'
                break
            if not proxy.alive():
                reason, ok = 'proxy_exited', False
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        reason, ok = 'interrupted', False
    finally:
        record = proxy.stop()
    record = dict(record, gets=gets, cli_stop_reason=reason)
    _emit(dict(event='stopped', record=record))
    if args.record:
        with open(args.record, 'x', encoding='utf-8', newline='\n') as handle:
            handle.write(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return 0 if ok else 2


if __name__ == '__main__':
    raise SystemExit(main())
