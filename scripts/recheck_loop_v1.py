#!/usr/bin/env python3
"""Live fresh-state recheck loop (collector tag recheck-v1): every 1.0 s, through the same ``kubectl proxy`` as the
watch, GET the Deployments, ReplicaSets, Pods, EndpointSlices and PodDisruptionBudgets of the two services and write
ONE record per scheduled tick. It never interprets anything live.

One record per response: request start, response receipt, acceptance, SHA-256 of the raw bytes, projected objects.
The governance analysis consumes a response only after its receipt x_R (condition R). Record format:
phase3/CAPTURE_FORMAT_STAGE2.md. Python 3.10+ standard library only; importing this module contacts no cluster.
"""
from __future__ import annotations

import argparse
import http.client
import json
import platform
import re
import statistics
import sys
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import collect_watch_v1 as watch_v1  # noqa: E402  (projection, HTTP helpers, CLI pieces; no side effects)
from collect_watch_v1 import (RESOURCES, RawArchive, add_common_arguments, connect_proxy, error_text,  # noqa: E402
                              install_stop_signals, parse_list, prepare_output, request_target, sort_objects,
                              validate_common, write_manifest, file_entry)
from kube_proxy_v1 import ProxyError, clock_info, host_time, iso_ns, put_time, sha256, sha256_file  # noqa: E402

COLLECTOR_TAG = 'recheck-v1'
SCHEMA_VERSION = 1
RECHECK_RESOURCES = ('deployments', 'replicasets', 'pods', 'endpointslices', 'poddisruptionbudgets')
DEFAULT_SERVICES = ('recommendationservice', 'productcatalogservice')
FILES = {'records': 'recheck.jsonl', 'manifest': 'recheck_manifest.json', 'raw': 'recheck_raw.jsonl.gz'}
NORMAL_STOPS = ('seconds', 'stop_file', 'stop_event')
STOP_POLL_SECONDS = 0.05
USER_AGENT = 'aiops-stage2-' + COLLECTOR_TAG
# A kept-alive connection that the server closed while idle fails on reuse with one of these; one retry on a fresh
# connection is made (an idempotent GET), and the GET's request_started_at stays the FIRST attempt's start.
STALE_CONNECTION_ERRORS = (http.client.RemoteDisconnected, http.client.BadStatusLine, ConnectionResetError,
                           ConnectionAbortedError, BrokenPipeError)


def default_selectors(services):
    """Server-side selectors: the `app` label of the manifests (infrastructure/rollout-telemetry/applications.json and
    infrastructure/stage2/applications_multi.json put it on Deployments, Pod templates and PDBs) and the label the
    EndpointSlice controller sets."""
    names = ','.join(services)
    app = 'app in ({})'.format(names)
    return {'deployments': app, 'replicasets': app, 'pods': app,
            'endpointslices': 'kubernetes.io/service-name in ({})'.format(names), 'poddisruptionbudgets': app}


def latency_summary(values):
    if not values:
        return {'n': 0, 'min': None, 'median': None, 'max': None}
    return {'n': len(values), 'min': min(values), 'median': statistics.median(values), 'max': max(values)}


class RecheckLoop:
    """One recheck collection; single-threaded (signal handlers only set a flag)."""

    def __init__(self, args, selectors, paths, base_url, host, port, proxy=None, stop_event=None):
        self.args, self.paths, self.proxy = args, paths, proxy
        self.namespace, self.services = args.namespace, list(args.services)
        self.selectors = dict(default_selectors(self.services))
        self.selectors.update(selectors)
        self.targets = {resource: request_target(resource, self.namespace,
                                                 {'labelSelector': self.selectors[resource]}
                                                 if self.selectors.get(resource) else None)
                        for resource in RECHECK_RESOURCES}
        self.base_url, self.host, self.port = base_url, host, port
        self.interval_ns = int(round(args.interval_seconds * 1e9))
        self.request_timeout = float(args.request_timeout_seconds)
        self.stop_file = Path(args.stop_file) if args.stop_file else None
        self.stop_event = stop_event or threading.Event()
        self.external_reason = None
        self.collection_id = str(uuid.uuid4())
        self.sequence, self.last_available_ns = 0, 0
        self.handle = self.archive = self.connection = None
        self.start = None
        self.deadline_ns = None
        self.status_counts, self.http_counts, self.outcomes = Counter(), Counter(), Counter()
        self.latencies, self.lateness = [], []
        self.first_tick = self.last_tick = self.first_answer = self.last_answer = None

    # -- writing --------------------------------------------------------------------------------
    def emit(self, record, observed):
        accepted = host_time()
        self.sequence += 1
        logical = max(accepted['at_ns'], observed['at_ns'] if observed else 0, self.last_available_ns)
        record.update(sequence=self.sequence, record_id='{}/{}'.format(self.collection_id, self.sequence),
                      collection_id=self.collection_id, collector=COLLECTOR_TAG,
                      observed_at=observed['at'] if observed else None, available_at=iso_ns(logical),
                      available_at_ns=logical, clock_adjusted=logical != accepted['at_ns'])
        put_time(record, 'accepted', accepted)
        self.last_available_ns = logical
        self.handle.write((json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n')
                          .encode('ascii'))
        self.handle.flush()
        return self.sequence

    def scheduled_time(self, scheduled_ns):
        """The tick's planned instant: monotonic exactly; wall clock = start wall time + monotonic offset (no wall
        reading is taken for a planned instant)."""
        wall = self.start['at_ns'] + (scheduled_ns - self.start['monotonic_ns'])
        return {'at': iso_ns(wall), 'at_ns': wall, 'monotonic_ns': scheduled_ns}

    # -- one GET --------------------------------------------------------------------------------
    def get(self, resource):
        target, kind = self.targets[resource], RESOURCES[resource][0]
        first_started, attempts, reused, status, body, error = None, 0, False, None, None, None
        while True:
            attempts += 1
            reused = self.connection.sock is not None
            started = host_time()
            first_started = first_started or started
            try:
                self.connection.request('GET', target, headers={'Accept': 'application/json',
                                                                'User-Agent': USER_AGENT})
                response = self.connection.getresponse()
                body = response.read()
                received = host_time()
                status, error = response.status, None
                if response.will_close:
                    self.connection.close()
                break
            except (OSError, http.client.HTTPException) as failure:
                received = host_time()
                self.connection.close()
                status, body, error = None, None, error_text(failure)
                if attempts == 1 and reused and isinstance(failure, STALE_CONNECTION_ERRORS):
                    continue
                break
        record = {'resource': resource, 'kind': kind, 'path': target, 'attempts': attempts,
                  'connection_reused': reused, 'http_status': status, 'error': error,
                  'body_bytes': len(body) if body is not None else None,
                  'body_sha256': sha256(body) if body is not None else None,
                  'list_resource_version': None, 'object_count': None, 'uids': None}
        put_time(record, 'request_started', first_started)
        put_time(record, 'response_received', received)
        objects = []
        if error is not None:
            outcome = 'transport_error'
        elif status != 200:
            outcome = 'http_error'
        else:
            try:
                version, objects = parse_list(json.loads(body), resource, self.namespace)
                outcome = 'ok'
                record.update(list_resource_version=version, object_count=len(objects),
                              uids=sorted(obj['metadata']['uid'] for obj in objects))
            except (ValueError, TypeError, KeyError, AttributeError) as failure:
                outcome, objects = 'invalid_body', []
                record['error'] = error_text(failure)
        record['outcome'] = outcome
        return record, objects, body

    # -- ticks ----------------------------------------------------------------------------------
    def tick(self, number, scheduled_ns):
        gets, objects, bodies, transport_failed = [], [], [], False
        for resource in RECHECK_RESOURCES:
            if transport_failed:
                skipped = {'resource': resource, 'kind': RESOURCES[resource][0], 'path': self.targets[resource],
                           'attempts': 0, 'connection_reused': None, 'http_status': None, 'error': None,
                           'body_bytes': None, 'body_sha256': None, 'list_resource_version': None,
                           'object_count': None, 'uids': None, 'outcome': 'skipped_after_transport_error'}
                put_time(skipped, 'request_started', None)
                put_time(skipped, 'response_received', None)
                gets.append(skipped)
                continue
            record, found, body = self.get(resource)
            gets.append(record)
            objects.extend(found)
            if body is not None:
                bodies.append((resource, body))
            transport_failed = record['outcome'] == 'transport_error'
            self.http_counts[str(record['http_status'])] += 1
        for record in gets:
            self.outcomes[record['outcome']] += 1
        attempted = [record for record in gets if record['request_started_at'] is not None]
        first, last = attempted[0], attempted[-1]
        started = {'at': first['request_started_at'], 'at_ns': first['request_started_at_ns'],
                   'monotonic_ns': first['request_started_monotonic_ns']}
        received = {'at': last['response_received_at'], 'at_ns': last['response_received_at_ns'],
                    'monotonic_ns': last['response_received_monotonic_ns']}
        answered = all(record['outcome'] == 'ok' for record in gets)
        result = {'record_type': 'live_recheck', 'observation_basis': 'live_recheck', 'tick': number,
                  'status': 'answered' if answered else 'failed', 'answered': answered, 'missed_reason': None,
                  'blocking_tick': None, 'namespace': self.namespace, 'services': self.services,
                  'read_latency_ms': (received['monotonic_ns'] - started['monotonic_ns']) / 1e6,
                  'start_lateness_ms': (started['monotonic_ns'] - scheduled_ns) / 1e6,
                  'gets': gets, 'object_count': len(objects), 'objects': sort_objects(objects)}
        put_time(result, 'scheduled', self.scheduled_time(scheduled_ns))
        put_time(result, 'request_started', started)
        put_time(result, 'response_received', received)
        sequence = self.emit(result, received)
        if self.archive is not None:
            for resource, body in bodies:
                self.archive.write('recheck_body', sequence, body, {'tick': number, 'resource': resource})
            self.archive.flush()
        self.status_counts[result['status']] += 1
        self.latencies.append(result['read_latency_ms'])
        self.lateness.append(result['start_lateness_ms'])
        self.first_tick = self.first_tick or result['scheduled_at']
        self.last_tick = result['scheduled_at']
        if answered:
            self.first_answer = self.first_answer or result['response_received_at']
            self.last_answer = result['response_received_at']

    def missed(self, number, scheduled_ns, blocking):
        result = {'record_type': 'live_recheck', 'observation_basis': 'live_recheck', 'tick': number,
                  'status': 'missed', 'answered': False, 'missed_reason': 'previous_tick_in_flight',
                  'blocking_tick': blocking, 'namespace': self.namespace, 'services': self.services,
                  'read_latency_ms': None, 'start_lateness_ms': None, 'gets': [], 'object_count': 0,
                  'objects': []}
        put_time(result, 'scheduled', self.scheduled_time(scheduled_ns))
        put_time(result, 'request_started', None)
        put_time(result, 'response_received', None)
        self.emit(result, None)
        self.status_counts['missed'] += 1
        self.first_tick = self.first_tick or result['scheduled_at']
        self.last_tick = result['scheduled_at']

    # -- schedule ---------------------------------------------------------------------------------
    def request_stop(self, reason):
        self.external_reason = self.external_reason or reason
        self.stop_event.set()

    def stop_reason(self):
        if self.external_reason:
            return self.external_reason
        if self.stop_event.is_set():
            return 'stop_event'
        if self.stop_file is not None and self.stop_file.exists():
            return 'stop_file'
        if self.deadline_ns is not None and time.monotonic_ns() >= self.deadline_ns:
            return 'seconds'
        if self.proxy is not None and not self.proxy.alive():
            return 'proxy_exited'
        return None

    def wait_until(self, scheduled_ns):
        while True:
            reason = self.stop_reason()
            if reason:
                return reason
            remaining = scheduled_ns - time.monotonic_ns()
            if remaining <= 0:
                return None
            self.stop_event.wait(min(remaining / 1e9, STOP_POLL_SECONDS))

    def run(self):
        self.handle = open(self.paths['records'], 'xb')
        if not self.args.no_raw:
            self.archive = RawArchive(self.paths['raw'])
        self.connection = http.client.HTTPConnection(self.host, self.port, timeout=self.request_timeout)
        self.start = host_time()
        if self.args.seconds is not None:
            self.deadline_ns = self.start['monotonic_ns'] + int(round(self.args.seconds * 1e9))
        write_manifest(self.paths['manifest'], self.manifest('collecting', None, None), first=True)
        number, reason = 0, None
        try:
            while True:
                scheduled = self.start['monotonic_ns'] + number * self.interval_ns
                reason = self.wait_until(scheduled)
                if reason:
                    break
                self.tick(number, scheduled)
                blocking, number = number, number + 1
                now = time.monotonic_ns()
                while True:
                    instant = self.start['monotonic_ns'] + number * self.interval_ns
                    if instant >= now or (self.deadline_ns is not None and instant >= self.deadline_ns):
                        break
                    if self.stop_reason():       # a stop requested during the slow tick: no ticks after it
                        break
                    self.missed(number, instant, blocking)
                    number += 1
        except KeyboardInterrupt:
            reason = 'interrupted'
        stop_at = host_time()
        end = {'record_type': 'collection_end', 'reason': reason, 'ticks': dict(self.status_counts)}
        put_time(end, 'stop_requested', stop_at)
        self.emit(end, stop_at)
        self.handle.close()
        if self.archive is not None:
            self.archive.close()
        self.connection.close()
        proxy_record = self.proxy.stop() if self.proxy is not None else None
        normal = reason in NORMAL_STOPS or str(reason).startswith('signal:')
        status = ('finished' if normal and self.status_counts['answered'] else
                  'interrupted' if reason == 'interrupted' else 'partial')
        manifest = self.manifest(status, reason, stop_at, proxy_record)
        write_manifest(self.paths['manifest'], manifest)
        return manifest

    def manifest(self, status, reason, stop_at, proxy_record=None):
        args = self.args
        finished = host_time() if status != 'collecting' else None
        total = sum(self.status_counts.values())
        files = {}
        if status != 'collecting':
            for key in ('records', 'raw'):
                entry = file_entry(self.paths[key])
                if entry is not None:
                    files[self.paths[key].name] = entry
        return {
            'schema_version': SCHEMA_VERSION, 'collector': COLLECTOR_TAG, 'collection_id': self.collection_id,
            'status': status, 'stop_reason': reason, 'namespace': self.namespace, 'services': self.services,
            'resources': list(RECHECK_RESOURCES), 'label_selectors': {name: self.selectors.get(name)
                                                                      for name in RECHECK_RESOURCES},
            'targets': self.targets, 'interval_seconds': args.interval_seconds,
            'request_timeout_seconds': self.request_timeout,
            'proxy': {'base_url': self.base_url, 'started_by_collector': self.proxy is not None,
                      'record': proxy_record},
            'options': {'seconds': args.seconds, 'stop_file': args.stop_file, 'raw_archive': not args.no_raw},
            'started_at': self.start['at'] if self.start else None,
            'started_monotonic_ns': self.start['monotonic_ns'] if self.start else None,
            'stop_requested_at': stop_at['at'] if stop_at else None,
            'finished_at': finished['at'] if finished else None,
            'elapsed_seconds': ((finished['monotonic_ns'] - self.start['monotonic_ns']) / 1e9
                                if finished and self.start else None),
            'ticks': {'total': total, 'answered': self.status_counts['answered'],
                      'failed': self.status_counts['failed'], 'missed': self.status_counts['missed'],
                      'answered_fraction': self.status_counts['answered'] / total if total else None},
            'first_tick_scheduled_at': self.first_tick, 'last_tick_scheduled_at': self.last_tick,
            'first_answered_response_at': self.first_answer, 'last_answered_response_at': self.last_answer,
            'read_latency_ms': latency_summary(self.latencies),
            'start_lateness_ms': latency_summary(self.lateness),
            'http_status_counts': dict(self.http_counts), 'get_outcomes': dict(self.outcomes),
            'records': self.sequence, 'raw_archive_entries': self.archive.count if self.archive else 0,
            'files': files,
            'sources': {'recheck_loop_v1.py': sha256_file(__file__),
                        'collect_watch_v1.py (projection)': sha256_file(watch_v1.__file__),
                        'kube_proxy_v1.py': sha256_file(SCRIPTS / 'kube_proxy_v1.py'),
                        'collect_deployment_history.py (projection, read-only)':
                            sha256_file(watch_v1.poller_v1.__file__)},
            'host': {'python': sys.version, 'platform': platform.platform(), 'clock': clock_info()},
            'semantics': ('never interpreted live; one record per scheduled tick (answered, failed or missed); '
                          'a tick is answered iff its five GETs returned HTTP 200 with a parseable list; '
                          'request_started_at = the first GET\'s (first attempt\'s) start, response_received_at = '
                          "the last GET's receipt (x_R)"),
            'format': 'phase3/CAPTURE_FORMAT_STAGE2.md'}


def collect(args, stop_event=None, install_signals=False):
    """Run one recheck collection (blocking) and return the final manifest."""
    selectors = validate_common(args)
    if not args.services or len(set(args.services)) != len(args.services):
        raise ValueError('--services must be unique')
    for service in args.services:
        if not isinstance(service, str) or not re.fullmatch(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?', service):
            raise ValueError('--services must be DNS labels: ' + repr(service))
    if not 0.05 <= args.interval_seconds <= 60:
        raise ValueError('--interval-seconds must be in [0.05, 60]')
    if not 0.05 <= args.request_timeout_seconds <= 60:
        raise ValueError('--request-timeout-seconds must be in [0.05, 60]')
    paths = prepare_output(args.output_dir, FILES)
    base, host, port, proxy = connect_proxy(args)
    loop = RecheckLoop(args, selectors, paths, base, host, port, proxy=proxy, stop_event=stop_event)
    if install_signals:
        install_stop_signals(loop.request_stop)
    try:
        return loop.run()
    except BaseException:
        if proxy is not None:
            proxy.stop()
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_arguments(result)
    result.add_argument('--services', nargs='+', default=list(DEFAULT_SERVICES),
                        help='the services whose objects are read (default: the two Stage-2 services)')
    result.add_argument('--interval-seconds', type=float, default=1.0, help='tick interval (1.0 s in the study)')
    result.add_argument('--request-timeout-seconds', type=float, default=5.0,
                        help='socket timeout of each GET (connect and each read)')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        manifest = collect(args, install_signals=True)
    except (ValueError, OSError, ProxyError) as error:
        raise SystemExit('Recheck loop failed: ' + error_text(error)) from error
    print(json.dumps({key: manifest[key] for key in ('collector', 'collection_id', 'status', 'stop_reason', 'ticks',
                                                      'read_latency_ms', 'files')}, indent=2))
    return 0 if manifest['status'] == 'finished' else 2


if __name__ == '__main__':
    raise SystemExit(main())
