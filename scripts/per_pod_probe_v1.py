#!/usr/bin/env python3
"""Per-Pod probe addressing for arm G of the follow-up captures: the client side of the effect probe server.

In arm G a fault on one of three replicas would reach only about a third of the probes sent through the Service,
so the runner sends the target Pod's IP for the active and recovery probes. The probe server
(scripts/fault_effect_probe_v2.py, unchanged) takes one JSON object per stdin line of a persistent ``kubectl exec``
session; each request names its ``recommendation_address`` and ``catalog_address`` (``host:port``, the containerPorts
8080 and 3550). This module builds those requests, schedules them with the development runner's counts and cadence,
and validates the responses. It is not a new probe server. Python 3.10+ standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))
from aiops_kg.fault_control_kill import DEFAULT_SERVICE_ADDRESSES, SERVICE_PORTS, pod_address  # noqa: E402

SCHEMA = 'per-pod-probe-row-v1'
ADDRESS_FIELDS = {'recommendationservice': 'recommendation_address', 'productcatalogservice': 'catalog_address'}
INPUT_PRODUCT = 'OLJCESPC7Z'          # fault_effect_probe_v2.INPUT_PRODUCT
MAX_LINE_BYTES = 16 * 1024            # fault_effect_probe_v2.MAX_LINE_BYTES, including the newline
MAX_PROBE_ID_CHARACTERS = 256         # fault_effect_probe_v2.serve
PHASES_SENT = ('nominal', 'active', 'recovery')
BLOCKS = ('nominal', 'pre_fault', 'active', 'recovery')
POD_ADDRESSED_BLOCKS = ('active', 'recovery')
# phase3/incident_plan.json defaults.probes (plan v1.1): the counts and cadence of the Phase-3 runner
PHASE3_PROBES = {'period_seconds': 1.0, 'max_nominal_pairs': 40, 'max_pre_fault_pairs': 25, 'drain_seconds': 5,
                 'recovery_seconds': 30, 'max_pairs': 120}
PHASE3_ACTIVE_SECONDS = 20            # defaults.fault.duration_seconds: active = ack .. ack + 20 s
WAIT_POLL_SECONDS = 0.05              # run_incident.Incident.probe_loop polls this often while waiting/skipping
# The nine catalogue IDs (phase3/run_incident.py FALLBACK_PRODUCT_IDS) for the command-line helper only; the runner
# passes the IDs it uses for the capture.
CATALOGUE_IDS = ['0PUK6V6EV0', '1YMWWN1N4O', '2ZYFJ3GM2N', '66VCHSJNUP', '6E92ZMYYFZ', '9SIQT8TOJO', 'L9ECAV7KIM',
                 'LS4PSXUNUM', 'OLJCESPC7Z']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def iso_from_ns(ns):
    seconds, rest = divmod(int(ns), 1_000_000_000)
    return '{}.{:06d}Z'.format(datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'),
                               rest // 1000)


# ---------------------------------------------------------------------------------------------------------------
# Pure request building
# ---------------------------------------------------------------------------------------------------------------
def make_target(service, pod_name, pod_uid, pod_ip):
    """The probe target: one Pod of one service, addressed at `<pod_ip>:<container port>`."""
    require(service in SERVICE_PORTS, 'unknown service {!r}'.format(service))
    for name, value in (('pod_name', pod_name), ('pod_uid', pod_uid)):
        require(isinstance(value, str) and value != '', name + ' must be a nonempty string')
    return {'service': service, 'pod_name': pod_name, 'pod_uid': pod_uid, 'pod_ip': pod_ip,
            'address': pod_address(pod_ip, SERVICE_PORTS[service])}


def target_from_pod(pod, service):
    """make_target from a Pod object as `kubectl get pods -o json` returns it (metadata.name/uid, status.podIP)."""
    meta, status = pod.get('metadata') or {}, pod.get('status') or {}
    return make_target(service, meta.get('name'), meta.get('uid'), status.get('podIP'))


def _validated_target(target):
    require(isinstance(target, dict), 'target must be an object')
    made = make_target(target.get('service'), target.get('pod_name'), target.get('pod_uid'), target.get('pod_ip'))
    require(target.get('address') in (None, made['address']), 'target address does not match its IP and port')
    return made


def request_addresses(target=None):
    """{'recommendation_address', 'catalog_address'}: the Service addresses (the probe server's defaults), with the
    target service's address replaced by the target Pod's address when a target is given."""
    addresses = {ADDRESS_FIELDS[service]: DEFAULT_SERVICE_ADDRESSES[service] for service in ADDRESS_FIELDS}
    if target is not None:
        target = _validated_target(target)
        addresses[ADDRESS_FIELDS[target['service']]] = target['address']
    return addresses


def build_probe_request(probe_id, phase, expected_product_ids, target=None):
    """One request line's object, checked as the server checks it (run_probe and serve)."""
    require(isinstance(probe_id, str) and 0 < len(probe_id) <= MAX_PROBE_ID_CHARACTERS,
            'probe_id must contain 1 to 256 characters')
    require(phase in PHASES_SENT, 'phase must be nominal, active or recovery (pre_fault is sent as nominal)')
    ids = list(expected_product_ids) if isinstance(expected_product_ids, (list, tuple)) else None
    require(ids is not None and len(ids) == 9 and len(set(ids)) == 9
            and all(isinstance(value, str) and value for value in ids) and INPUT_PRODUCT in ids,
            'expected_product_ids must be the 9 distinct catalogue IDs including ' + INPUT_PRODUCT)
    request = {'probe_id': probe_id, 'phase': phase, 'expected_product_ids': ids}
    request.update(request_addresses(target))
    require(len(encode_request(request)) <= MAX_LINE_BYTES, 'request line exceeds 16 KiB')
    return request


def encode_request(request):
    """The exact bytes ProbeSession.exchange writes: compact JSON plus a newline."""
    return (json.dumps(request, separators=(',', ':')) + '\n').encode()


def probe_block(marks, counts, cfg=PHASE3_PROBES):
    """Which block a probe issued now belongs to: the decisions of run_incident.Incident.probe_block, with the
    schedule marks passed in ('probe_start' for the probe-start event, then 'T0_trigger', 'pre_fault_end',
    'active_start', 'active_end', 'drain_end', 'recovery_end'). 'wait' / 'skip' mean do not probe now."""
    if 'probe_start' not in marks:
        return 'wait'
    if 'T0_trigger' not in marks:
        return 'nominal' if counts.get('nominal', 0) < int(cfg['max_nominal_pairs']) else 'skip'
    if 'pre_fault_end' not in marks:
        return 'pre_fault' if counts.get('pre_fault', 0) < int(cfg['max_pre_fault_pairs']) else 'skip'
    if 'active_start' not in marks:
        return 'skip'
    if 'active_end' not in marks:
        return 'active'
    if 'drain_end' not in marks:
        return 'skip'
    if 'recovery_end' not in marks:
        return 'recovery'
    return 'done'


def addressing_for(block):
    """Active and recovery pairs address the target Pod; nominal and pre_fault the Services."""
    require(block in BLOCKS, 'unknown block {!r}'.format(block))
    return 'pod_ip' if block in POD_ADDRESSED_BLOCKS else 'service'


# ---------------------------------------------------------------------------------------------------------------
# Thin runner (as run_incident.Incident.probe_loop, with per-Pod addressing and richer rows)
# ---------------------------------------------------------------------------------------------------------------
class PerPodProbeLoop:
    """Send one probe pair per period through `exchange` while the schedule's marks say so.

    exchange(payload) -> (batch, arrival): ProbeSession.exchange in the runner. marks() -> the schedule marks
    reached so far (see `probe_block`). The target may be set later with `set_target` (G1 draws it after the
    rollout); a pod-addressed block without a target stops the loop with an error row and sends nothing. As in
    Phase 3 an exchange error is recorded in its row and ends the loop. Rows are returned and passed to on_row.
    """

    def __init__(self, exchange, marks, expected_product_ids, *, target=None, cfg=None, sequence=None,
                 scenario_done=None, on_row=None, on_first=None, id_prefix='s2', monotonic=time.monotonic,
                 monotonic_ns=time.monotonic_ns, wall_ns=time.time_ns, sleep=time.sleep):
        self.exchange, self.marks = exchange, marks
        self.ids = list(expected_product_ids)
        build_probe_request('{}-check'.format(id_prefix), 'nominal', self.ids)       # fail early on bad IDs
        self.target = None if target is None else _validated_target(target)
        self.cfg = dict(PHASE3_PROBES if cfg is None else cfg)
        counter = iter(range(1, 1 << 62))
        self.sequence = sequence or (lambda: next(counter))
        self.scenario_done = scenario_done or (lambda: False)
        self.on_row, self.on_first, self.id_prefix = on_row, on_first, id_prefix
        self.monotonic, self.monotonic_ns, self.wall_ns, self.sleep = monotonic, monotonic_ns, wall_ns, sleep
        self.block_counts, self.rows, self.error = {}, [], None

    def set_target(self, target):
        self.target = _validated_target(target)

    def block(self):
        return probe_block(set(self.marks()), self.block_counts, self.cfg)

    def run(self):
        count, limit = 0, int(self.cfg['max_pairs'])
        period = float(self.cfg['period_seconds'])
        while count < limit:
            block = self.block()
            if block == 'done' or (self.scenario_done() and block != 'recovery'):
                break
            if block in ('wait', 'skip'):
                self.sleep(WAIT_POLL_SECONDS)
                continue
            if count == 0 and self.on_first is not None:
                self.on_first()
            tick = self.monotonic()
            count += 1
            self.block_counts[block] = self.block_counts.get(block, 0) + 1
            probe_id = '{}-{}-{:03d}'.format(self.id_prefix, block, count)
            phase = 'nominal' if block == 'pre_fault' else block
            addressing = addressing_for(block)
            target = self.target
            start_sequence, issued_ns, issued_wall = self.sequence(), self.monotonic_ns(), self.wall_ns()
            request = batch = arrival = None
            if addressing == 'pod_ip' and target is None:
                error = 'no target Pod set for the pod-addressed {} block; nothing was sent'.format(block)
            else:
                request = build_probe_request(probe_id, phase, self.ids, target if addressing == 'pod_ip' else None)
                try:
                    batch, arrival = self.exchange(request)
                    error = None
                except Exception as exc:          # recorded in the row, then the loop stops (as Phase 3)
                    error = repr(exc)
            received_ns, received_wall, end_sequence = self.monotonic_ns(), self.wall_ns(), self.sequence()
            row = {'schema': SCHEMA, 'probe_id': probe_id, 'block': block, 'phase_sent': phase,
                   'start_sequence': start_sequence, 'end_sequence': end_sequence,
                   'host_issued_monotonic_ns': issued_ns, 'host_received_monotonic_ns': received_ns,
                   'host_issued_wall_ns': issued_wall, 'host_received_wall_ns': received_wall,
                   'host_issued_at': iso_from_ns(issued_wall), 'host_received_at': iso_from_ns(received_wall),
                   'error': error, 'batch': batch, 'arrival': arrival, 'addressing': addressing,
                   'target_service': target['service'] if target else None,
                   'target_pod_name': target['pod_name'] if target else None,
                   'target_pod_uid': target['pod_uid'] if target else None,
                   'target_pod_ip': target['pod_ip'] if target else None,
                   'target_address': target['address'] if target else None,
                   'request_addresses': {key: request[key] for key in ADDRESS_FIELDS.values()} if request else None,
                   'request_sha256': hashlib.sha256(encode_request(request)).hexdigest() if request else None}
            self.rows.append(row)
            if self.on_row is not None:
                self.on_row(row)
            if error:
                self.error = error
                break
            self.sleep(max(0.0, period - (self.monotonic() - tick)))
        return self.rows


def main(argv=None):
    parser = argparse.ArgumentParser(description='Print one per-Pod probe request line for the probe server '
                                                 '(for a manual check; the runner builds these itself).')
    parser.add_argument('--service', required=True, choices=sorted(SERVICE_PORTS))
    parser.add_argument('--pod-name', required=True)
    parser.add_argument('--pod-uid', required=True)
    parser.add_argument('--pod-ip', required=True)
    parser.add_argument('--probe-id', default='s2-manual-001')
    parser.add_argument('--phase', default='active', choices=PHASES_SENT)
    args = parser.parse_args(argv)
    target = make_target(args.service, args.pod_name, args.pod_uid, args.pod_ip)
    sys.stdout.write(encode_request(build_probe_request(args.probe_id, args.phase, CATALOGUE_IDS, target)).decode())
    return 0


if __name__ == '__main__':
    sys.exit(main())
