"""Fault F2 of the follow-up captures (container kill): seeded target draw, crictl argv builders, the
activation/effect/recovery evaluator, the clock band with the clock-consistency rule, and K1 point observations.
Pure functions; no I/O.

- F2: SIGKILL of the target container through the kind node's runtime (``crictl stop`` with a zero timeout, run with
  ``docker exec`` in the node container). Activation = the container's restartCount increments and its
  lastState.terminated is stamped inside the planned window; effect = the target Pod's direct probes fail or slow
  while it is not Ready; recovery = Ready=True again and probes OK (``evaluate_kill``).
- Random targets: ``random.Random(int(sha256(capture_id), 16))`` over the candidates sorted by Pod UID, the draw
  logged before the fault starts (``KillPlan``, ``draw_target``); per-Pod probing addresses the target Pod's IP and
  container port (``pod_address``).
- K1 records: kubelet-stamped transitions as point observations of the Pod's STATE (``k1_observations``). Every K1
  observation cites its observer row (``source_record``) and the field that carries the stamp (``source_field``);
  the earlier valid time is always the source's own field, never inferred from arrival order. The injector causes a
  physical event and never writes a record.
- Clock probes, the clock band b_c and the clock-consistency rule (``clock_band``, ``clamp_stamp``).

The action-B labels are computed by the governance adapter, not here; this module's verdict is fault-control
evidence only. The structure follows src/aiops_kg/fault_control.py (the CPU-fault evaluator), imported read-only for
its constants, its probe validator and its per-phase summary, so both evaluators count probes the same way.

Time: every wall-clock instant is an integer number of microseconds since the Unix epoch (UTC); clock-probe readings
stay in integer nanoseconds. Python 3.10+ standard library only. Nothing here starts a process, reads a file or the
clock, or draws unseeded randomness.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import random
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fractions import Fraction

from aiops_kg.fault_control import MIN_SHIFT_NS, MIN_SUCCESS, pack, summarize_phase, validate_probe

SCHEMA = 'container_kill_fault_control_v1'
DRAW_SCHEMA = 'stage2_kill_target_draw_v1'
CLOCK_BAND_SCHEMA = 'stage2_clock_band_v1'
K1_SCHEMA = 'stage2_k1_observation_v1'
K1_EXTRACTION_SCHEMA = 'stage2_k1_extraction_v1'

US = 1_000_000
UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# The two services of both arms and their gRPC container ports, which are also the ports the probe server dials by
# default (scripts/fault_effect_probe_v2.py lines 47-49: 'recommendationservice:8080',
# 'productcatalogservice:3550'; infrastructure/rollout-telemetry/applications.json containerPort 8080 and 3550).
SERVICE_PORTS = {'recommendationservice': 8080, 'productcatalogservice': 3550}
DEFAULT_SERVICE_ADDRESSES = {'recommendationservice': 'recommendationservice:8080',
                             'productcatalogservice': 'productcatalogservice:3550'}
CONTAINER_NAME = 'server'                          # the application container of both Deployments
NODE = 'aiops-context-pilot-control-plane'         # phase3/run_incident.py NODE
DOCKER_ARGV = ('docker', '--context', 'desktop-linux')   # infrastructure/context-pilot/context-pilot.ps1; plan item 3
STOP_TIMEOUT_SECONDS = 0          # crictl stop --timeout 0: the CRI stop skips the graceful signal and sends SIGKILL
NODE_DATE_ARGS = ('date', '+%s.%N')   # node clock in ns; identical to infrastructure/stage2/smoke/clock_probe.py
POD_UID_LABEL = 'io.kubernetes.pod.uid'   # labels the kubelet puts on every Pod sandbox and container
POD_NAME_LABEL = 'io.kubernetes.pod.name'
POD_NAMESPACE_LABEL = 'io.kubernetes.pod.namespace'
CONTAINER_NAME_LABEL = 'io.kubernetes.container.name'

STAMP_RESOLUTION_NS = 1_000_000_000   # kubelet stamps are RFC 3339 seconds
STAMP_RESOLUTION_US = 1_000_000
CLAMP_STEP_US = 1                     # "moved to that observation's instant + 1 us"
MIN_EFFECT_PROBES = 1                 # at least one target probe certainly inside the not-Ready window
NOMINAL_MAD_MULTIPLIER = 3            # as fault_control.evaluate_fault_control

SEED_RULE = ("random.Random(int(hashlib.sha256(capture_id.encode('utf-8')).hexdigest(), 16)).randrange(n) over the "
             "Ready candidates sorted by Pod UID (Python string order). randrange(n) draws "
             "exactly as random.Random.choice does (both call _randbelow(n)).")
CLOCK_BAND_RULE = ("theta = host wall clock - node clock; one reading (host send, node date, host receive) bounds "
                   "theta to [send - node, receive - node]; b_c = 1 s (kubelet stamp resolution) + the widest offset "
                   "bound, read as the largest |bound| over every usable reading of the capture (start and end), so "
                   "that b_c covers the offset itself as well as its uncertainty; no correction is applied to any "
                   "timestamp")
CLAMP_RULE = ("a stamped transition earlier than (or at the same instant as) the last observation "
              "of the same Pod that contradicts it is moved to that observation's instant + 1 us and flagged "
              "clock_clamped; equality is included because a same-instant conflict is what the rule prevents")

_RFC3339 = re.compile(r'(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})')
_NODE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}')
_HEX_ID = re.compile(r'[0-9a-f]{12,64}')
_K8S_NAME = re.compile(r'[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?')
_POD_UID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_NODE_CLOCK = re.compile(r'(\d+)\.(\d{9})')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _is_int(value):
    return type(value) is int


# ---------------------------------------------------------------------------------------------------------------
# Time (integer microseconds since the epoch, UTC)
# ---------------------------------------------------------------------------------------------------------------
def parse_time_us(text, field='timestamp'):
    """RFC 3339 text ('2026-10-19T10:00:25Z', fraction up to 9 digits, 'Z' or an offset) -> integer us (exact; a
    fraction beyond microseconds is truncated, as datetime would). Kubelet stamps carry whole seconds; host receipts
    from `datetime.isoformat()` carry microseconds."""
    require(isinstance(text, str), '{} must be an RFC 3339 string, got {!r}'.format(field, text))
    match = _RFC3339.fullmatch(text.strip())
    require(match is not None, '{} is not an RFC 3339 timestamp: {!r}'.format(field, text))
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))     # range check only
    us = calendar.timegm((int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, 0)) * US
    if fraction:
        us += int(fraction[:6].ljust(6, '0'))
    if zone not in ('Z', 'z'):
        sign = 1 if zone[0] == '+' else -1
        us -= sign * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60) * US
    return us


def iso_us(us):
    """Integer us -> '2026-10-19T10:00:25.400001Z' (the format of aiops_kg.replay.iso)."""
    if us is None:
        return None
    require(_is_int(us), 'time must be integer microseconds')
    return (EPOCH + timedelta(microseconds=us)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _time_field(obj, name):
    """obj['<name>_us'] (int us) if present, else obj['<name>_ns'] (int ns, as the Stage-2 collectors write it,
    phase3/CAPTURE_FORMAT_STAGE2.md section 3; floored to us), else obj['<name>'] parsed as RFC 3339."""
    for suffix, divisor in (('_us', 1), ('_ns', 1000)):
        if isinstance(obj, dict) and obj.get(name + suffix) is not None:
            value = obj[name + suffix]
            require(_is_int(value), name + suffix + ' must be an integer')
            return value // divisor
    require(isinstance(obj, dict) and isinstance(obj.get(name), str), 'missing ' + name)
    return parse_time_us(obj[name], name)


# ---------------------------------------------------------------------------------------------------------------
# (a) Seeded target draw
# ---------------------------------------------------------------------------------------------------------------
def seed_for(capture_id):
    """(SHA-256 hex of the capture ID's UTF-8 bytes, that digest as an integer): the draw's seed."""
    require(isinstance(capture_id, str) and capture_id != '', 'capture_id must be a nonempty string')
    digest = hashlib.sha256(capture_id.encode('utf-8')).hexdigest()
    return digest, int(digest, 16)


def pod_address(ip, port):
    """'<ip>:<port>' for gRPC's insecure_channel; IPv6 literals in brackets ('[fd00::5]:8080')."""
    require(isinstance(ip, str) and ip != '' and ip == ip.strip(), 'Pod IP must be a nonempty string')
    require(_is_int(port) and 0 < port < 65536, 'port must be an integer in 1..65535')
    return ('[' + ip + ']' if ':' in ip else ip) + ':' + str(port)


def candidate_from_pod(pod):
    """One draw candidate from a Pod object (as `kubectl get pods -o json` returns it): name, UID, IP and readiness,
    with readiness decided exactly as phase3/run_incident.py `ready_pods` decides it (Running, Ready=True, no
    deletionTimestamp), the one rule Phase 3 shared between its change check and its fault-target choice."""
    require(isinstance(pod, dict), 'Pod must be an object')
    meta, status = pod.get('metadata') or {}, pod.get('status') or {}
    ready = (not meta.get('deletionTimestamp') and status.get('phase') == 'Running'
             and any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in status.get('conditions') or []))
    return {'name': meta.get('name'), 'uid': meta.get('uid'), 'ip': status.get('podIP'), 'ready': bool(ready)}


def _candidate(value, index):
    require(isinstance(value, dict), 'candidate {} must be an object'.format(index))
    name, uid, ip, ready = value.get('name'), value.get('uid'), value.get('ip'), value.get('ready')
    require(isinstance(name, str) and name != '', 'candidate {} has no Pod name'.format(index))
    require(isinstance(uid, str) and uid != '', 'candidate {} has no Pod UID'.format(index))
    require(ip is None or (isinstance(ip, str) and ip != ''), 'candidate {} has an invalid Pod IP'.format(index))
    require(type(ready) is bool, 'candidate {} must say ready true or false'.format(index))
    return {'name': name, 'uid': uid, 'ip': ip, 'ready': ready}


def draw_target(capture_id, scenario, candidates, *, service=None):
    """Draw one target among the Ready candidates and return the record of the draw.

    `candidates` are the Pods at draw time, each {name, uid, ip, ready} (see `candidate_from_pod`). The eligible
    set is the Ready candidates sorted by UID; the index is `random.Random(seed).randrange(len(eligible))` with the
    seed of `seed_for(capture_id)`. The record holds the seed derivation, the sorted list, the excluded (not Ready)
    candidates, the index and the chosen Pod; the runner logs it before the fault starts. Refuses duplicate UIDs or
    names, an empty eligible set and a Ready candidate without an IP (arm G probes the target by its IP).
    """
    require(isinstance(scenario, str) and scenario != '', 'scenario must be a nonempty string')
    require(service is None or service in SERVICE_PORTS, 'unknown service {!r}'.format(service))
    require(isinstance(candidates, (list, tuple)), 'candidates must be a list')
    given = [_candidate(value, index) for index, value in enumerate(candidates)]
    require(len({c['uid'] for c in given}) == len(given), 'duplicate Pod UID among the candidates')
    require(len({c['name'] for c in given}) == len(given), 'duplicate Pod name among the candidates')
    eligible = sorted((c for c in given if c['ready']), key=lambda c: c['uid'])
    excluded = sorted((c for c in given if not c['ready']), key=lambda c: c['uid'])
    require(bool(eligible), 'no Ready candidate: nothing to draw')
    for c in eligible:
        require(c['ip'] is not None, 'Ready candidate {} has no Pod IP'.format(c['name']))
    digest, seed = seed_for(capture_id)
    index = random.Random(seed).randrange(len(eligible))
    return {'schema': DRAW_SCHEMA, 'capture_id': capture_id, 'scenario': scenario, 'service': service,
            'seed_rule': SEED_RULE, 'capture_id_sha256': digest, 'seed_decimal': str(seed),
            'candidates_as_given': given, 'eligible_sorted_by_uid': eligible, 'excluded_not_ready': excluded,
            'n_eligible': len(eligible), 'index': index, 'chosen': dict(eligible[index]),
            'logging_rule': 'logged by the runner before the fault starts'}


@dataclass(frozen=True)
class KillPlan:
    """One F2 kill of one capture: the scenario's service, the candidates at draw time and where the kill runs.

    `draw()` returns the draw record of `draw_target` plus the kill's fixed parameters: the target (service, Pod
    name, UID, IP, container, probe address), the node, the docker prefix and the lookup argv for the chosen Pod.
    Nothing is executed; the runner runs the argv through scripts/host_command_receipt_v1.py.
    """
    capture_id: str
    scenario: str
    service: str
    candidates: tuple
    namespace: str | None = None
    container_name: str = CONTAINER_NAME
    node: str = NODE
    docker_argv: tuple = DOCKER_ARGV
    planned_offset_seconds: float | None = None

    def draw(self):
        require(self.service in SERVICE_PORTS, 'unknown service {!r}'.format(self.service))
        record = draw_target(self.capture_id, self.scenario, list(self.candidates), service=self.service)
        chosen = record['chosen']
        target = {'service': self.service, 'pod_name': chosen['name'], 'pod_uid': chosen['uid'],
                  'pod_ip': chosen['ip'], 'container_name': self.container_name,
                  'probe_address': pod_address(chosen['ip'], SERVICE_PORTS[self.service])}
        # Real Pod UIDs are UUIDs; only then can the lookup also filter on the exact UID label.
        uid = chosen['uid'] if _POD_UID.fullmatch(chosen['uid']) else None
        prefix = node_exec_argv(self.docker_argv, self.node, ['crictl'])
        lookup = {
            'sandbox_by_pod_name': find_sandbox_argv(self.docker_argv, self.node, chosen['name'],
                                                     namespace=self.namespace, pod_uid=uid),
            'container_in_sandbox_template': prefix + ['ps', '--pod', '<sandbox id from sandbox_by_pod_name>',
                                                       '--name', _k8s_name(self.container_name, 'container name'),
                                                       '--state', 'running', '-q'],
            'container_by_pod_uid': find_container_by_pod_uid_argv(self.docker_argv, self.node, uid,
                                                                   container_name=self.container_name)
            if uid else None,
            # the plan's rule (phase3/stage2_plan.json faults.F2.container_selection), exact labels
            'container_by_labels': find_container_by_labels_argv(self.docker_argv, self.node, chosen['name'],
                                                                 self.namespace, uid,
                                                                 container_name=self.container_name)
            if uid and self.namespace else None,
            'list_containers_json': list_containers_argv(self.docker_argv, self.node)}
        record.update(fault='F2 container kill', target=target,
                      namespace=self.namespace, container_name=self.container_name, node=self.node,
                      docker_argv=list(self.docker_argv), planned_offset_seconds=self.planned_offset_seconds,
                      lookup_argv=lookup,
                      kill_argv_template=prefix + ['stop', '--timeout', str(STOP_TIMEOUT_SECONDS),
                                                   '<container id from the lookup>'])
        return record


# ---------------------------------------------------------------------------------------------------------------
# (b) argv builders: pure functions, so the runner can record each argv in a host-command receipt
# ---------------------------------------------------------------------------------------------------------------
def _docker(docker_argv):
    argv = list(docker_argv) if isinstance(docker_argv, (list, tuple)) else None
    require(bool(argv) and all(isinstance(a, str) and a != '' and '\0' not in a for a in argv),
            'docker_argv must be a nonempty list of nonempty strings, e.g. ["docker", "--context", "desktop-linux"]')
    return argv


def _container_id(value, what='container ID'):
    require(isinstance(value, str) and _HEX_ID.fullmatch(value) is not None,
            '{} must be 12-64 lowercase hex characters (a bare crictl ID; strip "containerd://" with '
            'bare_container_id), got {!r}'.format(what, value))
    return value


def _k8s_name(value, what):
    require(isinstance(value, str) and _K8S_NAME.fullmatch(value) is not None,
            '{} must be a Kubernetes DNS name, got {!r}'.format(what, value))
    return value


def _pod_uid(value):
    require(isinstance(value, str) and _POD_UID.fullmatch(value) is not None,
            'Pod UID must be a lowercase UUID, got {!r}'.format(value))
    return value


def bare_container_id(value):
    """'containerd://<64 hex>' (a Pod status containerID) or a bare ID -> the bare hex ID crictl uses."""
    require(isinstance(value, str), 'container ID must be a string')
    _, separator, rest = value.partition('://')
    return _container_id(rest if separator else value)


def same_container_id(a, b):
    """Equal bare IDs, or one a unique-prefix form (>= 12 hex) of the other (crictl accepts unique prefixes)."""
    a, b = bare_container_id(a), bare_container_id(b)
    short, long_ = sorted((a, b), key=len)
    return long_.startswith(short)


def node_exec_argv(docker_argv, node, command):
    """`<docker argv> exec <node> <command...>`: no shell anywhere (subprocess argv on the host, exec in the node)."""
    require(isinstance(node, str) and _NODE_NAME.fullmatch(node) is not None, 'invalid node container name')
    require(isinstance(command, (list, tuple)) and bool(command)
            and all(isinstance(a, str) and a != '' and '\0' not in a for a in command), 'invalid command')
    return _docker(docker_argv) + ['exec', node] + list(command)


def kill_argv(docker_argv, node, container_id):
    """`docker exec <node> crictl stop --timeout 0 <id>`: SIGKILL with no grace period."""
    return node_exec_argv(docker_argv, node, ['crictl', 'stop', '--timeout', str(STOP_TIMEOUT_SECONDS),
                                              _container_id(container_id)])


def find_sandbox_argv(docker_argv, node, pod_name, *, namespace=None, pod_uid=None):
    """`crictl pods --name <pod> [--namespace <ns>] [--label io.kubernetes.pod.uid=<uid>] --state ready -q`: the
    Pod's sandbox ID (crictl's --name/--namespace are regular-expression filters; the UID label is exact, so with
    it the match is unique; parse with `single_crictl_id`)."""
    command = ['crictl', 'pods', '--name', _k8s_name(pod_name, 'Pod name')]
    if namespace is not None:
        command += ['--namespace', _k8s_name(namespace, 'namespace')]
    if pod_uid is not None:
        command += ['--label', POD_UID_LABEL + '=' + _pod_uid(pod_uid)]
    return node_exec_argv(docker_argv, node, command + ['--state', 'ready', '-q'])


def find_container_argv(docker_argv, node, sandbox_id, *, container_name=CONTAINER_NAME):
    """`crictl ps --pod <sandbox id> --name <container> --state running -q`: the running container's ID (crictl's
    Pod filter is `--pod`/`-p`; there is no `--pod-id` flag)."""
    return node_exec_argv(docker_argv, node, ['crictl', 'ps', '--pod', _container_id(sandbox_id, 'sandbox ID'),
                                              '--name', _k8s_name(container_name, 'container name'),
                                              '--state', 'running', '-q'])


def find_container_by_pod_uid_argv(docker_argv, node, pod_uid, *, container_name=CONTAINER_NAME):
    """One-step alternative: `crictl ps --label io.kubernetes.pod.uid=<uid> --name <container> --state running -q`."""
    return node_exec_argv(docker_argv, node, ['crictl', 'ps', '--label', POD_UID_LABEL + '=' + _pod_uid(pod_uid),
                                              '--name', _k8s_name(container_name, 'container name'),
                                              '--state', 'running', '-q'])


def find_container_by_labels_argv(docker_argv, node, pod_name, namespace, pod_uid, *, container_name=CONTAINER_NAME):
    """The plan's container selection (phase3/stage2_plan.json faults.F2.container_selection: the running container
    whose labels io.kubernetes.pod.name, io.kubernetes.pod.namespace and io.kubernetes.container.name name the
    target and whose io.kubernetes.pod.uid equals the API UID) as one exact-match `crictl ps -q` (crictl ANDs its
    --label filters; no regular expression is involved)."""
    labels = [(POD_NAME_LABEL, _k8s_name(pod_name, 'Pod name')), (POD_NAMESPACE_LABEL, _k8s_name(namespace, 'namespace')),
              (CONTAINER_NAME_LABEL, _k8s_name(container_name, 'container name')), (POD_UID_LABEL, _pod_uid(pod_uid))]
    command = ['crictl', 'ps']
    for key, value in labels:
        command += ['--label', key + '=' + value]
    return node_exec_argv(docker_argv, node, command + ['--state', 'running', '-q'])


def list_containers_argv(docker_argv, node):
    """`crictl ps -o json`: the running containers with their labels (read by `select_container`)."""
    return node_exec_argv(docker_argv, node, ['crictl', 'ps', '-o', 'json'])


def select_container(listing, pod_name, namespace, pod_uid, container_name=CONTAINER_NAME):
    """The one running container of `crictl ps -o json` output (bytes, text or the parsed object) whose labels name
    the target Pod, namespace and container and whose io.kubernetes.pod.uid equals the API UID (the plan's rule, as
    infrastructure/stage2/smoke/smoke_kill.py applies it). Returns {id, pod_sandbox_id, attempt, state, labels};
    refuses (ValueError) unless exactly one container matches."""
    if isinstance(listing, (bytes, bytearray)):
        listing = listing.decode('utf-8', 'replace')
    if isinstance(listing, str):
        try:
            listing = json.loads(listing)
        except ValueError as error:
            raise ValueError('crictl ps -o json output is not JSON: {}'.format(error)) from None
    require(isinstance(listing, dict) and isinstance(listing.get('containers'), list),
            'crictl ps -o json output has no containers list')
    wanted = {POD_NAME_LABEL: pod_name, POD_NAMESPACE_LABEL: namespace, CONTAINER_NAME_LABEL: container_name,
              POD_UID_LABEL: pod_uid}
    matches = [c for c in listing['containers'] if isinstance(c, dict)
               and all((c.get('labels') or {}).get(key) == value for key, value in wanted.items())
               and c.get('state', 'CONTAINER_RUNNING') == 'CONTAINER_RUNNING']
    require(len(matches) == 1, 'expected exactly one running container labelled {}, got {}'.format(wanted, len(matches)))
    match = matches[0]
    return {'id': _container_id(match.get('id')), 'pod_sandbox_id': match.get('podSandboxId'),
            'attempt': (match.get('metadata') or {}).get('attempt'), 'state': match.get('state'),
            'labels': {key: (match.get('labels') or {}).get(key) for key in wanted}}


def inspect_container_argv(docker_argv, node, container_id):
    """`crictl inspect <id>` (JSON): the runtime's own record of the container, for the capture's ground truth."""
    return node_exec_argv(docker_argv, node, ['crictl', 'inspect', _container_id(container_id)])


def clock_probe_argv(docker_argv, node):
    """`docker exec <node> date +%s.%N`: one node-clock reading."""
    return node_exec_argv(docker_argv, node, list(NODE_DATE_ARGS))


def parse_crictl_ids(output):
    """IDs printed by `crictl ... -q`, one per line (bytes or text; blank lines and CRLF ignored). Any other line
    is refused, so a warning printed to stdout cannot be mistaken for an ID."""
    text = output.decode('utf-8', 'replace') if isinstance(output, (bytes, bytearray)) else output
    require(isinstance(text, str), 'crictl output must be bytes or text')
    return [_container_id(line.strip(), 'crictl output line') for line in text.splitlines() if line.strip()]


def single_crictl_id(output):
    ids = parse_crictl_ids(output)
    require(len(ids) == 1, 'expected exactly one ID from crictl, got {}'.format(len(ids)))
    return ids[0]


def parse_node_clock_ns(output):
    """`date +%s.%N` output -> integer ns since the epoch (a `date` without %N support is refused)."""
    text = output.decode('utf-8', 'replace') if isinstance(output, (bytes, bytearray)) else output
    match = _NODE_CLOCK.fullmatch(text.strip()) if isinstance(text, str) else None
    require(match is not None, 'unexpected node date output {!r} (expected <seconds>.<9 digits>)'.format(output))
    return int(match.group(1)) * 1_000_000_000 + int(match.group(2))


def container_identity(pod, container_name, container_id):
    """Does the Pod's own status name the container that crictl found? (checked before the kill is issued)"""
    statuses = [s for s in (pod.get('status') or {}).get('containerStatuses') or [] if s.get('name') == container_name]
    status_id = statuses[0].get('containerID') if len(statuses) == 1 else None
    bare = bare_container_id(status_id) if isinstance(status_id, str) and status_id else None
    return {'container_name': container_name, 'pod_status_container_id': bare, 'crictl_container_id': container_id,
            'matches': bare is not None and same_container_id(bare, container_id)}


# ---------------------------------------------------------------------------------------------------------------
# (d) Clock band and the clock-consistency rule
# ---------------------------------------------------------------------------------------------------------------
def _first(mapping, *names):
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def clock_readings(documents):
    """Flatten clock-probe documents into readings with labels: a list of readings is returned as it is; a document
    with 'sets' (phase3/CAPTURE_FORMAT_STAGE2.md: [{phase, probes}]) or with 'pairs' and a top-level
    'label' (infrastructure/stage2/smoke/clock_probe.py, one document per label) is unrolled; a list of such
    documents is unrolled in order."""
    if isinstance(documents, dict):
        documents = [documents]
    require(isinstance(documents, (list, tuple)), 'clock readings must be a list or a probe document')
    out = []
    for item in documents:
        if isinstance(item, dict) and isinstance(item.get('sets'), list):
            for group in item['sets']:
                out.extend(dict(probe, label=probe.get('label', group.get('phase'))) for probe in group.get('probes') or [])
        elif isinstance(item, dict) and isinstance(item.get('pairs'), list):
            out.extend(dict(probe, label=probe.get('label', item.get('label'))) for probe in item['pairs'])
        else:
            out.append(item)
    return out


def clock_band(readings, *, stamp_resolution_ns=STAMP_RESOLUTION_NS):
    """The capture's clock band from paired clock-probe readings.

    Each reading is {host send, node time, host receive} in integer ns under any of three spellings:
    host_send_ns / node_ns / host_receive_ns; send_ns / node_ns / receive_ns (the rows of
    infrastructure/stage2/smoke/clock_probe.py); host_send_at_ns / node_time_ns / host_receive_at_ns (the proposal of
    phase3/CAPTURE_FORMAT_STAGE2.md section 11). Whole probe documents are accepted too (`clock_readings`).
    Optional: 'label' (or 'phase': start / end), 'exit_code', 'error'. With theta = host - node, a reading bounds
    theta to [send - node, receive - node]. A reading with an error, a non-zero exit code, a missing value or
    receive < send is rejected and listed. The band is b_c = stamp resolution (1 s) + the widest bound = max over
    usable readings of max(|low|, |high|); without a usable reading the band is None. The union and the
    intersection of the intervals are reported beside it (an empty intersection means the offset moved during the
    capture). No timestamp is corrected.
    """
    readings = clock_readings(readings)
    require(_is_int(stamp_resolution_ns) and stamp_resolution_ns >= 0, 'invalid stamp resolution')
    used, rejected = [], []
    for index, reading in enumerate(readings):
        if not isinstance(reading, dict):
            rejected.append({'index': index, 'label': None, 'reasons': ['not_an_object']})
            continue
        send = _first(reading, 'host_send_ns', 'send_ns', 'host_send_at_ns')
        receive = _first(reading, 'host_receive_ns', 'receive_ns', 'host_receive_at_ns')
        node = _first(reading, 'node_ns', 'node_time_ns')
        label = _first(reading, 'label', 'phase')
        reasons = []
        if reading.get('error'):
            reasons.append('reading_error: ' + str(reading['error'])[:200])
        if reading.get('exit_code') not in (None, 0):
            reasons.append('exit_code={}'.format(reading.get('exit_code')))
        for name, value in (('send', send), ('node', node), ('receive', receive)):
            if not _is_int(value):
                reasons.append(name + '_ns_missing_or_not_integer')
        if not reasons and receive < send:
            reasons.append('receive_before_send')
        if reasons:
            rejected.append({'index': index, 'label': label, 'reasons': reasons})
            continue
        used.append({'index': index, 'label': label, 'offset_low_ns': send - node, 'offset_high_ns': receive - node,
                     'width_ns': receive - send})
    result = {'schema': CLOCK_BAND_SCHEMA, 'rule': CLOCK_BAND_RULE, 'stamp_resolution_ns': stamp_resolution_ns,
              'readings_used': len(used), 'readings_rejected': rejected, 'per_reading': used}
    if not used:
        return dict(result, band_available=False, band_ns=None, band_us=None, widest_bound_ns=None, union_ns=None,
                    intersection_ns=None, intersection_empty=None, by_label={})
    lows = [u['offset_low_ns'] for u in used]
    highs = [u['offset_high_ns'] for u in used]
    widest = max(max(abs(u['offset_low_ns']), abs(u['offset_high_ns'])) for u in used)
    band_ns = stamp_resolution_ns + widest
    by_label = {}
    for label in sorted({str(u['label']) for u in used}):
        group = [u for u in used if str(u['label']) == label]
        by_label[label] = {'readings': len(group),
                           'union_ns': [min(u['offset_low_ns'] for u in group), max(u['offset_high_ns'] for u in group)],
                           'widest_bound_ns': max(max(abs(u['offset_low_ns']), abs(u['offset_high_ns'])) for u in group),
                           'max_width_ns': max(u['width_ns'] for u in group)}
    return dict(result, band_available=True, band_ns=band_ns, band_us=-(-band_ns // 1000), widest_bound_ns=widest,
                union_ns=[min(lows), max(highs)],
                intersection_ns=[max(lows), min(highs)] if max(lows) <= min(highs) else None,
                intersection_empty=max(lows) > min(highs), max_width_ns=max(u['width_ns'] for u in used),
                by_label=by_label)


def clamp_stamp(stamp_us, last_observation, band_us=None):
    """The clock-consistency rule for one stamped transition.

    `stamp_us`: the transition's kubelet stamp (us). `last_observation`: the last observation of the same Pod that
    contradicts the transition, {'observed_at_us', 'observation_id' (or 'record_id' / 'id')}, or None. If the stamp
    is at or before that observation, the transition is moved to the observation's instant + 1 us and flagged
    `clock_clamped`; otherwise it is unchanged. `band_us` (the capture's b_c) only labels the shift: a shift within
    the band is what clock skew and stamp resolution can explain; a larger one means the contradicting observation
    showed stale API state (report lag). Both are clamped and both are counted.
    """
    require(_is_int(stamp_us), 'stamp_us must be integer microseconds')
    require(band_us is None or (_is_int(band_us) and band_us >= 0), 'band_us must be None or integer us')
    result = {'stamp_us': stamp_us, 'observed_at_us': stamp_us, 'clock_clamped': False, 'reason': None,
              'reference_id': None, 'reference_observed_at_us': None, 'shift_us': 0, 'band_us': band_us,
              'shift_within_band': None}
    if last_observation is None:
        return result
    require(isinstance(last_observation, dict), 'last_observation must be an object or None')
    reference = last_observation.get('observed_at_us')
    require(_is_int(reference), 'last_observation needs integer observed_at_us')
    if stamp_us > reference:
        return result
    placed = reference + CLAMP_STEP_US
    shift = placed - stamp_us
    result.update(observed_at_us=placed, clock_clamped=True, reason='contradicted_by_earlier_known_observation',
                  reference_id=_first(last_observation, 'observation_id', 'record_id', 'id'),
                  reference_observed_at_us=reference, shift_us=shift,
                  shift_within_band=None if band_us is None else shift <= band_us)
    return result


# ---------------------------------------------------------------------------------------------------------------
# (e) K1 point observations
# ---------------------------------------------------------------------------------------------------------------
def pod_state(pod):
    """policy-gate v1's Pod STATE, copied from experiments/policy-gate-v1/run_policy_gate_audit.py `pod_state` (a
    test compares the two): failed | succeeded | terminating | ready (Running, every container ready) | not_ready."""
    status = pod.get('status', {})
    phase = status.get('phase')
    if phase == 'Failed':
        return 'failed'
    if phase == 'Succeeded':
        return 'succeeded'
    if pod['metadata'].get('deletionTimestamp'):
        return 'terminating'
    statuses = status.get('containerStatuses') or []
    if phase == 'Running' and statuses and all(c.get('ready') is True for c in statuses):
        return 'ready'
    return 'not_ready'


def pod_records(records):
    """Pod records with host receipts, in the observer's acceptance order.

    Each input row is {record_id, observed_at | observed_at_us, available_at | available_at_us | available_at_ns,
    and ONE Pod object under pod | resource_data | object, [observer | observation_basis]}: the poller's
    `resource_observation` rows (scripts/collect_deployment_history.py and v1.1) and the watch's `watch_list_object`
    and `api_watch_event` rows (phase3/CAPTURE_FORMAT_STAGE2.md) are accepted as they are. Rows
    without a Pod object (continuity gaps, list summaries, other kinds, BOOKMARK events) are skipped. A record that
    holds several objects (a recheck tick's `objects`, a resolved watch cache snapshot) must be flattened by the
    caller into one row per Pod with a unique record_id (e.g. '<record_id>#<uid>'); duplicate record_ids are refused.
    Sorted by (available_at, observed_at, input position).
    """
    require(isinstance(records, (list, tuple)), 'records must be a list')
    out, seen = [], set()
    for index, record in enumerate(records):
        require(isinstance(record, dict), 'record {} must be an object'.format(index))
        pod = next((record[key] for key in ('pod', 'resource_data', 'object') if isinstance(record.get(key), dict)),
                   None)
        if pod is None or pod.get('kind', 'Pod') != 'Pod':
            continue
        if str(_first(record, 'event_type', 'type') or '').upper() == 'BOOKMARK':
            continue
        meta = pod.get('metadata')
        require(isinstance(meta, dict) and isinstance(meta.get('uid'), str) and meta['uid'] != '',
                'record {} has no Pod UID'.format(index))
        record_id = record.get('record_id')
        require(isinstance(record_id, str) and record_id != '', 'record {} has no record_id'.format(index))
        require(record_id not in seen, 'duplicate record_id {} (flatten multi-object records with unique IDs)'.format(
            record_id))
        seen.add(record_id)
        observed, available = _time_field(record, 'observed_at'), _time_field(record, 'available_at')
        require(available >= observed, 'record {} is available before it was observed'.format(record_id))
        out.append({'index': index, 'record_id': record_id, 'observer': _first(record, 'observer', 'observation_basis'),
                    'observed_us': observed, 'available_us': available, 'uid': meta['uid'], 'name': meta.get('name'),
                    'pod': pod})
    out.sort(key=lambda r: (r['available_us'], r['observed_us'], r['index']))
    return out


def _ready_condition(pod):
    found = [c for c in (pod.get('status') or {}).get('conditions') or []
             if isinstance(c, dict) and c.get('type') == 'Ready']
    return found[0] if len(found) == 1 else None


def _container_statuses(pod):
    return {c.get('name'): c for c in (pod.get('status') or {}).get('containerStatuses') or [] if isinstance(c, dict)}


def _transitions(rec, prev, handled, skipped):
    """The stamped transitions that record `rec` reveals for the first time (keys in `handled` were seen before).

    - Ready condition: (lastTransitionTime, True -> ready, False -> not_ready); other statuses are skipped.
    - lastState.terminated.finishedAt of a container whose restartCount is larger than in the Pod's previous
      record (0 when the Pod has no previous record, or the container was absent from it): not_ready.
    - state.running.startedAt of a container with restartCount >= 1 ("after a restart"): not_ready (a restarted
      container starts not ready; readiness is reset with the new container), unless the same record's Ready
      condition says True since an earlier instant (then the record itself contradicts it and it is skipped).
    `rank` orders transitions with the same stamp physically: termination, start, Ready condition.
    """
    found = []
    pod = rec['pod']
    ready = _ready_condition(pod)
    ready_true_since = None
    if ready is not None:
        status, stamp = ready.get('status'), ready.get('lastTransitionTime')
        if status not in ('True', 'False') or not isinstance(stamp, str):
            key = ('ready_condition_unusable', status, stamp)
            if key not in handled:
                handled.add(key)
                skipped.append({'source_record': rec['record_id'], 'pod_uid': rec['uid'],
                                'source_field': 'status.conditions[type=Ready]',
                                'reason': 'ready_condition_status_{}_or_stamp_{!r}_unusable'.format(status, stamp)})
        else:
            stamp_us = parse_time_us(stamp, 'Ready lastTransitionTime')
            if status == 'True':
                ready_true_since = stamp_us
            key = ('ready_condition', status, stamp)
            if key not in handled:
                found.append({'key': key, 'tag': 'ready_condition', 'rank': 2,
                              'state': 'ready' if status == 'True' else 'not_ready', 'stamp': stamp,
                              'stamp_us': stamp_us, 'source_field': 'status.conditions[type=Ready].lastTransitionTime',
                              'container_name': None, 'restart_count': None, 'restart_count_before': None,
                              'restart_baseline': None})
    before = _container_statuses(prev['pod']) if prev is not None else {}
    for name, status in sorted(_container_statuses(pod).items(), key=lambda item: str(item[0])):
        count = status.get('restartCount')
        if not _is_int(count) or count < 1:
            continue
        prior = before.get(name, {}).get('restartCount')
        if _is_int(prior):
            baseline, basis = prior, 'previous_record'
        else:
            baseline = 0
            basis = 'pod_creation (no earlier record of this Pod)' if prev is None else \
                'pod_creation (container absent from the previous record)'
        terminated = (status.get('lastState') or {}).get('terminated') or {}
        finished = terminated.get('finishedAt')
        finished_us = parse_time_us(finished, 'finishedAt') if isinstance(finished, str) else None
        if count > baseline and finished_us is not None:
            key = ('terminated', name, finished)
            if key not in handled:
                found.append({'key': key, 'tag': 'terminated:' + str(name), 'rank': 0, 'state': 'not_ready',
                              'stamp': finished, 'stamp_us': finished_us,
                              'source_field': 'status.containerStatuses[name={}].lastState.terminated.finishedAt'.format(
                                  name),
                              'container_name': name, 'restart_count': count, 'restart_count_before': baseline,
                              'restart_baseline': basis, 'terminated_exit_code': terminated.get('exitCode'),
                              'terminated_container_id': terminated.get('containerID')})
        started = ((status.get('state') or {}).get('running') or {}).get('startedAt')
        if isinstance(started, str):
            key = ('started', name, started)
            if key in handled:
                continue
            started_us = parse_time_us(started, 'startedAt')
            reason = None
            if finished_us is not None and started_us < finished_us:
                reason = 'started_before_last_termination'
            elif ready_true_since is not None and ready_true_since < started_us:
                reason = 'ready_condition_predates_container_start'
            if reason:
                handled.add(key)
                skipped.append({'source_record': rec['record_id'], 'pod_uid': rec['uid'], 'reason': reason,
                                'source_field': 'status.containerStatuses[name={}].state.running.startedAt'.format(name),
                                'stamp': started})
                continue
            found.append({'key': key, 'tag': 'started:' + str(name), 'rank': 1, 'state': 'not_ready',
                          'stamp': started, 'stamp_us': started_us,
                          'source_field': 'status.containerStatuses[name={}].state.running.startedAt'.format(name),
                          'container_name': name, 'restart_count': count, 'restart_count_before': baseline,
                          'restart_baseline': basis})
    return found


def _place(rec, found, known, sighting_state, band_us):
    """Place one record's new transitions in valid time; returns (kept, dropped).

    1. A stamp later than the record's own observation instant o_R is capped at o_R (the record speaks for the state
       up to o_R; a later stamp is node-clock skew), flagged.
    2. The clock-consistency rule (`clamp_stamp`): a transition is contradicted by an observation of the same Pod
       from an EARLIER record whose state differs and whose instant lies inside the transition's own claim, i.e. at
       or after its stamp and before the record's next transition to another state (or, for the record's last
       state, up to o_R). It is moved to the last such observation + 1 us.
    3. No transition may sit at or after o_R with a state other than the record's own sighting: dropped.
    4. Transitions of different states keep their physical order (termination, start, Ready; ties within one
       second) strictly: a later one at or before an earlier one of another state is moved to it + 1 us, flagged
       (order_within_record), and dropped if that leaves no room before o_R.
    5. A transition at the same instant as a different-state observation already known (or kept) is dropped, so the
       A1 run derivation (policy_gate._derive_runs) never meets a same-instant conflict that K1 created.
    """
    o_r = rec['observed_us']
    items = sorted(found, key=lambda t: (t['stamp_us'], t['rank']))
    for item in items:
        item['placed_us'], item['clamps'] = item['stamp_us'], []
        if item['placed_us'] > o_r:
            item['clamps'].append({'reason': 'stamp_after_record_observation', 'from_us': item['placed_us'],
                                   'to_us': o_r, 'reference_id': rec['record_id'], 'reference_observed_at_us': o_r,
                                   'shift_us': o_r - item['placed_us'],
                                   'shift_within_band': None if band_us is None else item['placed_us'] - o_r <= band_us})
            item['placed_us'] = o_r
    capped = [item['placed_us'] for item in items]
    for i, item in enumerate(items):
        later = [capped[j] for j in range(i + 1, len(items)) if items[j]['state'] != item['state']]
        end, inclusive = (min(later), False) if later else (o_r, sighting_state == item['state'])
        contradicting = [x for x in known if x['state'] != item['state'] and x['observed_us'] >= item['placed_us']
                         and (x['observed_us'] < end or (inclusive and x['observed_us'] <= end))]
        if contradicting:
            reference = max(contradicting, key=lambda x: (x['observed_us'], x['id']))
            clamp = clamp_stamp(item['placed_us'], {'observed_at_us': reference['observed_us'],
                                                    'observation_id': reference['id']}, band_us)
            item['clamps'].append({'reason': clamp['reason'], 'from_us': item['placed_us'],
                                   'to_us': clamp['observed_at_us'], 'reference_id': reference['id'],
                                   'reference_state': reference['state'],
                                   'reference_observed_at_us': reference['observed_us'], 'shift_us': clamp['shift_us'],
                                   'shift_within_band': clamp['shift_within_band']})
            item['placed_us'] = clamp['observed_at_us']
    kept, dropped = [], []

    def no_room(item):
        return item['placed_us'] > o_r or (item['placed_us'] == o_r and item['state'] != sighting_state)

    for item in items:
        (dropped if no_room(item) else kept).append(item)
        if no_room(item):
            item['drop_reason'] = 'no_room_before_the_record_observation'
    ordered = []
    for item in kept:
        others = [x['placed_us'] for x in ordered if x['state'] != item['state']]
        if others and item['placed_us'] <= max(others):
            target = max(others) + CLAMP_STEP_US
            item['clamps'].append({'reason': 'order_within_record', 'from_us': item['placed_us'], 'to_us': target,
                                   'reference_id': rec['record_id'], 'reference_observed_at_us': max(others),
                                   'shift_us': target - item['placed_us'],
                                   'shift_within_band': None if band_us is None else target - item['stamp_us'] <= band_us})
            item['placed_us'] = target
            if no_room(item):
                item['drop_reason'] = 'no_room_before_the_record_observation_after_ordering'
                dropped.append(item)
                continue
        ordered.append(item)
    final = []
    for item in ordered:
        clash = [x for x in known if x['observed_us'] == item['placed_us'] and x['state'] != item['state']] + \
                [x for x in final if x['placed_us'] == item['placed_us'] and x['state'] != item['state']]
        if clash:
            item['drop_reason'] = 'same_instant_conflict'
            dropped.append(item)
        else:
            final.append(item)
    return final, dropped


def k1_extract(records, *, band_us=None, allow_mixed_observers=False):
    """K1 point observations of one observer's Pod records, with the clamp applied.

    Each kubelet-stamped transition becomes {pod_uid, state: ready | not_ready, observed_at: <kubelet stamp>,
    available_at: <the record's acceptance>, source_field, source_record}; a transition counts once, at the first
    record that reveals it (its first availability). Returns the observations, the transitions dropped or skipped
    with their reasons, and the counts to be reported (clock_clamped flags).

    K1 is extracted per observer (poller, watch, recheck): its availability is that observer's acceptance (section
    5.2), so records carrying two different `observer` values are refused unless allow_mixed_observers is set.
    """
    require(band_us is None or (_is_int(band_us) and band_us >= 0), 'band_us must be None or integer us')
    require(isinstance(records, (list, tuple)), 'records must be a list')
    tags = {record.get('observer') for record in records if isinstance(record, dict) and record.get('observer')}
    require(allow_mixed_observers or len(tags) <= 1,
            'K1 is extracted per observer; got records of {}'.format(sorted(tags)))
    parsed = pod_records(records)
    known = defaultdict(list)          # Pod UID -> observations of earlier records: sightings and kept K1
    previous, handled = {}, defaultdict(set)
    observations, dropped, skipped = [], [], []
    for rec in parsed:
        uid = rec['uid']
        sighting_state = pod_state(rec['pod'])
        found = _transitions(rec, previous.get(uid), handled[uid], skipped)
        for item in found:
            handled[uid].add(item['key'])
        kept, lost = _place(rec, found, known[uid], sighting_state, band_us)
        for item in lost:
            dropped.append({'pod_uid': uid, 'source_record': rec['record_id'], 'source_field': item['source_field'],
                            'state': item['state'], 'stamp': item['stamp'], 'stamp_us': item['stamp_us'],
                            'placed_us': item['placed_us'], 'clamps': item['clamps'], 'reason': item['drop_reason']})
        for item in kept:
            observation = {
                'schema': K1_SCHEMA, 'observation_id': 'k1:{}:{}'.format(rec['record_id'], item['tag']),
                'pod_uid': uid, 'pod_name': rec['name'], 'predicate': 'STATE', 'state': item['state'],
                'observed_at': iso_us(item['placed_us']), 'observed_at_us': item['placed_us'],
                'available_at': iso_us(rec['available_us']), 'available_at_us': rec['available_us'],
                'stamp': item['stamp'], 'stamp_us': item['stamp_us'], 'source_field': item['source_field'],
                'source_record': rec['record_id'], 'observer': rec['observer'],
                'record_observed_at_us': rec['observed_us'], 'container_name': item['container_name'],
                'restart_count': item['restart_count'], 'restart_count_before': item['restart_count_before'],
                'restart_baseline': item['restart_baseline'], 'clock_clamped': bool(item['clamps']),
                'clamps': item['clamps']}
            observations.append(observation)
            known[uid].append({'id': observation['observation_id'], 'state': item['state'],
                               'observed_us': item['placed_us']})
        known[uid].append({'id': rec['record_id'], 'state': sighting_state, 'observed_us': rec['observed_us']})
        previous[uid] = rec
    clamped = [o for o in observations if o['clock_clamped']]
    return {'schema': K1_EXTRACTION_SCHEMA, 'rule': CLAMP_RULE, 'band_us': band_us, 'observations': observations,
            'dropped': dropped, 'skipped': skipped,
            'counts': {'records': len(parsed), 'pods': len({r['uid'] for r in parsed}),
                       'observations': len(observations), 'clock_clamped': len(clamped),
                       'clamped_beyond_band': sum(1 for o in clamped
                                                  if any(c.get('shift_within_band') is False for c in o['clamps'])),
                       'dropped': len(dropped), 'skipped': len(skipped)}}


def k1_observations(records, *, band_us=None, allow_mixed_observers=False):
    """The K1 point observations alone (see `k1_extract` for the dropped/skipped lists and the counts)."""
    return k1_extract(records, band_us=band_us, allow_mixed_observers=allow_mixed_observers)['observations']


# ---------------------------------------------------------------------------------------------------------------
# (c) The F2 evaluator, in the structure of fault_control.evaluate_fault_control
# ---------------------------------------------------------------------------------------------------------------
PHASES = ('nominal', 'active', 'recovery')
FAILED_OUTCOMES = ('rpc_error', 'timeout', 'invalid_response')


def _band_us(value):
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get('band_us')
    require(value is None or (_is_int(value) and value >= STAMP_RESOLUTION_US),
            'clock band must be integer us >= 1 s (or a clock_band() record)')
    return value


def _target(records):
    target = records.get('target')
    if target is None and isinstance(records.get('draw'), dict):
        target = records['draw'].get('target')
    require(isinstance(target, dict), 'records need a target {service, pod_uid, pod_name, pod_ip} or a draw record')
    target = dict(target)
    target.setdefault('container_name', CONTAINER_NAME)
    return target


def _row_times(row):
    """(issued_us, received_us) of a probe row: host_issued_at / host_received_at, or (Phase 3 rows, which have no
    issue wall time) the receipt minus the monotonic duration, rounded so that the issue is never later."""
    received = _time_field(row, 'host_received_at')
    if row.get('host_issued_at') is not None or row.get('host_issued_at_us') is not None:
        return _time_field(row, 'host_issued_at'), received
    issued_ns, received_ns = row.get('host_issued_monotonic_ns'), row.get('host_received_monotonic_ns')
    require(_is_int(issued_ns) and _is_int(received_ns) and received_ns >= issued_ns,
            'probe row {} has no issue time'.format(row.get('probe_id')))
    return received - -(-(received_ns - issued_ns) // 1000), received


def _status_of(pod, name):
    statuses = [s for s in (pod.get('status') or {}).get('containerStatuses') or [] if s.get('name') == name]
    return statuses[0] if len(statuses) == 1 else None


def _record_ref(rec, role):
    return {'role': role, 'record_id': rec['record_id'], 'observer': rec['observer'],
            'observed_at': iso_us(rec['observed_us']), 'available_at': iso_us(rec['available_us'])}


def evaluate_kill(records):
    """Evaluate one F2 container kill from supplied records; performs no process or network action.

    `records` = {
      'target' (or 'draw', a KillPlan.draw() record): {service, pod_uid, pod_name, pod_ip, [container_name]},
      'kill_receipt': the host-command receipt of `kill_argv` (scripts/host_command_receipt_v1.py layout:
                      executed, exit_code, args, request_started_at, response_received_at),
      'container_id': the bare ID that was stopped (default: the receipt argv's last element),
      'pod_records': the target's Pod records with host receipts (watch, poller v1.1 or recheck rows; `pod_records`),
      'probe_rows': per-Pod probe rows (scripts/per_pod_probe_v1.py; Phase 3 rows are accepted too),
      'clock_band': a `clock_band()` record or band_us,
      ['docker_argv', 'node']: when given, the receipt argv must equal kill_argv(docker_argv, node, container_id)}.

    Windows (host clock, us; b_c = the clock band):
      kill window K = [kill request start - b_c, kill response receipt + b_c]: the container exited between the
        command's start and its return (the CRI stop returns after the container stopped), so its kubelet-stamped
        finishedAt (node clock, whole seconds) lies in K whatever the offset, if the band holds;
      not-Ready window = [kill response receipt, Ready-again stamp - b_c]: the container is certainly dead from the
        kill's return, and the Pod is certainly not yet Ready before its kubelet-stamped return to Ready minus b_c;
      recovery = probes issued at or after the Ready-again stamp + b_c.
    A probe overlapping a boundary is boundary_ambiguous and excluded, as the CPU evaluator excludes unbracketed
    active probes. Activation, effect and recovery are then checked.
    """
    require(isinstance(records, dict), 'records must be an object')
    target = _target(records)
    service, uid = target.get('service'), target.get('pod_uid')
    container_name = target['container_name']
    comparison = next((s for s in SERVICE_PORTS if s != service), None)
    receipt = records.get('kill_receipt') or {}
    argv = receipt.get('args') if isinstance(receipt.get('args'), list) else receipt.get('argv')
    argv = list(argv) if isinstance(argv, list) else []
    container_id = records.get('container_id') or (argv[-1] if argv else None)
    band_us = _band_us(records.get('clock_band'))
    kill_start = _time_field(receipt, 'request_started_at') if receipt else None
    kill_end = _time_field(receipt, 'response_received_at') if receipt else None
    identity_declared = (service in SERVICE_PORTS and all(isinstance(target.get(k), str) and target[k] != ''
                                                          for k in ('pod_uid', 'pod_name', 'pod_ip')))
    target_address = pod_address(target['pod_ip'], SERVICE_PORTS[service]) if identity_declared else None
    id_valid = isinstance(container_id, str) and _HEX_ID.fullmatch(container_id) is not None
    pods = [r for r in pod_records(records.get('pod_records') or []) if r['uid'] == uid]
    pre = [r for r in pods if kill_start is not None and r['observed_us'] < kill_start]
    post = [r for r in pods if kill_start is not None and r['observed_us'] >= kill_start]
    baseline_rec = max(pre, key=lambda r: (r['observed_us'], r['available_us'], r['index'])) if pre else None
    baseline_status = _status_of(baseline_rec['pod'], container_name) if baseline_rec else None
    baseline_count = baseline_status.get('restartCount') if baseline_status else None
    baseline_cid = baseline_status.get('containerID') if baseline_status else None

    # ---- probes: classify every call of the nominal, active and recovery blocks ----
    calls, seen, not_evaluated = [], set(), []
    rows = records.get('probe_rows') or []
    require(isinstance(rows, list), 'probe_rows must be a list')

    # ---- activation (needs the band and the receipt) ----
    window = (kill_start - band_us, kill_end + band_us) if None not in (kill_start, kill_end, band_us) else None
    first_restart, finished_us, terminated = None, None, {}
    if _is_int(baseline_count):
        for rec in post:
            status = _status_of(rec['pod'], container_name)
            count = status.get('restartCount') if status else None
            last = ((status or {}).get('lastState') or {}).get('terminated') or {}
            if _is_int(count) and count > baseline_count and isinstance(last.get('finishedAt'), str):
                first_restart, terminated = rec, last
                finished_us = parse_time_us(last['finishedAt'], 'finishedAt')
                break
    terminated_cid = terminated.get('containerID')
    activation = {
        'kill_command_succeeded': receipt.get('executed') is True and receipt.get('exit_code') == 0,
        'pre_kill_restart_count_known': _is_int(baseline_count),
        'restart_count_incremented': first_restart is not None,
        'terminated_finished_at_inside_kill_window': window is not None and finished_us is not None
                                                     and window[0] <= finished_us <= window[1],
        'terminated_container_is_killed_container': id_valid and isinstance(terminated_cid, str)
                                                    and _same_bare(terminated_cid, container_id),
    }
    activation_passed = all(activation.values())

    # ---- Ready history of the target after the kill (kubelet stamps) ----
    floor_us = finished_us if finished_us is not None else (window[0] if window else None)
    ready_again, ready_again_us, not_ready_seen = None, None, None
    for rec in post:
        condition = _ready_condition(rec['pod'])
        if not condition or not isinstance(condition.get('lastTransitionTime'), str) or floor_us is None:
            continue
        stamp_us = parse_time_us(condition['lastTransitionTime'], 'Ready lastTransitionTime')
        if condition.get('status') == 'False' and not_ready_seen is None and stamp_us >= floor_us - STAMP_RESOLUTION_US:
            not_ready_seen = (rec, stamp_us)
        if condition.get('status') == 'True' and stamp_us >= floor_us:
            ready_again, ready_again_us = rec, stamp_us
            break
    not_ready_end = ready_again_us - band_us if ready_again_us is not None and band_us is not None else None
    recovery_from = ready_again_us + band_us if ready_again_us is not None and band_us is not None else None

    def timing(issued, received):
        """Where a probe's [issue, receipt] lies; without the band or a stamped return to Ready nothing after the
        kill is certain (no probe is counted either way)."""
        if kill_start is None or kill_end is None:
            return 'kill_time_unknown'
        if received < kill_start:
            return 'before_kill'
        if issued < kill_end:
            return 'kill_boundary_ambiguous'
        if band_us is None:
            return 'clock_band_unknown'
        if ready_again_us is None:
            return 'ready_time_unknown'
        if received <= not_ready_end:
            return 'not_ready_certain'
        if issued >= recovery_from:
            return 'ready_certain'
        return 'ready_boundary_ambiguous'

    for row in rows:
        require(isinstance(row, dict), 'probe rows must be objects')
        block, batch = row.get('block'), row.get('batch')
        if block not in PHASES or not isinstance(batch, dict):
            not_evaluated.append({'probe_id': row.get('probe_id'), 'block': block,
                                  'reason': 'block_not_evaluated' if block not in PHASES else 'no_batch'})
            continue
        issued, received = _row_times(row)
        for call in batch.get('calls') or []:
            record = dict(call, phase=block, start_sequence=row.get('start_sequence'),
                          end_sequence=row.get('end_sequence'), host_issued_at_us=issued, host_received_at_us=received,
                          row_probe_id=row.get('probe_id'))
            validate_probe(record)
            require(record['probe_id'] not in seen, 'Repeated probe ID')
            seen.add(record['probe_id'])
            is_target = record['service'] == service
            address = record.get('address')
            record['addressing'] = ('target_pod' if target_address is not None and address == target_address else
                                    'service' if address == DEFAULT_SERVICE_ADDRESSES.get(record['service']) else 'other')
            record['window'] = timing(issued, received)
            reasons = []
            if block == 'nominal':
                state = 'nominal' if record['window'] == 'before_kill' else 'boundary_ambiguous'
                if state != 'nominal':
                    reasons.append('nominal_probe_not_before_kill')
            elif not is_target:
                state = block                     # the comparison service: descriptive only
            else:
                wanted = 'not_ready_certain' if block == 'active' else 'ready_certain'
                if record['addressing'] != 'target_pod':
                    reasons.append('not_addressed_to_target_pod')
                if record['window'] != wanted:
                    reasons.append('outside_{}_window:{}'.format('not_ready' if block == 'active' else 'recovery',
                                                                 record['window']))
                state = ('verified_not_ready' if block == 'active' else 'verified_ready') if not reasons \
                    else 'boundary_ambiguous'
            record['control_classification'], record['control_exclusion_reasons'] = state, reasons
            calls.append(record)

    services, medians, mads = {}, {}, {}
    for name in (service, comparison):
        services[name] = {}
        for phase in PHASES:
            summary, median, mad = summarize_phase([c for c in calls if c['service'] == name and c['phase'] == phase])
            services[name][phase], medians[(name, phase)], mads[(name, phase)] = summary, median, mad

    # ---- controls ----
    ordered = True
    for earlier, later in (('nominal', 'active'), ('active', 'recovery')):
        first = [c['end_sequence'] for c in calls if c['phase'] == earlier]
        second = [c['start_sequence'] for c in calls if c['phase'] == later]
        ordered = ordered and bool(first) and bool(second) and max(first) < min(second)
    target_calls = [c for c in calls if c['service'] == service and c['phase'] in ('active', 'recovery')]
    expected_argv = None
    if records.get('docker_argv') is not None and records.get('node') is not None and id_valid:
        expected_argv = kill_argv(records['docker_argv'], records['node'], container_id)
    controls = {
        'target_identity_declared': identity_declared,
        'kill_command_executed': receipt.get('executed') is True,
        'kill_command_exit_zero': receipt.get('exit_code') == 0,
        'kill_argv_is_crictl_stop_timeout_0': id_valid and len(argv) >= 7 and 'exec' in argv
                                              and argv[-5:] == ['crictl', 'stop', '--timeout', '0', container_id]
                                              and (expected_argv is None or argv == expected_argv),
        'kill_receipt_times_ordered': kill_start is not None and kill_end is not None and kill_start <= kill_end,
        'clock_band_available': band_us is not None,
        'pre_kill_record_of_target': baseline_rec is not None,
        'pre_kill_container_is_killed_container': id_valid and isinstance(baseline_cid, str)
                                                  and _same_bare(baseline_cid, container_id),
        'active_and_recovery_target_calls_addressed_to_target_pod': bool(target_calls) and all(
            c['addressing'] == 'target_pod' for c in target_calls),
        'phase_order_verified': ordered,
    }
    control_passed = all(controls.values())

    # ---- effect ----
    nominal = services[service]['nominal']
    nominal_median, nominal_mad = medians[(service, 'nominal')], mads[(service, 'nominal')]
    threshold = max(Fraction(MIN_SHIFT_NS), NOMINAL_MAD_MULTIPLIER * nominal_mad) if nominal_mad is not None else None
    eligible = [c for c in calls if c['service'] == service and c['phase'] == 'active'
                and c['control_classification'] == 'verified_not_ready']
    failed = [c for c in eligible if c['outcome'] in FAILED_OUTCOMES or c['functional_ok'] is not True]
    latencies = [Fraction(c['latency_ns']) for c in eligible if c['outcome'] == 'ok' and c['functional_ok'] is True]
    not_ready_median = statistics.median(latencies) if latencies else None
    shift = not_ready_median - nominal_median if None not in (not_ready_median, nominal_median) else None
    slowed = shift is not None and threshold is not None and shift >= threshold
    effect_checks = {
        'activation_verified': activation_passed,
        'nominal_support': nominal['successful'] >= MIN_SUCCESS['nominal'],
        'nominal_target_responses_functional': nominal['all_attempted_functional'],
        'target_probe_inside_not_ready_window': len(eligible) >= MIN_EFFECT_PROBES,
        'failed_or_slowed_while_not_ready': bool(failed) or slowed,
    }
    effect = all(effect_checks.values())

    # ---- recovery ----
    recovered_calls = [c for c in calls if c['service'] == service and c['phase'] == 'recovery'
                       and c['control_classification'] == 'verified_ready']
    recovery_summary = services[service]['recovery']
    recovery_median = medians[(service, 'recovery')]
    recovery_difference = recovery_median - nominal_median if None not in (recovery_median, nominal_median) else None
    recovery_checks = {
        'ready_true_again': ready_again is not None,
        'ready_again_record_not_terminating': ready_again is not None
                                              and not ready_again['pod']['metadata'].get('deletionTimestamp'),
        'recovery_support': recovery_summary['successful'] >= MIN_SUCCESS['recovery'],
        'all_recovery_target_responses_functional': bool(recovered_calls) and all(
            c['outcome'] == 'ok' and c['functional_ok'] is True for c in recovered_calls),
    }
    recovered = all(recovery_checks.values())

    reasons = []
    if not control_passed:
        reasons.append('control_or_identity_not_established')
    if not activation_passed:
        reasons.append('activation_not_established')
    if not effect_checks['nominal_support'] or not effect_checks['nominal_target_responses_functional']:
        reasons.append('insufficient_or_nonfunctional_nominal_support')
    if not effect_checks['target_probe_inside_not_ready_window']:
        reasons.append('no_target_probe_inside_not_ready_window')
    if not effect_checks['failed_or_slowed_while_not_ready']:
        reasons.append('no_failed_or_slowed_target_probe_while_not_ready')
    if not recovered:
        reasons.append('service_recovery_not_established')
    used = [_record_ref(r, 'target_record') for r in pods]
    evidence = {
        'kill_receipt_id': receipt.get('id'), 'container_id': container_id,
        'kill_request_started_at': iso_us(kill_start), 'kill_response_received_at': iso_us(kill_end),
        'kill_window': [iso_us(window[0]), iso_us(window[1])] if window else None,
        'pre_kill_baseline': dict(_record_ref(baseline_rec, 'pre_kill_baseline'), restart_count=baseline_count,
                                  container_id=baseline_cid) if baseline_rec else None,
        'first_restart_record': dict(_record_ref(first_restart, 'first_restart'),
                                     restart_count=_status_of(first_restart['pod'], container_name)['restartCount'],
                                     terminated=terminated) if first_restart else None,
        'restart_increment': (_status_of(first_restart['pod'], container_name)['restartCount'] - baseline_count)
                             if first_restart else None,
        'terminated_exit_code': terminated.get('exitCode'), 'terminated_reason': terminated.get('reason'),
        'exit_code_is_sigkill': terminated.get('exitCode') == 137 if terminated else None,
        'finished_at': terminated.get('finishedAt'),
        'first_restart_available_after_kill_us': (first_restart['available_us'] - kill_end)
                                                 if first_restart and kill_end is not None else None,
    }
    ready_history = {
        'not_ready_transition': dict(_record_ref(not_ready_seen[0], 'not_ready_transition'),
                                     stamp=iso_us(not_ready_seen[1])) if not_ready_seen else None,
        'ready_again': dict(_record_ref(ready_again, 'ready_again'), stamp=iso_us(ready_again_us))
                       if ready_again else None,
        'not_ready_window': [iso_us(kill_end), iso_us(not_ready_end)] if kill_end is not None else None,
        'recovery_from': iso_us(recovery_from),
    }
    return {
        'schema': SCHEMA, 'fault': 'F2 container kill: crictl stop --timeout 0 in the kind node',
        'scope': 'Engineering verification of one container kill; no causal diagnosis or statistical inference',
        'target_service': service, 'comparison_service': comparison, 'target': target,
        'constants': {'minimum_successes': {'nominal': MIN_SUCCESS['nominal'], 'recovery': MIN_SUCCESS['recovery']},
                      'minimum_effect_probes': MIN_EFFECT_PROBES, 'minimum_shift_ns': MIN_SHIFT_NS,
                      'nominal_mad_multiplier': NOMINAL_MAD_MULTIPLIER, 'stamp_resolution_us': STAMP_RESOLUTION_US,
                      'clock_band_us': band_us},
        'control_checks': controls, 'control_passed': control_passed,
        'activation_checks': activation, 'activation_verified': activation_passed, 'activation_evidence': evidence,
        'ready_history': ready_history,
        'support_checks': {'nominal': effect_checks['nominal_support'],
                           'not_ready_window': effect_checks['target_probe_inside_not_ready_window'],
                           'recovery': recovery_checks['recovery_support']},
        'services': services,
        'effect_threshold_ns': pack(threshold), 'not_ready_minus_nominal_median_ns': pack(shift),
        'failed_target_probes_while_not_ready': [c['probe_id'] for c in failed],
        'latency_threshold_crossed_descriptively': bool(slowed),
        'effect_checks': effect_checks, 'effect_established': effect,
        'recovery_minus_nominal_median_ns': pack(recovery_difference),
        'recovery_checks': recovery_checks, 'recovery_established': recovered,
        'fault_control_passed': bool(control_passed and activation_passed and effect and recovered),
        'reasons': reasons, 'pod_records_used': used, 'probe_records': calls, 'probe_rows_not_evaluated': not_evaluated,
        'diagnostic_rankings': None, 'diagnosis_accuracy': None, 'new_research_novelty_claim': False,
        'limitations': [
            'One kill is an engineering check of one fault, not a calibrated effect size or a recovery-time estimate.',
            'Kubelet stamps have 1 s resolution and the node clock is not calibrated against the host: every '
            'comparison between them uses the clock band b_c and no timestamp is corrected.',
            'Probes overlapping the kill or the Ready boundary (+- b_c) are excluded, not counted either way.',
            'Direct Pod-IP probes bypass the Service and can succeed before the kubelet marks the Pod Ready '
            '(readiness lags serving), so the effect is read only while the Pod was certainly not Ready.',
            'The nominal block addresses the Service (moves only active and recovery probes to '
            'the Pod IP), so recovery and nominal latencies are compared descriptively only.',
            'Fault-control evidence is evaluator-only: it is not a diagnostic feature and not an action-B label '
            '(labels are computed by the Stage-2 adapter).'],
    }


def _same_bare(a, b):
    try:
        return same_container_id(a, b)
    except ValueError:
        return False
