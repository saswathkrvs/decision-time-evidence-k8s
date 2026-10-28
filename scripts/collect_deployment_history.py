"""Bounded, read-only Kubernetes observations; never infer validity intervals.

Standard library only. No cluster is contacted merely by importing this module.
"""
import argparse
import hashlib
import ipaddress
import json
import math
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


KINDS = {'pods': 'Pod', 'replicasets': 'ReplicaSet', 'deployments': 'Deployment', 'nodes': 'Node'}
DEFAULT_KINDS = ('pods', 'replicasets', 'deployments')
REVISION = 'deployment.kubernetes.io/revision'


def utc_now():
    return datetime.now(timezone.utc)


def stamp(value):
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Collector clock must be timezone-aware')
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def nonempty(value, field):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(field + ' must be a nonempty string without outer whitespace')
    return value


def validate_options(args):
    nonempty(args.context, 'context')
    if not isinstance(args.namespace, str) or not re.fullmatch(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?', args.namespace):
        raise ValueError('An explicit DNS-label namespace is required')
    if args.namespace in {'default', 'kube-system', 'kube-public', 'kube-node-lease'}:
        raise ValueError('Use a dedicated research namespace')
    if not args.kinds or len(set(args.kinds)) != len(args.kinds) or any(k not in DEFAULT_KINDS for k in args.kinds):
        raise ValueError('Kinds must be unique members of pods, replicasets, deployments')
    for name, low, high in [('samples', 1, 120), ('duration_seconds', 1, 600),
                            ('interval_seconds', 0, 60), ('request_timeout_seconds', 0.1, 30)]:
        value = getattr(args, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError('{} must be in [{}, {}]'.format(name, low, high))
    if not isinstance(args.samples, int):
        raise ValueError('samples must be an integer')


def validated_endpoint(config, context, allowed_host=None):
    """Read the explicitly selected context, never the user's current context."""
    contexts = [c for c in config.get('contexts', []) if c.get('name') == context]
    if len(contexts) != 1:
        raise ValueError('Named context was not uniquely returned by kubeconfig')
    cluster_name = contexts[0]['context']['cluster']
    clusters = [c for c in config.get('clusters', []) if c.get('name') == cluster_name]
    if len(clusters) != 1:
        raise ValueError('Named context cluster was not uniquely returned')
    cluster = clusters[0]['cluster']
    if cluster.get('proxy-url'):
        raise ValueError('Kubeconfig proxy-url is unsupported for this local collector')
    server = nonempty(cluster.get('server'), 'API server')
    parsed = urlsplit(server)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Unsupported API server URL')
    host = parsed.hostname.lower()
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == 'localhost'
    if not local and host != allowed_host:
        raise ValueError('API endpoint is not loopback; explicitly permit its exact host only after verifying the local testbed')
    return {'server': server, 'cluster_name': cluster_name,
            'endpoint_policy': 'loopback' if local else 'explicit_host_exception'}


def selected_containers(values):
    return [{key: item[key] for key in ('name', 'image') if key in item} for item in values or []]


def project_resource(item, resource, namespace):
    """Keep identity and placement evidence without saving arbitrary pod specs."""
    if not isinstance(item, dict) or item.get('kind') != KINDS[resource]:
        raise ValueError('Unexpected resource kind in ' + resource)
    metadata = item.get('metadata', {})
    for key in ('uid', 'name', 'resourceVersion'):
        nonempty(metadata.get(key), key)
    if resource != 'nodes' and metadata.get('namespace') != namespace:
        raise ValueError('Snapshot contains an object outside the requested namespace')
    owners = metadata.get('ownerReferences', [])
    if not isinstance(owners, list):
        raise ValueError('ownerReferences must be a list')
    for owner in owners:
        for key in ('kind', 'name', 'uid'):
            nonempty(owner.get(key), 'ownerReferences.' + key)
    projected = {key: metadata[key] for key in ('uid', 'name', 'namespace', 'resourceVersion',
                 'generation', 'creationTimestamp', 'deletionTimestamp', 'labels') if key in metadata}
    projected['ownerReferences'] = owners
    revision = metadata.get('annotations', {}).get(REVISION)
    if revision is not None:
        projected['annotations'] = {REVISION: revision}
    spec, status = item.get('spec', {}), item.get('status', {})
    result = {'apiVersion': item.get('apiVersion'), 'kind': item['kind'], 'metadata': projected}
    if resource == 'pods':
        result['spec'] = {'nodeName': spec.get('nodeName'),
                          'containers': selected_containers(spec.get('containers')),
                          'initContainers': selected_containers(spec.get('initContainers'))}
        result['status'] = {key: status[key] for key in ('phase', 'startTime') if key in status}
        result['status']['containerStatuses'] = [
            {key: value[key] for key in ('name', 'image', 'imageID', 'containerID', 'ready', 'restartCount') if key in value}
            for value in status.get('containerStatuses', [])]
    elif resource in {'replicasets', 'deployments'}:
        template = spec.get('template', {})
        result['spec'] = {'replicas': spec.get('replicas'), 'selector': spec.get('selector'),
                          'template': {'metadata': {'labels': template.get('metadata', {}).get('labels', {})},
                                       'spec': {'containers': selected_containers(template.get('spec', {}).get('containers'))}}}
        result['status'] = {key: status[key] for key in ('observedGeneration', 'replicas',
                            'updatedReplicas', 'readyReplicas', 'availableReplicas', 'unavailableReplicas') if key in status}
    return result


def parse_snapshot(payload, resource, namespace):
    if not isinstance(payload, dict) or payload.get('kind') not in {'List', KINDS[resource] + 'List'}:
        raise ValueError('Expected a Kubernetes resource list')
    metadata = payload.get('metadata', {})
    if metadata.get('continue'):
        raise ValueError('Incomplete paginated list; no complete snapshot accepted')
    # kubectl's generic List printer may discard the source list version.
    # Preserve an exposed version, otherwise keep the absence explicit.
    version = metadata.get('resourceVersion') or None
    if version is not None:
        nonempty(version, 'list resourceVersion')
    items = payload.get('items')
    if not isinstance(items, list):
        raise ValueError('Expected list items')
    if len(items) > 10000:
        raise ValueError('Research snapshot exceeds 10000 objects')
    resources = [project_resource(item, resource, namespace) for item in items]
    uids = [item['metadata']['uid'] for item in resources]
    if len(uids) != len(set(uids)):
        raise ValueError('Duplicate UID in list')
    return version, resources


def collect(args, run=subprocess.run, clock=utc_now, monotonic=time.monotonic, sleep=time.sleep):
    """Collect through injected process/clock boundaries; tests never call kubectl."""
    validate_options(args)
    output = Path(args.output)
    if output.exists():
        raise ValueError('Output directory already exists; choose a new collection path')
    start = monotonic()
    deadline = start + args.duration_seconds
    base = [args.kubectl, '--context', args.context, '--namespace', args.namespace]
    if args.kubeconfig:
        base += ['--kubeconfig', str(Path(args.kubeconfig).resolve())]
    # This command reads local config only; no unselected config is persisted.
    timeout = min(args.request_timeout_seconds, max(0.001, deadline - monotonic()))
    configured = run(base + ['config', 'view', '--minify', '-o', 'json'],
                     capture_output=True, text=True, encoding='utf-8', timeout=timeout, check=True)
    endpoint = validated_endpoint(json.loads(configured.stdout), args.context, args.allow_server_host)
    base += ['--server', endpoint['server']]
    kinds = list(args.kinds) + (['nodes'] if args.include_nodes else [])
    output.mkdir(parents=True, exist_ok=False)
    manifest_path, records_path = output / 'manifest.json', output / 'observations.jsonl'
    collection_id = str(uuid.uuid4())
    manifest = {'schema_version': 1, 'collection_id': collection_id, 'status': 'collecting',
                'mode': 'bounded_snapshot_polling', 'context': args.context, 'namespace': args.namespace,
                'endpoint': endpoint, 'kubeconfig': str(Path(args.kubeconfig).resolve()) if args.kubeconfig else None,
                'resources': kinds, 'samples_requested': args.samples,
                'snapshots_requested': args.samples * len(kinds),
                'duration_limit_seconds': args.duration_seconds, 'interval_seconds': args.interval_seconds,
                'request_timeout_seconds': args.request_timeout_seconds, 'started_at': stamp(clock()),
                'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'temporal_semantics': 'observed_state_only; validity_bounds_unknown; no_continuous_watch',
                'cluster_identity': 'context/endpoint label only; not an immutable cluster UID',
                'cross_kind_atomicity': False, 'errors': 0, 'successful_snapshots': 0}
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    last_seen, last_uids = {}, {}
    sequence = 0
    last_available = None
    reason = 'sample_limit'
    with records_path.open('x', encoding='utf-8') as stream:
        def emit(record, observed=None):
            nonlocal sequence, last_available
            observed = observed or clock()
            accepted = clock()
            # Keep a monotone local knowledge clock; report wall-clock rollback.
            logical = max(value for value in (observed, accepted, last_available) if value is not None)
            sequence += 1
            record.update(record_id=collection_id + '/' + str(sequence), collection_id=collection_id,
                          observed_at=stamp(observed), available_at=stamp(logical),
                          clock_adjusted=logical != accepted)
            last_available = logical
            stream.write(json.dumps(record, sort_keys=True) + '\n')
            stream.flush()

        emit({'record_type': 'continuity_gap', 'reason': 'history_before_collection_unknown',
              'gap_from': None, 'gap_to': manifest['started_at'], 'resources': kinds})
        try:
            for sample in range(1, args.samples + 1):
                for resource in kinds:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        reason = 'duration_limit'
                        break
                    snapshot_id = '{:03d}-{}'.format(sample, resource)
                    requested_at = clock()
                    timeout = min(args.request_timeout_seconds, remaining)
                    command = base + ['--request-timeout={:.3f}s'.format(timeout),
                                      'get', resource, '-o', 'json', '--chunk-size=0']
                    try:
                        response = run(command, capture_output=True, text=True, encoding='utf-8',
                                       timeout=timeout, check=True)
                        observed = clock()
                        version, objects = parse_snapshot(json.loads(response.stdout), resource, args.namespace)
                    except (subprocess.SubprocessError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
                        manifest['errors'] += 1
                        emit({'record_type': 'continuity_gap', 'reason': 'snapshot_failed',
                              'resource': resource, 'snapshot_id': snapshot_id,
                              'gap_from': last_seen.get(resource), 'gap_to': stamp(clock()),
                              'error_type': type(error).__name__,
                              'return_code': getattr(error, 'returncode', None), 'command': command})
                        continue
                    if resource in last_seen:
                        emit({'record_type': 'continuity_gap', 'reason': 'unobserved_between_snapshots',
                              'resource': resource, 'gap_from': last_seen[resource], 'gap_to': stamp(observed)}, observed)
                    uids = {item['metadata']['uid'] for item in objects}
                    emit({'record_type': 'snapshot', 'snapshot_id': snapshot_id, 'resource': resource,
                          'request_started_at': stamp(requested_at), 'response_received_at': stamp(observed),
                          'list_resource_version': version,
                          'list_resource_version_status': 'provided' if version is not None else 'not_exposed_by_kubectl',
                          'object_count': len(objects),
                          'uids': sorted(uids), 'absent_uids_since_previous_success': sorted(last_uids.get(resource, set()) - uids),
                          'absence_semantics': 'not observed in this complete list; deletion time unknown',
                          'response_sha256': hashlib.sha256(response.stdout.encode('utf-8')).hexdigest(),
                          'command': command, 'continuous_history': False}, observed)
                    for item in objects:
                        emit({'record_type': 'resource_observation', 'snapshot_id': snapshot_id,
                              'resource': resource, 'observation_basis': 'snapshot_receipt',
                              'resource_data': item, 'valid_from': None, 'valid_to': None,
                              'known_open': False, 'confirmed_at': None,
                              'validity_status': 'unknown; source timestamps are not relationship validity'}, observed)
                    manifest['successful_snapshots'] += 1
                    last_seen[resource], last_uids[resource] = stamp(observed), uids
                if reason == 'duration_limit':
                    break
                if sample < args.samples:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        reason = 'duration_limit'
                        break
                    sleep(min(args.interval_seconds, remaining))
        except KeyboardInterrupt:
            reason = 'interrupted'
        finally:
            emit({'record_type': 'continuity_gap', 'reason': 'history_after_last_snapshot_unknown',
                  'last_successful_observation_by_resource': last_seen, 'gap_to': None})
            emit({'record_type': 'collection_end', 'reason': reason,
                  'successful_snapshots': manifest['successful_snapshots'], 'errors': manifest['errors']})
    complete = manifest['successful_snapshots'] == manifest['snapshots_requested']
    manifest.update(status='interrupted' if reason == 'interrupted' else ('finished' if complete else 'partial'),
                    stop_reason=reason, finished_at=stamp(clock()), elapsed_seconds=monotonic() - start,
                    record_count=sequence, last_successful_observation_by_resource=last_seen,
                    observations_sha256=hashlib.sha256(records_path.read_bytes()).hexdigest())
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--context', required=True)
    result.add_argument('--namespace', required=True)
    result.add_argument('--kubeconfig')
    result.add_argument('--output', required=True, help='New collection directory; never overwritten')
    result.add_argument('--kubectl', default='kubectl')
    result.add_argument('--kinds', nargs='+', choices=DEFAULT_KINDS, default=list(DEFAULT_KINDS))
    result.add_argument('--include-nodes', action='store_true', help='Explicitly include cluster-scoped Node identity snapshots')
    result.add_argument('--allow-server-host', help='Exact non-loopback hostname of a separately verified local testbed')
    result.add_argument('--samples', type=int, default=3)
    result.add_argument('--interval-seconds', type=float, default=5)
    result.add_argument('--duration-seconds', type=float, default=60)
    result.add_argument('--request-timeout-seconds', type=float, default=10)
    return result


if __name__ == '__main__':
    try:
        summary = collect(parser().parse_args())
        print(json.dumps(summary, indent=2))
        raise SystemExit(0 if summary['status'] == 'finished' else 2)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('Collection failed: ' + type(error).__name__ + ': ' + str(error))
