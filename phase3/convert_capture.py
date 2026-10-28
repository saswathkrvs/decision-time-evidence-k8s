#!/usr/bin/env python3
r"""Convert one raw Phase 3 capture into the evidence-record format the offline replay reads.

    python phase3\convert_capture.py --capture phase3\captures\I2-001      # writes <capture>\evidence\
    python phase3\convert_capture.py --self-test                           # checks against the 22 Sep rollout

Output rows use exactly the field names of results/evidence-index-pilot-002/accepted_evidence.jsonl:
{"available_ns", "logical_confirmation_ns", "record": {evidence_id, logical_id, kind, subject,
payload, supports, supersedes, source_ref, source_sha256, acquired_at}}, validated with
src/aiops_kg/evidence.py (Evidence, Accepted). Kinds read by the existing loaders are
api_observation and span_claim; new kinds (change_receipt, api_event, metric_sample,
log_line, client_request) are ignored by them.

available_ns = the CAPTURE-ERA host pipeline acceptance time of the record (not an
offline import time as in evidence-index-pilot-002). The replay engine derives
delayed / missing / corrected views by transforming these rows, never the raw capture.
The change patch and its rollout wait are two change_receipt rows, each acquired at its
own host receipt; the rollout-wait row supports the patch row.

Evaluation-only material (ground_truth/, the probe traffic) is never converted into
evidence. Spans whose trace ID belongs to an evaluator probe are excluded by default.
The configuration row keeps only what an operator knows at deployment time: the
incident id, the planned change and runnable. The full plan entry (fault, labels,
ground truth) is copied to <output>/evaluation_only/, which is never a model input.
Nothing in the capture is modified; the output directory must not exist yet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'src'))
from aiops_kg.evidence import Accepted, Evidence, canonical, timestamp_ns   # noqa: E402

# v3: the change patch and its rollout wait are separate change_receipt rows, each available at its own host receipt
# v2: configuration keeps only id/change/runnable
CONVERTER_VERSION = 'phase3-capture-to-evidence-v3'
API_GROUPS = {'Pod': '', 'Node': '', 'ReplicaSet': 'apps', 'Deployment': 'apps', 'Event': ''}
LINE_SEMANTICS = 'Exact original JSONL line bytes, including line ending if present'
ENVELOPE_SEMANTICS = 'Exact original OTLP JSONL envelope line bytes, including line ending if present'
# The plan-entry fields an operator legitimately knows at deployment time. Everything else (fault, ground_truth,
# label, repeat_of, blocked_reason, options, ...) is evaluator-only and never enters accepted evidence.
CONFIGURATION_INCIDENT_KEYS = ('id', 'change', 'runnable')
EVALUATION_ONLY_README = (
    'EVALUATION ONLY -- NEVER A MODEL INPUT.\n'
    'Written by phase3/convert_capture.py. Nothing in this folder is accepted evidence; no replay, ranking, policy or\n'
    'other consumer may read it as input. Use it only to score results.\n'
    'incident_entry.json = the full incident plan entry (fault specification, ground_truth labels, label, repeat_of).\n'
    'The configuration evidence row keeps only the entry fields ' + ', '.join(CONFIGURATION_INCIDENT_KEYS) + '.\n')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def subject(cluster, kind, namespace, uid, group=None):
    return canonical([cluster, API_GROUPS.get(kind, '') if group is None else group, kind,
                      '' if kind == 'Node' else (namespace or ''), uid])


def flatten(attributes):
    result = {}
    for item in attributes or []:
        value = item.get('value', {})
        result[item['key']] = next(iter(value.values())) if len(value) == 1 else value
    return result


def lines_with_bytes(path: Path):
    with path.open('rb') as handle:
        for number, raw in enumerate(handle, start=1):
            if raw.strip():
                yield number, raw


def row(evidence: Evidence, available_ns: int):
    Accepted(evidence, available_ns)          # acquisition must not follow acceptance
    return {'available_ns': available_ns, 'logical_confirmation_ns': available_ns, 'record': evidence.to_dict()}


# ------------------------------------------------------------------------------------------
# Mappings used by the existing loaders (checked by --self-test against pilot-002)
# ------------------------------------------------------------------------------------------
def api_observation(raw: bytes, line_number: int, cluster: str, source_ref: str, file_sha256: str):
    record = json.loads(raw)
    if record.get('record_type') != 'resource_observation':
        return None
    meta = record['resource_data']['metadata']
    payload = dict(record, _source_record_hash_semantics=LINE_SEMANTICS, _source_record_sha256=sha(raw))
    evidence = Evidence.from_dict({
        'evidence_id': 'api:' + record['record_id'], 'logical_id': 'api:' + record['record_id'],
        'kind': 'api_observation',
        'subject': subject(cluster, record['resource_data']['kind'], meta.get('namespace'), meta['uid']),
        'payload': payload, 'supports': [], 'supersedes': [],
        'source_ref': '{}#L{}'.format(source_ref, line_number), 'source_sha256': file_sha256,
        'acquired_at': record['available_at']})
    return evidence


def span_claims(raw: bytes, line_number: int, receipt: dict, source_ref: str, file_sha256: str,
                acquired_at: str, extra=None):
    envelope = json.loads(raw)
    for r_index, resource_spans in enumerate(envelope.get('resourceSpans', [])):
        resource = resource_spans.get('resource', {})
        resource_attributes = flatten(resource.get('attributes'))
        for s_index, scope_spans in enumerate(resource_spans.get('scopeSpans', [])):
            scope = scope_spans.get('scope', {})
            for p_index, span in enumerate(scope_spans.get('spans', [])):
                attributes = flatten(span.get('attributes'))
                locator = {'line': line_number, 'resourceSpans': r_index, 'scopeSpans': s_index, 'spans': p_index}
                payload = {'_fragment_canonical_sha256': sha(canonical({'resource': resource, 'scope': scope,
                                                                         'span': span}).encode()),
                           '_source_record_hash_semantics': ENVELOPE_SEMANTICS, '_source_record_sha256': sha(raw),
                           'collector_processed_at_raw': attributes.get('aiops.collector_processed_at'),
                           'identity_status': 'raw_resource_claim; no API match or cutoff eligibility asserted',
                           'resource': resource, 'resource_attributes': resource_attributes, 'scope': scope,
                           'source_locator': locator, 'span': span, 'span_attributes': attributes,
                           'span_id': span['spanId'], 'trace_export_receipt': receipt, 'trace_id': span['traceId']}
                if extra:
                    payload.update(extra)
                identity = subject(resource_attributes.get('project.cluster_incarnation_id', 'unknown-cluster'), 'Pod',
                                   resource_attributes.get('k8s.namespace.name', ''),
                                   resource_attributes.get('k8s.pod.uid', 'unknown-pod'))
                ref = '{}#L{}/resourceSpans/{}/scopeSpans/{}/spans/{}'.format(source_ref, line_number, r_index, s_index, p_index)
                evidence_id = 'span:{}:{}'.format(span['traceId'], span['spanId'])
                yield Evidence.from_dict({'evidence_id': evidence_id, 'logical_id': evidence_id, 'kind': 'span_claim',
                                          'subject': identity, 'payload': payload, 'supports': [], 'supersedes': [],
                                          'source_ref': ref, 'source_sha256': file_sha256, 'acquired_at': acquired_at})


# ------------------------------------------------------------------------------------------
# Whole-capture conversion
# ------------------------------------------------------------------------------------------
def convert(capture: Path, output: Path, include_probe_traffic=False):
    if output.exists():
        raise SystemExit('Output exists; choose a new directory: ' + str(output))
    doc = json.loads((capture / 'capture.json').read_text(encoding='utf-8'))
    receipts = {r['id']: r for r in doc['command_receipts']}
    cluster = doc.get('cluster_incarnation_id') or 'unknown-cluster'
    namespace = doc['namespace']
    rel = capture.name
    rows, counts, notes = [], Counter(), []

    def add(evidence, acquired):
        rows.append(row(evidence, timestamp_ns(acquired)))
        counts[evidence.kind] += 1

    # configuration: rendered manifests + the operator-known part of the incident plan entry (id, change, runnable)
    entry = json.loads((capture / 'incident.json').read_text(encoding='utf-8'))['incident']
    config_payload = {'deployment_manifests': {p.name: json.loads(p.read_text(encoding='utf-8'))
                                               for p in sorted((capture / 'manifests').glob('*.json'))},
                      'incident': {k: entry[k] for k in CONFIGURATION_INCIDENT_KEYS if k in entry},
                      'rollout_patch': json.loads((capture / 'rollout-patch.json').read_text(encoding='utf-8')),
                      'source_sha256': doc.get('source_sha256'),
                      'acquisition_semantics': 'Applied by the orchestrator; acquired when the collector manifest apply returned'}
    digest = sha(canonical(config_payload).encode())
    applied = receipts['apply-collector']['collector_available_at']
    add(Evidence.from_dict({'evidence_id': 'configuration:' + digest, 'logical_id': 'configuration:' + digest,
                            'kind': 'configuration', 'subject': canonical([cluster, 'aiops.project', 'Configuration', namespace, digest]),
                            'payload': config_payload, 'supports': [], 'supersedes': [], 'source_ref': rel + '/manifests',
                            'source_sha256': digest, 'acquired_at': applied}), applied)

    # api_observation: the API poller's own records (observed_at + available_at per record)
    observations = capture / 'context' / 'observations.jsonl'
    if observations.exists():
        file_sha = sha(observations.read_bytes())
        for number, raw in lines_with_bytes(observations):
            evidence = api_observation(raw, number, cluster, rel + '/context/observations.jsonl', file_sha)
            if evidence is not None:
                add(evidence, evidence.acquired_at)
    else:
        notes.append('context/observations.jsonl missing')

    # span_claim: final export; acquisition = earliest host receipt of the identical line in the live tail
    probe_traces = set()
    probe_rows = capture / 'ground_truth' / 'probe_rows.jsonl'
    if probe_rows.exists() and not include_probe_traffic:
        for number, raw in lines_with_bytes(probe_rows):
            batch = json.loads(raw).get('batch') or {}
            probe_traces.update(call['trace_id'] for call in batch.get('calls', []))
    tail = {}
    tail_arrivals = capture / 'raw' / 'trace-tail.arrivals.jsonl'
    if tail_arrivals.exists():
        for _, raw in lines_with_bytes(tail_arrivals):
            arrival = json.loads(raw)
            tail.setdefault(arrival['line_sha256'], arrival)
    export = capture / 'raw' / 'trace-export.stdout'
    seen = set()
    if export.exists() and 'trace-export' in receipts:
        receipt = receipts['trace-export']
        file_sha = sha(export.read_bytes())
        for number, raw in lines_with_bytes(export):
            arrival = tail.get(sha(raw)) or tail.get(sha(raw.rstrip(b'\r\n') + b'\n'))
            acquired = arrival['collector_available_at'] if arrival else receipt['collector_available_at']
            extra = {'acquisition_basis': 'live_tail_line' if arrival else 'final_export_file',
                     'trace_tail_arrival': arrival}
            for evidence in span_claims(raw, number, receipt, rel + '/raw/trace-export.stdout', file_sha, acquired, extra):
                if evidence.payload['trace_id'] in probe_traces:
                    counts['excluded_probe_span'] += 1
                    continue
                if evidence.evidence_id in seen:
                    counts['duplicate_span'] += 1
                    continue
                seen.add(evidence.evidence_id)
                add(evidence, acquired)
    else:
        notes.append('trace export missing')

    # change_receipt: the patch command and its rollout wait (host clock) as TWO rows, each acquired at its own
    # receipt. One row at the patch time exposed the later rollout-wait outcome early (audit recheck 30 Sep, P2).
    change = doc.get('change')
    if change and 'change-patch' in receipts:
        patch, wait = receipts['change-patch'], receipts.get('change-wait')
        deployment_uid = 'unknown'
        before = capture / 'raw' / 'deploy-before-{}.stdout'.format(change['service'])
        if before.exists() and before.stat().st_size:
            deployment_uid = json.loads(before.read_bytes())['metadata']['uid']
        deployment = subject(cluster, 'Deployment', namespace, deployment_uid)
        patch_id = 'change:{}:{}:patch'.format(rel, change['service'])
        add(Evidence.from_dict({'evidence_id': patch_id, 'logical_id': patch_id, 'kind': 'change_receipt',
                                'subject': deployment,
                                'payload': {'service': change['service'], 'patch_receipt': patch,
                                            'deployment_uid': deployment_uid,
                                            'semantics': 'Host-observed patch command times; not the Kubernetes event '
                                                         'time of the Pod replacement. The rollout-status outcome '
                                                         '(awaited only after a successful patch) is a separate '
                                                         'rollout-wait row, available only from its own receipt'},
                                'supports': [], 'supersedes': [],
                                'source_ref': rel + '/capture.json#change-patch', 'source_sha256': patch['stdout_sha256'],
                                'acquired_at': patch['collector_available_at']}), patch['collector_available_at'])
        if wait is not None:
            wait_id = 'change:{}:{}:rollout-wait'.format(rel, change['service'])
            add(Evidence.from_dict({'evidence_id': wait_id, 'logical_id': wait_id, 'kind': 'change_receipt',
                                    'subject': deployment,
                                    'payload': {'service': change['service'], 'wait_receipt': wait,
                                                'wait_exit_code': wait['exit_code'],
                                                'semantics': 'Host-observed return of kubectl rollout status (exit 0: '
                                                             'the rollout was reported complete); not the Kubernetes '
                                                             'event time of the Pod replacement'},
                                    'supports': [patch_id], 'supersedes': [],
                                    'source_ref': rel + '/capture.json#change-wait',
                                    'source_sha256': wait['stdout_sha256'],
                                    'acquired_at': wait['collector_available_at']}), wait['collector_available_at'])

    # api_event: every distinct (uid, resourceVersion) of Event objects at its first host receipt
    event_versions = set()
    for name in sorted(r for r in receipts if r.startswith('events-')):
        receipt = receipts[name]
        path = capture / receipt['stdout_file']
        if receipt['exit_code'] or not path.exists() or not path.stat().st_size:
            continue
        for item in json.loads(path.read_bytes()).get('items', []):
            meta = item.get('metadata', {})
            key = (meta.get('uid'), meta.get('resourceVersion'))
            if key in event_versions or not meta.get('uid'):
                continue
            event_versions.add(key)
            involved = item.get('involvedObject', {})
            group = (involved.get('apiVersion') or 'v1').split('/')[0] if '/' in (involved.get('apiVersion') or '') else ''
            identifier = 'event:{}:{}'.format(meta['uid'], meta.get('resourceVersion'))
            add(Evidence.from_dict({'evidence_id': identifier, 'logical_id': 'event:' + meta['uid'], 'kind': 'api_event',
                                    'subject': subject(cluster, involved.get('kind', 'Event'), involved.get('namespace', namespace),
                                                       involved.get('uid') or meta['uid'], group),
                                    'payload': {'event': item, 'snapshot_id': name, 'observed_at': receipt['response_received_at'],
                                                'available_at': receipt['collector_available_at']},
                                    'supports': [], 'supersedes': [], 'source_ref': rel + '/' + receipt['stdout_file'],
                                    'source_sha256': receipt['stdout_sha256'], 'acquired_at': receipt['collector_available_at']}),
                receipt['collector_available_at'])

    # metric_sample: kubelet summary per Pod of this namespace (source sample time kept in payload)
    for name in sorted(r for r in receipts if r.startswith('metrics-')):
        receipt = receipts[name]
        path = capture / receipt['stdout_file']
        if receipt['exit_code'] or not path.exists() or not path.stat().st_size:
            continue
        for pod in json.loads(path.read_bytes()).get('pods', []):
            ref = pod.get('podRef', {})
            if ref.get('namespace') != namespace:
                continue
            identifier = 'metric:{}:{}'.format(name, ref.get('uid'))
            add(Evidence.from_dict({'evidence_id': identifier, 'logical_id': identifier, 'kind': 'metric_sample',
                                    'subject': subject(cluster, 'Pod', namespace, ref.get('uid', 'unknown')),
                                    'payload': {'pod': pod, 'snapshot_id': name, 'observed_at': receipt['response_received_at'],
                                                'available_at': receipt['collector_available_at']},
                                    'supports': [], 'supersedes': [], 'source_ref': rel + '/' + receipt['stdout_file'],
                                    'source_sha256': receipt['stdout_sha256'], 'acquired_at': receipt['collector_available_at']}),
                receipt['collector_available_at'])

    # log_line and client_request: streamed lines with per-line host receipt
    for receipt in doc['command_receipts']:
        if not receipt.get('streamed') or not (receipt['id'].startswith('logs-') or receipt['id'].startswith('client-')):
            continue
        out, arrivals = capture / receipt['stdout_file'], capture / receipt['arrivals_file']
        arrival_by_line = {json.loads(raw)['line_index']: json.loads(raw) for _, raw in lines_with_bytes(arrivals)}
        for number, raw in lines_with_bytes(out):
            arrival = arrival_by_line.get(number)
            if not arrival:
                continue
            if receipt['id'].startswith('logs-'):
                text = raw.decode('utf-8', 'replace').rstrip('\r\n')
                identifier = 'log:{}:{}'.format(receipt['pod_uid'], number)
                kind, sub = 'log_line', subject(cluster, 'Pod', namespace, receipt['pod_uid'])
                payload = {'line': text, 'kubelet_timestamp': text.split(' ', 1)[0], 'line_sha256': arrival['line_sha256'],
                           'service_name': receipt.get('service_name'), 'pod_name': receipt.get('pod_name'), 'arrival': arrival}
            else:
                try:
                    record = json.loads(raw)
                except ValueError:
                    continue
                if record.get('record_type') != 'client_request':
                    continue
                identifier = '{}:{}'.format(receipt['id'], record['request_index'])
                kind, sub = 'client_request', subject(cluster, 'Pod', namespace, receipt['pod_uid'])
                payload = dict(record, block=receipt['id'], arrival=arrival)
            add(Evidence.from_dict({'evidence_id': identifier, 'logical_id': identifier, 'kind': kind, 'subject': sub,
                                    'payload': payload, 'supports': [], 'supersedes': [],
                                    'source_ref': '{}/{}#L{}'.format(rel, receipt['stdout_file'], number),
                                    'source_sha256': receipt['stdout_sha256'], 'acquired_at': arrival['collector_available_at']}),
                arrival['collector_available_at'])

    ids = [r['record']['evidence_id'] for r in rows]
    duplicates = [k for k, v in Counter(ids).items() if v > 1]
    if duplicates:
        raise ValueError('Duplicate evidence IDs: {}'.format(duplicates[:5]))
    rows.sort(key=lambda r: (r['available_ns'], r['record']['evidence_id']))
    output.mkdir(parents=True)
    evaluation_only = output / 'evaluation_only'      # the full plan entry: kept for scoring, never a model input
    evaluation_only.mkdir()
    (evaluation_only / 'README.txt').write_text(EVALUATION_ONLY_README, encoding='utf-8')
    (evaluation_only / 'incident_entry.json').write_text(json.dumps(entry, indent=2) + '\n', encoding='utf-8')
    with (output / 'accepted_evidence.jsonl').open('w', encoding='utf-8', newline='\n') as handle:
        for value in rows:
            handle.write(canonical(value) + '\n')
    # Loader-compatible side files (same shape as data/raw/rollout-telemetry/pilot-001/{protocol,capture}.json)
    protocol = {'namespace': namespace, 'cluster_incarnation_id': cluster, 'capture_id': doc['capture_id'],
                'incident_id': doc['incident_id'], 'replacement_service': (change or {}).get('service'),
                'request_trigger_index': (doc.get('protocol') or {}).get('request_trigger_index'),
                'services': ['recommendationservice', 'productcatalogservice', 'pilot-client']}
    (output / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    loader_receipts = []
    if change and 'change-patch' in receipts:
        loader_receipts.append(dict(receipts['change-patch'], id='rollout-patch'))
    (output / 'capture.json').write_text(json.dumps({'run_id': doc['capture_id'], 'namespace': namespace,
                                                     'started_at': doc.get('started_at'), 'finished_at': doc.get('finished_at'),
                                                     'command_receipts': loader_receipts}, indent=2) + '\n', encoding='utf-8')
    report = {'converter': CONVERTER_VERSION, 'capture': str(capture), 'rows': len(rows), 'counts_by_kind': dict(counts),
              'excluded_probe_trace_ids': len(probe_traces), 'notes': notes,
              'configuration_incident_keys': sorted(config_payload['incident']),
              'evaluation_only': 'evaluation_only/incident_entry.json (never a model input; see README.txt there)',
              'available_ns_semantics': 'capture-era host acceptance (collector_available_at / available_at), not offline import',
              'accepted_evidence_sha256': sha((output / 'accepted_evidence.jsonl').read_bytes())}
    (output / 'conversion_report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


# ------------------------------------------------------------------------------------------
# Self-test on the real 22 Sep 2026 rollout (only its converted evidence and capture.json exist here)
# ------------------------------------------------------------------------------------------
def self_test():
    pilot = ROOT / 'data/raw/rollout-telemetry/pilot-001'
    stored = [json.loads(line) for line in (ROOT / 'results/evidence-index-pilot-002/accepted_evidence.jsonl')
              .read_text(encoding='utf-8').splitlines()]
    protocol = json.loads((pilot / 'protocol.json').read_text(encoding='utf-8'))
    capture = json.loads((pilot / 'capture.json').read_text(encoding='utf-8'))
    cluster = protocol['cluster_incarnation_id']
    checks = Counter()
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        # 1. API: rebuild each original observations.jsonl line (Windows CRLF), re-map, compare everything
        apis = [e for e in stored if e['record']['kind'] == 'api_observation']
        rebuilt = temp / 'observations.jsonl'
        with rebuilt.open('wb') as handle:
            for entry in apis:
                original = {k: v for k, v in entry['record']['payload'].items() if not k.startswith('_source')}
                raw = (json.dumps(original, sort_keys=True) + '\r\n').encode()
                assert sha(raw) == entry['record']['payload']['_source_record_sha256'], 'API line bytes not reproduced'
                handle.write(raw)
                checks['api_line_bytes_reproduced'] += 1
        for entry, (_, raw) in zip(apis, lines_with_bytes(rebuilt)):
            old = entry['record']
            line = int(old['source_ref'].rsplit('#L', 1)[1])
            new = json.loads(json.dumps(api_observation(raw, line, cluster, old['source_ref'].rsplit('#L', 1)[0],
                                                        old['source_sha256']).to_dict()))
            assert new == old, 'API mapping differs for ' + old['evidence_id']
            checks['api_records_identical'] += 1
        # 2. Spans: rebuild envelopes per source line, re-map, compare every field except the envelope byte hash
        spans = [e['record'] for e in stored if e['record']['kind'] == 'span_claim']
        by_line = defaultdict(list)
        for record in spans:
            by_line[record['payload']['source_locator']['line']].append(record)
        receipt = next(r for r in capture['command_receipts'] if r['id'] == 'trace-export')
        for line, records in sorted(by_line.items()):
            envelope = {'resourceSpans': []}
            for record in sorted(records, key=lambda r: tuple(r['payload']['source_locator'][k]
                                                              for k in ('resourceSpans', 'scopeSpans', 'spans'))):
                loc, p = record['payload']['source_locator'], record['payload']
                while len(envelope['resourceSpans']) <= loc['resourceSpans']:
                    envelope['resourceSpans'].append({'resource': None, 'scopeSpans': []})
                rs = envelope['resourceSpans'][loc['resourceSpans']]
                rs['resource'] = p['resource']
                while len(rs['scopeSpans']) <= loc['scopeSpans']:
                    rs['scopeSpans'].append({'scope': None, 'spans': []})
                rs['scopeSpans'][loc['scopeSpans']]['scope'] = p['scope']
                rs['scopeSpans'][loc['scopeSpans']]['spans'].append(p['span'])
            raw = (json.dumps(envelope) + '\n').encode()
            source_ref = records[0]['source_ref'].split('#L', 1)[0]
            for new in span_claims(raw, line, receipt, source_ref, records[0]['source_sha256'], receipt['collector_available_at']):
                old = next(r for r in records if r['evidence_id'] == new.evidence_id)
                new = json.loads(json.dumps(new.to_dict()))
                for key in ('_source_record_sha256',):   # envelope bytes are rebuilt, not original
                    new['payload'].pop(key)
                    old = dict(old, payload={k: v for k, v in old['payload'].items() if k != key})
                assert new == old, 'span mapping differs for ' + old['evidence_id']
                checks['span_records_identical_except_envelope_hash'] += 1
        assert checks['span_records_identical_except_envelope_hash'] == len(spans) == 727
        # 3. The existing loaders accept converter output (attribution-lag and policy-gate, read-only imports)
        converted = temp / 'accepted_evidence.jsonl'
        with converted.open('w', encoding='utf-8') as handle:
            for entry in stored:
                if entry['record']['kind'] in ('api_observation', 'span_claim'):
                    handle.write(canonical(entry) + '\n')
        import importlib.util
        spec = importlib.util.spec_from_file_location('attr_lag_readonly', ROOT / 'experiments/attribution-lag-v1/run_attribution_lag.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.EVIDENCE = converted
        requests = module.load_requests()
        checks['attribution_lag_loader_requests'] = len(requests)
        module.pga.INPUTS['api_sightings'] = converted
        sightings = module.pga.load_sightings(protocol)
        checks['policy_gate_loader_sightings'] = len(sightings)
        patch = module.pga.patch_receipt(capture)
        checks['policy_gate_patch_receipt_found'] = int(patch['id'] == 'rollout-patch')
    expected = {'api_line_bytes_reproduced': 396, 'api_records_identical': 396,
                'span_records_identical_except_envelope_hash': 727, 'attribution_lag_loader_requests': 120,
                'policy_gate_loader_sightings': 396, 'policy_gate_patch_receipt_found': 1}
    ok = all(checks[k] == v for k, v in expected.items())
    print(json.dumps({'self_test_passed': ok, 'checks': dict(checks), 'expected': expected,
                      'limits': ['pilot-001 raw files (context/, raw/) are not in this working copy; lines and envelopes '
                                 'were rebuilt from the stored evidence, so the whole-file source_sha256 and the original '
                                 'envelope byte hash could not be re-derived',
                                 'kinds without a stored reference (change_receipt, api_event, metric_sample, log_line, '
                                 'client_request) are exercised only on a Phase 3 capture']}, indent=2))
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--capture', type=Path, help='phase3/captures/<ID>-<NNN>')
    parser.add_argument('--output', type=Path, help='default: <capture>/evidence (must not exist)')
    parser.add_argument('--include-probe-traffic', action='store_true', help='keep spans of evaluator probes (not recommended)')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.capture:
        parser.error('--capture or --self-test is required')
    capture = args.capture.resolve()
    report = convert(capture, (args.output or capture / 'evidence').resolve(), args.include_probe_traffic)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
