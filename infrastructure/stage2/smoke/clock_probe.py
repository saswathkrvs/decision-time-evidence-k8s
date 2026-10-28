#!/usr/bin/env python3
"""Clock probe: paired readings of the kind node's clock bracketed by the host clock.

Per pair: host wall clock before (send), ``docker exec <node> date +%s.%N`` (node clock, ns), host wall clock after
(receive). With theta = host clock - node clock, the node read its clock at some instant between send and receive,
so  send - node <= theta <= receive - node.  The summary gives the intersection of the ten intervals (the tightest
bound if the clocks did not step), their union, the widest absolute bound, and the capture's clock band
b_c = 1 s (stamp resolution) + the widest absolute bound. No timestamp is corrected. Python 3.10+ standard library.

    python infrastructure/stage2/smoke/clock_probe.py --docker "docker --context desktop-linux" --label start \
        --versions --out <file>.json
    python infrastructure/stage2/smoke/clock_probe.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import smoke_common as common  # noqa: E402

DATE_ARGS = ['date', '+%s.%N']
NODE_OUTPUT = re.compile(r'^(\d+)\.(\d{9})$')
EXPECTED_CLIENT = 'v1.34.1'
EXPECTED_SERVER = 'v1.34.11'
PINS = common.ROOT / 'infrastructure' / 'context-pilot' / 'pins.json'
STAMP_RESOLUTION_SECONDS = 1.0       # kubelet stamps are RFC 3339 seconds


def parse_node_ns(text: str) -> int:
    """'1760870400.123456789' -> ns. Anything else (e.g. a date without %N support) is a ValueError."""
    match = NODE_OUTPUT.match(text.strip())
    if not match:
        raise ValueError('unexpected node date output {!r} (expected <seconds>.<9 digits>)'.format(text.strip()[:80]))
    return int(match.group(1)) * 1_000_000_000 + int(match.group(2))


def probe(docker_argv, node, pairs=10, runner=subprocess.run, wall_ns=time.time_ns, mono_ns=time.monotonic_ns,
          pause=time.sleep, pause_seconds=0.2):
    """The paired readings; never raises for a failed reading (it is recorded with its error)."""
    argv = list(docker_argv) + ['exec', node] + DATE_ARGS
    rows = []
    for index in range(1, pairs + 1):
        send, send_mono = wall_ns(), mono_ns()
        try:
            done = runner(argv, capture_output=True, timeout=15)
            out, err, code = done.stdout or b'', done.stderr or b'', done.returncode
        except subprocess.TimeoutExpired as error:
            out, err, code = error.stdout or b'', error.stderr or b'', 124
        except OSError as error:
            out, err, code = b'', repr(error).encode('utf-8'), 127
        receive, receive_mono = wall_ns(), mono_ns()
        row = {'index': index, 'send_ns': send, 'send_at': common.iso_from_ns(send), 'receive_ns': receive,
               'receive_at': common.iso_from_ns(receive), 'round_trip_seconds': (receive_mono - send_mono) / 1e9,
               'exit_code': code, 'node_output': out.decode('utf-8', 'replace').strip(),
               'stderr': err.decode('utf-8', 'replace').strip()[-500:], 'error': None}
        try:
            if code != 0:
                raise ValueError('docker exec exit code {}'.format(code))
            node_ns = parse_node_ns(row['node_output'])
            row.update(node_ns=node_ns, node_at=common.iso_from_ns(node_ns),
                       offset_low_ns=send - node_ns, offset_high_ns=receive - node_ns,
                       offset_low_seconds=(send - node_ns) / 1e9, offset_high_seconds=(receive - node_ns) / 1e9)
        except ValueError as error:
            row['error'] = str(error)
        rows.append(row)
        if index < pairs:
            pause(pause_seconds)
    return argv, rows


def summarise(rows):
    good = [row for row in rows if row['error'] is None]
    summary = {'pairs': len(rows), 'pairs_ok': len(good), 'offset_definition':
               'theta = host wall clock - node clock; each pair bounds theta to [send - node, receive - node]'}
    if not good:
        return dict(summary, verdict='no usable pair; see the errors')
    lows = [row['offset_low_ns'] for row in good]
    highs = [row['offset_high_ns'] for row in good]
    low, high = max(lows), min(highs)
    widest = max(max(abs(a), abs(b)) for a, b in zip(lows, highs)) / 1e9
    trips = [row['round_trip_seconds'] for row in good]
    summary.update(
        intersection_seconds=[low / 1e9, high / 1e9] if low <= high else None,
        intersection_note=None if low <= high else 'empty: the intervals do not overlap (a clock stepped, or the '
                                                   'node read its clock outside the bracket); report it',
        union_seconds=[min(lows) / 1e9, max(highs) / 1e9],
        midpoint_median_seconds=common.median([(a + b) / 2e9 for a, b in zip(lows, highs)]),
        widest_abs_bound_seconds=widest,
        clock_band_candidate_seconds=STAMP_RESOLUTION_SECONDS + widest,
        clock_band_rule='b_c = 1 s (stamp resolution) + widest |bound|',
        round_trip_seconds={'min': min(trips), 'median': common.median(trips), 'max': max(trips)})
    return summary


def versions(kubectl_argv, docker_argv, node, runner=subprocess.run):
    """kubectl client/server versions and the node image, against the recorded pins."""
    result = {}
    done = common.run_timed(kubectl_argv + ['--request-timeout=15s', 'version', '-o', 'json'], 30, runner)
    try:
        parsed = json.loads(done['stdout'].decode('utf-8', 'replace'))
        client = parsed.get('clientVersion', {}).get('gitVersion')
        server = parsed.get('serverVersion', {}).get('gitVersion')
    except ValueError:
        client = server = None
    result['kubectl'] = {'client': client, 'server': server, 'exit_code': done['exit_code'],
                         'client_matches_pin': client == EXPECTED_CLIENT, 'server_matches_pin': server == EXPECTED_SERVER,
                         'expected': {'client': EXPECTED_CLIENT, 'server': EXPECTED_SERVER},
                         'stderr': done['stderr'].decode('utf-8', 'replace').strip()[-300:]}
    done = common.run_timed(list(docker_argv) + ['inspect', node, '--format', '{{.Config.Image}}'], 30, runner)
    image = done['stdout'].decode('utf-8', 'replace').strip()
    try:
        pinned = json.loads(PINS.read_text(encoding='utf-8-sig')).get('node_image')
    except (OSError, ValueError):
        pinned = None
    result['node_image'] = {'image': image, 'pinned': pinned, 'matches_pin': bool(image) and image == pinned,
                            'exit_code': done['exit_code']}
    return result


def print_rows(rows):
    for row in rows:
        if row['error']:
            print('pair {:2d}: ERROR {} (exit {}; output {!r}; stderr {!r})'.format(
                row['index'], row['error'], row['exit_code'], row['node_output'][:60], row['stderr'][:120]))
        else:
            print('pair {:2d}: send {}  node {}  receive {}  ->  host-node in [{:+.6f}, {:+.6f}] s  (round trip {:.3f} s)'
                  .format(row['index'], row['send_at'][11:], row['node_at'][11:], row['receive_at'][11:],
                          row['offset_low_seconds'], row['offset_high_seconds'], row['round_trip_seconds']))


def self_test():
    assert parse_node_ns('1760870400.123456789\n') == 1760870400123456789
    for bad in ('1760870400.N', '1760870400', 'Mon Oct 19', '1760870400.12345'):
        try:
            parse_node_ns(bad)
            raise AssertionError('accepted ' + bad)
        except ValueError:
            pass
    # node clock 0.25 s behind the host; each docker exec takes 0.1 s on the host's clocks
    state = {'wall': 1_760_870_400_000_000_000, 'mono': 0}

    def wall():
        return state['wall']

    def mono():
        return state['mono']

    class Done:
        def __init__(self, out):
            self.stdout, self.stderr, self.returncode = out, b'', 0

    def runner(argv, **kwargs):
        assert argv[1:3] == ['exec', 'node'] and argv[3:] == DATE_ARGS, argv
        state['wall'] += 40_000_000
        state['mono'] += 40_000_000
        node = state['wall'] - 250_000_000
        state['wall'] += 60_000_000
        state['mono'] += 60_000_000
        return Done('{}.{:09d}\n'.format(node // 1_000_000_000, node % 1_000_000_000).encode())

    argv, rows = probe(['docker'], 'node', pairs=3, runner=runner, wall_ns=wall, mono_ns=mono, pause=lambda s: None)
    assert argv == ['docker', 'exec', 'node', 'date', '+%s.%N'], argv
    summary = summarise(rows)
    assert summary['pairs_ok'] == 3
    low, high = summary['intersection_seconds']
    assert abs(low - 0.21) < 1e-9 and abs(high - 0.31) < 1e-9, (low, high)
    assert abs(summary['widest_abs_bound_seconds'] - 0.31) < 1e-9
    assert abs(summary['clock_band_candidate_seconds'] - 1.31) < 1e-9
    assert abs(summary['round_trip_seconds']['median'] - 0.1) < 1e-9
    bad_rows = [dict(rows[0], error='x')]
    assert summarise(bad_rows)['pairs_ok'] == 0
    print('clock_probe self-test: OK')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path, help='new JSON file for the readings (never overwritten)')
    parser.add_argument('--label', default='probe', help='free label, e.g. start or end')
    parser.add_argument('--pairs', type=int, default=10)
    parser.add_argument('--docker', default=common.DEFAULT_DOCKER,
                        help='docker command prefix, e.g. "docker --context desktop-linux" (default: docker)')
    parser.add_argument('--node', default=common.NODE)
    parser.add_argument('--versions', action='store_true',
                        help='also record kubectl client/server versions and the node image against the pins')
    parser.add_argument('--kubectl', default='kubectl')
    parser.add_argument('--kubeconfig', default=str(common.KUBECONFIG))
    parser.add_argument('--context', default=common.CONTEXT)
    parser.add_argument('--self-test', action='store_true', help='check the arithmetic with a fake node; no docker')
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.out:
        parser.error('--out is required (or --self-test)')
    if not 1 <= args.pairs <= 100:
        parser.error('--pairs must be in [1, 100]')
    if args.out.exists():
        parser.error('{} exists; choose a new file'.format(args.out))
    docker_argv = common.docker_base(args.docker)
    started = common.host_now()
    command, rows = probe(docker_argv, args.node, args.pairs)
    print_rows(rows)
    summary = summarise(rows)
    document = {'test': 'S-4 clock probe',
                'script': 'infrastructure/stage2/smoke/clock_probe.py',
                'script_sha256': common.file_sha256(Path(__file__)), 'written_by': common.WRITTEN_BY,
                'label': args.label, 'started_at': started['at'], 'host_clock': common.clock_info(),
                'node': args.node, 'command': command, 'pairs': rows, 'summary': summary}
    if args.versions:
        kubectl_argv = common.kubectl_base(args.kubectl, args.kubeconfig, args.context)
        document['versions'] = versions(kubectl_argv, docker_argv, args.node)
    digest = common.write_json_exclusive(args.out, document)
    short = {key: summary.get(key) for key in ('pairs', 'pairs_ok', 'intersection_seconds', 'union_seconds',
                                               'widest_abs_bound_seconds', 'clock_band_candidate_seconds',
                                               'round_trip_seconds', 'intersection_note', 'verdict')}
    short.update(label=args.label, output=str(args.out), output_sha256=digest)
    if args.versions:
        short['versions'] = document['versions']
    common.print_summary('S-4 clock probe ({})'.format(args.label), short)
    return 0 if summary.get('pairs_ok') == args.pairs else 2


if __name__ == '__main__':
    sys.exit(main())
