"""Pure engineering checks for one bounded CPU-contender feasibility run.

Controller evidence is evaluator-only. These checks do not diagnose causes,
estimate statistical significance, or select a diagnostic training baseline.
"""
from collections import Counter
from fractions import Fraction
import statistics

TARGET = 'recommendationservice'
COMPARISON = 'productcatalogservice'
PHASES = ('nominal', 'active', 'recovery')
MIN_SUCCESS = {'nominal': 20, 'active': 10, 'recovery': 20}
MIN_WORKER_CPU_NS = 1_000_000_000
MIN_SHIFT_NS = 20_000_000
MIN_DRAIN_NS = 5_000_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def is_int(value, minimum=0):
    return type(value) is int and value >= minimum


def pack(value):
    if value is None:
        return None
    value = Fraction(value)
    return {'numerator': value.numerator, 'denominator': value.denominator}


def worker_identity_valid(value):
    return (isinstance(value, dict)
            and isinstance(value.get('run_token'), str) and bool(value['run_token'])
            and is_int(value.get('pid'), 1) and is_int(value.get('start_ticks'), 1)
            and isinstance(value.get('cgroup'), str) and bool(value['cgroup']))


def active_membership(probe, expected_worker):
    """Require a matching live worker independently observed around the RPC.

    Sequence values belong to the one host controller, not source wall clocks.
    The observations may bracket a complete two-service probe batch; this is
    conservative because an uncertain batch excludes both component RPCs.
    """
    reasons = []
    if probe.get('phase_boundary_verified') is False:
        reasons.append('phase_boundary_unproven')
    if not worker_identity_valid(expected_worker):
        reasons.append('expected_worker_identity_invalid')
    before, after = probe.get('before'), probe.get('after')
    if not isinstance(before, dict) or not isinstance(after, dict):
        return {'state': 'boundary_ambiguous', 'reasons': sorted(reasons + ['missing_control_observation'])}
    sequence = [before.get('controller_sequence'), probe.get('start_sequence'),
                probe.get('end_sequence'), after.get('controller_sequence')]
    if not all(is_int(v, 1) for v in sequence) or not all(a < b for a, b in zip(sequence, sequence[1:])):
        reasons.append('control_order_unproven')
    for label, observation in [('before', before), ('after', after)]:
        identity = observation.get('worker_identity')
        if not worker_identity_valid(identity) or not worker_identity_valid(expected_worker) or any(
                identity.get(k) != expected_worker.get(k) for k in ('run_token', 'pid', 'start_ticks', 'cgroup')):
            reasons.append(label + '_worker_identity_mismatch')
        for key in ('alive', 'within_deadline', 'app_identity_verified', 'quota_verified'):
            if observation.get(key) is not True:
                reasons.append(label + '_' + key + '_unproven')
    return {'state': 'boundary_ambiguous' if reasons else 'verified_active', 'reasons': sorted(set(reasons))}


def validate_probe(probe):
    require(isinstance(probe, dict), 'Probe must be an object')
    require(isinstance(probe.get('probe_id'), str) and bool(probe['probe_id']), 'Missing probe ID')
    require(probe.get('phase') in PHASES, 'Unknown probe phase')
    require(probe.get('service') in (TARGET, COMPARISON), 'Unknown probe service')
    require(probe.get('outcome') in ('ok', 'rpc_error', 'timeout', 'invalid_response'), 'Unknown probe outcome')
    require(type(probe.get('functional_ok')) is bool, 'Functional result must be explicit boolean')
    require(is_int(probe.get('client_start_monotonic_ns')) and is_int(probe.get('client_end_monotonic_ns')),
            'Invalid client monotonic timestamps')
    require(is_int(probe.get('elapsed_ns')) and probe['elapsed_ns'] ==
            probe['client_end_monotonic_ns'] - probe['client_start_monotonic_ns'], 'Inconsistent attempt elapsed duration')
    require(is_int(probe.get('start_sequence'), 1) and is_int(probe.get('end_sequence'), 1)
            and probe['start_sequence'] < probe['end_sequence'], 'Invalid controller request sequence')
    successful = probe['outcome'] == 'ok' and probe['functional_ok'] is True
    require((probe['outcome'] == 'ok') == probe['functional_ok'], 'Contradictory functional outcome')
    require((successful and is_int(probe.get('latency_ns')) and probe['latency_ns'] == probe['elapsed_ns'])
            or (not successful and probe.get('latency_ns') is None), 'Failure latency must remain absent')


def summarize_phase(records):
    eligible = [r for r in records if r['control_classification'] != 'boundary_ambiguous']
    successes = [r for r in eligible if r['outcome'] == 'ok' and r['functional_ok']]
    values = [Fraction(r['latency_ns']) for r in successes]
    median = statistics.median(values) if values else None
    mad = statistics.median([abs(v - median) for v in values]) if values else None
    return {
        'attempted': len(records), 'eligible_attempts': len(eligible), 'successful': len(successes),
        'boundary_ambiguous': len(records) - len(eligible),
        'all_attempted_functional': bool(records) and all(r['functional_ok'] for r in records),
        'outcomes_all_attempts': dict(Counter(r['outcome'] for r in records)),
        'attempt_ids': [r['probe_id'] for r in records],
        'successful_probe_ids': [r['probe_id'] for r in successes],
        'boundary_ambiguous_ids': [r['probe_id'] for r in records if r['control_classification'] == 'boundary_ambiguous'],
        'median_ns': pack(median), 'mad_ns': pack(mad),
    }, median, mad


def evaluate_fault_control(probes, control):
    """Evaluate supplied immutable records; performs no process or network action.

    Required control fields: expected_worker; identity_verified; worker_cpu_delta_ns;
    pressure_counters_retained; quota_unchanged; app_identity_unchanged;
    lifetime_bound_verified; worker_exit_confirmed; drain_elapsed_ns; cleanup_errors
    (list); emergency_cleanup (bool).
    """
    require(isinstance(probes, list) and isinstance(control, dict), 'Expected probe list and control object')
    seen = set()
    records = []
    for probe in probes:
        validate_probe(probe)
        require(probe['probe_id'] not in seen, 'Repeated probe ID')
        seen.add(probe['probe_id'])
        membership = (active_membership(probe, control.get('expected_worker')) if probe['phase'] == 'active'
                      else ({'state': probe['phase'], 'reasons': []} if probe.get('phase_boundary_verified') is True
                            else {'state': 'boundary_ambiguous', 'reasons': ['phase_boundary_unproven']}))
        records.append(dict(probe, control_classification=membership['state'],
                            control_exclusion_reasons=membership['reasons']))

    ordered = True
    for earlier, later in [('nominal', 'active'), ('active', 'recovery')]:
        first = [r['end_sequence'] for r in records if r['phase'] == earlier]
        second = [r['start_sequence'] for r in records if r['phase'] == later]
        ordered = ordered and bool(first) and bool(second) and max(first) < min(second)
    controls = {
        'worker_identity_declared': worker_identity_valid(control.get('expected_worker')),
        'identity_verified': control.get('identity_verified') is True,
        'quota_unchanged': control.get('quota_unchanged') is True,
        'app_identity_unchanged': control.get('app_identity_unchanged') is True,
        'lifetime_bound_verified': control.get('lifetime_bound_verified') is True,
        'no_cleanup_error': isinstance(control.get('cleanup_errors'), list) and not control['cleanup_errors'],
        'no_emergency_cleanup': control.get('emergency_cleanup') is False,
        'phase_order_verified': ordered,
    }
    control_passed = all(controls.values())
    activation = {
        'matching_control_passed': control_passed,
        'worker_cpu_at_least_one_second': is_int(control.get('worker_cpu_delta_ns'))
                                          and control['worker_cpu_delta_ns'] >= MIN_WORKER_CPU_NS,
        'pressure_counters_retained': control.get('pressure_counters_retained') is True,
        'independently_bracketed_active_probe': any(r['control_classification'] == 'verified_active' for r in records),
    }
    activation_passed = all(activation.values())
    services = {}
    medians, mads = {}, {}
    for service in (TARGET, COMPARISON):
        services[service] = {}
        for phase in PHASES:
            summary, median, mad = summarize_phase([r for r in records if r['service'] == service and r['phase'] == phase])
            services[service][phase] = summary
            medians[(service, phase)], mads[(service, phase)] = median, mad
    primary = services[TARGET]
    nominal, active, recovery = (medians[(TARGET, phase)] for phase in PHASES)
    nominal_mad = mads[(TARGET, 'nominal')]
    threshold = max(Fraction(MIN_SHIFT_NS), 3 * nominal_mad) if nominal_mad is not None else None
    shift = active - nominal if active is not None and nominal is not None else None
    recovery_difference = recovery - nominal if recovery is not None and nominal is not None else None
    support = {phase: primary[phase]['successful'] >= MIN_SUCCESS[phase] for phase in PHASES}
    functional_effect = primary['nominal']['all_attempted_functional'] and primary['active']['all_attempted_functional']
    threshold_crossed = shift is not None and threshold is not None and shift >= threshold
    effect = activation_passed and support['nominal'] and support['active'] and functional_effect and threshold_crossed
    recovery_checks = {
        'worker_exit_confirmed': control.get('worker_exit_confirmed') is True,
        'drain_at_least_five_seconds': is_int(control.get('drain_elapsed_ns')) and control['drain_elapsed_ns'] >= MIN_DRAIN_NS,
        'same_app_and_clean_control': control_passed,
        'nominal_support': support['nominal'], 'recovery_support': support['recovery'],
        'all_recovery_responses_functional': all(services[s]['recovery']['all_attempted_functional'] for s in (TARGET, COMPARISON)),
        'median_within_threshold': recovery_difference is not None and threshold is not None
                                   and abs(recovery_difference) <= threshold,
    }
    recovered = all(recovery_checks.values())
    reasons = []
    if not control_passed:
        reasons.append('control_or_identity_not_established')
    if not activation_passed:
        reasons.append('activation_not_established')
    if not support['nominal'] or not support['active']:
        reasons.append('insufficient_nominal_or_unambiguous_active_support')
    if not functional_effect:
        reasons.append('nonfunctional_nominal_or_active_target_responses')
    if not threshold_crossed:
        reasons.append('latency_effect_threshold_not_met_or_unavailable')
    if not recovered:
        reasons.append('service_recovery_not_established')
    return {
        'schema': 'bounded_cpu_fault_control_v1', 'scope': 'Engineering feasibility only; no causal diagnosis or statistical inference',
        'target_service': TARGET, 'comparison_service': COMPARISON,
        'constants': {'minimum_successes': MIN_SUCCESS, 'minimum_worker_cpu_ns': MIN_WORKER_CPU_NS,
                      'minimum_shift_ns': MIN_SHIFT_NS, 'nominal_mad_multiplier': 3, 'minimum_drain_ns': MIN_DRAIN_NS},
        'control_checks': controls, 'control_passed': control_passed,
        'activation_checks': activation, 'activation_verified': activation_passed,
        'support_checks': support, 'services': services,
        'effect_threshold_ns': pack(threshold), 'active_minus_nominal_median_ns': pack(shift),
        'latency_threshold_crossed_descriptively': bool(threshold_crossed),
        'all_nominal_and_active_target_responses_functional': functional_effect,
        'latency_effect_established': bool(effect),
        'recovery_minus_nominal_median_ns': pack(recovery_difference),
        'recovery_checks': recovery_checks, 'recovery_established': recovered,
        'fault_control_passed': bool(effect and recovered), 'reasons': reasons,
        'probe_records': records, 'diagnostic_rankings': None, 'diagnosis_accuracy': None,
        'new_research_novelty_claim': False,
        'limitations': ['A one-run engineering gate is not a calibrated anomaly threshold or confidence statement.',
                       'Controller proofs are evaluator-only and must not become diagnostic features or baseline selectors.',
                       'Successful-subset medians do not turn timeouts into completed latency observations.',
                       'The catalog comparison is descriptive; unchanged behavior or isolation is not assumed.'],
    }
