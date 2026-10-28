"""Statistics of the follow-up study: the design check, paired capture counts and the stratified capture bootstrap.

The bootstrap resamples captures within scenario strata:

    rng = random.Random(0)                     # one generator per population (arm G; arm D)
    for each of the 10,000 resamples:
        for each scenario, in plan order, with its captures in plan order (n_s >= 1):
            draw n_s captures with replacement: n_s calls of rng.randrange(n_s)

All comparisons of a population, and both differences of a comparison (unsafe executions and missed
opportunities), use the same resamples. The statistic of a resample is the sum of the drawn captures'
differences. Percentiles use linear interpolation between order statistics (R type 7, NumPy's default), computed
with exact fractions: 95 % interval q = 1/40, 39/40; 98.33 % interval (0.05 / 3) q = 1/120, 119/120.
Standard library only.
"""
from __future__ import annotations

import random
from fractions import Fraction

RESAMPLES = 10_000
SEED = 0
Q95 = (Fraction(1, 40), Fraction(39, 40))
Q9833 = (Fraction(1, 120), Fraction(119, 120))
THRESHOLD_TOTAL = 30          # at least 30 contested decisions over the included captures of the arm
THRESHOLD_SHARE = (1, 2)      # ... and at least one in at least half of them (2 m >= k)


def percentile(sorted_values, q: Fraction) -> Fraction:
    """R type 7 / numpy 'linear' percentile of an ascending sequence, as an exact fraction."""
    n = len(sorted_values)
    if n == 0:
        raise ValueError("no values")
    h = (n - 1) * Fraction(q)
    low = h.numerator // h.denominator
    if low >= n - 1:
        return Fraction(sorted_values[-1])
    weight = h - low
    a, b = Fraction(sorted_values[low]), Fraction(sorted_values[low + 1])
    return a + weight * (b - a)


def interval(sorted_values, quantiles) -> tuple:
    return percentile(sorted_values, quantiles[0]), percentile(sorted_values, quantiles[1])


def number(value):
    """A Fraction as a JSON number (int when whole)."""
    value = Fraction(value)
    return int(value) if value.denominator == 1 else float(value)


def draw_resamples(strata, *, resamples: int = RESAMPLES, seed: int = SEED) -> list:
    """strata: lists of capture positions (0-based, into the population's captures), in plan order; empty strata draw
    nothing. Returns one tuple of drawn positions per resample."""
    rng = random.Random(seed)
    groups = [list(s) for s in strata if s]
    out = []
    for _ in range(resamples):
        picks = []
        for members in groups:
            size = len(members)
            for _ in range(size):
                picks.append(members[rng.randrange(size)])
        out.append(tuple(picks))
    return out


def bootstrap(resamples, values) -> dict:
    """Point value (the sum over the population) and the 95 % and 98.33 % percentile intervals of one per-capture
    difference."""
    sums = sorted(sum(values[i] for i in draw) for draw in resamples)
    ci95, ci9833 = interval(sums, Q95), interval(sums, Q9833)
    return {"point": sum(values), "interval_95": [number(ci95[0]), number(ci95[1])],
            "interval_98_33": [number(ci9833[0]), number(ci9833[1])],
            "excludes_0_95": ci95[0] > 0 or ci95[1] < 0, "includes_0_95": ci95[0] <= 0 <= ci95[1],
            "excludes_0_98_33": ci9833[0] > 0 or ci9833[1] < 0}


def design_check(per_capture_counts) -> dict:
    """Passes if the included captures hold at least 30 contested decisions in all and at least one in at least half
    of them. A contested decision is one at which the compared views could have differed in knowledge (from record
    timing alone)."""
    counts = [int(c) for c in per_capture_counts]
    n = sum(counts)
    m = sum(1 for c in counts if c >= 1)
    k = len(counts)
    share_num, share_den = THRESHOLD_SHARE
    passes = n >= THRESHOLD_TOTAL and k > 0 and share_den * m >= share_num * k
    return {"contested": n, "captures_with_one": m, "captures": k, "passes": passes}


def paired_table(rows) -> dict:
    """rows: per capture (U_X, U_Y). Captures in which X has fewer / equal / more unsafe executions than Y."""
    return {"fewer": sum(1 for ux, uy in rows if ux < uy), "equal": sum(1 for ux, uy in rows if ux == uy),
            "more": sum(1 for ux, uy in rows if ux > uy), "captures": len(rows)}


def b_m(gt2_requests: int) -> int:
    """Tolerance for missed opportunities: floor(0.05 x the eligible (GT-2) requests in the primary cells)."""
    return int(gt2_requests) // 20


def label(design: dict, du: dict, dm: dict, bm: int, identical: bool) -> str:
    """The comparison rule. "fewer unsafe executions" only if the difference in unsafe executions is positive with a
    95 % interval excluding zero, at no more missed opportunities (the missed-opportunity difference is at most 0, or
    its interval includes 0 and it is at most b_M); "more unsafe executions" if the difference is negative with an
    interval excluding zero; "identical" if every capture's counts and every first verdict and disposition coincide;
    otherwise "no difference shown". A comparison whose design check failed is "uninformative"."""
    if not design["passes"]:
        return "uninformative"
    if du["point"] > 0 and du["excludes_0_95"] and (dm["point"] <= 0 or (dm["includes_0_95"] and dm["point"] <= bm)):
        return "fewer unsafe executions"
    if du["point"] < 0 and du["excludes_0_95"]:
        return "more unsafe executions"
    if identical:
        return "identical"
    return "no difference shown"
