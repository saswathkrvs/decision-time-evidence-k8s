"""Shared helpers: repository paths, integer-microsecond time, canonical JSON and hashing.

Every time in the adapter is an integer number of microseconds since the Unix epoch (UTC), as in
``aiops_kg.replay``; ``policy_gate`` needs timezone-aware datetimes, converted exactly with ``replay.from_us`` /
``replay.to_us``. Nothing here reads the wall clock or uses randomness.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent         # experiments/governance-pilot-v0/govpilot
PILOT_DIR = PACKAGE_DIR.parent                         # experiments/governance-pilot-v0
ROOT = PILOT_DIR.parents[1]                            # repository root
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aiops_kg import replay as R  # noqa: E402  (read-only import)

US = 1_000_000
UTC = timezone.utc
LIVE_AUDIT_SCRIPT = ROOT / "experiments/policy-gate-live-v1/run_policy_gate_live.py"


class InputError(ValueError):
    """An input violates the input contract (binding, mapping or side-channel); the run must stop."""


def ts_us(text: str) -> int:
    """ISO-8601 text (with Z or an offset) -> integer microseconds since the epoch (exact)."""
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise InputError(f"timestamp without a timezone: {text!r}")
    return R.to_us(value.astimezone(UTC))


def dt(us: int) -> datetime:
    return R.from_us(us)


def iso(us: int | None) -> str | None:
    return R.iso(us)


def seconds(us: int) -> float:
    """Microseconds -> seconds, rounded to the microsecond for stable printing."""
    return round(us / US, 6)


def s_to_us(value: float) -> int:
    return R.seconds_to_us(value)


def canonical(obj) -> str:
    """Canonical JSON text: sorted keys, no insignificant whitespace, UTF-8 characters kept."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).as_posix()


