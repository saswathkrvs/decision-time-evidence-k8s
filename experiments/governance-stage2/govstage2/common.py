"""Shared helpers of the governance adapter: paths, read-only imports, time, canonical JSON, hashing and streaming gzip
logs.

Time. Every instant is an integer number of microseconds since the Unix epoch (UTC), as in the development adapter
(experiments/governance-pilot-v0/govpilot/common.py) and src/aiops_kg/fault_control_kill.py. The collectors write
nine-digit fractions; ``ts_us`` (govpilot's) parses them only on Python >= 3.11 and truncates to the microsecond,
which equals ``available_ns // 1000`` of the same row.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent          # experiments/governance-stage2/govstage2
ADAPTER_DIR = PACKAGE_DIR.parent                       # experiments/governance-stage2
ROOT = ADAPTER_DIR.parents[1]                          # repository root
SRC = ROOT / "src"
PILOT_DIR = ROOT / "experiments/governance-pilot-v0"
for _path in (SRC, PILOT_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from aiops_kg import replay as R  # noqa: E402  (read-only)
from govpilot import common as GC  # noqa: E402  (read-only: Stage 1's time and hashing helpers)

US = 1_000_000
DEFAULT_PLAN = ROOT / "phase3/stage2_plan.json"
EXPECTATION_FILE = PACKAGE_DIR / "fixture_expectation.json"

class AdapterError(ValueError):
    """An input violates the adapter's input contract; the run stops."""


class Refused(SystemExit):
    """The run refuses to start (an excluded capture, an existing output directory)."""


# ---------------------------------------------------------------------------------------------------------------
# Time and text
# ---------------------------------------------------------------------------------------------------------------
ts_us = GC.ts_us
s_to_us = GC.s_to_us
seconds = GC.seconds
canonical = GC.canonical
sha256_text = GC.sha256_text
sha256_file = GC.sha256_file


def iso(us):
    return R.iso(us)


def dt(us: int):
    return R.from_us(us)


def to_us(value) -> int:
    return R.to_us(value)


def ns_to_us(ns: int) -> int:
    """Integer ns -> integer us, floored (as datetime.fromisoformat truncates nine-digit fractions)."""
    return int(ns) // 1000


def rel(path) -> str:
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).as_posix()


def json_dump(path, doc) -> str:
    """Write a JSON document deterministically (sorted keys, indent 1, LF); returns its SHA-256."""
    text = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return sha256_text(text)


# ---------------------------------------------------------------------------------------------------------------
# Streaming gzip JSON-lines logs (one per capture and observer)
# ---------------------------------------------------------------------------------------------------------------
class GzipJsonlWriter:
    """Canonical JSON lines streamed into a deterministic gzip (mtime 0, no file name), with the SHA-256 and size of
    the uncompressed text kept as it is written. Nothing is held in memory beyond a 1 MiB buffer."""

    def __init__(self, path):
        self.path = Path(path)
        self._raw = open(self.path, "xb")
        self._gz = gzip.GzipFile(filename="", mode="wb", fileobj=self._raw, mtime=0, compresslevel=6)
        self._digest = hashlib.sha256()
        self._chunk: list[bytes] = []
        self._pending = 0
        self.lines = 0
        self.text_bytes = 0
        self.counts: dict[str, int] = {}
        self.closed = False

    def write(self, kind: str, obj) -> None:
        if self.closed:
            raise AdapterError(f"{self.path.name} is closed; a written decision log takes no more lines")
        data = (canonical({kind: obj}) + "\n").encode("utf-8")
        self._digest.update(data)
        self.text_bytes += len(data)
        self.lines += 1
        self.counts[kind] = self.counts.get(kind, 0) + 1
        self._chunk.append(data)
        self._pending += len(data)
        if self._pending >= 1 << 20:
            self._gz.write(b"".join(self._chunk))
            self._chunk, self._pending = [], 0

    def close(self) -> dict:
        if not self.closed:
            if self._chunk:
                self._gz.write(b"".join(self._chunk))
            self._gz.close()
            self._raw.close()
            self.closed = True
        return {"file": self.path.name, "sha256_of_uncompressed_text": self._digest.hexdigest(),
                "text_bytes": self.text_bytes, "gzip_bytes": self.path.stat().st_size, "lines": self.lines,
                "lines_by_kind": dict(sorted(self.counts.items()))}


def gzip_digest(path) -> str:
    digest = hashlib.sha256()
    with gzip.open(path, "rb") as handle:
        for line in handle:
            digest.update(line)
    return digest.hexdigest()


def iter_gzip_records(path, kinds: tuple[str, ...] | None = None):
    """(kind, object) of every line of a decision log, optionally only some kinds (a cheap prefix test first)."""
    prefixes = None if kinds is None else tuple(('{"' + k + '":').encode("utf-8") for k in kinds)
    with gzip.open(path, "rb") as handle:
        for line in handle:
            if prefixes is not None and not line.startswith(prefixes):
                continue
            doc = json.loads(line)
            (kind, obj), = doc.items()
            yield kind, obj
