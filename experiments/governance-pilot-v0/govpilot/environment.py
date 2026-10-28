"""Environment records of a capture, which are not decision inputs.

The runner saved ``kubectl version -o json`` as ``raw/kubectl-version.stdout`` in every capture. Its client and
server ``gitVersion`` strings confirm the kubectl / Kubernetes pin of R7 (``rollout.KUBECTL_REFERENCE``). This file
is read only by the input dry run (``run_dev.py --dry-run-inputs``), outside the decision reader; nothing read here
reaches a view or a rule.
"""
from __future__ import annotations

import json
from pathlib import Path

from .common import sha256_file
from .rollout import KUBECTL_CLIENT_PIN, KUBERNETES_SERVER_PIN

KUBECTL_VERSION_FILE = "raw/kubectl-version.stdout"


def recorded_kubectl_versions(capture_dir: Path) -> dict:
    """The client and server gitVersion strings in a capture's raw/kubectl-version.stdout, read-only."""
    path = Path(capture_dir) / KUBECTL_VERSION_FILE
    out = {"file": KUBECTL_VERSION_FILE, "present": path.is_file(), "sha256": None,
           "client_gitVersion": None, "server_gitVersion": None, "parsed": False}
    if not out["present"]:
        return out
    out["sha256"] = sha256_file(path)
    text = path.read_bytes().decode("utf-8", errors="replace")
    start = text.find("{")
    if start < 0:
        return out
    try:
        doc, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return out
    out["parsed"] = True
    out["client_gitVersion"] = ((doc.get("clientVersion") or {}).get("gitVersion"))
    out["server_gitVersion"] = ((doc.get("serverVersion") or {}).get("gitVersion"))
    return out


def kubectl_pin_check(capture_dir: Path) -> dict:
    """``recorded_kubectl_versions`` plus whether both strings equal the pin (client v1.34.1, server v1.34.11)."""
    found = recorded_kubectl_versions(capture_dir)
    found["matches_pin"] = (found["client_gitVersion"] == KUBECTL_CLIENT_PIN
                            and found["server_gitVersion"] == KUBERNETES_SERVER_PIN)
    return found
