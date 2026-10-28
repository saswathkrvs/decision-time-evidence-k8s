"""Anomaly-weighted personalized PageRank root-cause ranker ("graph-rank v1").

A small, fully specified ranker in the MicroRCA / MicroScope family of
graph-based root-cause analysis (RCA) methods. It is a project
re-implementation for development experiments. It is **not** a reproduction
of either paper's code or published results.

All rules below were fixed before the first evaluation, on 18 development
incidents. Changing any rule creates a new method version.

Pipeline and rules
------------------
1. **Input windows** (:func:`load_metric_windows`, :func:`load_trace_windows`).
   Metrics (``simple_metrics.csv``, 1 s sampling) follow the pinned RCAEval
   runner (commit ``bb48c5aa``, ``main.py`` L271-316) exactly:

   - drop columns ending ``_latency-50``;
   - for Train Ticket keep only ``ts-`` columns (plus ``time``);
   - replace +/-inf by NaN, forward-fill, then fill remaining NaN with 0;
   - normal window N = the last 300 rows with ``time < onset``; anomalous
     window A = the first 300 rows with ``time >= onset`` (``--length 10``);
   - rename ``_latency-90`` to ``_latency``.

   Trace series (``tracets_lat.csv`` / ``tracets_err.csv``, 15 s sampling)
   use the same cleaning and 20 rows per side (5 min, as the project's TORAI
   case runner windows non-metric files). ``logts.csv`` is **not** used.
2. **Indicator -> node.** The node of a column is the token before its first
   underscore, after the alias ``frontendservice -> frontend`` (TORAI's own
   alias, ``RCAEval/e2e/torai.py`` L224-226). Metric, trace-latency and
   trace-error columns are separate *indicators* (``metric:``,
   ``trace_lat:`` and ``trace_err:`` prefixes).
3. **Indicator anomaly score** (:func:`score_indicator`; one-sided robust
   n-sigma). With ``m = median(N)`` and ``MAD = median(|N - m|)``:

   - scale ``s = 1.4826 * MAD``; if ``MAD == 0`` then ``s = SD(N)``
     (population SD, ``ddof=0``); if N is constant, the indicator is
     **excluded** (no scale can be estimated). It is recorded as excluded,
     with a flag saying whether A differs from the constant;
   - ``z_t = (x_t - m) / s`` for every ``t`` in A;
   - statistic: ``p90`` (primary) = 90th percentile of ``z_t`` (numpy
     default linear interpolation), i.e. the deviation must persist in at
     least 10 % of A; ``max`` (sensitivity only) = maximum of ``z_t``, the
     n-sigma / BARO convention;
   - indicator score ``= max(0, statistic)``, so only *upward* deviations
     count. The six injected fault types (cpu, mem, disk, delay, loss,
     socket) are expected to raise indicators at the faulty service. This
     is also the sign convention of the RCAEval BARO scorer.
4. **Node anomaly score** (:func:`node_anomaly_scores`): ``a(u)`` = maximum
   indicator score over u's usable indicators (0 if none). Evidence = the
   top 3 indicators by score (ties by indicator name).
5. **Walk graph** (:func:`build_walk_graph`). Walk edges ``u -> v`` mean
   "the walker at u may step to v". For a call graph (``u`` calls ``v``) the
   walk edges are the call edges, caller -> callee. Faults propagate
   callee -> caller, so this is the *reversed propagation graph*: the walk
   moves from symptoms toward the callees that could explain them. An
   inferred (correlation) graph carries no direction, so each inferred link
   is used in both directions. Transition weights from u:

   - to each out-neighbour v: ``w(u, v) = a(v)``, so the walker prefers
     more anomalous callees;
   - self-loop: ``w(u, u) = max(0, a(u) - max_{v in out(u)} a(v))``, with
     the max over an empty set = 0. The walker stays at a node that is more
     anomalous than all of its callees. This follows the CloudRanger /
     MicroCause self-loop rule, using anomaly instead of correlation;
   - zero-weight transitions are omitted. A node with no positive outgoing
     weight is *dangling*, and its mass is redistributed by the
     personalization vector (networkx default).

   Graph nodes that are not candidates are dropped. Candidates that are
   absent from the graph are added as isolated nodes. Both are recorded.
6. **Personalized PageRank** (:func:`personalized_pagerank`): damping 0.85,
   personalization ``p(u) = a(u) / sum(a)`` (uniform if all ``a`` are 0),
   ``networkx.pagerank`` with ``tol=1e-12`` and ``max_iter=10000``.
7. **Ranking** (:func:`rank_nodes`): nodes sorted by PageRank score (rounded
   to 12 decimals) descending, then anomaly score descending, then name
   ascending. There is no randomness anywhere.
8. **Service ranking and scoring** (:func:`to_service_ranking`,
   :func:`score_service_ranking`). This is the pinned runner's evaluator:
   token before the first underscore, remove ``-db``, then deduplicate while
   keeping the first occurrence. Top-k means the labelled service is within
   the first k services. ``Avg@5 = mean(AC@1..AC@5)``.

The *anomaly-only* ablation ranks nodes by ``a(u)`` alone
(:func:`rank_by_anomaly`), using the same tie rule, without a graph.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import networkx as nx
import numpy as np
import pandas as pd

DAMPING = 0.85
MAD_TO_SIGMA = 1.4826
METRIC_ROWS_PER_SIDE = 300  # RCAEval main.py: args.length * 60 // 2 with --length 10
TRACE_ROWS_PER_SIDE = 20  # 20 x 15 s = 5 min, the project's TORAI runner window for trace/log files
TOP_EVIDENCE = 3
PPR_TOL = 1e-12
PPR_MAX_ITER = 10000
RANK_DECIMALS = 12
STATISTICS = ("p90", "max")
PRIMARY_STATISTIC = "p90"
SERVICE_ALIASES = {"frontendservice": "frontend"}
INFERENCE_SUFFIXES = ("_latency", "_error")
INFERENCE_K = 3


# ---------------------------------------------------------------------------
# 1. Input windows
# ---------------------------------------------------------------------------
def _clean(data: pd.DataFrame, app: str) -> pd.DataFrame:
    """Apply the runner's column filter and missing-value rule (see module doc)."""
    if app == "torai-TT":
        time_col = data["time"]
        data = data.loc[:, data.columns.str.startswith("ts-")].copy()
        data["time"] = time_col
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.ffill()
    return data.fillna(0)


def _split(data: pd.DataFrame, onset: int, rows_per_side: int) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Return (last ``rows_per_side`` rows before onset, first ``rows_per_side`` rows at/after onset)."""
    normal = data[data["time"] < onset].tail(rows_per_side).reset_index(drop=True)
    anomalous = data[data["time"] >= onset].head(rows_per_side).reset_index(drop=True)
    return normal, anomalous


def load_metric_windows(path, onset: int, app: str,
                        rows_per_side: int = METRIC_ROWS_PER_SIDE) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load ``simple_metrics.csv`` with the pinned runner's preparation.

    Drops ``*_latency-50``, keeps ``ts-`` columns for Train Ticket, replaces
    inf by NaN, forward-fills then zero-fills, selects the last/first
    ``rows_per_side`` rows around ``onset`` and renames ``*_latency-90`` to
    ``*_latency``. Returns ``(normal, anomalous)`` frames, both including
    ``time``.
    """
    data = pd.read_csv(path)
    data = data.loc[:, ~data.columns.str.endswith("_latency-50")]
    data = _clean(data, app)
    normal, anomalous = _split(data, onset, rows_per_side)
    rename = {c: c[: -len("_latency-90")] + "_latency" for c in data.columns if c.endswith("_latency-90")}
    return normal.rename(columns=rename), anomalous.rename(columns=rename)


def load_trace_windows(path, onset: int, app: str,
                       rows_per_side: int = TRACE_ROWS_PER_SIDE) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load a ``tracets_*.csv`` file with the same cleaning and ``rows_per_side`` rows per side."""
    data = _clean(pd.read_csv(path), app)
    return _split(data, onset, rows_per_side)


def node_of(column: str) -> str:
    """Node of a raw column: token before the first underscore, after ``SERVICE_ALIASES``."""
    token = column.split("_", 1)[0]
    return SERVICE_ALIASES.get(token, token)


def indicators_from_windows(normal: pd.DataFrame, anomalous: pd.DataFrame, prefix: str,
                            source: str) -> List[dict]:
    """Turn a pair of window frames into indicator records (one per non-time column)."""
    if list(normal.columns) != list(anomalous.columns):
        raise ValueError("normal/anomalous windows must have identical columns")
    records = []
    for column in normal.columns:
        if column == "time":
            continue
        records.append({
            "indicator": prefix + ":" + column,
            "node": node_of(column),
            "source": source,
            "feature": column.split("_", 1)[1] if "_" in column else "",
            "normal": normal[column].to_numpy(dtype=float),
            "anomalous": anomalous[column].to_numpy(dtype=float),
        })
    return records


# ---------------------------------------------------------------------------
# 3-4. Anomaly scores
# ---------------------------------------------------------------------------
def score_indicator(normal: Sequence[float], anomalous: Sequence[float], statistic: str = PRIMARY_STATISTIC) -> dict:
    """One-sided robust n-sigma score of one indicator (rule 3 in the module doc).

    Returns a dict with ``score`` (>= 0), ``excluded`` (bool), ``reason``,
    ``centre`` (normal median), ``scale``, ``scale_rule`` (``mad``/``sd``),
    ``statistic_value`` (unclipped), ``anomalous_max``/``anomalous_median``
    and, for excluded constant indicators, ``changed_in_anomalous``.
    """
    if statistic not in STATISTICS:
        raise ValueError("statistic must be one of %s" % (STATISTICS,))
    normal = np.asarray(normal, dtype=float)
    anomalous = np.asarray(anomalous, dtype=float)
    out = {"score": 0.0, "excluded": False, "reason": None, "centre": None, "scale": None,
           "scale_rule": None, "statistic_value": None, "anomalous_max": None, "anomalous_median": None,
           "changed_in_anomalous": None}
    if normal.size == 0 or anomalous.size == 0:
        out.update(excluded=True, reason="empty_window")
        return out
    if not (np.all(np.isfinite(normal)) and np.all(np.isfinite(anomalous))):
        raise ValueError("indicator windows must be finite after cleaning")
    centre = float(np.median(normal))
    out.update(centre=centre, anomalous_max=float(np.max(anomalous)), anomalous_median=float(np.median(anomalous)))
    if np.all(normal == normal[0]):
        out.update(excluded=True, reason="constant_normal_window",
                   changed_in_anomalous=bool(np.any(anomalous != normal[0])))
        return out
    mad = float(np.median(np.abs(normal - centre)))
    if mad > 0:
        scale, rule = MAD_TO_SIGMA * mad, "mad"
    else:
        scale, rule = float(np.std(normal)), "sd"
    z = (anomalous - centre) / scale
    value = float(np.quantile(z, 0.9)) if statistic == "p90" else float(np.max(z))
    out.update(score=max(0.0, value), scale=scale, scale_rule=rule, statistic_value=value)
    return out


def node_anomaly_scores(indicators: Iterable[dict], nodes: Optional[Iterable[str]] = None,
                        statistic: str = PRIMARY_STATISTIC, top: int = TOP_EVIDENCE) -> Dict[str, dict]:
    """Aggregate indicator scores to nodes: ``a(u)`` = max usable indicator score (rule 4).

    ``nodes`` adds candidates that have no indicator (score 0). Each node's
    record holds ``score``, ``evidence`` (top ``top`` indicators),
    ``indicator_count``, ``usable_count``, ``excluded_constant`` and
    ``excluded_constant_changed`` (constant-in-normal indicators whose
    anomalous window differs, i.e. signal that the rule cannot use).
    """
    by_node: Dict[str, List[Tuple[dict, dict]]] = {}
    for record in indicators:
        result = score_indicator(record["normal"], record["anomalous"], statistic)
        by_node.setdefault(record["node"], []).append((record, result))
    for node in nodes or ():
        by_node.setdefault(node, [])
    summary = {}
    for node in sorted(by_node):
        pairs = by_node[node]
        usable = [(r, s) for r, s in pairs if not s["excluded"]]
        usable.sort(key=lambda rs: (-rs[1]["score"], rs[0]["indicator"]))
        excluded = sorted(r["indicator"] for r, s in pairs if s["excluded"])
        changed = sorted(r["indicator"] for r, s in pairs if s["excluded"] and s["changed_in_anomalous"])
        summary[node] = {
            "score": usable[0][1]["score"] if usable else 0.0,
            "evidence": [{
                "indicator": r["indicator"], "source": r["source"], "score": s["score"],
                "statistic_value": s["statistic_value"], "normal_median": s["centre"],
                "normal_scale": s["scale"], "scale_rule": s["scale_rule"],
                "anomalous_median": s["anomalous_median"], "anomalous_max": s["anomalous_max"],
            } for r, s in usable[:top]],
            "indicator_count": len(pairs),
            "usable_count": len(usable),
            "excluded_constant": excluded,
            "excluded_constant_changed": changed,
        }
    return summary


# ---------------------------------------------------------------------------
# 5. Graphs
# ---------------------------------------------------------------------------
def restrict_edges(edges: Iterable[Sequence[str]], candidates: Iterable[str]) -> dict:
    """Keep edges whose endpoints are both candidates (rule 5).

    Returns ``kept`` (sorted, deduplicated, no self-edges), ``dropped``
    (edges touching a non-candidate), ``unmapped_graph_nodes`` (graph nodes
    that are not candidates) and ``isolated_candidates`` (candidates with no
    kept edge).
    """
    cand = set(candidates)
    edges = sorted({(str(u), str(v)) for u, v in edges if u != v})
    kept = [e for e in edges if e[0] in cand and e[1] in cand]
    dropped = [e for e in edges if e not in kept]
    graph_nodes = {n for e in edges for n in e}
    touched = {n for e in kept for n in e}
    return {"kept": kept, "dropped": dropped,
            "unmapped_graph_nodes": sorted(graph_nodes - cand),
            "isolated_candidates": sorted(cand - touched)}


def build_walk_graph(walk_edges: Iterable[Sequence[str]], anomaly: Mapping[str, float],
                     nodes: Iterable[str]) -> nx.DiGraph:
    """Weighted walk graph with anomaly-weighted transitions and self-loops (rule 5).

    ``walk_edges`` are ``(u, v)`` pairs meaning the walker at u may step to
    v. For a call graph pass caller -> callee edges. For an undirected
    inferred graph pass both directions. Only edges whose endpoints are in
    ``nodes`` are used. Zero-weight transitions are omitted.
    """
    nodes = sorted(set(nodes))
    node_set = set(nodes)
    a = {n: max(0.0, float(anomaly.get(n, 0.0))) for n in nodes}
    out: Dict[str, set] = {n: set() for n in nodes}
    for u, v in walk_edges:
        if u in node_set and v in node_set and u != v:
            out[u].add(v)
    graph = nx.DiGraph()
    graph.add_nodes_from(nodes)
    for u in nodes:
        for v in sorted(out[u]):
            if a[v] > 0:
                graph.add_edge(u, v, weight=a[v])
        loop = max(0.0, a[u] - max((a[v] for v in out[u]), default=0.0))
        if loop > 0:
            graph.add_edge(u, u, weight=loop)
    return graph


def personalized_pagerank(walk_graph: nx.DiGraph, anomaly: Mapping[str, float],
                          damping: float = DAMPING) -> Dict[str, float]:
    """Personalized PageRank with ``p(u) = a(u) / sum(a)`` (uniform if all zero) (rule 6)."""
    nodes = sorted(walk_graph.nodes)
    if not nodes:
        return {}
    a = {n: max(0.0, float(anomaly.get(n, 0.0))) for n in nodes}
    total = sum(a.values())
    p = {n: (a[n] / total if total > 0 else 1.0 / len(nodes)) for n in nodes}
    return nx.pagerank(walk_graph, alpha=damping, personalization=p, weight="weight",
                       tol=PPR_TOL, max_iter=PPR_MAX_ITER, dangling=None)


# ---------------------------------------------------------------------------
# 7-8. Ranking and scoring
# ---------------------------------------------------------------------------
def rank_nodes(scores: Mapping[str, float], anomaly: Mapping[str, float]) -> List[str]:
    """Sort by score desc (12 decimals), then anomaly desc, then name asc (rule 7)."""
    return sorted(scores, key=lambda n: (-round(float(scores[n]), RANK_DECIMALS),
                                         -round(float(anomaly.get(n, 0.0)), RANK_DECIMALS), n))


def rank_by_anomaly(anomaly: Mapping[str, float]) -> List[str]:
    """Anomaly-only ablation: rank nodes by ``a(u)`` with the same tie rule."""
    return rank_nodes(anomaly, anomaly)


def to_service_ranking(node_ranking: Sequence[str]) -> List[str]:
    """The pinned evaluator: first token before ``_``, remove ``-db``, stable deduplicate (rule 8)."""
    return list(dict.fromkeys(n.split("_")[0].replace("-db", "") for n in node_ranking))


def score_service_ranking(services: Sequence[str], expected_service: str) -> dict:
    """Top-1/3/5, Avg@5 = mean(AC@1..AC@5), candidate count and answer presence (rule 8)."""
    answer = expected_service.replace("-db", "")
    rank = services.index(answer) + 1 if answer in services else None
    return {"true_service_rank": rank,
            "top1_hit": rank is not None and rank <= 1,
            "top3_hit": rank is not None and rank <= 3,
            "top5_hit": rank is not None and rank <= 5,
            "avg_at_5": sum(rank is not None and rank <= k for k in range(1, 6)) / 5.0,
            "candidate_count": len(services),
            "answer_in_candidates": answer in services}


def graph_rank(anomaly: Mapping[str, dict], walk_edges: Iterable[Sequence[str]],
               damping: float = DAMPING) -> dict:
    """Run the full ranker for one incident.

    ``anomaly`` is the output of :func:`node_anomaly_scores`; its keys are
    the candidate nodes. ``walk_edges`` are ``(u, v)`` walk edges (caller ->
    callee for a call graph, both directions for an undirected graph). Graph
    nodes outside the candidates are dropped, and candidates outside the
    graph are isolated. Returns the node ranking with PageRank and anomaly
    scores plus evidence, the service ranking, and graph bookkeeping.
    """
    candidates = sorted(anomaly)
    a = {n: float(anomaly[n]["score"]) for n in candidates}
    restricted = restrict_edges(walk_edges, candidates)
    walk = build_walk_graph(restricted["kept"], a, candidates)
    ppr = personalized_pagerank(walk, a, damping)
    order = rank_nodes(ppr, a)
    ranking = [{"rank": i + 1, "node": n, "ppr": ppr[n], "anomaly": a[n],
                "evidence": anomaly[n]["evidence"]} for i, n in enumerate(order)]
    return {"node_ranking": ranking, "service_ranking": to_service_ranking(order),
            "graph": {"walk_edges_used": [list(e) for e in restricted["kept"]],
                      "edges_dropped_unmapped": [list(e) for e in restricted["dropped"]],
                      "unmapped_graph_nodes": restricted["unmapped_graph_nodes"],
                      "isolated_candidates": restricted["isolated_candidates"],
                      "self_loops": sorted(u for u, v in walk.edges if u == v)}}


def anomaly_only_rank(anomaly: Mapping[str, dict]) -> dict:
    """Ablation: the same output structure as :func:`graph_rank`, ranked by ``a(u)`` alone."""
    a = {n: float(anomaly[n]["score"]) for n in anomaly}
    order = rank_by_anomaly(a)
    ranking = [{"rank": i + 1, "node": n, "anomaly": a[n], "evidence": anomaly[n]["evidence"]}
               for i, n in enumerate(order)]
    return {"node_ranking": ranking, "service_ranking": to_service_ranking(order)}


def undirected_to_walk_edges(links: Iterable[Sequence[str]]) -> List[Tuple[str, str]]:
    """Use each undirected link in both directions (correlation has no direction)."""
    edges = set()
    for u, v in links:
        if u != v:
            edges.add((u, v))
            edges.add((v, u))
    return sorted(edges)


# ---------------------------------------------------------------------------
# Inferred topology
# ---------------------------------------------------------------------------
def infer_correlation_topology(normal_metrics: pd.DataFrame, k: int = INFERENCE_K) -> dict:
    """INFERRED graph from the pre-injection normal window (not a call graph).

    Rule: take the metric columns ending ``_latency`` (the runner's renamed
    latency-90) or ``_error`` in the normal window (the same 300 rows used for
    anomaly scoring), drop columns that are constant there, and compute
    Spearman's rho for every column pair (Pearson on average ranks). The
    similarity of services u != v is ``r(u, v)`` = the maximum rho over their
    column pairs. Each service links to its top-``k`` services by ``r``
    among those with ``r > 0`` (ties by name). The graph is the undirected
    union of these links. Services without a usable latency/error column are
    isolated. Returns ``links`` (sorted ``[u, v, rho]`` with ``u < v``),
    ``services_with_series``, ``excluded_constant_columns`` and
    ``neighbours``.
    """
    columns = [c for c in normal_metrics.columns if c != "time" and c.endswith(INFERENCE_SUFFIXES)]
    usable = [c for c in columns if normal_metrics[c].nunique(dropna=False) > 1]
    excluded = sorted(set(columns) - set(usable))
    services: Dict[str, List[int]] = {}
    for i, c in enumerate(usable):
        services.setdefault(node_of(c), []).append(i)
    names = sorted(services)
    result = {"rule": "top-%d positive Spearman rho per service over *_latency/*_error metric columns "
                      "in the normal window; undirected union" % k,
              "k": k, "services_with_series": names, "excluded_constant_columns": excluded,
              "links": [], "neighbours": {}}
    if len(names) < 2:
        return result
    ranks = normal_metrics[usable].rank(method="average").to_numpy(dtype=float)
    rho = np.corrcoef(ranks, rowvar=False)
    sim: Dict[Tuple[str, str], float] = {}
    for u in names:
        for v in names:
            if u < v:
                value = max(float(rho[i, j]) for i in services[u] for j in services[v])
                sim[(u, v)] = sim[(v, u)] = value
    links = {}
    for u in names:
        others = sorted((v for v in names if v != u and sim[(u, v)] > 0), key=lambda v: (-sim[(u, v)], v))
        result["neighbours"][u] = [[v, sim[(u, v)]] for v in others[:k]]
        for v in others[:k]:
            links[tuple(sorted((u, v)))] = sim[(u, v)]
    result["links"] = [[u, v, links[(u, v)]] for u, v in sorted(links)]
    return result


# ---------------------------------------------------------------------------
# Incident loading helper
# ---------------------------------------------------------------------------
def load_incident_indicators(case_dir, app: str) -> dict:
    """Load one RE2-format incident directory into indicator records and window metadata."""
    case_dir = Path(case_dir)
    onset = int((case_dir / "inject_time.txt").read_text().strip())
    normal, anomalous = load_metric_windows(case_dir / "simple_metrics.csv", onset, app)
    indicators = indicators_from_windows(normal, anomalous, "metric", "simple_metrics.csv")
    windows = {"simple_metrics.csv": _window_meta(normal, anomalous)}
    for name, prefix in (("tracets_lat.csv", "trace_lat"), ("tracets_err.csv", "trace_err")):
        path = case_dir / name
        if path.exists():
            tn, ta = load_trace_windows(path, onset, app)
            indicators += indicators_from_windows(tn, ta, prefix, name)
            windows[name] = _window_meta(tn, ta)
    return {"onset": onset, "indicators": indicators, "windows": windows,
            "normal_metrics": normal, "candidates": sorted({r["node"] for r in indicators})}


def _window_meta(normal: pd.DataFrame, anomalous: pd.DataFrame) -> dict:
    def meta(frame):
        if frame.empty:
            return {"rows": 0, "first_time": None, "last_time": None}
        return {"rows": int(len(frame)), "first_time": int(frame["time"].iloc[0]),
                "last_time": int(frame["time"].iloc[-1])}
    return {"normal": meta(normal), "anomalous": meta(anomalous),
            "columns": int(len(normal.columns) - 1)}
