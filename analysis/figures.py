"""Figures 3-6 of the paper, drawn from the replay summaries in results/stage2/analyses/.

    python -m analysis.figures --out figures

Writes PDF and PNG (300 dpi). Colours follow one fixed categorical order (blue, orange, aqua, yellow, magenta) with
distinct markers or printed values, so that no figure depends on colour alone; text is black or grey.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

BLUE, ORANGE, AQUA, YELLOW, MAGENTA = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"
ORANGE_LIGHT = "#f7bfa3"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
SEQ = ["#f4f3f0", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
SCENARIOS = ("G1", "G2", "G3", "G4")
SCENARIO_LABEL = {"G1": "G1 rollout + CPU fault", "G2": "G2 rollout + termination", "G3": "G3 catalog rollout\n+ termination",
                  "G4": "G4 benign\nrollout"}


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8,
        "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7.5, "axes.edgecolor": MUTED,
        "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED, "axes.linewidth": 0.6,
        "pdf.fonttype": 42, "ps.fonttype": 42})
    return plt


def _save(fig, out: Path, name: str):
    out.mkdir(parents=True, exist_ok=True)
    fig.savefig(out / (name + ".pdf"), bbox_inches="tight")
    fig.savefig(out / (name + ".png"), dpi=300, bbox_inches="tight")


def _clean(ax):
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.grid(color=GRID, lw=0.5)
    ax.set_axisbelow(True)


def per_capture(summary: dict, captures: dict, out: Path):
    """Invalid restarts per capture and view, as a table of printed counts shaded by size."""
    plt = _plt()
    views = [("T_p", "two-clock gate (also latest\nsnapshot, watch)"), ("T_p+lag", "two-clock, recheck's lag"),
             ("T_p@R", "two-clock, recheck's instants"), ("R", "fresh recheck"), ("L-kappa", "approval reuse")]
    order = [c for s in SCENARIOS for c in captures[s]]
    xpos, x = {}, 0.0
    for s in SCENARIOS:
        for c in captures[s]:
            xpos[c] = x
            x += 1.0
        x += 0.35
    per = summary["per_capture_U"]
    fig, ax = plt.subplots(figsize=(6.6, 2.15))
    for i, (v, _) in enumerate(views):
        for c in order:
            j = xpos[c]
            n = per[c][v]
            level = 0 if n == 0 else min(len(SEQ) - 1, 1 + int(math.log10(n) * 2.4))
            ax.add_patch(plt.Rectangle((j, i), 0.94, 0.86, color=SEQ[level], lw=0))
            ax.text(j + 0.47, i + 0.45, format(n, ","), ha="center", va="center", fontsize=6.6,
                    color="white" if level >= 4 else INK)
    ax.set_xlim(0, x - 0.35)
    ax.set_ylim(len(views), -1.15)
    ax.set_yticks([i + 0.43 for i in range(len(views))])
    ax.set_yticklabels([lab for _, lab in views])
    ax.set_xticks([xpos[c] + 0.47 for c in order])
    ax.set_xticklabels([c.split("-")[1] for c in order], fontsize=6.6)
    ax.tick_params(length=0)
    for s in SCENARIOS:
        xs = [xpos[c] for c in captures[s]]
        ax.text((min(xs) + max(xs) + 0.94) / 2, -0.55, SCENARIO_LABEL[s], ha="center", va="center", fontsize=7,
                color=MUTED, linespacing=1.0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xlabel("capture (number within scenario)")
    _save(fig, out, "fig_per_capture")
    plt.close(fig)


def by_delay(table: dict, out: Path):
    """Invalid executions and executions by dispatch delay."""
    plt = _plt()
    delays = [0, 10, 30, 80]
    series = [("T_p", "two-clock gate, F = 30 s", BLUE, "o", "-"),
              ("T@F600", "two-clock gate, F = 600 s", ORANGE, "s", "-"),
              ("L-kappa", "approval reuse", AQUA, "^", "-"),
              ("R", "fresh recheck", YELLOW, "D", "-")]
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.1))
    for key, label, color, marker, ls in series:
        u = [table[key]["delta %d s" % d]["U"] for d in delays]
        e = [table[key]["delta %d s" % d]["executions"] for d in delays]
        axes[0].plot(delays, u, color=color, marker=marker, ms=3.8, lw=1.4, ls=ls, mec="white", mew=0.5,
                     label=label)
        axes[1].plot(delays, e, color=color, marker=marker, ms=3.8, lw=1.4, ls=ls, mec="white", mew=0.5)
    posed = table["T_p"]["delta 0 s"]["posed"]
    axes[0].set_title("(a) invalid executions", loc="left", color=INK)
    axes[1].set_title("(b) executions (of %s posed per delay)" % format(posed, ","), loc="left", color=INK)
    for ax in axes:
        ax.set_xticks(delays)
        ax.set_xlabel("dispatch delay δ (s)")
        _clean(ax)
    axes[1].yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: format(int(v), ",")))
    axes[0].legend(loc="upper center", bbox_to_anchor=(1.12, 1.36), ncol=4, frameon=False, handlelength=2.0,
                   columnspacing=1.0)
    _save(fig, out, "fig_delay")
    plt.close(fig)


def stress(summary: dict, out: Path):
    """Faulty Pod ranked first (captures) against the availability delay, per policy and cutoff."""
    plt = _plt()
    policies = [("latest_state", "latest state", BLUE, "o", "-", 1.3),
                ("temporal_join", "temporal join", ORANGE, "s", (0, (1, 1.2)), 1.6),
                ("bitemporal_abstain_F600", "two-clock (F = 600 s)", AQUA, "D", (0, (4, 2)), 1.3),
                ("hindsight", "span identity (reference)", MUTED, None, (0, (2.5, 2)), 1.1)]
    panels = (("follow_up", "delayed_api", "follow-up (8 captures):\nevery API record delayed"),
              ("development", "delayed_switch", "development (4 captures):\nswitch record delayed"))
    cutoffs = (5, 30, 60)
    fig, axes = plt.subplots(2, 3, figsize=(6.6, 3.3), sharex=True)
    for i, (stage, fam, title) in enumerate(panels):
        curves = summary[stage]["curves_top1_of_n"]
        for j, delta in enumerate(cutoffs):
            ax = axes[i][j]
            top = 0
            for pol, label, color, marker, ls, lw in policies:
                pts = [p for p in (curves.get("%s | %s | %d s" % (fam, pol, delta)) or []) if p[2] > 0]
                if not pts:
                    continue
                top = max(top, max(p[2] for p in pts))
                ax.plot([p[0] for p in pts], [p[1] for p in pts], color=color, marker=marker, ms=3.0, lw=lw, ls=ls,
                        mec=color, mfc="white" if pol == "temporal_join" else color, label=label,
                        zorder=1 if pol == "hindsight" else 3)
            ax.set_ylim(-0.4, top + 0.4)
            ax.set_yticks(range(0, top + 1, 2 if top > 5 else 1))
            _clean(ax)
            if i == 0:
                ax.set_title("cutoff = onset + %d s" % delta, color=INK)
            if j == 0:
                ax.set_ylabel(title + "\nfaulty Pod ranked first", fontsize=7.5)
            if i == 1:
                ax.set_xlabel("availability delay d (s)")
    axes[0][0].legend(loc="upper center", bbox_to_anchor=(1.75, 1.52), ncol=4, frameon=False, handlelength=2.4,
                      columnspacing=1.0)
    fig.subplots_adjust(hspace=0.35, wspace=0.25)
    _save(fig, out, "fig_diagnosis_stress")
    plt.close(fig)


def audit(summary: dict, out: Path, unreachable: int | None = None, receipt: dict | None = None,
          own: dict | None = None):
    """Share of first verdicts an audit with one clock (valid-time replays; receipt-time replays from
    ``sweeps_summary.json``, if given), from a receipt log that keeps the records' own timestamps (``own``, the
    summary's ``own_timestamps_audit``, if given) or without history (end-of-capture replay) misreports.
    ``unreachable``: the end-of-capture misreports that are abstentions or requests for approval, which a replay from
    complete records cannot produce; drawn as the bar's upper part."""
    plt = _plt()
    a = summary["audit"]
    posed = a["posed"]
    lat = summary["latency"]["event_time_reconstruction_differs"]
    bars = [("captured", a["event_time_reconstruction"]["first_verdict_differs"], BLUE),
            ("+5 s", lat["T_p[late 5]"]["first_verdict_differs"], BLUE),
            ("+30 s", lat["T_p[late 30]"]["first_verdict_differs"], BLUE)]
    groups_n = 1
    if receipt:
        bars += [(label, receipt[key]["receipt_time_vs_gate"]["first_verdict_differs"], AQUA)
                 for label, key in (("captured", "0 s"), ("+5 s", "5 s"), ("+30 s", "30 s"))]
        groups_n += 1
    if receipt and own:
        bars += [(label, own[key]["own_timestamps_vs_gate"]["first_verdict_differs"], YELLOW)
                 for label, key in (("captured", "0 s"), ("+5 s", "5 s"), ("+30 s", "30 s"))]
        groups_n += 1
    bars.append(("", a["final_store_verdict"]["first_verdict_differs"], ORANGE))
    fig, ax = plt.subplots(figsize=({1: 4.4, 2: 6.0, 3: 7.6}[groups_n], 2.4))
    gap = [0.45 * (i // 3) for i in range(3 * groups_n)] + [0.45 * groups_n + (0.6 if groups_n == 3 else 0.0)]
    xs = [i + g for i, g in enumerate(gap)]
    vals = [100.0 * n / posed for _, n, _ in bars]
    last = len(bars) - 1
    ax.bar(xs[:last], vals[:last], width=0.62, color=[c for _, _, c in bars[:last]], zorder=3)
    if unreachable is None:
        ax.bar([xs[last]], [vals[last]], width=0.62, color=ORANGE, zorder=3)
    else:
        inverted = 100.0 * (bars[last][1] - unreachable) / posed
        ax.bar([xs[last]], [inverted], width=0.62, color=ORANGE, zorder=3, label="allow and deny inverted")
        ax.bar([xs[last]], [vals[last] - inverted], width=0.62, bottom=[inverted], color=ORANGE_LIGHT, zorder=3,
               edgecolor="white", linewidth=0.8, label="abstention or approval request")
        ax.legend(loc="upper left", frameon=False, fontsize=6.5, handlelength=1.2)
    for x, v, (_, n, _) in zip(xs, vals, bars):
        ax.text(x, v + 1.5, "%.1f%%\n(%s)" % (v, format(n, ",")), ha="center", va="bottom", fontsize=6.6, color=INK)
    ax.set_xticks(xs)
    ax.set_xticklabels([b for b, _, _ in bars], fontsize=7)
    groups = [("valid times only\n(pipeline latency)", xs[1])]
    if receipt:
        groups.append(("receipt times only\n(pipeline latency)", xs[4]))
    if receipt and own:
        groups.append(("receipt times and the records'\nown timestamps (pipeline latency)", xs[7]))
    groups.append(("end-of-capture\nstate", xs[last]))
    for text, x in groups:
        ax.text(x, -0.22, text, transform=ax.get_xaxis_transform(), ha="center", va="top", fontsize=7, color=INK)
    ax.set_ylabel("first verdicts misreported (%)")
    ax.set_ylim(0, 85)
    _clean(ax)
    ax.grid(axis="x", visible=False)
    _save(fig, out, "fig_audit")
    plt.close(fig)


def unreachable_misreports(results: Path, captures) -> int | None:
    """End-of-capture misreports that no replay from complete records can avoid: the two-clock gate's first verdicts
    that are abstentions or requests for approval, when every end-of-capture verdict is an allow or a deny."""
    finals, count = set(), 0
    for c in captures:
        finals.update(json.loads((results / "stage2/analyses/replays" / (c + ".json")).read_text(encoding="utf-8"))
                      ["audit"]["final_store_verdict"]["verdicts"])
        for cell in json.loads((results / "stage2/adapter" / (c + ".json")).read_text(encoding="utf-8"))["T1_cells"]:
            if (cell["action"], cell["stream"], cell["condition"]) == ("B", "S0", "T_p"):
                count += sum(x for k, x in cell["first_verdicts"]["counts"].items()
                             if k.split("[")[0] in ("ABSTAIN", "NEEDS_APPROVAL"))
    return count if finals <= {"ALLOW", "DENY"} else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    res, out = Path(a.results) / "stage2/analyses", Path(a.out)
    summary = json.loads((res / "replays_summary.json").read_text(encoding="utf-8"))
    pops = json.loads((Path(a.results) / "stage2/captures.json").read_text(encoding="utf-8"))["populations"]["G"]
    captures = {p["scenario"]: sorted(p["captures"]) for p in pops}
    per_capture(summary, captures, out)
    if (res / "by_delay.json").exists():
        by_delay(json.loads((res / "by_delay.json").read_text(encoding="utf-8")), out)
    stress(json.loads((res / "diagnosis_stress_summary.json").read_text(encoding="utf-8")), out)
    sweeps = res / "sweeps_summary.json"
    sw = json.loads(sweeps.read_text(encoding="utf-8")) if sweeps.exists() else {}
    audit(summary, out, unreachable_misreports(Path(a.results), [c for p in pops for c in p["captures"]]),
          sw.get("audit"), sw.get("own_timestamps_audit"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
