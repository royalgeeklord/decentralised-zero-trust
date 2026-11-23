import json, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2,
    "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
    "axes.spines.right": False, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.axisbelow": True, "legend.frameon": False, "savefig.dpi": 300})
lat = json.load(open("results/e2_latency.json")); tp = json.load(open("results/e2_throughput.json"))
fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.8))
for mode, col, lab in (("cache", BLUE, "In-memory state cache"), ("indexed", AQUA, "Indexed ledger query"), ("scan", ORANGE, "Unindexed scan (worst case)")):
    rows = [r for r in lat if r["mode"] == mode and r["devices"] == 100]
    xs = [r["records"] for r in rows]; ys = [r["gw_p95"] for r in rows]
    ax[0].plot(xs, ys, color=col, lw=2, marker="o", ms=4, label=lab)
ax[0].set_xscale("log"); ax[0].set_yscale("log")
ax[0].set_xlabel("Ledger size (records)"); ax[0].set_ylabel("Gateway processing, p95 (ms)")
ax[0].set_title("(a) Authorisation latency (100 devices)", loc="left", fontsize=9, color=INK)
ax[0].legend(fontsize=7, loc="upper left")
c = [r["concurrency"] for r in tp]; s = [r["sessions_per_s"] for r in tp]
b = ax[1].bar([str(x) for x in c], s, color=BLUE, width=0.6)
for rect, r in zip(b, tp):
    ax[1].text(rect.get_x() + rect.get_width() / 2, r["sessions_per_s"] + 20, f"{r['sessions_per_s']:.0f}/s\np95 {r['p95_ms']:.0f} ms",
               ha="center", va="bottom", fontsize=7, color=INK)
ax[1].set_xlabel("Concurrent devices"); ax[1].set_ylabel("Authorised sessions per second")
ax[1].set_ylim(0, max(s) * 1.35); ax[1].grid(axis="x", visible=False)
ax[1].set_title("(b) Throughput", loc="left", fontsize=9, color=INK)
fig.tight_layout(); fig.savefig("results/fig_e2.png")
