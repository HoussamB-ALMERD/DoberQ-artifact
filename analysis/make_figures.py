"""Generate the manuscript figures from data/*.csv (and the handler chain in doberq/handler.py for Fig. 1).

fig1_pipeline.pdf      DoberMan handler chain with DoberQ, DoberTwin and DoberFed
fig2_kem_latency.pdf   distributions of key-establishment latencies (log scale)
fig3_sig_latency.pdf   distributions of signature latencies (log scale)
fig4_sizes.pdf         public key, ciphertext/signature sizes (log scale)
fig5_overhead.pdf      capsule composition for the three payload sizes
"""
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
DATA, OUT = ROOT / "data", ROOT / "manuscript" / "figures"
OUT.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.size": 9, "axes.linewidth": 0.6, "pdf.fonttype": 42})
PQ, CL = "#2b6c8f", "#b5651d"


def load(name):
    with open(DATA / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


prim = load("doberq_benchmark.csv")
lat = defaultdict(list)
for r in prim:
    lat[(r["algorithm"], r["operation"])].append(float(r["latency_ms"]))


# ------------------------------------------------------------------ Fig. 1
def box(ax, x, y, w, h, text, fc, ec="#333333", fs=8, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=0.8))
    ax.text(x + w / 2, y + h / 2, text.replace("|", chr(10)), ha="center", va="center", fontsize=fs, weight="bold" if bold else "normal")


def arrow(ax, x0, y0, x1, y1, style="-|>", ls="-"):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle=style, lw=0.8, color="#333333", linestyle=ls, shrinkA=0, shrinkB=0))


fig, ax = plt.subplots(figsize=(7.2, 3.0))
ax.set_xlim(0, 16.6); ax.set_ylim(0, 6); ax.axis("off")
box(ax, 0.1, 2.3, 1.7, 1.6, "Legacy|medical|devices", "#eeeeee", fs=7.2)
ax.text(0.95, 1.95, "local segment", ha="center", fontsize=6.5, style="italic")
ax.add_patch(FancyBboxPatch((2.2, 0.5), 11.85, 5.0, boxstyle="round,pad=0.02,rounding_size=0.1", fc="none",
                            ec="#555555", lw=0.8, ls="--"))
ax.text(8.1, 5.15, "DoberMan edge gateway", ha="center", fontsize=8.5, weight="bold")
steps = [("Flow|capture", "#f4f4f4"), ("Classifier|RF + IF|explanations", "#f4f4f4"),
         ("Mitigation|allow, throttle,|block", "#f4f4f4"), ("Audit|(DoberChain)", "#f4f4f4"),
         ("DoberQ|ML-KEM-768|ML-DSA-65", "#d6e8f2")]
x = 2.45
for i, (t, c) in enumerate(steps):
    box(ax, x, 2.4, 2.0, 1.4, t, c, fs=6.3, bold=(i == 4))
    if i:
        arrow(ax, x - 0.3, 3.1, x, 3.1)
    x += 2.3
arrow(ax, 1.8, 3.1, 2.45, 3.1)
box(ax, 2.45, 0.8, 3.2, 1.0, "DoberTwin decoy|(beside the chain)", "#f4f4f4", fs=6.8)
box(ax, 9.5, 0.8, 4.1, 1.0, "DoberFed: model updates|sealed with the DoberQ engine", "#f4f4f4", fs=6.8)
arrow(ax, 12.65, 2.4, 12.65, 1.8, ls=":")
box(ax, 14.5, 2.3, 2.0, 1.6, "Hospital|backbone|receiver", "#eeeeee", fs=7.2)
arrow(ax, 13.65, 3.1, 14.5, 3.1)
ax.text(15.5, 2.0, "capsules over UDP", ha="center", va="top", fontsize=6.5)
fig.savefig(OUT / "fig1_pipeline.pdf", bbox_inches="tight")
plt.close(fig)


# ------------------------------------------------------------------ latency distributions
def dist_fig(groups, fname, ylabel="Latency (ms, log scale)"):
    fig, ax = plt.subplots(figsize=(7.0, 2.8))
    data, labels, colors = [], [], []
    for alg, op, lab, fam in groups:
        data.append(lat[(alg, op)]); labels.append(lab); colors.append(PQ if fam == "pq" else CL)
    bp = ax.boxplot(data, patch_artist=True, showfliers=True, widths=0.6,
                    flierprops=dict(marker=".", markersize=2, alpha=0.4), medianprops=dict(color="black", lw=0.8))
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c); patch.set_alpha(0.55); patch.set_linewidth(0.6)
    ax.set_yscale("log"); ax.set_ylabel(ylabel)
    ax.set_xticks(range(1, len(labels) + 1)); ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=7)
    ax.grid(axis="y", which="major", lw=0.3, alpha=0.6)
    ax.plot([], [], "s", color=PQ, alpha=0.55, label="post-quantum"); ax.plot([], [], "s", color=CL, alpha=0.55, label="classical")
    ax.legend(frameon=False, fontsize=7, loc="upper left")
    fig.savefig(OUT / fname, bbox_inches="tight"); plt.close(fig)


dist_fig([("ML-KEM-512", "keygen", "ML-KEM-512 keygen", "pq"), ("ML-KEM-768", "keygen", "ML-KEM-768 keygen", "pq"),
          ("ML-KEM-1024", "keygen", "ML-KEM-1024 keygen", "pq"), ("ML-KEM-512", "encapsulate", "ML-KEM-512 encaps", "pq"),
          ("ML-KEM-768", "encapsulate", "ML-KEM-768 encaps", "pq"), ("ML-KEM-1024", "encapsulate", "ML-KEM-1024 encaps", "pq"),
          ("ML-KEM-512", "decapsulate", "ML-KEM-512 decaps", "pq"), ("ML-KEM-768", "decapsulate", "ML-KEM-768 decaps", "pq"),
          ("ML-KEM-1024", "decapsulate", "ML-KEM-1024 decaps", "pq"),
          ("ECDH-P256", "keygen", "ECDH-P256 keygen", "cl"), ("ECDH-P256", "encapsulate", "ECDH-P256 agreement", "cl"),
          ("ECDH-P384", "keygen", "ECDH-P384 keygen", "cl"), ("ECDH-P384", "encapsulate", "ECDH-P384 agreement", "cl"),
          ("RSA-2048", "keygen", "RSA-2048 keygen", "cl"), ("RSA-2048", "encapsulate", "RSA-2048 encrypt", "cl"),
          ("RSA-2048", "decapsulate", "RSA-2048 decrypt", "cl"), ("RSA-4096", "decapsulate", "RSA-4096 decrypt", "cl")],
         "fig2_kem_latency.pdf")
dist_fig([(a, o, f"{a} {o}", "pq") for a in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87") for o in ("keygen", "sign", "verify")]
         + [("ECDSA-P256", o, f"ECDSA-P256 {o}", "cl") for o in ("keygen", "sign", "verify")], "fig3_sig_latency.pdf")


# ------------------------------------------------------------------ sizes
def size(alg, col):
    return max(int(r[col]) for r in prim if r["algorithm"] == alg)


rows = [("ECDH-P256", "public_key_bytes", None), ("ML-KEM-768", "public_key_bytes", "ciphertext_bytes"),
        ("RSA-2048", "public_key_bytes", "ciphertext_bytes"), ("ECDSA-P256", "public_key_bytes", "signature_bytes"),
        ("ML-DSA-65", "public_key_bytes", "signature_bytes")]
fig, ax = plt.subplots(figsize=(5.0, 2.4))
names = [r[0] for r in rows]
pk = [size(a, c) for a, c, _ in rows]
ct = [size(a, c2) if c2 else 0 for a, _, c2 in rows]
xs = range(len(rows))
b1 = ax.bar([x - 0.18 for x in xs], pk, 0.36, color=[PQ if n.startswith("ML") else CL for n in names], alpha=0.85,
            label="public key")
b2 = ax.bar([x + 0.18 for x in xs], ct, 0.36, color=[PQ if n.startswith("ML") else CL for n in names], alpha=0.45,
            hatch="///", label="ciphertext / signature")
for bars in (b1, b2):
    for b in bars:
        if b.get_height() > 0:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() * 1.12, f"{int(b.get_height()):,}", ha="center",
                    fontsize=6.3)
ax.set_yscale("log"); ax.set_ylim(30, 20000); ax.set_ylabel("Bytes (log scale)")
ax.set_xticks(list(xs)); ax.set_xticklabels(names, fontsize=7.5)
ax.legend(frameon=False, fontsize=7, loc="upper left")
fig.savefig(OUT / "fig4_sizes.pdf", bbox_inches="tight"); plt.close(fig)

# ------------------------------------------------------------------ capsule composition
two = load("two_party_benchmark.csv")
cap = {}
for r in two:
    cap[int(r["payload_bytes"])] = int(r["capsule_total_bytes"])
kem_ct = size("ML-KEM-768", "ciphertext_bytes"); sig = size("ML-DSA-65", "signature_bytes")
fig, ax = plt.subplots(figsize=(5.0, 2.0))
for i, p in enumerate(sorted(cap)):
    other = cap[p] - p - kem_ct - sig
    parts = [(p, "payload", "#999999"), (kem_ct, "KEM ciphertext", PQ), (sig, "ML-DSA signature", "#1d4a63"),
             (other, "header, nonce, tag", "#cccccc")]
    left = 0
    for w, lab, c in parts:
        ax.barh(i, w, left=left, color=c, height=0.55, label=lab if i == 0 else None, edgecolor="white", lw=0.4)
        left += w
    ax.text(left + 60, i, f"{cap[p]:,} B ({100 * p / cap[p]:.0f}% payload)", va="center", fontsize=7)
ax.set_yticks(range(len(cap))); ax.set_yticklabels([f"{p:,} B payload" for p in sorted(cap)], fontsize=7.5)
ax.set_xlim(0, 7600); ax.set_xlabel("Capsule size (bytes)")
ax.legend(frameon=False, fontsize=6.8, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.32))
fig.savefig(OUT / "fig5_overhead.pdf", bbox_inches="tight"); plt.close(fig)
print("figures written to", OUT)
