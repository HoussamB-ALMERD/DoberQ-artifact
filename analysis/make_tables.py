"""Generate every result table and the number macros used in the prose, from the benchmark CSVs only.

Inputs (data/):
  doberq_benchmark.csv     primitive benchmarks (ML-KEM, ML-DSA, RSA, ECDH, ECDSA) and single-party wrap_flow
  two_party_benchmark.csv  gateway wrap_flow + backbone unwrap_flow round trips
Outputs (manuscript/):
  tables/tab_kem.tex, tab_sig.tex, tab_sizes.tex, tab_layout.tex, tab_capsule.tex, tab_mem.tex
  numbers.tex              \newcommand macros for every number quoted in the text

The capsule byte layout is derived from the field widths in doberq/capsule.py (magic+version 3 B, timestamp 8 B,
one 4-byte length prefix per variable field) and checked against the measured capsule sizes.
"""
import csv, statistics as st
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA, OUT = ROOT / "data", ROOT / "manuscript"


def load(name):
    with open(DATA / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def stats(xs):
    xs = sorted(xs)
    n = len(xs)
    return {"n": n, "mean": st.mean(xs), "median": st.median(xs), "p95": xs[max(0, int(round(0.95 * n)) - 1)],
            "std": st.stdev(xs) if n > 1 else 0.0}


prim = load("doberq_benchmark.csv")
lat = defaultdict(list)
meta = {}
for r in prim:
    key = (r["algorithm"], r["operation"], r["payload_bytes"] if r["operation"] == "wrap_flow" else "")
    lat[key].append(float(r["latency_ms"]))
    meta.setdefault((r["algorithm"], r["operation"]), r)
S = {k: stats(v) for k, v in lat.items()}


def s(alg, op, payload=""):
    return S[(alg, op, payload)]


def f(x, d=3):
    return f"{x:.{d}f}"


macros = {}


def m(name, value):
    macros[name] = value


# ---------------------------------------------------------------- KEM table
KEM_ROWS = [
    ("ML-KEM-512", "post-quantum", ["keygen", "encapsulate", "decapsulate"]),
    ("ML-KEM-768", "post-quantum", ["keygen", "encapsulate", "decapsulate"]),
    ("ML-KEM-1024", "post-quantum", ["keygen", "encapsulate", "decapsulate"]),
    ("ECDH-P256", "classical", ["keygen", "encapsulate"]),
    ("ECDH-P384", "classical", ["keygen", "encapsulate"]),
    ("RSA-2048", "classical", ["keygen", "encapsulate", "decapsulate"]),
    ("RSA-4096", "classical", ["keygen", "encapsulate", "decapsulate"]),
]
OPNAME = {"keygen": "Key generation", "encapsulate": "Encapsulation", "decapsulate": "Decapsulation",
          "sign": "Signing", "verify": "Verification"}
CLASSICAL_OP = {("ECDH-P256", "encapsulate"): "Key agreement", ("ECDH-P384", "encapsulate"): "Key agreement",
                ("RSA-2048", "encapsulate"): "Encryption (OAEP)", ("RSA-4096", "encapsulate"): "Encryption (OAEP)",
                ("RSA-2048", "decapsulate"): "Decryption (OAEP)", ("RSA-4096", "decapsulate"): "Decryption (OAEP)"}


def latency_table(rows, caption, label, note):
    lines = [r"\begin{table}[!htbp]", r"\centering", r"\caption{" + caption + "}", r"\label{" + label + "}",
             r"\small", r"\setlength{\tabcolsep}{4pt}", r"\begin{tabular}{llrrrrr}", r"\toprule",
             r"Algorithm & Operation & $N$ & Mean & Median & p95 & SD \\", r"\midrule"]
    first = True
    for alg, fam, ops in rows:
        if not first and fam != prev_fam:
            lines.append(r"\midrule")
        first, prev_fam = False, fam
        for op in ops:
            x = s(alg, op)
            name = CLASSICAL_OP.get((alg, op), OPNAME[op])
            lines.append(f"{alg} & {name} & {x['n']} & {f(x['mean'])} & {f(x['median'])} & {f(x['p95'])} & {f(x['std'])} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\par\smallskip\parbox{\linewidth}{\footnotesize " + note + "}",
              r"\end{table}"]
    return "\n".join(lines) + "\n"


prev_fam = None
(OUT / "tables").mkdir(parents=True, exist_ok=True)
(OUT / "tables" / "tab_kem.tex").write_text(latency_table(
    KEM_ROWS, "Latency of key-establishment operations on the edge node (ms).", "tab:kem",
    "Post-quantum timings include constructing the liboqs object for each call, as the deployed engine does; "
    "classical timings cover the operation only. ECDH key agreement is one exchange with an existing peer key."),
    encoding="utf-8")

SIG_ROWS = [("ML-DSA-44", "post-quantum", ["keygen", "sign", "verify"]),
            ("ML-DSA-65", "post-quantum", ["keygen", "sign", "verify"]),
            ("ML-DSA-87", "post-quantum", ["keygen", "sign", "verify"]),
            ("ECDSA-P256", "classical", ["keygen", "sign", "verify"])]
prev_fam = None
(OUT / "tables" / "tab_sig.tex").write_text(latency_table(
    SIG_ROWS, "Latency of signature operations on the edge node (ms).", "tab:sig",
    "Signatures are computed over the same test message for every algorithm; ECDSA uses SHA-256."),
    encoding="utf-8")

# ---------------------------------------------------------------- sizes
SIZE_ROWS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ECDH-P256", "ECDH-P384", "RSA-2048", "RSA-4096",
             "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ECDSA-P256"]
lines = [r"\begin{table}[!htbp]", r"\centering", r"\caption{Sizes of keys, ciphertexts and signatures (bytes).}",
         r"\label{tab:sizes}", r"\small", r"\begin{tabular}{lrrrr}", r"\toprule",
         r"Algorithm & Public key & Secret key & Ciphertext & Signature \\", r"\midrule"]
for a in SIZE_ROWS:
    rows = [r for r in prim if r["algorithm"] == a]
    pk = max(int(r["public_key_bytes"]) for r in rows)
    sk = max(int(r["private_key_bytes"]) for r in rows)
    ct = max(int(r["ciphertext_bytes"]) for r in rows)
    sg = sorted({int(r["signature_bytes"]) for r in rows if int(r["signature_bytes"]) > 0})
    sgs = "--" if not sg else (f"{sg[0]:,}" if len(sg) == 1 else f"{sg[0]:,}--{sg[-1]:,}")
    cts = f"{ct:,}" if ct else "--"
    lines.append(f"{a} & {pk:,} & {sk:,} & {cts} & {sgs} \\\\".replace(",", "{,}"))
    if a == "RSA-4096":
        lines.append(r"\midrule")
lines += [r"\bottomrule", r"\end{tabular}", r"\par\smallskip\parbox{\linewidth}{\footnotesize Classical keys are "
          r"DER-encoded (SubjectPublicKeyInfo, PKCS\#8); post-quantum sizes are the raw FIPS~203/204 encodings "
          r"returned by liboqs. ECDSA signatures are DER-encoded and vary by a few bytes.}", r"\end{table}"]
(OUT / "tables" / "tab_sizes.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")

# ---------------------------------------------------------------- capsule layout (capsule.py)
kem_ct = int(meta[("ML-KEM-768", "encapsulate")]["ciphertext_bytes"])
sig_len = int(meta[("ML-DSA-65", "sign")]["signature_bytes"])
layout = [("Magic and version", 3, "header"), ("Timestamp (float64)", 8, "header"),
          ("KEM algorithm name, with 4-byte length", 4 + len("ML-KEM-768"), "header"),
          ("Signature algorithm name, with 4-byte length", 4 + len("ML-DSA-65"), "header"),
          ("ML-KEM-768 ciphertext, with 4-byte length", 4 + kem_ct, "KEM"),
          ("AES-GCM nonce, with 4-byte length", 4 + 12, "DEM"),
          ("Payload length prefix", 4, "header"), ("AES-GCM authentication tag", 16, "DEM"),
          ("ML-DSA-65 signature, with 4-byte length", 4 + sig_len, "signature")]
overhead = sum(b for _, b, _ in layout)
two = load("two_party_benchmark.csv")
measured_overhead = {int(r["amplification_bytes"]) for r in two} | {
    int(r["amplification_bytes"]) for r in prim if r["operation"] == "wrap_flow"}
assert measured_overhead == {overhead}, (overhead, measured_overhead)
lines = [r"\begin{table}[!htbp]", r"\centering", r"\caption{Byte layout of a DoberQ capsule (ML-KEM-768, ML-DSA-65).}",
         r"\label{tab:layout}", r"\small", r"\begin{tabular}{lr}", r"\toprule", r"Field & Bytes \\", r"\midrule"]
def num(x):
    return f"{x:,}".replace(",", "{,}")


for name, b, _ in layout:
    lines.append(f"{name} & {num(b)} \\\\")
lines += [r"Encrypted payload & $L$ \\", r"\midrule", f"Total & $L + {num(overhead)}$ \\\\",
          r"\bottomrule", r"\end{tabular}", r"\par\smallskip\parbox{\linewidth}{\footnotesize $L$ is the length of "
          r"the serialised flow record. The signature covers the KEM ciphertext, the nonce and the encrypted payload "
          r"with its tag; the header fields are not signed.}", r"\end{table}"]
(OUT / "tables" / "tab_layout.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
# prose split: raw KEM ciphertext + raw signature + (nonce, its prefix, tag) + everything else (header fields and the
# remaining length prefixes, including those of the ciphertext and the signature)
hdr = overhead - kem_ct - sig_len - (4 + 12 + 16)
assert hdr == sum(b for _, b, k in layout if k == "header") + 8
m("CapOverhead", f"{overhead:,}".replace(",", "{,}"))
m("CapKemCt", f"{kem_ct:,}".replace(",", "{,}"))
m("CapSig", f"{sig_len:,}".replace(",", "{,}"))
m("CapHeader", str(hdr))
m("CapKemSig", f"{kem_ct + sig_len:,}".replace(",", "{,}"))
m("CapSigPct", f"{100 * sig_len / overhead:.0f}")
m("CapNonceTag", str(4 + 12 + 16))

# ---------------------------------------------------------------- per-capsule cost
tp = defaultdict(lambda: defaultdict(list))
hosts, ok = set(), 0
for r in two:
    p = int(r["payload_bytes"])
    hosts.add(r["hw_platform"])
    ok += r["correctness_ok"] == "True"
    for k in ("wrap_latency_ms", "unwrap_latency_ms", "round_trip_latency_ms"):
        tp[p][k].append(float(r[k]))
    tp[p]["cap"].append(int(r["capsule_total_bytes"]))
lines = [r"\begin{table}[!htbp]", r"\centering",
         r"\caption{Per-capsule cost: gateway wrapping, backbone unwrapping and capsule size.}",
         r"\label{tab:capsule}", r"\small", r"\begin{tabular}{rrrrrrr}", r"\toprule",
         r"\begin{tabular}[b]{@{}r@{}}Payload\\(B)\end{tabular} & $N$ & \begin{tabular}[b]{@{}r@{}}Wrap\\(ms)\end{tabular} & \begin{tabular}[b]{@{}r@{}}Unwrap\\(ms)\end{tabular} & \begin{tabular}[b]{@{}r@{}}Round trip\\(ms)\end{tabular} & \begin{tabular}[b]{@{}r@{}}p95 round\\trip (ms)\end{tabular} & \begin{tabular}[b]{@{}r@{}}Capsule\\(B)\end{tabular} \\",
         r"\midrule"]
for p in sorted(tp):
    w, u, rt = (stats(tp[p][k]) for k in ("wrap_latency_ms", "unwrap_latency_ms", "round_trip_latency_ms"))
    cap = tp[p]["cap"][0]
    lines.append(f"{p:,} & {rt['n']} & {f(w['median'])} & {f(u['median'])} & {f(rt['median'])} & {f(rt['p95'])} & "
                 f"{cap:,} \\\\".replace(",", "{,}"))
    m(f"RT{p}", f(rt["median"]))
    m(f"RTp{p}", f(rt["p95"]))
    m(f"Wrap{p}", f(w["median"]))
    m(f"Unwrap{p}", f(u["median"]))
    m(f"Cap{p}", f"{cap:,}".replace(",", "{,}"))
    m(f"Amp{p}", f"{100 * (cap - p) / p:.1f}")
lines += [r"\bottomrule", r"\end{tabular}", r"\par\smallskip\parbox{\linewidth}{\footnotesize Gateway and backbone "
          r"identities are distinct key pairs; every recovered payload was compared with the original. Wrap, unwrap and round trip are medians of $N$ timings. Both parties "
          r"run in one process on one host, so no network time is included.}", r"\end{table}"]
(OUT / "tables" / "tab_capsule.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
m("RTok", str(ok))
m("RTtotal", str(len(two)))

# ---------------------------------------------------------------- memory (RSS growth over the timed loop)
lines = [r"\begin{table}[!htbp]", r"\centering",
         r"\caption{Growth of the benchmark process's resident memory over 200 iterations (MB).}",
         r"\label{tab:mem}", r"\small", r"\begin{tabular}{lr}", r"\toprule", r"Algorithm & RSS growth \\",
         r"\midrule"]
for a in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
    v = float(meta[(a, "keygen")]["ram_delta_mb"])
    lines.append(f"{a} & {v:.3f} \\\\")
    m("Mem" + a.replace("-", "").replace("ML", "ml"), f"{v:.2f}")
lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
(OUT / "tables" / "tab_mem.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")

# ---------------------------------------------------------------- number macros for the prose
def put(prefix, alg, op):
    x = s(alg, op)
    m(prefix, f(x["mean"]))
    m(prefix + "Med", f(x["median"]))


put("KemSevenGen", "ML-KEM-768", "keygen"); put("KemSevenEnc", "ML-KEM-768", "encapsulate")
put("KemSevenDec", "ML-KEM-768", "decapsulate"); put("KemFiveEnc", "ML-KEM-512", "encapsulate")
put("KemTenEnc", "ML-KEM-1024", "encapsulate")
put("EcdhGen", "ECDH-P256", "keygen"); put("EcdhAgree", "ECDH-P256", "encapsulate")
put("EcdhThreeAgree", "ECDH-P384", "encapsulate")
put("RsaGen", "RSA-2048", "keygen"); put("RsaEnc", "RSA-2048", "encapsulate"); put("RsaDec", "RSA-2048", "decapsulate")
put("RsaFourDec", "RSA-4096", "decapsulate"); put("RsaFourGen", "RSA-4096", "keygen")
put("DsaGen", "ML-DSA-65", "keygen"); put("DsaSign", "ML-DSA-65", "sign"); put("DsaVer", "ML-DSA-65", "verify")
put("EcdsaGen", "ECDSA-P256", "keygen"); put("EcdsaSign", "ECDSA-P256", "sign"); put("EcdsaVer", "ECDSA-P256", "verify")
m("EcdhEphemeral", f(s("ECDH-P256", "keygen")["median"] + s("ECDH-P256", "encapsulate")["median"]))
m("KemLevelMin", f(min(s(a, "encapsulate")["median"] for a in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"))))
m("KemLevelMax", f(max(s(a, "encapsulate")["median"] for a in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"))))
for p in ("256", "512", "1024"):
    m(f"SpWrap{p}", f(s("ML-KEM-768+ML-DSA-65", "wrap_flow", p)["median"]))
m("RsaKemGenRatio", f"{s('RSA-2048', 'keygen')['median'] / s('ML-KEM-768', 'keygen')['median']:.0f}")
m("RsaFourDecRatio", f"{s('RSA-4096', 'decapsulate')['median'] / s('ML-KEM-768', 'decapsulate')['median']:.1f}")
m("PrimN", str(s("ML-KEM-768", "encapsulate")["n"]))

# ---------------------------------------------------------------- repeatability: main run + three repeats (same VM, same day)
REP = ["doberq_benchmark.csv"] + [f"repeat_2026-10-09/primitives_rep{i}.csv" for i in (1, 2, 3)]
REP_TP = ["two_party_benchmark.csv"] + [f"repeat_2026-10-09/two_party_rep{i}.csv" for i in (1, 2, 3)]
rmed = []
for name in REP:
    d = defaultdict(list)
    for r in load(name):
        d[(r["algorithm"], r["operation"])].append(float(r["latency_ms"]))
    rmed.append({k: st.median(v) for k, v in d.items()})
tmed, tp_ok, tp_n = [], 0, 0
for name in REP_TP:
    rows = load(name)
    tp_ok += sum(r["correctness_ok"] == "True" for r in rows); tp_n += len(rows)
    tmed.append({(k, p): st.median(float(r[k]) for r in rows if r["payload_bytes"] == p)
                 for k in ("wrap_latency_ms", "unwrap_latency_ms") for p in ("256", "512", "1024")})
REP_ROWS = [("ML-KEM-768 encapsulation", lambda d: d[("ML-KEM-768", "encapsulate")]),
            ("ML-KEM-768 decapsulation", lambda d: d[("ML-KEM-768", "decapsulate")]),
            ("ECDH-P256 keygen + agreement", lambda d: d[("ECDH-P256", "keygen")] + d[("ECDH-P256", "encapsulate")]),
            ("ECDH-P384 agreement", lambda d: d[("ECDH-P384", "encapsulate")]),
            ("RSA-2048 decryption (OAEP)", lambda d: d[("RSA-2048", "decapsulate")]),
            ("ML-DSA-65 signing", lambda d: d[("ML-DSA-65", "sign")]),
            ("ECDSA-P256 signing", lambda d: d[("ECDSA-P256", "sign")]),
            ("ML-DSA-65 verification", lambda d: d[("ML-DSA-65", "verify")]),
            ("ECDSA-P256 verification", lambda d: d[("ECDSA-P256", "verify")])]
RATIOS = [("Ephem. ECDH-P256 / ML-KEM-768 enc.", "EphRatio",
           lambda d: (d[("ECDH-P256", "keygen")] + d[("ECDH-P256", "encapsulate")]) / d[("ML-KEM-768", "encapsulate")]),
          ("ECDH-P384 agr. / ML-KEM-768 enc.", "PThreeRatio",
           lambda d: d[("ECDH-P384", "encapsulate")] / d[("ML-KEM-768", "encapsulate")]),
          ("RSA-2048 dec. / ML-KEM-768 dec.", "RsaDecRatio",
           lambda d: d[("RSA-2048", "decapsulate")] / d[("ML-KEM-768", "decapsulate")]),
          ("ML-DSA-65 / ECDSA-P256 sign", "SignRatio", lambda d: d[("ML-DSA-65", "sign")] / d[("ECDSA-P256", "sign")]),
          ("ML-DSA-65 / ECDSA-P256 verify", "VerRatio", lambda d: d[("ML-DSA-65", "verify")] / d[("ECDSA-P256", "verify")])]
lines = [r"\begin{table}[!htbp]", r"\centering",
         r"\caption{Repeatability: medians of four runs of $N=200$ on the same machine (ms), and ratios computed within each run.}",
         r"\label{tab:repeat}", r"\footnotesize", r"\setlength{\tabcolsep}{3.5pt}", r"\begin{tabular}{lrrrrr}", r"\toprule",
         r"Operation & Run 1 & Run 2 & Run 3 & Run 4 & Range \\", r"\midrule"]
for lab, fn in REP_ROWS:
    v = [fn(d) for d in rmed]
    lines.append(f"{lab} & " + " & ".join(f(x) for x in v) + f" & {f(min(v))}--{f(max(v))} \\\\")
lines.append(r"\midrule")
for p in ("256", "1024"):
    for k, lab in (("wrap_latency_ms", "Capsule wrap"), ("unwrap_latency_ms", "Capsule unwrap")):
        v = [d[(k, p)] for d in tmed]
        size = f"{int(p):,}".replace(",", "{,}")
        lines.append(f"{lab}, {size} B record & " + " & ".join(f(x) for x in v) + f" & {f(min(v))}--{f(max(v))} \\\\")
lines.append(r"\midrule")
for lab, key, fn in RATIOS:
    v = [fn(d) for d in rmed]
    lines.append(f"{lab} & " + " & ".join(f"{x:.1f}" for x in v) + f" & {min(v):.1f}--{max(v):.1f} \\\\")
    m(key + "Min", f"{min(v):.1f}"); m(key + "Max", f"{max(v):.1f}")
lines += [r"\bottomrule", r"\end{tabular}",
          r"\par\smallskip\parbox{\linewidth}{\footnotesize Run 1 is the run reported in Tables~\ref{tab:kem}, "
          r"\ref{tab:sig} and \ref{tab:capsule}; runs 2--4 repeat both benchmarks unchanged (without RSA-4096). "
          r"In the first three ratio rows a value above 1 means the post-quantum operation is faster; in the last "
          r"two, a value above 1 means it is slower.}", r"\end{table}"]
(OUT / "tables" / "tab_repeat.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
allw = [d[("wrap_latency_ms", p)] for d in tmed for p in ("256", "512", "1024")]
allu = [d[("unwrap_latency_ms", p)] for d in tmed for p in ("256", "512", "1024")]
m("RepWrapMin", f(min(allw))); m("RepWrapMax", f(max(allw)))
m("RepUnwrapMin", f(min(allu))); m("RepUnwrapMax", f(max(allu)))
m("RepTPok", f"{tp_ok:,}".replace(",", "{,}")); m("RepTPn", f"{tp_n:,}".replace(",", "{,}"))
m("RepRuns", str(len(REP)))
# slowest wrapping median observed in any run (two-party or single-party) -> serial capsules per second
worst_wrap = max(allw + [s("ML-KEM-768+ML-DSA-65", "wrap_flow", p)["median"] for p in ("256", "512", "1024")])
m("WorstWrap", f(worst_wrap))
m("WrapRate", f"{int(1000 / worst_wrap // 100 * 100):,}".replace(",", "{,}"))
m("CapRatioTwoFiveSix", f"{tp[256]['cap'][0] / 256:.1f}")
assert tp_ok == tp_n

def latex_name(k):
    digits = {"0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four", "5": "Five", "6": "Six", "7": "Seven",
              "8": "Eight", "9": "Nine"}
    return "N" + "".join(digits.get(c, c) for c in k)

(OUT / "numbers.tex").write_text("% generated by tools/make_tables.py from data/*.csv -- do not edit\n" + "".join(
    f"\\newcommand{{\\{latex_name(k)}}}{{{v}}}\n" for k, v in sorted(macros.items())), encoding="utf-8")
print(f"tables written; {len(macros)} macros; two-party hosts={hosts}; correct={ok}/{len(two)}; overhead={overhead}")
for k, v in sorted(macros.items()):
    print(f"  \\{latex_name(k)} = {v}")
