"""
DoberQ Two-Party Handshake Benchmark
=====================================
Fixes the self-encapsulation gap in benchmark_pqc.py::_bench_wrap_flow.

That benchmark has the gateway encapsulate to its OWN KEM public key
(KeyStore's documented dry-run fallback), which measures the raw cost of
the cryptographic primitives but NOT a real two-endpoint handshake: no
distinct backbone identity, and no unwrap_flow (decapsulate + verify +
decrypt) cost on the receiving side.

This script instead instantiates two DISTINCT identities:
  - Gateway:  ML-DSA-65 signing keypair only (signs outbound capsules)
  - Backbone: ML-KEM-768 KEM keypair only (receives/decapsulates)

and times the full round trip: wrap_flow() on the gateway side, followed
by unwrap_flow() on the backbone side, verifying the recovered plaintext
matches the original payload on every iteration.

Usage:
    OQS_INSTALL_PATH=/mnt/d/edge/liboqs_install \\
        ~/doberq_bench_venv/bin/python3 benchmark_two_party.py

Requires: liboqs-python, pointed at the existing liboqs v0.15.0 build via
OQS_INSTALL_PATH (matches the paper's stated liboqs version exactly).
"""

from __future__ import annotations

import csv
import json
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import oqs  # noqa: E402  (must come after OQS_INSTALL_PATH is set by caller)

# Import pqc_engine.py / capsule.py directly by file path, bypassing
# doberq/__init__.py (which pulls in handler.py -> flow_extractor -> scapy/
# sklearn/pandas — the full detection pipeline, unneeded for pure crypto
# benchmarking and not installed in this benchmark-only venv).
import importlib.util as _ilu

_DOBERQ_DIR = Path(__file__).parent.parent


def _load_module(name: str, filename: str):
    spec = _ilu.spec_from_file_location(name, _DOBERQ_DIR / filename)
    module = _ilu.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_stub_pkg = type(sys)("doberq")
_stub_pkg.__path__ = [str(_DOBERQ_DIR)]  # makes `doberq` look like a real package for relative imports
sys.modules["doberq"] = _stub_pkg
_capsule_mod = _load_module("doberq.capsule", "capsule.py")
_pqc_engine_mod = _load_module("doberq.pqc_engine", "pqc_engine.py")
PQCEngine = _pqc_engine_mod.PQCEngine

_TDP_WATTS = 15.0
_KEM_ALG = "ML-KEM-768"
_SIG_ALG = "ML-DSA-65"
_PAYLOAD_SIZES = [256, 512, 1024]
_ITERATIONS = 200
_WARMUP = 20


@dataclass
class TwoPartyResult:
    run_id: int = 0
    payload_bytes: int = 0
    wrap_latency_ms: float = 0.0       # gateway-side: KEM-encap + HKDF + AES-GCM-encrypt + ML-DSA-sign
    unwrap_latency_ms: float = 0.0     # backbone-side: ML-DSA-verify + KEM-decap + HKDF + AES-GCM-decrypt
    round_trip_latency_ms: float = 0.0
    capsule_total_bytes: int = 0
    amplification_bytes: int = 0
    amplification_pct: float = 0.0
    wrap_energy_proxy_mj: float = 0.0
    unwrap_energy_proxy_mj: float = 0.0
    round_trip_energy_proxy_mj: float = 0.0
    correctness_ok: bool = False
    kem_alg: str = _KEM_ALG
    sig_alg: str = _SIG_ALG
    liboqs_version: str = ""
    hw_platform: str = ""
    timestamp_utc: str = ""


def main() -> None:
    hw = platform.node() + "/" + platform.machine()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    liboqs_ver = oqs.oqs_version()

    print(f"liboqs version: {liboqs_ver}")
    print(f"KEM: {_KEM_ALG}  SIG: {_SIG_ALG}")
    print(f"Iterations: {_ITERATIONS}  Warmup: {_WARMUP}  Payload sizes: {_PAYLOAD_SIZES}\n")

    engine = PQCEngine(kem_alg=_KEM_ALG, sig_alg=_SIG_ALG)

    # Two DISTINCT identities — this is the actual fix.
    gateway_sig_pk, gateway_sig_sk = engine.generate_sig_keypair()
    backbone_kem_pk, backbone_kem_sk = engine.generate_kem_keypair()

    print(f"Gateway signing public key:  {len(gateway_sig_pk)} bytes")
    print(f"Backbone KEM public key:     {len(backbone_kem_pk)} bytes\n")

    all_results: list[TwoPartyResult] = []

    for payload_size in _PAYLOAD_SIZES:
        flow_json = bytes(f'{{"padding":"{"X"*(payload_size-20)}"}}'[:payload_size], "utf-8")
        if len(flow_json) < payload_size:
            flow_json += b"X" * (payload_size - len(flow_json))

        print(f"--- payload {payload_size} B ---")

        # Warm-up (not timed)
        for _ in range(_WARMUP):
            capsule = engine.wrap_flow(flow_json, backbone_kem_pk, gateway_sig_sk)
            engine.unwrap_flow(capsule, backbone_kem_sk, gateway_sig_pk)

        for run_id in range(_ITERATIONS):
            t0 = time.perf_counter()
            capsule = engine.wrap_flow(flow_json, backbone_kem_pk, gateway_sig_sk)
            t1 = time.perf_counter()
            recovered = engine.unwrap_flow(capsule, backbone_kem_sk, gateway_sig_pk)
            t2 = time.perf_counter()

            wrap_ms = (t1 - t0) * 1000
            unwrap_ms = (t2 - t1) * 1000
            round_trip_ms = (t2 - t0) * 1000

            cap_bytes = capsule.total_bytes
            amp_bytes = cap_bytes - payload_size

            all_results.append(TwoPartyResult(
                run_id=run_id,
                payload_bytes=payload_size,
                wrap_latency_ms=round(wrap_ms, 4),
                unwrap_latency_ms=round(unwrap_ms, 4),
                round_trip_latency_ms=round(round_trip_ms, 4),
                capsule_total_bytes=cap_bytes,
                amplification_bytes=amp_bytes,
                amplification_pct=round(amp_bytes / payload_size * 100, 2),
                wrap_energy_proxy_mj=round(_TDP_WATTS * wrap_ms, 4),
                unwrap_energy_proxy_mj=round(_TDP_WATTS * unwrap_ms, 4),
                round_trip_energy_proxy_mj=round(_TDP_WATTS * round_trip_ms, 4),
                correctness_ok=(recovered == flow_json),
                liboqs_version=liboqs_ver,
                hw_platform=hw,
                timestamp_utc=ts,
            ))

        n_correct = sum(1 for r in all_results if r.payload_bytes == payload_size and r.correctness_ok)
        print(f"  correctness: {n_correct}/{_ITERATIONS} round trips recovered exact plaintext")

    # ---- write CSV ----
    out_path = Path(__file__).parent / "results" / "two_party_benchmark.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [f.name for f in TwoPartyResult.__dataclass_fields__.values()]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_results:
            writer.writerow(asdict(r))
    print(f"\nWrote {len(all_results)} rows -> {out_path}")

    # ---- summary table ----
    print("\n== Two-Party wrap_flow + unwrap_flow Summary (N=%d per payload size) ==" % _ITERATIONS)
    print(f"{'Payload':>8} {'Wrap mean':>10} {'Wrap p95':>10} {'Unwrap mean':>12} {'Unwrap p95':>11} "
          f"{'RT mean':>9} {'RT p95':>9} {'Capsule B':>10} {'Amp %':>8}")
    for payload_size in _PAYLOAD_SIZES:
        rows = [r for r in all_results if r.payload_bytes == payload_size]
        wraps = sorted(r.wrap_latency_ms for r in rows)
        unwraps = sorted(r.unwrap_latency_ms for r in rows)
        rts = sorted(r.round_trip_latency_ms for r in rows)
        n = len(rows)
        p95 = lambda s: s[min(int(0.95 * n), n - 1)]
        print(f"{payload_size:>7}B "
              f"{sum(wraps)/n:>10.4f} {p95(wraps):>10.4f} "
              f"{sum(unwraps)/n:>12.4f} {p95(unwraps):>11.4f} "
              f"{sum(rts)/n:>9.4f} {p95(rts):>9.4f} "
              f"{rows[0].capsule_total_bytes:>10} {rows[0].amplification_pct:>7.1f}%")


if __name__ == "__main__":
    main()
