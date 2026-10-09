"""
DoberQ PQC Micro-Benchmark Suite
=================================
Measures cryptographic handshake latency, CPU/RAM utilization, packet size
amplification, and energy proxies for NIST ML-KEM and ML-DSA algorithms
against classical RSA/ECDH/ECDSA baselines.

Usage:
    python doberq/benchmarks/benchmark_pqc.py \\
        --iterations 1000 \\
        --warmup 100 \\
        --algorithms ML-KEM-512 ML-KEM-768 ML-KEM-1024 \\
                     ML-DSA-44 ML-DSA-65 ML-DSA-87 \\
        --baselines RSA-2048 RSA-4096 ECDH-P256 ECDH-P384 ECDSA-P256 \\
        --output results/doberq_benchmark.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import platform
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

# ── stdlib-only guard for early import failures ────────────────────────────
try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False
    print("[WARNING] psutil not installed — CPU/RAM metrics will be 0. pip install psutil")

try:
    import oqs
    _OQS = True
except ImportError:
    _OQS = False
    print("[ERROR] liboqs-python not installed. pip install oqs")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    _CRYPTO = True
except ImportError:
    _CRYPTO = False
    print("[WARNING] cryptography not installed — classical baselines disabled. pip install cryptography")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("doberq.benchmark")

# Representative edge-device TDP (Raspberry Pi 4 / Intel NUC at load)
_TDP_WATTS = 15.0
_PAYLOAD_SIZES = [256, 512, 1024]   # bytes — simulated flow_json sizes


# =========================================================================
# Result dataclass
# =========================================================================

@dataclass
class BenchmarkResult:
    run_id: int = 0
    algorithm: str = ""
    algorithm_family: str = ""
    nist_security_level: Optional[int] = None
    operation: str = ""
    latency_ms: float = 0.0
    cpu_pct_mean: float = 0.0
    cpu_pct_p95: float = 0.0
    ram_delta_mb: float = 0.0
    public_key_bytes: int = 0
    private_key_bytes: int = 0
    ciphertext_bytes: int = 0
    signature_bytes: int = 0
    payload_bytes: int = 0
    capsule_total_bytes: int = 0
    amplification_bytes: int = 0
    amplification_pct: float = 0.0
    energy_proxy_mj: float = 0.0
    rapl_energy_j: float = float("nan")
    hw_platform: str = ""
    liboqs_version: str = ""
    python_version: str = ""
    timestamp_utc: str = ""


# =========================================================================
# CPU sampling helper
# =========================================================================

class _CPUSampler:
    """Background thread that samples psutil.cpu_percent() at 10ms intervals."""

    def __init__(self) -> None:
        self._samples: list[float] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            if _PSUTIL:
                self._samples.append(psutil.cpu_percent(interval=None))
            time.sleep(0.010)

    def start(self) -> None:
        if _PSUTIL:
            psutil.cpu_percent(interval=None)  # reset
        self._thread.start()

    def stop(self) -> tuple[float, float]:
        self._stop.set()
        self._thread.join(timeout=1.0)
        if not self._samples:
            return 0.0, 0.0
        mean = sum(self._samples) / len(self._samples)
        sorted_s = sorted(self._samples)
        p95_idx = max(0, int(math.ceil(0.95 * len(sorted_s))) - 1)
        return mean, sorted_s[p95_idx]


# =========================================================================
# RAPL energy reader
# =========================================================================

def _read_rapl_uj() -> Optional[int]:
    """Read Intel RAPL package energy counter in microjoules."""
    rapl_path = Path("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")
    try:
        return int(rapl_path.read_text().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return None


def _rapl_delta_joules(start_uj: Optional[int], end_uj: Optional[int]) -> float:
    if start_uj is None or end_uj is None:
        return float("nan")
    delta_uj = end_uj - start_uj
    if delta_uj < 0:
        delta_uj += 2**32  # counter wrap
    return delta_uj / 1e6


# =========================================================================
# PQC benchmarks
# =========================================================================

_PQC_KEM_LEVEL = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}
_PQC_DSA_LEVEL = {"ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}


def _bench_kem(alg: str, iterations: int, warmup: int) -> list[BenchmarkResult]:
    results = []
    hw = platform.node() + "/" + platform.machine()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ver = oqs.__version__ if hasattr(oqs, "__version__") else "unknown"
    level = _PQC_KEM_LEVEL.get(alg)

    logger.info("  Benchmarking KEM: %s (%d warm-up + %d timed iterations)", alg, warmup, iterations)

    # Warm-up
    for _ in range(warmup):
        with oqs.KeyEncapsulation(alg) as k:
            pk = k.generate_keypair()
            ct, _ = k.encap_secret(pk)

    # RAM baseline
    rss_before = psutil.Process(os.getpid()).memory_info().rss / 1e6 if _PSUTIL else 0.0

    for run_id in range(iterations):
        # --- keygen ---
        sampler = _CPUSampler(); sampler.start()
        rapl0 = _read_rapl_uj()
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            pk_len = kem.details["length_public_key"]
            sk_len = len(sk)
            ct_len = kem.details["length_ciphertext"]
        lat_ms = (time.perf_counter() - t0) * 1000
        rapl1 = _read_rapl_uj()
        cpu_mean, cpu_p95 = sampler.stop()
        results.append(BenchmarkResult(
            run_id=run_id, algorithm=alg, algorithm_family="post-quantum",
            nist_security_level=level, operation="keygen",
            latency_ms=round(lat_ms, 4), cpu_pct_mean=round(cpu_mean, 2),
            cpu_pct_p95=round(cpu_p95, 2),
            public_key_bytes=pk_len, private_key_bytes=sk_len, ciphertext_bytes=ct_len,
            energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
            rapl_energy_j=_rapl_delta_joules(rapl0, rapl1),
            hw_platform=hw, liboqs_version=ver,
            python_version=platform.python_version(), timestamp_utc=ts,
        ))

        # --- encapsulate ---
        sampler = _CPUSampler(); sampler.start()
        rapl0 = _read_rapl_uj()
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(alg) as kem:
            ct, ss = kem.encap_secret(pk)
        lat_ms = (time.perf_counter() - t0) * 1000
        rapl1 = _read_rapl_uj()
        cpu_mean, cpu_p95 = sampler.stop()
        results.append(BenchmarkResult(
            run_id=run_id, algorithm=alg, algorithm_family="post-quantum",
            nist_security_level=level, operation="encapsulate",
            latency_ms=round(lat_ms, 4), cpu_pct_mean=round(cpu_mean, 2),
            cpu_pct_p95=round(cpu_p95, 2),
            public_key_bytes=pk_len, private_key_bytes=sk_len, ciphertext_bytes=len(ct),
            energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
            rapl_energy_j=_rapl_delta_joules(rapl0, rapl1),
            hw_platform=hw, liboqs_version=ver,
            python_version=platform.python_version(), timestamp_utc=ts,
        ))

        # --- decapsulate ---
        sampler = _CPUSampler(); sampler.start()
        rapl0 = _read_rapl_uj()
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(alg, sk) as kem:
            _ = kem.decap_secret(ct)
        lat_ms = (time.perf_counter() - t0) * 1000
        rapl1 = _read_rapl_uj()
        cpu_mean, cpu_p95 = sampler.stop()
        results.append(BenchmarkResult(
            run_id=run_id, algorithm=alg, algorithm_family="post-quantum",
            nist_security_level=level, operation="decapsulate",
            latency_ms=round(lat_ms, 4), cpu_pct_mean=round(cpu_mean, 2),
            cpu_pct_p95=round(cpu_p95, 2),
            public_key_bytes=pk_len, private_key_bytes=sk_len, ciphertext_bytes=len(ct),
            energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
            rapl_energy_j=_rapl_delta_joules(rapl0, rapl1),
            hw_platform=hw, liboqs_version=ver,
            python_version=platform.python_version(), timestamp_utc=ts,
        ))

    rss_after = psutil.Process(os.getpid()).memory_info().rss / 1e6 if _PSUTIL else 0.0
    ram_delta = round(rss_after - rss_before, 3)
    for r in results:
        r.ram_delta_mb = ram_delta

    return results


def _bench_dsa(alg: str, iterations: int, warmup: int) -> list[BenchmarkResult]:
    results = []
    hw = platform.node() + "/" + platform.machine()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ver = oqs.__version__ if hasattr(oqs, "__version__") else "unknown"
    level = _PQC_DSA_LEVEL.get(alg)
    msg = b"X" * 512  # representative flow_json size

    logger.info("  Benchmarking DSA: %s (%d warm-up + %d timed iterations)", alg, warmup, iterations)

    for _ in range(warmup):
        with oqs.Signature(alg) as s:
            pk = s.generate_keypair()
            sig = s.sign(msg)

    rss_before = psutil.Process(os.getpid()).memory_info().rss / 1e6 if _PSUTIL else 0.0

    for run_id in range(iterations):
        # --- keygen ---
        sampler = _CPUSampler(); sampler.start()
        t0 = time.perf_counter()
        with oqs.Signature(alg) as sig_obj:
            pk = sig_obj.generate_keypair()
            sk = sig_obj.export_secret_key()
            pk_len = sig_obj.details["length_public_key"]
            sk_len = len(sk)
            sig_len = sig_obj.details["length_signature"]
        lat_ms = (time.perf_counter() - t0) * 1000
        cpu_mean, cpu_p95 = sampler.stop()
        results.append(BenchmarkResult(
            run_id=run_id, algorithm=alg, algorithm_family="post-quantum",
            nist_security_level=level, operation="keygen",
            latency_ms=round(lat_ms, 4), cpu_pct_mean=round(cpu_mean, 2),
            cpu_pct_p95=round(cpu_p95, 2),
            public_key_bytes=pk_len, private_key_bytes=sk_len, signature_bytes=sig_len,
            energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
            hw_platform=hw, liboqs_version=ver,
            python_version=platform.python_version(), timestamp_utc=ts,
        ))

        # --- sign ---
        sampler = _CPUSampler(); sampler.start()
        t0 = time.perf_counter()
        with oqs.Signature(alg, sk) as sig_obj:
            signature = sig_obj.sign(msg)
        lat_ms = (time.perf_counter() - t0) * 1000
        cpu_mean, cpu_p95 = sampler.stop()
        results.append(BenchmarkResult(
            run_id=run_id, algorithm=alg, algorithm_family="post-quantum",
            nist_security_level=level, operation="sign",
            latency_ms=round(lat_ms, 4), cpu_pct_mean=round(cpu_mean, 2),
            cpu_pct_p95=round(cpu_p95, 2),
            public_key_bytes=pk_len, private_key_bytes=sk_len, signature_bytes=len(signature),
            payload_bytes=len(msg), energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
            hw_platform=hw, liboqs_version=ver,
            python_version=platform.python_version(), timestamp_utc=ts,
        ))

        # --- verify ---
        sampler = _CPUSampler(); sampler.start()
        t0 = time.perf_counter()
        with oqs.Signature(alg) as sig_obj:
            _ = sig_obj.verify(msg, signature, pk)
        lat_ms = (time.perf_counter() - t0) * 1000
        cpu_mean, cpu_p95 = sampler.stop()
        results.append(BenchmarkResult(
            run_id=run_id, algorithm=alg, algorithm_family="post-quantum",
            nist_security_level=level, operation="verify",
            latency_ms=round(lat_ms, 4), cpu_pct_mean=round(cpu_mean, 2),
            cpu_pct_p95=round(cpu_p95, 2),
            public_key_bytes=pk_len, private_key_bytes=sk_len, signature_bytes=len(signature),
            payload_bytes=len(msg), energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
            hw_platform=hw, liboqs_version=ver,
            python_version=platform.python_version(), timestamp_utc=ts,
        ))

    rss_after = psutil.Process(os.getpid()).memory_info().rss / 1e6 if _PSUTIL else 0.0
    for r in results:
        r.ram_delta_mb = round(rss_after - rss_before, 3)

    return results


# =========================================================================
# Classical baselines
# =========================================================================

def _bench_classical(alg: str, iterations: int, warmup: int) -> list[BenchmarkResult]:
    if not _CRYPTO:
        logger.warning("Skipping classical baseline %s — cryptography not installed", alg)
        return []

    results = []
    hw = platform.node() + "/" + platform.machine()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    msg = b"X" * 512

    logger.info("  Benchmarking classical: %s (%d warm-up + %d timed iterations)", alg, warmup, iterations)

    def _run(run_id: int) -> list[BenchmarkResult]:
        rows = []
        be = default_backend()

        if alg.startswith("RSA-"):
            key_size = int(alg.split("-")[1])

            # keygen
            t0 = time.perf_counter()
            private_key = rsa.generate_private_key(65537, key_size, be)
            lat_ms = (time.perf_counter() - t0) * 1000
            pk_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sk_bytes = private_key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="keygen", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

            # encrypt (OAEP, RSA used as KEM proxy)
            short_msg = b"shared_secret_32_bytes_placeholder"
            t0 = time.perf_counter()
            ct = private_key.public_key().encrypt(
                short_msg, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            )
            lat_ms = (time.perf_counter() - t0) * 1000
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="encapsulate", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                ciphertext_bytes=len(ct),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

            # decrypt
            t0 = time.perf_counter()
            _ = private_key.decrypt(
                ct, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
            )
            lat_ms = (time.perf_counter() - t0) * 1000
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="decapsulate", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                ciphertext_bytes=len(ct),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

        elif alg.startswith("ECDH-"):
            curve_name = alg.split("-")[1]
            curve = ec.SECP256R1() if curve_name == "P256" else ec.SECP384R1()

            t0 = time.perf_counter()
            private_key = ec.generate_private_key(curve, be)
            lat_ms = (time.perf_counter() - t0) * 1000
            pk_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sk_bytes = private_key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="keygen", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

            peer_key = ec.generate_private_key(curve, be)
            t0 = time.perf_counter()
            from cryptography.hazmat.primitives.asymmetric.ec import ECDH
            _ = private_key.exchange(ECDH(), peer_key.public_key())
            lat_ms = (time.perf_counter() - t0) * 1000
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="encapsulate", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

        elif alg == "ECDSA-P256":
            curve = ec.SECP256R1()
            t0 = time.perf_counter()
            private_key = ec.generate_private_key(curve, be)
            lat_ms = (time.perf_counter() - t0) * 1000
            pk_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sk_bytes = private_key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="keygen", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

            t0 = time.perf_counter()
            sig = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
            lat_ms = (time.perf_counter() - t0) * 1000
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="sign", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                signature_bytes=len(sig), payload_bytes=len(msg),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

            t0 = time.perf_counter()
            private_key.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            lat_ms = (time.perf_counter() - t0) * 1000
            rows.append(BenchmarkResult(
                run_id=run_id, algorithm=alg, algorithm_family="classical",
                operation="verify", latency_ms=round(lat_ms, 4),
                public_key_bytes=len(pk_bytes), private_key_bytes=len(sk_bytes),
                signature_bytes=len(sig), payload_bytes=len(msg),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, python_version=platform.python_version(), timestamp_utc=ts,
            ))

        return rows

    # Warm-up
    for _ in range(warmup):
        _run(-1)

    for run_id in range(iterations):
        results.extend(_run(run_id))

    return results


# =========================================================================
# wrap_flow benchmark (end-to-end capsule creation)
# =========================================================================

def _bench_wrap_flow(
    kem_alg: str, sig_alg: str, iterations: int, warmup: int
) -> list[BenchmarkResult]:
    """Benchmark the full DoberQ wrap_flow pipeline."""
    # Defer import — pqc_engine requires oqs
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from doberq.pqc_engine import PQCEngine

    engine = PQCEngine(kem_alg=kem_alg, sig_alg=sig_alg)
    kem_pk, kem_sk = engine.generate_kem_keypair()
    sig_pk, sig_sk = engine.generate_sig_keypair()

    hw = platform.node() + "/" + platform.machine()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ver = oqs.__version__ if hasattr(oqs, "__version__") else "unknown"
    label = f"{kem_alg}+{sig_alg}"
    level = _PQC_KEM_LEVEL.get(kem_alg)

    results = []
    for _ in range(warmup):
        engine.wrap_flow(b"X" * 512, kem_pk, sig_sk)

    for payload_size in _PAYLOAD_SIZES:
        flow_json = b"X" * payload_size
        for run_id in range(iterations):
            t0 = time.perf_counter()
            capsule = engine.wrap_flow(flow_json, kem_pk, sig_sk)
            lat_ms = (time.perf_counter() - t0) * 1000
            cap_bytes = capsule.total_bytes
            amp = cap_bytes - payload_size
            results.append(BenchmarkResult(
                run_id=run_id, algorithm=label, algorithm_family="post-quantum",
                nist_security_level=level, operation="wrap_flow",
                latency_ms=round(lat_ms, 4),
                ciphertext_bytes=len(capsule.kem_ciphertext),
                signature_bytes=len(capsule.signature),
                payload_bytes=payload_size,
                capsule_total_bytes=cap_bytes,
                amplification_bytes=amp,
                amplification_pct=round(amp / payload_size * 100, 2),
                energy_proxy_mj=round(_TDP_WATTS * lat_ms, 4),
                hw_platform=hw, liboqs_version=ver,
                python_version=platform.python_version(), timestamp_utc=ts,
            ))

    return results


# =========================================================================
# CSV writer
# =========================================================================

_FIELDNAMES = [f.name for f in BenchmarkResult.__dataclass_fields__.values()]


def _write_csv(results: list[BenchmarkResult], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    logger.info("Wrote %d rows → %s", len(results), output_path)


# =========================================================================
# Summary printer
# =========================================================================

def _print_summary(results: list[BenchmarkResult]) -> None:
    from collections import defaultdict
    groups: dict[tuple, list[float]] = defaultdict(list)
    for r in results:
        groups[(r.algorithm, r.operation)].append(r.latency_ms)

    print("\n── DoberQ Benchmark Summary ────────────────────────────────────")
    print(f"{'Algorithm':<30} {'Operation':<16} {'N':>6} {'Mean (ms)':>10} {'p50 (ms)':>10} {'p95 (ms)':>10}")
    print("-" * 90)
    for (alg, op), latencies in sorted(groups.items()):
        n = len(latencies)
        mean = sum(latencies) / n
        sorted_l = sorted(latencies)
        p50 = sorted_l[int(0.50 * n)]
        p95 = sorted_l[min(int(0.95 * n), n - 1)]
        print(f"{alg:<30} {op:<16} {n:>6} {mean:>10.4f} {p50:>10.4f} {p95:>10.4f}")
    print("────────────────────────────────────────────────────────────────\n")


# =========================================================================
# CLI
# =========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="DoberQ PQC Micro-Benchmark Suite",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--iterations", type=int, default=100,
                        help="Timed iterations per operation")
    parser.add_argument("--warmup", type=int, default=20,
                        help="Warm-up iterations (excluded from results)")
    parser.add_argument("--algorithms", nargs="+",
                        default=["ML-KEM-768", "ML-DSA-65"],
                        help="PQC algorithms to benchmark")
    parser.add_argument("--baselines", nargs="+",
                        default=["RSA-2048", "ECDH-P256", "ECDSA-P256"],
                        help="Classical baselines to benchmark")
    parser.add_argument("--wrap-flow", action="store_true",
                        help="Include end-to-end wrap_flow benchmark")
    parser.add_argument("--kem-alg", default="ML-KEM-768",
                        help="KEM algorithm for wrap_flow benchmark")
    parser.add_argument("--sig-alg", default="ML-DSA-65",
                        help="DSA algorithm for wrap_flow benchmark")
    parser.add_argument("--output", default="results/doberq_benchmark.csv",
                        help="Output CSV path")
    parser.add_argument("--json-output", default=None,
                        help="Optional JSON output path")
    args = parser.parse_args()

    all_results: list[BenchmarkResult] = []

    # PQC algorithms
    for alg in args.algorithms:
        if alg in _PQC_KEM_LEVEL:
            all_results.extend(_bench_kem(alg, args.iterations, args.warmup))
        elif alg in _PQC_DSA_LEVEL:
            all_results.extend(_bench_dsa(alg, args.iterations, args.warmup))
        else:
            logger.warning("Unknown algorithm: %s — skipping", alg)

    # Classical baselines
    for alg in args.baselines:
        all_results.extend(_bench_classical(alg, args.iterations, args.warmup))

    # wrap_flow
    if args.wrap_flow:
        all_results.extend(_bench_wrap_flow(
            args.kem_alg, args.sig_alg, args.iterations, args.warmup
        ))

    _write_csv(all_results, args.output)

    if args.json_output:
        from dataclasses import asdict
        Path(args.json_output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in all_results], f, indent=2)
        logger.info("Wrote JSON → %s", args.json_output)

    _print_summary(all_results)


if __name__ == "__main__":
    main()
