"""Run benchmark_pqc.py unchanged, except that the per-operation CPU-sampler thread is replaced by a no-op.

benchmark_pqc.py starts a psutil sampling thread immediately before every timed ML-KEM / ML-DSA operation, but not
before the classical baselines or wrap_flow, so the post-quantum primitive timings carry thread start-up and
sampling cost that the baselines do not. This wrapper removes that asymmetry; every other setting (iterations,
warm-up, algorithms, timing code) is the original script's. CPU columns are written as 0 in this run.

Usage (same arguments as benchmark_pqc.py):
    OQS_INSTALL_PATH=... python3 run_nosampler.py --iterations 200 --warmup 20 \
        --algorithms ML-KEM-512 ML-KEM-768 ML-KEM-1024 ML-DSA-44 ML-DSA-65 ML-DSA-87 \
        --baselines RSA-2048 RSA-4096 ECDH-P256 ECDH-P384 ECDSA-P256 --wrap-flow \
        --output results/doberq_benchmark_nosampler.csv

As in benchmark_two_party.py, doberq/__init__.py is bypassed with a stub package so that importing the engine does
not pull in the detection pipeline (scapy, sklearn), which this benchmark-only venv does not have.
"""
import importlib.util as _ilu
import sys
from pathlib import Path

import benchmark_pqc as bp

_DOBERQ_DIR = Path(__file__).resolve().parent.parent
_stub_pkg = type(sys)("doberq")
_stub_pkg.__path__ = [str(_DOBERQ_DIR)]
sys.modules["doberq"] = _stub_pkg
for _name, _file in (("doberq.capsule", "capsule.py"), ("doberq.pqc_engine", "pqc_engine.py")):
    _spec = _ilu.spec_from_file_location(_name, _DOBERQ_DIR / _file)
    _mod = _ilu.module_from_spec(_spec)
    sys.modules[_name] = _mod
    _spec.loader.exec_module(_mod)


class _NoSampler:
    def start(self) -> None:
        pass

    def stop(self) -> tuple[float, float]:
        return 0.0, 0.0


bp._CPUSampler = _NoSampler

if __name__ == "__main__":
    bp.main()
