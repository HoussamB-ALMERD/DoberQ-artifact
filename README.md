# DoberQ: research artifact

This repository accompanies the paper *DoberQ: a post-quantum encapsulation proxy for legacy medical IoT telemetry at the edge gateway*. It contains what is needed to check and reproduce the paper's measurements:

- the DoberQ cryptographic engine and capsule format (`doberq/`): ML-KEM-768 encapsulation, HKDF-SHA256, AES-256-GCM and an ML-DSA-65 signature per record;
- the benchmark scripts (`doberq/benchmarks/`);
- the raw per-iteration results of every run reported in the paper (`data/`);
- the scripts that generate every table, number and figure in the paper from those results (`analysis/`).

The DoberMan gateway that DoberQ belongs to (flow capture, detection, mitigation and the other modules) is not part of this artifact.

## License

PolyForm Noncommercial License 1.0.0 (see `LICENSE.md`). You may use, run and modify this code for noncommercial purposes, including research and teaching. **Commercial use is not permitted**; for a commercial license, contact the authors.

## Reproducing the tables and figures

```bash
pip install -r requirements.txt
python analysis/make_tables.py    # -> manuscript/tables/*.tex and manuscript/numbers.tex
python analysis/make_figures.py   # -> manuscript/figures/*.pdf
```

Both scripts read only `data/`. The tables they produce are identical to those in the paper.

## Re-running the benchmarks

Requirements: Python 3.12, liboqs 0.15.0 built as a shared library, and the packages in `requirements.txt`.

```bash
export OQS_INSTALL_PATH=/path/to/liboqs_install
cd doberq/benchmarks
mkdir -p results

# Primitive benchmarks (ML-KEM, ML-DSA, RSA, ECDH, ECDSA) and single-party capsule wrapping
python run_nosampler.py --iterations 200 --warmup 20 \
    --algorithms ML-KEM-512 ML-KEM-768 ML-KEM-1024 ML-DSA-44 ML-DSA-65 ML-DSA-87 \
    --baselines RSA-2048 RSA-4096 ECDH-P256 ECDH-P384 ECDSA-P256 --wrap-flow \
    --output results/doberq_benchmark_nosampler.csv

# Capsule round trips with distinct gateway (ML-DSA-65) and receiver (ML-KEM-768) keys
python benchmark_two_party.py     # -> results/two_party_benchmark.csv
```

`run_nosampler.py` runs `benchmark_pqc.py` unchanged except that its optional CPU-utilisation sampling thread is disabled. That thread was started before each timed post-quantum operation but not before the classical ones, so it inflated only the post-quantum timings; all results in the paper were measured without it. `main_run.sh` and `repeat_runs.sh` are the exact scripts used for the main run and the three repeats.

## Data

| File | Content |
|---|---|
| `data/doberq_benchmark.csv` | Run 1: primitives (N = 200 per operation) and single-party wrapping (N = 200 per record size) |
| `data/two_party_benchmark.csv` | Run 1: capsule round trips, 256 / 512 / 1,024-byte records, N = 200 each |
| `data/repeat_2026-10-09/` | Runs 2–4 of both benchmarks (RSA-4096 omitted) |
| `data/env_vm_2026-10-09.txt` | Platform: CPU, memory, kernel and library versions |
| `data/log_*.txt` | Console output of the runs |

Absolute timings vary by up to a factor of two between runs on the virtual machine used; see the paper's repeatability table.
