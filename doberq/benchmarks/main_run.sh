export OQS_INSTALL_PATH=$HOME/liboqs_install
P=$HOME/doberq_bench_venv2/bin/python
{ date -u; uname -a; lscpu | grep -E "Model name|^CPU\(s\)|Hypervisor"; free -m | head -2; $P -c "import oqs,cryptography,sys;print(oqs.oqs_version(),oqs.oqs_python_version(),cryptography.__version__,sys.version)"; } > results/env_2026-10-09.txt 2>&1
$P run_nosampler.py --iterations 200 --warmup 20 --algorithms ML-KEM-512 ML-KEM-768 ML-KEM-1024 ML-DSA-44 ML-DSA-65 ML-DSA-87 --baselines RSA-2048 RSA-4096 ECDH-P256 ECDH-P384 ECDSA-P256 --wrap-flow --output results/doberq_benchmark_nosampler.csv > results/log_nosampler.txt 2>&1
$P benchmark_two_party.py > results/log_two_party.txt 2>&1
echo DONE >> results/log_two_party.txt
