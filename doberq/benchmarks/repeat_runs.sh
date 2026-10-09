export OQS_INSTALL_PATH=$HOME/liboqs_install
P=$HOME/doberq_bench_venv2/bin/python
for i in 1 2 3; do
  $P benchmark_two_party.py > results/repeat/log_two_party_$i.txt 2>&1
  cp results/two_party_benchmark.csv results/repeat/two_party_rep$i.csv
  $P run_nosampler.py --iterations 200 --warmup 20 --algorithms ML-KEM-512 ML-KEM-768 ML-KEM-1024 ML-DSA-44 ML-DSA-65 ML-DSA-87 --baselines RSA-2048 ECDH-P256 ECDH-P384 ECDSA-P256 --wrap-flow --output results/repeat/primitives_rep$i.csv > results/repeat/log_prim_$i.txt 2>&1
done
cp results/repeat/two_party_rep1.csv /dev/null
echo ALLDONE > results/repeat/done.txt
