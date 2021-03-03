#!/bin/bash
set -o nounset
set -o errexit

BENCH_TRGT="old_benchmarks/`date --utc --iso-8601=seconds`"

if [ ! -d $BENCH_TRGT ]; then
    mkdir -p $BENCH_TRGT
fi

# Speed optimized
make clean
make PLATFORM=nucleo-f207zg -j16 DEBUG=0
./scripts/benchmark_all.sh cycles 1
./scripts/benchmark_all.sh stack 1
mv benchmarks $BENCH_TRGT/benchmarks_speed

# Speed LTO optimized
make clean
make PLATFORM=nucleo-f207zg -j16 DEBUG=0 LTO=1
./scripts/benchmark_all.sh cycles 1
# ./scripts/benchmark_all.sh stack 1
mv benchmarks $BENCH_TRGT/benchmarks_speed_lto

# Size optimized
make clean
make PLATFORM=nucleo-f207zg -j16 OPT_SIZE=1
./scripts/benchmark_all.sh cycles 1
./scripts/benchmark_all.sh stack 1
mv benchmarks $BENCH_TRGT/benchmarks_size