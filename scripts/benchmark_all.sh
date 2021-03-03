#!/bin/bash
set -o nounset
set -o errexit


if [ $# -eq 0 ]; then
    echo "Bechmark name missing. Call: $0 BENCHMARK_NAME"
    echo "Example: $0 cycles"
    exit 1
fi

BENCHMARK_NAME=$1
NUM_TEST_CASES=${2:-0}
BENCHMARK_DIR=benchmarks

if [ ! -d $BENCHMARK_DIR ]; then 
	mkdir -p $BENCHMARK_DIR
fi

if [ ! -d streaming ]; then 
	echo "Folder 'streaming' does not exist. Are you in the project root?"
        exit 1
fi

for target in elf/crypto_sign_*_${BENCHMARK_NAME}.elf; do
    if [[ $target == *"dummy"* ]]; then
        echo "Skipping dummy test case"
        continue
    fi
	echo "Flashing ${target}"
	openocd -f nucleo-f2.cfg -c "program ${target} exit"
	echo "Sarting benchmarks for ${target}"
	python3 streaming/benchmark.py -n $NUM_TEST_CASES -s $target > ${BENCHMARK_DIR}/$(basename ${target}.csv)||(echo "A benchmark failed. Exiting." && exit 1)
done
