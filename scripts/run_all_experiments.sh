#!/bin/bash
set -o nounset
set -o errexit

BENCHMARKS="cycles stack"

./scripts/benchmark_all.sh cycles

./scripts/benchmark_all.sh hashing

./scripts/benchmark_all.sh stack 1

./streaming/print_benchmarks.py
