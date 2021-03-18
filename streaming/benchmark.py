import argparse
import logging
import os
import sys
import re
import hashlib
from collections import defaultdict
from subprocess import check_output
import subprocess

import stream
import flashing
from testcases import TestCases

log = logging.getLogger(__name__)

SIZE_BINARY = "arm-none-eabi-size"
NM_BINARY   = "arm-none-eabi-nm"

SIZE_COMPARE_TARGET = "elf/crypto_sign_stream_size_compare_dummy_clean_{binary}.elf"
BINARY_NAME_RE = r"_([a-z]+).elf"

SHA3_SYMBOLS = ["shake128_absorb",  "shake128_squeezeblocks",  "cshake128_simple_absorb",
"cshake128_simple_squeezeblocks",  "cshake128_simple",  "shake128_inc_absorb",
"shake128_inc_finalize",  "shake128_inc_squeeze",  "shake256_absorb",
"shake256_squeezeblocks",  "cshake256_simple_absorb",  "cshake256_simple_squeezeblocks",
"cshake256_simple",  "shake256_inc_absorb",  "shake256_inc_finalize",
"shake256_inc_squeeze",  "shake128",  "shake256",  "sha3_256_inc_absorb",
"sha3_256_inc_finalize",  "sha3_256",  "sha3_384_inc_absorb",  "sha3_384_inc_finalize",
"sha3_384",  "sha3_512_inc_absorb",  "sha3_512_inc_finalize",  "sha3_512"]

PK_HASH_FUNCTION = {
    "crypto_sign_stream_gemss-128_m3" :                   lambda msg: hashlib.shake_128(msg).digest(32),
    "crypto_sign_stream_dilithium2_m3" :                  lambda msg: hashlib.shake_256(msg).digest(32),
    "crypto_sign_stream_falcon-512_opt-ct":               lambda msg: hashlib.shake_256(msg).digest(32),
    "crypto_sign_stream_rainbowI-classic_m3":             lambda msg: hashlib.sha256(msg).digest(),
    "crypto_sign_stream_sphincs-sha256-128f-simple_clean": lambda msg: msg,
    "crypto_sign_stream_sphincs-sha256-128s-simple_clean": lambda msg: msg,
}

def _parse_args():
    parser = argparse.ArgumentParser("Program for benchmarking PQC implementations on the NUCLEO-F207ZG.")
    parser.add_argument("target", help="Actual ELF target that is flashed and tested.")
    parser.add_argument("-n", "--num", type=int, help="Number of test cases to run.")
    parser.add_argument(
        "-u", "--summary", action="store_true",
        help="Print summary of benchmark instead of detailed results."
    )
    parser.add_argument(
        "-s", "--size", action="store_true",
        help="Additionally conduct a size benchmark on the binary."
    )
    parser.add_argument(
        "-o", "--only-size", action="store_true",
        help="Only conduct the size benchmark on the binary."
    )
    parser.add_argument(
        "-v", "--verbosity", type=int,
        choices=[logging.DEBUG, logging.INFO, logging.ERROR, logging.CRITICAL],
        help="Specify loglevel. Lower number = More Verbosity.",
        default=logging.INFO
    )
    return parser.parse_args()


def calc_benchmark_results(values):
    max_val = max(values)
    min_val = min(values)
    avg = sum(values) / len(values)
    return min_val, max_val, avg


def print_benchmarks(benchmarks):
    print("Name,value")
    for k in benchmarks:
        for v in benchmarks[k]:
            print(f"{k},{v}")


def print_benchmarks_results(benchmarks):
    print("Name,Min,Max,Avg")
    for b_name in benchmarks:
        min_v, max_v, avg = calc_benchmark_results(benchmarks[b_name])
        print(f"{b_name},{min_v},{max_v},{avg}")


def run_benchmarks(cases, print_immediately, scheme_name):
    benchmark_results = defaultdict(list)

    def update_benchmark(result):
        name, value = result
        value = int(value)
        log.debug("Received new benchmark: %s:%d", name, value)
        if print_immediately:
            print(f"{name},{value}")
        benchmark_results[name].append(value)

    def verify_result(result):
        if not bool(result):
            log.error("Signature verification during benchmark did not work! Stopping!")
            sys.exit(1)

    for test_case in cases:
        if not flashing.reset_device():
            log.critical("Could not reset device. Halting.")
            sys.exit(3)
        log.info("Running test case %s.", test_case["name"])
        s = stream.Stream(test_case["sm"], test_case["pk"], PK_HASH_FUNCTION[scheme_name])
        s.subscribe_message_type(stream.MessageType.BENCHMARK, update_benchmark)
        s.subscribe_message_type(stream.MessageType.RESULT, verify_result)
        s.stream()
    return benchmark_results


def run_size_benchmarks(target_path):
    try:
        outputSize = check_output(f"{SIZE_BINARY}  -A {target_path}", shell=True)
        outputNm   = subprocess.run(f"{NM_BINARY} --print-size -t d {target_path} | grep sha", shell=True, stdout=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as ex:
        log.error(f"Could not call {SIZE_BINARY} on {target_path}: {ex}")
        return None

    lines = outputSize.decode().split("\n")
    # Skip headers and suffix
    lines = lines[2:-4]

    results = {}

    for line in lines:
        segment_name, size, address = filter(None, line.split(' '))
        results[f"binary_size_{segment_name}"] = int(size)

    lines = outputNm.decode().strip().split("\n")
    hashingSizeTotal = 0
    needsKeccak = False
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 4:
            continue
        symbol = parts[3]
        size   = int(parts[1])

        hashingSizeTotal += size
        results[f"binary_size_{symbol}"] = size

        if symbol in SHA3_SYMBOLS:
            needsKeccak = True

    if needsKeccak:
        results[f"binary_size_keccak"] = 7052
        hashingSizeTotal += 7052

    results[f"binary_size_hashing_total"] = hashingSizeTotal
    return results

def do_size_benchmarks(target_path, compare_binary, print_immediately):
    size_benchmarks = run_size_benchmarks(target_path)

    if size_benchmarks is None:
        log.error("Could not determine binary size. Exiting.")
        sys.exit(1)

    compare_benchmarks = run_size_benchmarks(compare_binary)
    actual_bencharks = {}

    for name in size_benchmarks:
        if name not in compare_benchmarks:
            actual_bencharks[name] = [size_benchmarks[name]]
        else:
            actual_bencharks[name] = [size_benchmarks[name] - compare_benchmarks[name]]

    if print_immediately:
        for name, value in actual_bencharks.items():
            print(f"{name},{value[0]}")

    return actual_bencharks

def do_interactive_benchmarks(target_name, num_cases, print_immediately):
    try:
        cases = TestCases(target_name)
    except ValueError:
        sys.exit(2)

    log.info("Found %d test cases for target %s", len(cases), target_name)

    if num_cases:
        cases = cases[:num_cases]

    scheme_name = "_".join(target_name.split("_")[:-1])
    return run_benchmarks(cases, print_immediately, scheme_name)

def main():
    args = _parse_args()
    logging.basicConfig(level=args.verbosity)

    target_path = args.target
    target_name = os.path.basename(args.target)
    benchmark_results = {}

    if not os.path.isfile(target_path):
        log.error("Target file %s does not exist or is not a regular file.", target_path)
        sys.exit(1)

    print_immediately = not args.summary
    if print_immediately:
        print("name,value")

    if args.size:
        bin_name = re.findall(BINARY_NAME_RE, target_name)[0]
        compare_binary = SIZE_COMPARE_TARGET.format(binary=bin_name)
        if not os.path.isfile(compare_binary):
            log.error("Binary for size comparison not available. Generate %s first.", compare_binary)
            sys.exit(1)

        benchmark_results.update(
            do_size_benchmarks(target_path, compare_binary, print_immediately)
        )
        # todo error handling

    if not args.only_size:
        benchmark_results.update(
            do_interactive_benchmarks(target_name, args.num, print_immediately)
        )


    if args.summary:
        print_benchmarks_results(benchmark_results)


if __name__ == '__main__':
    main()
