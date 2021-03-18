#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import pathlib
import re
from collections import defaultdict

try:
    from tabulate import tabulate
except ImportError:
    print("tabulate is not installed. Please do a `pip install tabulate`.")
    sys.exit(1)

log = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser("Program for collecting and printing benchmarks.")
    parser.add_argument("-s", "--scheme", action="append", help="Scheme to collect, e.g. falcon-512_opt-ct. Can be stacked.")
    parser.add_argument(
        "-f", "--format",
        choices=["pretty", "html", "latex"],
        default="pretty",
        help="Table output format."
    )
    parser.add_argument(
        "-p", "--paper",
        action="store_true",
        help="Print tables for final paper."
    )
    parser.add_argument(
        "-v", "--verbosity", type=int,
        choices=[logging.DEBUG, logging.INFO, logging.ERROR, logging.CRITICAL],
        help="Specify loglevel. Lower number = More Verbosity.",
        default=logging.INFO
    )
    parser.add_argument(
        "-l", "--location",
        help="Use alternative location/folder for reading benchmarks."
    )
    return parser.parse_args()



SIZE_BENCHMARKS = {
    "binary_size_.text": ".text",
    "binary_size_.data": ".data",
    "binary_size_.bss": ".bss"
}

SPEED_BENCHMARKS = {
    "crypto_sign_open_init_stream_cycles": "init_stream",
    "crypto_sign_open_consume_sm_chunk_cycles": "consume_sm_chunk",
    "crypto_sign_open_consume_pk_chunk": "consume_pk_chunk",
    "crypto_sign_open_get_result_cycles": "get_result"
}

MEMORY_BENCHMARKS = {
    "crypto_sign_open_init_stream_stack": "init_stream",
    "crypto_sign_open_consume_pk_chunk_stack": "consume_pk_chunk",
    "crypto_sign_open_consume_sm_chunk_stack": "consume_sm_chunk",
    "crypto_sign_open_get_result_stack": "get_result"
}

HASHING_BENCHMARKS = {
    "crypto_sign_open_init_stream_cycles": "init_stream",
    "crypto_sign_open_init_stream_aescycles": "init_stream_aes",
    "crypto_sign_open_init_stream_sha2cycles": "init_stream_sha2",
    "crypto_sign_open_init_stream_sha3cycles": "init_stream_sha3",

    "crypto_sign_open_consume_sm_chunk_cycles": "consume_sm_chunk",
    "crypto_sign_open_consume_sm_chunk_aescycles": "consume_sm_chunk_aes",
    "crypto_sign_open_consume_sm_chunk_sha2cycles": "consume_sm_chunk_sha2",
    "crypto_sign_open_consume_sm_chunk_sha3cycles": "consume_sm_chunk_sha3",

    "crypto_sign_open_consume_pk_chunk": "consume_pk_chunk",
    "crypto_sign_open_consume_pk_chunk_aescycles": "consume_pk_chunk_aes",
    "crypto_sign_open_consume_pk_chunk_sha2cycles": "consume_pk_chunk_sha2",
    "crypto_sign_open_consume_pk_chunk_sha3cycles": "consume_pk_chunk_sha3",

    "crypto_sign_open_get_result_cycles": "get_result",
    "crypto_sign_open_get_result_aescycles": "get_result_aes",
    "crypto_sign_open_get_result_sha2cycles": "get_result_sha2",
    "crypto_sign_open_get_result_sha3cycles": "get_result_sha3",

    "crypto_sign_open_hash_pk_chunk_aescycles": "hash_pk_chunk_aes",
    "crypto_sign_open_hash_pk_chunk_sha2cycles": "hash_pk_chunk_sha2",
    "crypto_sign_open_hash_pk_chunk_sha3cycles": "hash_pk_chunk_sha3",
}


BENCHMARK_NAMES = {
    "size": SIZE_BENCHMARKS,
    "speed": SPEED_BENCHMARKS,
    "memory": MEMORY_BENCHMARKS,
    "hashing": HASHING_BENCHMARKS
}

BENCHMARK_FOLDER_PATH = pathlib.Path(__file__).parent.parent
BENCHMARK_FOLDER_DEFAULT = BENCHMARK_FOLDER_PATH / "benchmarks"
BENCHMARK_FILE_RE = r"crypto_sign_stream_(.*)_[a-z]+.elf.csv"
BENCHMARK_FILE_PREFIX = "crypto_sign_stream_"
SCHEMES_SORTED = ['sphincs-sha256-128s-simple_clean',
                  'sphincs-sha256-128f-simple_clean',
                   'rainbowI-classic_m3',
                   'gemss-128_m3',
                   'dilithium2_m3',
                   'falcon-512_opt-ct']

FIXED_BUFFER_SIZES = {
    'sphincs-sha256-128s-simple_clean': 4928,
    'sphincs-sha256-128f-simple_clean': 4864,
    'rainbowI-classic_m3': 214*32,
    'gemss-128_m3': 228*20,
    'falcon-512_opt-ct': 897,
    'dilithium2_m3': 40
}

DISPLAY_NAMES = {
    'sphincs-sha256-128s-simple_clean': '\\texttt{sphincs-s}\\tnote{a}',
    'sphincs-sha256-128f-simple_clean': '\\texttt{sphincs-f}\\tnote{b}',
    'rainbowI-classic_m3': '\\paramrainbow',
    'gemss-128_m3': '\\paramgemss',
    'falcon-512_opt-ct': '\\paramfalcon',
    'dilithium2_m3': '\\paramdilithium'
}

STREAMING_SPEED_SLOW = (500/8)
STREAMING_SPEED_FAST = (20000/8)
STREAMING_TIME_MS = {
    'sphincs-sha256-128s-simple_clean': 7888 /STREAMING_SPEED_FAST,
    'sphincs-sha256-128f-simple_clean': 17120/STREAMING_SPEED_FAST,
    'rainbowI-classic_m3': 161666/STREAMING_SPEED_FAST,
    'gemss-128_m3': 1408785/STREAMING_SPEED_FAST,
    'falcon-512_opt-ct': 3732 / STREAMING_SPEED_FAST,
    'dilithium2_m3': 1587/STREAMING_SPEED_FAST
}

def collect_schemes(folder):
    schemes = defaultdict(list)
    for f in folder.iterdir():
        scheme_name = re.findall(BENCHMARK_FILE_RE, str(f))
        if scheme_name:
            schemes[scheme_name[0]].append(f)
    return schemes



def parse_benchmark_file(path):
    benchmarks = defaultdict(list)
    with open(path) as f:
        content = f.read()
        lines = content.split("\n")
        for line in lines[1:]:
            if not line:
                continue
            name, val = line.split(",")
            benchmarks[name].append(int(val))
    return benchmarks


def collect_benchmarks(schemes):
    benchmarks = defaultdict(dict)
    for scheme, benchmark_files in schemes.items():
        for f in benchmark_files:
            benchmarks[scheme].update(parse_benchmark_file(f))
    return benchmarks

def collect_average(results):
    avg_benchmarks = defaultdict(dict)
    for scheme, result in results.items():
        for name, values in result.items():
            avg_benchmarks[scheme][name] = int(sum(values) / len(values))
    return avg_benchmarks

def benchmarks_to_table(benchmark_names, results, category):
    if not results:
        raise ValueError("Benchmark results are empty.")
    bn_sorted = sorted(list(benchmark_names.keys()))
    header = [benchmark_names[n] for n in bn_sorted]
    if category == "speed":
        header += ["total"]
    rows = []

    for scheme in SCHEMES_SORTED:
        row = [scheme]
        total = 0
        if scheme not in results:
            continue
        
        result = results[scheme]

        for name in bn_sorted:
            row.append(result[name])
            total += int(result[name])
        if category == "speed":
            row.append(total)
        rows.append(row)
    return header, rows



def formatCell(value, k):
    if value < 1000:
        value = f"{value:,}"
    elif k:
        value = round(value, -3) // 1000
        if value == 0:
            return str(value)
        value = f"{value:,}"
        value = f"{value}k"
    else:
        value = f"{value:,}"
    value = value.replace(",", "\\,")
    return value

def benchmarks_to_table_speed(benchmarks):
    #header = ["scheme", "total", "sha2", "sha3", "sym", ""]
    header = []
    rows = []

    rowsHashing = []
    for scheme in SCHEMES_SORTED:
        if scheme not in benchmarks:
            continue 
        row = [DISPLAY_NAMES[scheme]]
        rowHashing = [DISPLAY_NAMES[scheme]]
        cry_open = benchmarks[scheme]['crypto_sign_open_init_stream_cycles']
        cry_sm = benchmarks[scheme]['crypto_sign_open_consume_sm_chunk_cycles']
        cry_pk = benchmarks[scheme]['crypto_sign_open_consume_pk_chunk']
        cry_result = benchmarks[scheme]['crypto_sign_open_get_result_cycles']
        total = cry_open + cry_sm + cry_pk + cry_result
        row.append(formatCell(total, True))

        sha2_open = benchmarks[scheme]['crypto_sign_open_init_stream_sha2cycles']
        sha2_sm = benchmarks[scheme]['crypto_sign_open_consume_sm_chunk_sha2cycles']
        sha2_pk = benchmarks[scheme]['crypto_sign_open_consume_pk_chunk_sha2cycles']
        sha2_result = benchmarks[scheme]['crypto_sign_open_get_result_sha2cycles']
        sha2_total = sha2_open + sha2_sm + sha2_pk + sha2_result
        #row.append(formatCell(sha2_total, True))

        sha3_open = benchmarks[scheme]['crypto_sign_open_init_stream_sha3cycles']
        sha3_sm = benchmarks[scheme]['crypto_sign_open_consume_sm_chunk_sha3cycles']
        sha3_pk = benchmarks[scheme]['crypto_sign_open_consume_pk_chunk_sha3cycles']
        sha3_result = benchmarks[scheme]['crypto_sign_open_get_result_sha3cycles']
        sha3_total = sha3_open + sha3_sm + sha3_pk + sha3_result
        #row.append(formatCell(sha3_total, True))

        # aes_open = benchmarks[scheme]['crypto_sign_open_init_stream_aescycles']
        # aes_sm = benchmarks[scheme]['crypto_sign_open_consume_sm_chunk_aescycles']
        # aes_pk = benchmarks[scheme]['crypto_sign_open_consume_pk_chunk_aescycles']
        # aes_result = benchmarks[scheme]['crypto_sign_open_get_result_aescycles']
        # aes_total = aes_open + aes_sm + aes_pk + aes_result
        # row.append(formatCell(aes_total, True))

        sym_total = sha2_total + sha3_total
        sym_total_fmt = formatCell(sym_total, True)
        if sha3_total > 0:
            sym_total_fmt += "\\tnote{b}"
        elif sha2_total > 0:
            sym_total_fmt += "\\tnote{c}"
        rowHashing.append(sym_total_fmt)
        rowHashing.append("({}\\%)".format(round(sym_total / total, 2) * 100))


        sha2_pk_verify = benchmarks[scheme]['crypto_sign_open_hash_pk_chunk_sha2cycles']
        sha3_pk_verify = benchmarks[scheme]['crypto_sign_open_hash_pk_chunk_sha3cycles']

        pk_verify = sha2_pk_verify + sha3_pk_verify
        # pk_verify = benchmarks[scheme]['crypto_sign_open_hash_pk_chunk']
        pk_verify_fmt = formatCell(pk_verify, True)
        if sha3_pk_verify > 0:
            pk_verify_fmt += "\\tnote{c}"
        elif sha2_pk_verify > 0:
            pk_verify_fmt += "\\tnote{d}"
        row.append(pk_verify_fmt)

        pk_verify_total = total + pk_verify
        row.append(formatCell(pk_verify_total, True))

        # time in milliseconds
        pk_verify_total_time = round(1000*pk_verify_total/(100*1000*1000),1)
        row.append(formatCell(pk_verify_total_time, False)+" ms")


        time_including_streaming = STREAMING_TIME_MS[scheme] + pk_verify_total_time
        row.append(formatCell(round(time_including_streaming,1), False)+" ms")

        rows.append(row)
        rowsHashing.append(rowHashing)
    return header, rows, rowsHashing



def benchmarks_to_table_hash_pk_speed(benchmarks):
    header = ["scheme", "sha2", "sha3"]

    rows = []

    for scheme in SCHEMES_SORTED:
        if scheme not in benchmarks:
            continue
        row = [
            DISPLAY_NAMES[scheme],
            formatCell(benchmarks[scheme]['crypto_sign_open_hash_pk_chunk_sha2cycles'], True),
            formatCell(benchmarks[scheme]['crypto_sign_open_hash_pk_chunk_sha3cycles'], True)
        ]

        rows.append(row)
    return header, rows


def benchmarks_to_table_memory(benchmarks):
    header = ["scheme", "total", "buffer", ".bss", "stack", "code"]

    rows = []

    for scheme in SCHEMES_SORTED:
        if scheme not in benchmarks:
            continue 
        bss = benchmarks[scheme]['binary_size_.bss']
        text = benchmarks[scheme]['binary_size_.text']
        stack = max(
            benchmarks[scheme]['crypto_sign_open_init_stream_stack'],
            benchmarks[scheme]['crypto_sign_open_consume_pk_chunk_stack'],
            benchmarks[scheme]['crypto_sign_open_consume_sm_chunk_stack'],
            benchmarks[scheme]['crypto_sign_open_get_result_stack']
        )
        buffer = FIXED_BUFFER_SIZES[scheme]
        bss -= buffer
        bss += 8

        textHash =  benchmarks[scheme]['binary_size_hashing_total']
        text -= textHash

        rows.append(
            [
                DISPLAY_NAMES[scheme],
                formatCell(buffer + bss + stack, False),
                formatCell(buffer, False),
                formatCell(bss, False),
                formatCell(stack, False),
                formatCell(text, False)
            ]
        )
    return header, rows


def main():
    args = _parse_args()
    logging.basicConfig(level=args.verbosity)

    if args.location:
        folder = BENCHMARK_FOLDER_PATH / args.location
    else:
        folder = BENCHMARK_FOLDER_DEFAULT

    if not os.path.isdir(folder):
        log.error(f"Benchmark folder {folder} does not exist!")
        sys.exit(1)

    schemes = collect_schemes(folder)

    if args.scheme:
        try:
            schemes = {scheme: schemes[scheme] for scheme in args.scheme}
        except KeyError:
            log.error("Supplied scheme `%s` does not have a benchmarking file in %s.", scheme, BENCHMARK_FOLDER)
            sys.exit(1)


    benchmarks = collect_average(collect_benchmarks(schemes))

    benchmark_tables = {}

    if args.paper:
        try:
            (header, speed, hashing) = benchmarks_to_table_speed(benchmarks)
            benchmark_tables['cycles'] = (header, speed)
            benchmark_tables['hashing'] = (header, hashing)
            benchmark_tables['memory'] = benchmarks_to_table_memory(benchmarks)
            benchmark_tables['cycles_pk_hashing'] = benchmarks_to_table_hash_pk_speed(benchmarks)
        except KeyError as ex:
            log.error("The benchmark `%s` is missing. Can't generate table for paper.", ex)
            sys.exit(1)
    else:
        for category in BENCHMARK_NAMES:
            try:
                benchmark_tables[category] = benchmarks_to_table(BENCHMARK_NAMES[category], benchmarks, category)
            except KeyError:
                log.info("Benchmark %s seems to be missing. Skipping.", category)
    if args.format == "latex":
        args.format = "latex_raw"

    for category, table in benchmark_tables.items():
        header, rows = table
        print(f"{category}:")
        print(tabulate(rows, header, tablefmt=args.format))


if __name__ == '__main__':
    main()
