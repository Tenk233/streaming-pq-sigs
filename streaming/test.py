import argparse
import os
import logging
import sys
import flashing
import hashlib

import stream
from testcases import TestCases
from tests.bitflip import ValidTest, PKBitflipTest, SMBitflipTest


TESTS = [
    ValidTest,
    PKBitflipTest,
    SMBitflipTest
]


PK_HASH_FUNCTION = {
    "crypto_sign_stream_gemss-128_m3" :                   lambda msg: hashlib.shake_128(msg).digest(32),
    "crypto_sign_stream_dilithium2_m3" :                  lambda msg: hashlib.shake_256(msg).digest(32),
    "crypto_sign_stream_falcon-512_opt-ct":               lambda msg: hashlib.shake_256(msg).digest(32),
    "crypto_sign_stream_rainbowI-classic_m3":             lambda msg: hashlib.sha256(msg).digest(),
    "crypto_sign_stream_sphincs-sha256-128f-simple_clean": lambda msg: msg,
    "crypto_sign_stream_sphincs-sha256-128s-simple_clean": lambda msg: msg,
}


def _parse_args():
    parser = argparse.ArgumentParser("Program for testing PQC implementations on the NUCLEO-F207ZG.")
    parser.add_argument("target", help="Actual ELF target that is flashed and tested.")
    parser.add_argument("-n", "--num", type=int, help="Number of test cases to run.")
    parser.add_argument(
        "-v", "--verbosity", type=int,
        choices=[logging.DEBUG, logging.INFO, logging.ERROR, logging.CRITICAL],
        help="Specify loglevel. Lower number = More Verbosity.",
        default=logging.INFO
    )
    return parser.parse_args()


def main():
    args = _parse_args()
    logging.basicConfig(level=args.verbosity)
    log = logging.getLogger(__name__)

    target_path = args.target
    target_name = os.path.basename(args.target)

    if not os.path.isfile(target_path):
        log.error("Target file %s does not exist or is not a regular file.", target_path)
        sys.exit(1)

    try:
        cases = TestCases(target_name)
    except ValueError as ex:
        sys.exit(2)

    test_n = 0
    passed_n = 0

    if args.num:
        cases = cases[:args.num]

    for test_case in cases:
        for test in TESTS:
            if not flashing.reset_device():
                log.critical("Could not reset device. Halting.")
                sys.exit(3)
            test_n += 1
            t = test(test_case["sm"], test_case["pk"])
            test_name = t.__class__.__name__

            log.info("Doing test %s", test_name)

            scheme_name = "_".join(target_name.split("_")[:-1])
            s = stream.Stream(t.sm, t.pk, PK_HASH_FUNCTION[scheme_name])
            s.subscribe_message_type(stream.MessageType.RESULT, t.update_passed)
            s.stream()

            log.info("%s TEST %s on test case %s!", test_name, "PASSED" if t.passed else "FAILED", test_case["name"])
            passed_n += int(t.passed)
    failed = test_n - passed_n
    log.info("Out of %d test, %d passed and %d failed.", test_n, passed_n, failed)
    # Exit with != 0 when a test failed. This can be caught in scripts.
    if failed:
        sys.exit(255)


if __name__ == '__main__':
    main()
