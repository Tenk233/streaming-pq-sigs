[![forthebadge](https://forthebadge.com/images/badges/uses-badges.svg)](https://forthebadge.com) [![forthebadge](https://forthebadge.com/images/badges/powered-by-electricity.svg)](https://forthebadge.com)
# Streaming Post-Quantum Public Keys and Signatures
This repository contains the code accompanying the paper "Verifying Post-Quantum Signatures in 8 kB of RAM".

All benchmarking results claimed in the paper can be reproduced with this code.
It builds on top of [PQM3](https://github.com/mupq/pqm3) and [PQClean](https://github.com/pqclean/pqclean) libraries.

To get started, clone the repository:

```bash
git clone --recursive https://git.fslab.de/pqc/streaming-pq-sigs
```

**Only the STM NUCLEO-F207ZG** (nucleo-f207zg target of pqm3) is supported.
For a general setup of the board, see the [PQM3](https://github.com/mupq/pqm3) documentation.

## Prerequisites
In order to use the code in this repository, a list of software components needs to be installed:

* [An up to date ARM toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads)
* Python 3 with `pyserial` and `tabluate` packages installed. This can be done with `pip install -r streaming/requirements.txt`.
* [OpenOCD](http://openocd.org/), which is available as a package in all major Linux distributions
* Make, which is also available as a package in all major Linux distributions


## Adding a Scheme

To add a scheme, the following functions have to be added to its API:

```c
/* Initialize stream with given length of sm.
 * This function has to initialize the context ctx with chunk size etc.
 */
int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen);
/* Consume chunk of public key. */
int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
/* Includes the pk chunk into the pk validation hash. 
 * This hash is used to determine if the correct public key was streamed in
 */
int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
/* Consume chunk of sm. */
int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos);
/* Return result of verification process and the extracted message.
 * Signature was valid if this function returns 0.
 */
int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen);
```

The included schemes reside in the  [crypto_sign_stream](crypto_sign_stream/) folder.

## Building the Schemes
Every inlcuded scheme can be compiled into 4 targets:

* [test](crypto_sign_streaming/test.c) - Just runs the scheme
* [cycles](crypto_sign_streaming/cycles.c) - Reports cycle counts for all implemented functions
* [stack](crypto_sign_streaming/stack.c) - Reports stack usage
* [hashing](crypto_sign_stream/hashing.c) - Reports cycle counts spend in symmetric primitves

To build all targets, call:

```bash
make PLATFORM=nucleo-f207zg -j8
```

The outputted binaries are now in the `elf` folder.

## Test Data
The test data goes in the [streaming/test_data](streaming/test_data) directory.

Each target (elf file that can be build with make) has its own test_data subdirectory.
For example:
```
streaming/test_data/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
``` 
contains test data for this specific target. Since many targets of the same scheme need the same test data, symlinks can be used instead of directories.


Test cases are of the form:

```
sm: $SM_IN HEX
pk: $PK_IN_HEX
```

### Generating Test Cases
To generate test cases, the script [generate_testcases.sh](./scripts/generate_testcases.sh) can be used.
It uses the PQClean testvectors program.

It can be invoked like this:
```bash
./scripts/generate_testcases.sh $PQCLEAN_SCHEME_NAME $NUM_TEST_CASES $TARGET
```

* `$PQCLEAN_SCHEME_NAME` is the scheme's directory name within PQClean.
* `$NUM_TEST_CASES` is the number of test cases that should be procuced
* `$TARGET` is the target the test cases should be created for

To create 10 falcon-512 test cases for the

* `crypto_sign_stream_falcon-512_opt-ct_cycles.elf` 

target and place them into

* `streaming/test_data/streaming/test_data/crypto_sign_stream_falcon-512_opt-ct_cycles.elf`

, one can use this command:

```bash
./scripts/generate_testcases.sh  falcon-512 10 elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
```


## Tests
All target binaries can be tested, using the [test.py](streaming/test.py) script.

There are three tests included:

* **ValidTest**, checks if signature gets computed correctly
* **PKBitflipTest**, Flips a bit in the pubkey and fails if the signature verification still succeeds
* **SMBitflipTest**, Flips a bit in the sm value and fails if the signature verification still succeeds

### Running Tests on an Implementation
To test the [cycles.c](crypto_sign_stream/cycles.c) implementation with the `falcon-512` scheme do the following steps:

1. Build the binary
2. Flash the binary to the STM NUCLEO-F207ZG
3. Run the tests

Or in shell commands:
```bash
# 1
make PLATFORM=nucleo-f207zg -j8 ./elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
# 2
./scripts/flash.sh elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
# 3
python3 streaming/test.py elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
```

Supplying the `-h` option to `test.py` shows various command line parameters.
To enable DEBUG messages supply `-v 10`.

### Run All Tests
To run the tests on all available targets in the `elf` directory, call the `test_all.sh` script:

```bash
./scripts/test_all.sh
```

## Benchmarks
A benchmark sends benchmark results via a benchmark messages (e.g. `STREAM_SPEED_BENCHMARK`).

There are three benchmark implementations included:

* [cycles.c](crypto_sign_stream/cycles.c), measures cpu cycle counts
* [stack.c](crypto_sign_stream/stack.c), measures stack usage
* [hashing.c](crypto_sign_stream/hashing.c), measures how many cpu cycles are spend within symmetric primitives

### Runing Benchmarks on an Implementation
To run the `cycles.c` benchmark with the `falcon-512` scheme do the following steps:

1. Build the binary
2. Flash the binary to the STM NUCLEO-F207ZG
3. Run the benchmarks

Or in shell commands:
```bash
# 1
make PLATFORM=nucleo-f207zg -j8 ./elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
# 2
./scripts/flash.sh elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf
# 3
python3 streaming/benchmark.py elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf > benchmark.csv
```

Supplying the `-h` option to `benchmark.py` lists various command line parameters.
To enable DEBUG messages supply `-v 10`, supplying `-s` additionally measures the sizes of the binary's relevant sections.

### Run All Benchmarks
To run a benchmark on all available targets in the `elf` directory, call the [benchmark_all.sh](benchmark_all.sh) script with the benchmark name, e.g.:

```bash
./scripts/benchmark_all.sh cycles
```

The script will generate `csv` files in the `benchmarks` directory. 
One `csv` file per target is generated.
Every test case (see section *Test Data*) is run once and benchmarked.

To run **all** benchmarks on **all** targets, call the [run_all_experiments.sh](scripts/run_all_experiments.sh) script:

```bash
./scripts/run_all_experiments.sh
```

### Print Benchmarks
To print tables with benchmark results, call the [print_benchmarks.py](streaming/print_benchmarks.py) script:

```bash
./streaming/print_benchmarks.py
```

This requires the benchmarks to be located in the `benchmarks` folder.
Calling the script with `-h` prints out all supported parameters.

Important parameters:

* `-s` for selecting a specific scheme or multiple schemes
* `-f` specifying the output format (plain, html or latex)
* `-p` to output the final tables used in the paper
* `-l` supplies a different path (location) to look for benchmarks

Example calls:

```bash
# Print table in plain format with two selected schemes
./scripts/print_benchmarks.py -s falcon-512_opt-ct -s dilithium2_m3
# Print table in latex format for all schemes
./scripts/print_benchmarks.py -f latex
```

## Communication
A very simple protocol on top of UART is used to stream the signature and public key.
Communication works as follows:
```
[HOST]                 [M3 DEVICE]
        <---[Init]---
       ---[sm length]--->
      <---[req X bytes]---
       ---[send X bytes]-->
       <---[req X bytes]---
       ---[send X bytes]-->
       [...]
```

The length of `sm` (signed message) is transferred to the device, since it is not known during compile time. The possibility for the device to request chunks individually makes precise timing measurements possible. 
The sending and receiving of UART data is implemented with polling. This makes it possible to disable interrupts for precise timing measurement.

The device can send strings (e.g. for debugging purposes) to the host at any time.
