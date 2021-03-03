# PQM3 with Streaming API
This is a fork of PQM3 used for an experiment with streaming signatures and public keys of post-quantum schemes.

**Only the STM NUCLEO-F207ZG** (nucleo-f207zg target of pqm3) is supported.
The communication between host and M3 board works via serial communication. 
For a setup, see the [PQM3](https://github.com/mupq/pqm3) documentation.

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

## Add a Scheme

To add a scheme, the following functions have to be added to its API:

```C
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

### Patching PQClean
To allow for non-deterministic test case generation, our patch has to be applied:

```bash
# Change into pqclean submodule
cd pqclean
# Apply patch
patch < ../patches/pqclean.patch -p1
```

This patch makes sure that actually random test cases are generated.
If it is not apploed, PQClean will always generate the same test case.

### Generating Test Cases
To generate test data, the script [generate_testcases.sh](./scripts/generate_testcases.sh) can be used.
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
./scripts/generate_testcases.sh  falcon-512 10 elf/crypto_sign_stream_falcon-512_opt-ct_test.elf
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
A benchmark sends benchmark results via a benchmark message (e.g. `STREAM_SPEED_BENCHMARK`).

There are three benchmark implementations included:

* [cycles.c](crypto_sign_stream/cycles.c), measuring cpu cycle counts
* [stack.c](crypto_sign_stream/stack.c), measuring stack usage
* [hashing.c](crypto_sign_stream/hashing.c), measuring how many cpu cycles are used within symmetric primitives

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

To run **all** benchmarks on **all** targets, call the [run_all_experiments.sh](run_all_experiments.sh) script:

```bash
./scripts/run_all_experiments.sh
```

### Print Benchmarks
To print tables with benchmark results, call the [print_benchmarks.py](streaming/print_benchmarks.py) script:

```bash
./streaming/print_benchmarks.py
```

Calling the script with `-h` prints out all supported parameters.

Important parameters:

* `-s` for selecting a specific scheme or multiple schemes
* `-f` specifying the output format (plain, html or latex)

Example calls:

```bash
# Print table in plain format with two selected schemes
./scripts/print_benchmarks.py -s falcon-512_opt-ct -s dilithium2_m3
# Print table in latex format for all schemes
./scripts/print_benchmarks.py -f latex
```

# PQM3

PQM3 contains _post quantum_ crypto schemes to the _Cortex M3_.

We target any scheme that is a finalist or alternate third round candidate in the [NIST competition](https://csrc.nist.gov/news/2020/pqc-third-round-candidate-announcement).
Our goal is to show which schemes are feasible for deployment om Cortex M3
devices, and show how they compare in speed and size.

This project is based on its sister project [`pqm4`](https://github.com/mupq/pqm4) and builds upon [`mupq`](https://github.com/mupq/mupq) and [`PQClean`](https://github.com/PQClean/PQClean)

## Getting started

We currently support multiple boards, but also support the schemes to be
emulated using QEMU. Let me get you up to speed:

```shell
# Clone the repository and cd into it.
git clone --recursive https://github.com/mupq/pqm3.git
cd pqm3

# Install all the required dependencies.
# Arch linux
sudo pacman -S arm-none-eabi-gcc arm-none-eabi-binutils qemu qemu-arch-extra

# Ubuntu
sudo apt install gcc-arm-none-eabi binutils-arm-none-eabi qemu-system-arm

# QEMU emulates the lm3s platform. So build all the schemes with `PLATFORM=lm3s`.
make -j PLATFORM=lm3s

# At this point there is a bunch of binaries in the `elf/` directory.
# You can run any of these binaries using `qemu-system-arm`. For example, to
# test kyber768, run:
qemu-system-arm -cpu cortex-m3 \
                -machine lm3s6965evb \
                -nographic \
                -semihosting-config enable=on,target=native \
                -kernel ./elf/crypto_kem_kyber768_m3_test.elf

# To kill the qemu emulator, press Ctrl+A and then X.
```

## Running on hardware

We currently support the following platforms:

- `lm3s`: The board emulated by QEMU (default).
- `sam3x8e`: The [Arduino Due](https://store.arduino.cc/arduino-due) development board.
- `nucleo-f207zg`: The [Nucleo STM32F207ZG](https://www.st.com/en/evaluation-tools/nucleo-f207zg.html).
<!-- This next link was broken on the ST website? Had the board been discontinued? -->
- `stm32l100c-disco`: The [STM32L100 Discovery board](https://web.archive.org/web/20200902192134/https://www.st.com/en/evaluation-tools/32l100cdiscovery.html).
  (See [#2](https://github.com/mupq/pqm3/pull/2))

### Arduino Due

For flashing the firmwares to the Arduino Due, we use the [Bossa](https://www.shumatech.com/web/products/bossa) tool.
We will use the `miniterm` serial monitor to read the output from the Arduino.

First, to compile for the Arduino Due, set the `PLATFORM` variable to `sam3x8e`.

The Arduino Due binaries are written to `bin/`, but are not built by default.
So you will have to tell `make` what you want.
For example, to produce a speed benchmark of Kyber768, plug in your Due and run:

```shell
make PLATFORM=sam3x8e ./bin/crypto_kem_kyber768_m3_speed.bin
# (You might need to run `make clean` first, if you previously built for a different platform.)

# Flash the binary using bossac.
bossac -a --erase --write --verify --boot=1 --port=/dev/ttyACM0 ./bin/crypto_kem_kyber768_m3_speed.bin

# Open the serial monitor.
miniterm.py /dev/ttyACM0

```

If everything went well, you should have gotten something looking like this:

```
--- Miniterm on /dev/ttyACM0  9600,8,N,1 ---
--- Quit: Ctrl+] | Menu: Ctrl+T | Help: Ctrl+T followed by Ctrl+H ---
==========================
keypair cycles:
1087702
encaps cycles:
1281392
decaps cycles:
1228259
OK KEYS
```

### Nucleo-F207ZG

For flashing the firmwares to the Nucleo-F207ZG board, you will need an up to date GIT version of [OpenOCD](http://openocd.org/) (we tested with commit `9a877a83a1c8b1f105cdc0de46c5cbc4d9e8799e`).
You may also need to [update the firmware](https://www.st.com/en/development-tools/stsw-link007.html) of the STLINK/v2-1 probe (we tested with version `V2J37M26`).
The [stlink](https://github.com/stlink-org/stlink) tool may also work, depending on the firmware version of your STLINK/v2-1 probe.
We use OpenOCD, as the `stlink` tool caused problems on our board.

To compile code for this board, pass the `PLATFORM=nucleo-f207zg` variable to make.
Then you can either flash the ELF or BIN files to your board using OpenOCD.

```shell
make PLATFORM=nucleo-f207zg -j4
openocd -f nucleo-f2.cfg -c "program elf/crypto_kem_kyber768_m3_speed.bin reset exit"
```

Alternatively, you could also debug the code using OpenOCD as a GDB server.

```shell
# Start the GDB Server (in another shell)
openocd -f nucleo-f2.cfg # This starts the GDB server
# Start GDB and...
arm-none-eabi-gdb -ex "target remote :3333" elf/crypto_kem_kyber768_m3_speed.bin
# ... `load` to flash, set your breakpoints with `break`, ...
```

The board also includes a serial interface that you can tap in with your favourite serial monitor.

```shell
# With miniterm...
miniterm.py /dev/ttyACM0
# ... or screen
screen /dev/ttyACM0 9600
```

### STM32L100 Discovery

`TODO: Write this when you get the board.`

## Build System

The build system of PQM3 is quite modular and supports multiple targets.
The main configuration is happening in the `common/config.mk` file.
This file will set the general compilation/linker flags that are
independent to the target platform.
It will then also include a platform dependent file, named after the
value of the `PLATFORM` variable (e.g., the `common/sam3x8e.mk` for the
Arduino DUE).
This platform dependent file will then set all the platform specific
compilation flags and define a `libpqm3hal.a` target that contains the
code for the platform abstraction layer.
Furthermore, this makefile should set the `EXCLUDED_SCHEMES` variable
that contains a list of patterns defining the Schemes that will not fit
this target platform.

The configuration can be parameterized by the following variables:

- `PLATFORM=<yourplatform>`: The chosen target board/platform.
- `DEBUG=1`: Compile all code without optimization and with debug symbols.
- `OPT_SIZE=1`: Optimize all code for size (otherwise the default is `-O3`).
- `LTO=1`: Enable link-time optimization.
- `AIO=1`: Use all-in-one compilation of schemes, i.e. pass all sources
  instead of compiled modules to the linking step (this can, in some
  cases, be faster than link-time optimization).

The `common/config.mk` also includes a mechanism that remembers all the
values of the the chosen configuration variables named above.
It will generate and include a `obj/.config.mk` file, that contains the
chosen configuration.
If you run `make` a second time with changed values, the compilation
will fail and you will have to run `make clean`.
This is to prevent accidental mixing of compiled code for different
platforms or different optimization levels.

The build system now also discovers and compiles all schemes it finds in
the configured search paths.
This mechanism is present in the `common/schemes.mk` file.
A small shell script is used to discover all folders containing schemes,
and the result is a `obj/.schemes.mk` file that is included by the make
file.
The make file will then define all library- and test-targets for all
schemes accordingly.

The build system will also build a library of symmetric ciphers and hash
functions that are used by the kem/sign schemes.
This is done in the `common/crypto.mk` file.
All code is compiled twice, once with and without the
`-DPROFILE_HASHING` compiler flag.
The flag should turn on profiling functionality in the library.
The `*_hashing` tests then use this profiled library instead of the
normal one.
