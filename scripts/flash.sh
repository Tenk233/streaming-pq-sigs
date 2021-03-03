#!/bin/bash
set -o nounset
set -o errexit


if [ $# -eq 0 ]; then
    echo "Target name missing. Call: $0 TARGET"
    echo "Example: $0 elf/crypto_sign_stream_falcon-512_opt-ct_cycles.elf"
    exit 1
fi

if [ ! -e $1 ]; then
	echo "File ${1} does not exist!"
	exit 1
fi

openocd -f nucleo-f2.cfg -c "program ${1} exit"