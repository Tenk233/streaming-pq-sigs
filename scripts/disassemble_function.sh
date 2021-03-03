#!/bin/bash
set -o nounset
set -o errexit

if [ $# -lt 2 ] ; then
    echo "ELF file or function name missing. Call: $0 elf_path func_name"
    echo "Example: $0 elf/crypto_sign_stream_falcon-512_opt-ct_serial.elf crypto_sign_open_consume_pk_chunk"
    exit 1
fi

arm-none-eabi-gdb -batch -ex "file ${1}" -ex "disassemble ${2}"
