import sys
from subprocess import check_output

_symbol_names = """cshake128_simple
cshake128_simple_absorb
cshake128_simple_squeezeblocks
cshake256_simple
cshake256_simple_absorb
cshake256_simple_squeezeblocks
sha3_256
sha3_256_inc_absorb
sha3_256_inc_ctx_clone
sha3_256_inc_ctx_release
sha3_256_inc_finalize
sha3_256_inc_init
sha3_384
sha3_384_inc_absorb
sha3_384_inc_ctx_clone
sha3_384_inc_ctx_release
sha3_384_inc_finalize
sha3_384_inc_init
sha3_512
sha3_512_inc_absorb
sha3_512_inc_ctx_clone
sha3_512_inc_ctx_release
sha3_512_inc_finalize
sha3_512_inc_init
shake128
shake128_absorb
shake128_ctx_clone
shake128_ctx_release
shake128_inc_absorb
shake128_inc_ctx_clone
shake128_inc_ctx_release
shake128_inc_finalize
shake128_inc_init
shake128_inc_squeeze
shake128_squeezeblocks
shake256
shake256_absorb
shake256_ctx_clone
shake256_ctx_release
shake256_inc_absorb
shake256_inc_ctx_clone
shake256_inc_ctx_release
shake256_inc_finalize
shake256_inc_init
shake256_inc_squeeze
shake256_squeezeblocks
crypto_hashblocks_sha256.isra.0
sha224
sha224_inc_blocks
sha224_inc_ctx_clone
sha224_inc_ctx_release
sha224_inc_finalize
sha224_inc_init
sha256
sha256_inc_blocks
sha256_inc_ctx_clone
sha256_inc_ctx_release
sha256_inc_finalize
sha256_inc_init
sha384
sha384_inc_blocks
sha384_inc_ctx_clone
sha384_inc_ctx_release
sha384_inc_finalize
sha384_inc_init
sha512
sha512_inc_blocks
sha512_inc_ctx_clone
sha512_inc_ctx_release
sha512_inc_finalize
sha512_inc_init
cshake128
cshake128_inc_absorb
cshake128_inc_ctx_clone
cshake128_inc_ctx_release
cshake128_inc_finalize
cshake128_inc_init
cshake128_inc_squeeze
cshake256
cshake256_inc_absorb
cshake256_inc_ctx_clone
cshake256_inc_ctx_release
cshake256_inc_finalize
cshake256_inc_init
cshake256_inc_squeeze"""

SYMBOL_NAMES = set(_symbol_names.split("\n"))

def get_symbol_sizes(target):
    outp = check_output(f"nm --print-size {target}", shell=True).decode()
    total_size = 0
    for line in outp.split('\n'):
        print(line)
        for sym in SYMBOL_NAMES:
            if sym in line:
                print(line)
                size = line.split(" ")[1]
                total_size += int(size, 16)
    return total_size

target = sys.argv[1]
print(get_symbol_sizes(target))
