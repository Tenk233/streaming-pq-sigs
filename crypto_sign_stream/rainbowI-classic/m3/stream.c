#include "streaming.h"
#include "api.h"
#include "rainbow_config.h"
#include "utils_hash.h"
#include "blas.h"
#include "blas_comm.h"
#include "rainbow_asm.h"
#include "sha2.h"

#include <string.h>

static u8 msg[CRYPTO_STREAM_MAX_MSG_LEN];
static u8 digest[_HASH_LEN];
static u8 salt[_SALT_BYTE];
static u8 sig_b[100];
// 32B, 64eq
static u32 y[15][32/4] = {{0},{0},{0},{0},{0},{0},{0},{0}};

/* Number of variables in a poly */
#define NUM_VARS 100
static u32 x_i, x_j;
static u32 x1, x2, xx;

/* This is where the hash of the actual public key would be */
#define VERIF_HASH_LEN 32
u8 pk_hash[VERIF_HASH_LEN];

sha256ctx sha2_ctx;

int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen, u8 *pk_hash_init){
    size_t i;
    /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    ctx->sm_chunk_size = smlen;
    
    ctx->pk_chunk_size = COLUMNS_PER_CHUNK*32;
    sha256_inc_init(&sha2_ctx);


    // Warning: In the real world the pk_hash would be embedded into the firmware.
    // As we don't want to do that in our experiments, we just copy it here
    for(i=0;i<VERIF_HASH_LEN;i++){
        pk_hash[i] = pk_hash_init[i];
    }
    return 0;
}

const uint8_t gf16mul_lut[] =
{
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd,
    0xe, 0xf, 0x0, 0x2, 0x3, 0x1, 0x8, 0xa, 0xb, 0x9, 0xc, 0xe, 0xf, 0xd, 0x4,
    0x6, 0x7, 0x5, 0x0, 0x3, 0x1, 0x2, 0xc, 0xf, 0xd, 0xe, 0x4, 0x7, 0x5, 0x6,
    0x8, 0xb, 0x9, 0xa, 0x0, 0x4, 0x8, 0xc, 0x6, 0x2, 0xe, 0xa, 0xb, 0xf, 0x3,
    0x7, 0xd, 0x9, 0x5, 0x1, 0x0, 0x5, 0xa, 0xf, 0x2, 0x7, 0x8, 0xd, 0x3, 0x6,
    0x9, 0xc, 0x1, 0x4, 0xb, 0xe, 0x0, 0x6, 0xb, 0xd, 0xe, 0x8, 0x5, 0x3, 0x7,
    0x1, 0xc, 0xa, 0x9, 0xf, 0x2, 0x4, 0x0, 0x7, 0x9, 0xe, 0xa, 0xd, 0x3, 0x4,
    0xf, 0x8, 0x6, 0x1, 0x5, 0x2, 0xc, 0xb, 0x0, 0x8, 0xc, 0x4, 0xb, 0x3, 0x7,
    0xf, 0xd, 0x5, 0x1, 0x9, 0x6, 0xe, 0xa, 0x2, 0x0, 0x9, 0xe, 0x7, 0xf, 0x6,
    0x1, 0x8, 0x5, 0xc, 0xb, 0x2, 0xa, 0x3, 0x4, 0xd, 0x0, 0xa, 0xf, 0x5, 0x3,
    0x9, 0xc, 0x6, 0x1, 0xb, 0xe, 0x4, 0x2, 0x8, 0xd, 0x7, 0x0, 0xb, 0xd, 0x6,
    0x7, 0xc, 0xa, 0x1, 0x9, 0x2, 0x4, 0xf, 0xe, 0x5, 0x3, 0x8, 0x0, 0xc, 0x4,
    0x8, 0xd, 0x1, 0x9, 0x5, 0x6, 0xa, 0x2, 0xe, 0xb, 0x7, 0xf, 0x3, 0x0, 0xd,
    0x6, 0xb, 0x9, 0x4, 0xf, 0x2, 0xe, 0x3, 0x8, 0x5, 0x7, 0xa, 0x1, 0xc, 0x0,
    0xe, 0x7, 0x9, 0x5, 0xb, 0x2, 0xc, 0xa, 0x4, 0xd, 0x3, 0xf, 0x1, 0x8, 0x6,
    0x0, 0xf, 0x5, 0xa, 0x1, 0xe, 0x4, 0xb, 0x2, 0xd, 0x7, 0x8, 0x3, 0xc, 0x6,
    0x9
};

int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    /*
     * Luckily all possible chunk sizes (16384 and 14144) are divisible by 64.
     */
    sha256_inc_blocks(&sha2_ctx, chunk, ctx->pk_chunk_size / 64);

    if (pk_pos + ctx->pk_chunk_size >= CRYPTO_PUBLICKEYBYTES) {
        u8 streamed_pk_hash[VERIF_HASH_LEN];
        sha256_inc_finalize(streamed_pk_hash, &sha2_ctx, NULL, 0);
        unsigned char cc = 0;
        for (unsigned int i = 0; i < VERIF_HASH_LEN; i++) {
            cc |= (streamed_pk_hash[i] ^ pk_hash[i]);
        }
        if (cc) {
            return -1;
        }
    }
    return 0;
}

int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    for (u32 k = 0; k < ctx->pk_chunk_size / 32; k++) {
        if (x_j >= NUM_VARS) {
            x_i++;
            x1 = sig_b[x_i];
            x_j = x_i;
        }

        x2 = sig_b[x_j++];
        xx = gf16mul_lut[(x2<<4) + x1];
        if (xx){
            for (int i=0; i < 8; i++) {
                y[xx-1][i] ^= ((u32*)chunk)[i];
            }
        }
        chunk += 32;
    }

    if(pk_pos + 2*ctx->pk_chunk_size > CRYPTO_PUBLICKEYBYTES)
        ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES - pk_pos - ctx->pk_chunk_size;
    return 0;
}

int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos) {
    (void) sm_pos;
    size_t i;
    // sm will be only one chunk

    unsigned int mlen = ctx->sm_len - CRYPTO_BYTES;
    for(i=0;i<mlen;i++){
        msg[i] = chunk[i];
    }

    hash_msg(digest, _HASH_LEN, chunk, mlen);
    chunk += mlen;

    for(i=0; i<_PUB_N_BYTE;i++){
        sig_b[2*i] = chunk[i] & 0xf;
        sig_b[2*i+1] = chunk[i] >> 4;
    }

    chunk += _PUB_N_BYTE;

    for(i=0; i<_SALT_BYTE;i++){
        salt[i] = chunk[i];
    }

    x1 = sig_b[0];

    ctx->sm_chunk_size = 0;
    return 0;
}
int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){
    unsigned char correct[_PUB_M_BYTE];
    unsigned char digest_salt[_HASH_LEN + _SALT_BYTE];

    memcpy(digest_salt, digest, _HASH_LEN);
    memcpy(digest_salt + _HASH_LEN, salt, _SALT_BYTE);
    hash_msg(correct, _PUB_M_BYTE, digest_salt, _HASH_LEN + _SALT_BYTE); // H( digest || salt )

    /* Do the actual multiplication on the bins */
    gf16v_bitslice_asm((uint8_t*)y[0], sizeof(y[0])/16);
    for (int i=1; i < 15; i++) {
        gf16v_madd_32B_asm(y[0], y[i], i+1);
    }
    gf16v_bitslice_asm((uint8_t*)y[0], sizeof(y[0])/16);

    u8 *digest_ck = (u8 *)y[0];
    // check consistancy.
    unsigned char cc = 0;
    for (unsigned int i = 0; i < _PUB_M_BYTE; i++) {
        cc |= (digest_ck[i] ^ correct[i]);
    }

    if(!cc) {
        *mlen = ctx->sm_len - CRYPTO_BYTES;
        memmove(msg, m, (size_t)(*mlen));
    } else {
        *mlen = 0;
    }
    return (0 == cc) ? 0 : -1;
}