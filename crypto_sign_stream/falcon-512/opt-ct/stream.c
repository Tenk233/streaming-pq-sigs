#include "api.h"
#include "streaming.h"
#include "types.h"
#include "fips202.h"

static u8 sm[CRYPTO_STREAM_MAX_MSG_LEN + CRYPTO_BYTES];
static u8 pk[CRYPTO_PUBLICKEYBYTES];
/* This is where the hash of the public key would be */
#define VERIF_HASH_LEN 32
const u8 pk_hash[VERIF_HASH_LEN] = {0};
static shake128incctx shake_s;

int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen) {
    /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    ctx->sm_chunk_size = smlen;
    
    ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES;
    /* Initialize state */
    shake128_inc_init(&shake_s);
    return 0;
}

int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    shake128_inc_absorb(&shake_s, chunk, ctx->pk_chunk_size);

    if (pk_pos + ctx->pk_chunk_size >= CRYPTO_PUBLICKEYBYTES) {
        u8 streamed_pk_hash[VERIF_HASH_LEN];
        shake128_inc_finalize(&shake_s);
        shake128_inc_squeeze(streamed_pk_hash, VERIF_HASH_LEN, &shake_s);
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
    for (u32 i = 0; i < ctx->pk_chunk_size; ++i)
    {
        pk[pk_pos++] = chunk[i];
    }
    ctx->pk_chunk_size = 0;
    return 0;
}

int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos){
    for (u32 i = 0; i < ctx->sm_chunk_size; ++i)
    {
        sm[sm_pos++] = chunk[i];
    }
    ctx->sm_chunk_size = 0;
    return 0;
}


int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){
    return crypto_sign_open(m, (size_t*)mlen, sm, ctx->sm_len, pk);
}

