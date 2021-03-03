#include "api.h"

int __attribute__((noinline)) crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen){
     /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    ctx->sm_chunk_size = smlen;
    ctx->pk_chunk_size = 32;
    return 0;
}


int __attribute__((noinline)) crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    /* to avoid inlining */
    asm("");
    if(pk_pos + ctx->pk_chunk_size == CRYPTO_PUBLICKEYBYTES){
        // we're done
        ctx->pk_chunk_size = 0;
    }
    return 0;
}

int __attribute__((noinline)) crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    /* to avoid inlining */
    asm("");
    return 0;
}

int __attribute__((noinline)) crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos) {
    /* to avoid inlining */
    asm("");
    if(sm_pos + ctx->sm_chunk_size == CRYPTO_BYTES){
        // we're done
        ctx->sm_chunk_size = 0;
    }
    return 0;
}
int __attribute__((noinline)) crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){
    /* to avoid inlining */
    asm("");
    return 0;
}