#include "api.h"


#define VERIF_HASH_LEN 32
u8 pk_hash[VERIF_HASH_LEN];

int __attribute__((noinline)) crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen, u8 *pk_hash_init){
    size_t i;
     /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    ctx->sm_chunk_size = smlen;
    ctx->pk_chunk_size = 32;

    // Warning: In the real world the pk_hash would be embedded into the firmware.
    // As we don't want to do that in our experiments, we just copy it here
    for(i=0;i<VERIF_HASH_LEN;i++){
        pk_hash[i] = pk_hash_init[i];
    }

    return 0;
}


int __attribute__((noinline)) crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    (void) chunk;
    /* to avoid inlining */
    asm("");
    if(pk_pos + ctx->pk_chunk_size == CRYPTO_PUBLICKEYBYTES){
        // we're done
        ctx->pk_chunk_size = 0;
    }
    return 0;
}

int __attribute__((noinline)) crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    (void) chunk;
    (void) ctx;
    (void) pk_pos;
    /* to avoid inlining */
    asm("");
    return 0;
}

int __attribute__((noinline)) crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos) {
    (void) chunk;
    /* to avoid inlining */
    asm("");
    if(sm_pos + ctx->sm_chunk_size == CRYPTO_BYTES){
        // we're done
        ctx->sm_chunk_size = 0;
    }
    return 0;
}
int __attribute__((noinline)) crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){
    (void) ctx;
    (void) m;
    (void) mlen;
    /* to avoid inlining */
    asm("");
    return 0;
}