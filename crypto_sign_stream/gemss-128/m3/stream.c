#include "api.h"
#include "streaming.h"
#include "sign_openHFE.h"
#include "convMQ_gf2.h"
#include "hash.h"
#include "evalMQSnocst8_quo_gf2.h"
#include "types.h"
#include <string.h>
#include <stddef.h>
#include "fips202.h"

/* This is where the hash of the public key would be */
#define VERIF_HASH_LEN 32
u8 pk_hash[VERIF_HASH_LEN];
static shake128incctx shake_s;


#define SIZE_SIGN_UNCOMPRESSED (NB_WORD_GF2nv+(NB_ITE-1)*NB_WORD_GF2nvm)

/* NB_EQ = 8*quo + rem */
#define NB_EQ  (HFEm)
#define NB_EQq (NB_EQ>>3)
#define NB_EQr (NB_EQ&7)

static u64 sig[SIZE_SIGN_UNCOMPRESSED];
static u8  msg[CRYPTO_STREAM_MAX_MSG_LEN];

static u64 msg_hash[NB_ITE * SIZE_DIGEST_UINT];

static u64 acc0[NB_WORD_GF2nv] = {0};
static u64 acc1[NB_WORD_GF2nv] = {0};
static stream_state state;
int iq, ir, jq, jr;



int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen, u8 *pk_hash_init) {
    size_t i;
    /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    ctx->sm_chunk_size = smlen;

    ctx->pk_chunk_size = PK_CHUNK_SIZE;
    state = STREAM_IT_0;

    // Warning: In the real world the pk_hash would be embedded into the firmware.
    // As we don't want to do that in our experiments, we just copy it here
    for(i=0;i<VERIF_HASH_LEN;i++){
        pk_hash[i] = pk_hash_init[i];
    }


    iq = 0, ir = 0, jq = 0, jr = -1;
    return 0;
}

int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    // We stream the public key for every iteration, i.e., 4 times;
    // In each iteration we have to verify it.
    if(pk_pos == 0){
        shake128_inc_init(&shake_s);
    }
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

static void finish_iteration(uint64_t *acc, uint64_t *D, unsigned int i, const uint64_t *sm){
    unsigned int index;
    /* Compute Si = xor(p(S_i+1,X_i+1),D_i+1) */
    add2_gf2m(acc, D + i * SIZE_DIGEST_UINT);
    /* Compute Si||Xi */
    index = NB_WORD_GF2nv + (NB_ITE - 1 - i) * NB_WORD_GF2nvm;
    acc[NB_WORD_GF2m - 1] &= MASK_GF2m;
    /* Concatenation(Si,Xi): the intersection between S1 and X1 is
     * not null */
    acc[NB_WORD_GF2m - 1] ^= sm[index];
}
/* NB_VAR = NB_BITS_UINT*quo + rem */
#define NB_VAR (HFEnv)
#define NB_VARq (NB_VAR/NB_BITS_UINT)
#define NB_VARr (NB_VAR%NB_BITS_UINT)

int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    // the last 2 equations are stored in a compressed format that is annoying to uncompress
    // we just keep it around in uncompressed format.
    if(state == STREAM_IT_0){
        // apply first 160 equations of public map
        evalMQSnocst8_quo_gf2_column(acc0, sig, chunk, ctx->pk_chunk_size / HFEmq8);
        if(pk_pos + ctx->pk_chunk_size == OFFSET_LAST_EQUATIONS) {
            state = STREAM_LAST_0;
            ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES - OFFSET_LAST_EQUATIONS;
        }
    } else if(state == STREAM_LAST_0) {
        // apply last 2 equations
        sign_openHFE_eval_last(acc0, sig, chunk);
        // add hash to accumulator
        finish_iteration(acc0, msg_hash, 3, sig);

        state = STREAM_IT_1;
        iq = 0, ir = 0, jq = 0, jr = -1;
        ctx->pk_chunk_size = PK_CHUNK_SIZE;
    } else if(state == STREAM_IT_1){
        evalMQSnocst8_quo_gf2_column(acc1, acc0, chunk, ctx->pk_chunk_size / HFEmq8);
        if(pk_pos + ctx->pk_chunk_size == OFFSET_LAST_EQUATIONS) {
            state = STREAM_LAST_1;
            ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES - OFFSET_LAST_EQUATIONS;
        }
    } else if(state == STREAM_LAST_1){
        sign_openHFE_eval_last(acc1, acc0, chunk);
        finish_iteration(acc1, msg_hash, 2, sig);
        state = STREAM_IT_2;
        iq = 0, ir = 0, jq = 0, jr = -1;
        ctx->pk_chunk_size = PK_CHUNK_SIZE;
        // do nothing
    } else if(state == STREAM_IT_2){
        evalMQSnocst8_quo_gf2_column(acc0, acc1, chunk, ctx->pk_chunk_size / HFEmq8);
        if(pk_pos + ctx->pk_chunk_size == OFFSET_LAST_EQUATIONS) {
            state = STREAM_LAST_2;
            ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES - OFFSET_LAST_EQUATIONS;
        }
    } else if(state == STREAM_LAST_2){
        sign_openHFE_eval_last(acc0, acc1, chunk);
        finish_iteration(acc0, msg_hash, 1, sig);
        state = STREAM_IT_3;
        iq = 0, ir = 0, jq = 0, jr = -1;
        ctx->pk_chunk_size = PK_CHUNK_SIZE;
    } else if(state == STREAM_IT_3){
        evalMQSnocst8_quo_gf2_column(acc1, acc0, chunk, ctx->pk_chunk_size / HFEmq8);
        if(pk_pos + ctx->pk_chunk_size == OFFSET_LAST_EQUATIONS) {
            state = STREAM_LAST_3;
            ctx->pk_chunk_size = CRYPTO_PUBLICKEYBYTES - OFFSET_LAST_EQUATIONS;
        }
    } else if(state == STREAM_LAST_3) {
        sign_openHFE_eval_last(acc1, acc0, chunk);
        // we are done now
        state = STREAM_DONE;
        ctx->pk_chunk_size = 0;
    }

    // the last chunk needs to be smaller
    if((state == STREAM_IT_0 || state == STREAM_IT_1 || state == STREAM_IT_2 || state == STREAM_IT_3)
        && pk_pos + 2*PK_CHUNK_SIZE >= OFFSET_LAST_EQUATIONS && pk_pos + PK_CHUNK_SIZE < CRYPTO_PUBLICKEYBYTES) {
        ctx->pk_chunk_size = OFFSET_LAST_EQUATIONS - PK_CHUNK_SIZE - pk_pos;
    }

    return 0;
}

int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos){
    (void) sm_pos;
    size_t i;
    // copy message
    memcpy(msg, chunk + CRYPTO_BYTES, ctx->sm_len - CRYPTO_BYTES);
    // uncompress signature
    uncompress_signHFE(sig, chunk);

    /* Compute H1 = H(m), the m first bits are D1 */
    HASH((unsigned char *)msg_hash, msg, ctx->sm_len - CRYPTO_BYTES);

    for (i = 1; i < NB_ITE; ++i) {
        /* Compute Hi = H(H_(i-1)), the m first bits are Di */
        HASH((unsigned char *)(msg_hash + i * SIZE_DIGEST_UINT),
             (unsigned char *)(msg_hash + (i - 1)*SIZE_DIGEST_UINT), SIZE_DIGEST);
        /* Clean the previous hash (= extract D_(i-1) from H_(i-1)) */
        msg_hash[SIZE_DIGEST_UINT * (i - 1) + NB_WORD_GF2m - 1] &= MASK_GF2m;
    }
    /* Clean the previous hash (= extract D_(i-1) from H_(i-1)) */
    msg_hash[SIZE_DIGEST_UINT * (i - 1) + NB_WORD_GF2m - 1] &= MASK_GF2m;


    ctx->sm_chunk_size = 0;
    return 0;
}


int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){
    int result;
    *mlen = ctx->sm_len - CRYPTO_BYTES;
    result = !isEqual_nocst_gf2m(acc1, msg_hash);
    if(!result) {
        memmove(m, msg, (size_t)(*mlen));
    }
    return result;
}

