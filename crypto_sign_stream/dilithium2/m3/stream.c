#include "api.h"
#include "streaming.h"
#include "packing.h"
#include "sign.h"
#include "types.h"
#include "fips202.h"

#ifndef USE_MINIMUM_MEMORY
static u8 sm[CRYPTO_STREAM_MAX_MSG_LEN + CRYPTO_BYTES - 3*POLYZ_PACKEDBYTES];
// as we have memory leftover, we cache NTT(c) and NTT(z_0),NTT(z_1),NTT(z_2)
poly c_poly;
poly z_poly[3];
#else
static u8 sm[CRYPTO_STREAM_MAX_MSG_LEN + CRYPTO_BYTES];
#endif

/* This is where the hash of the public key would be */
#define VERIF_HASH_LEN 32
u8 pk_hash[VERIF_HASH_LEN];

static shake256incctx shake_s; // hash state for pk verification
static int result;             // will contain the verification result (0=valid)
static int k_idx;              // current index of the polynomial t1_i in the public to be processed next
static poly tmp_poly;          // work space used throughout verification
static size_t tmp_poly_pos;    // position within tmp_poly during streaing

static u8 pk_rho[SEEDBYTES];   // hold the seed of the public key (rho)
static shake256incctx w1_state;// incremental hashing state for computing h( h( h(pk) || m) || w1)




int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen, u8 *pk_hash_init) {
    size_t i;
    /* Stream sm one byte at a time */
    ctx->sm_len = smlen;
    // We stream the SM in two (or more chunks)
    ctx->sm_chunk_size = CRYPTO_STREAM_MAX_CHUNK_SIZE;
    ctx->pk_chunk_size = SEEDBYTES;
    /* Initialize state */
    shake256_inc_init(&shake_s);
    result = 0;
    k_idx = 0;
    if(ctx->sm_len < CRYPTO_BYTES) {
        result = -1;
        return -1;
    }

    // Warning: In the real world the pk_hash would be embedded into the firmware.
    // As we don't want to do that in our experiments, we just copy it here
    for(i=0;i<VERIF_HASH_LEN;i++){
        pk_hash[i] = pk_hash_init[i];
    }
    return 0;
}

int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    u8 streamed_pk_hash[32];
    shake256_inc_absorb(&shake_s, chunk, ctx->pk_chunk_size);

    if (pk_pos + ctx->pk_chunk_size >= CRYPTO_PUBLICKEYBYTES) {
        shake256_inc_finalize(&shake_s);
        shake256_inc_squeeze(streamed_pk_hash, VERIF_HASH_LEN, &shake_s);
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
static void polyt1_unpack_inline(int32_t *r, const uint8_t a[5]) {
  r[0] = ((a[0] >> 0) | ((uint32_t)a[1] << 8)) & 0x3FF;
  r[1] = ((a[1] >> 2) | ((uint32_t)a[2] << 6)) & 0x3FF;
  r[2] = ((a[2] >> 4) | ((uint32_t)a[3] << 4)) & 0x3FF;
  r[3] = ((a[3] >> 6) | ((uint32_t)a[4] << 2)) & 0x3FF;
}


static void __attribute__ ((noinline)) compute_w1_crh(shake256incctx *state,
                            uint8_t *msg, size_t msglen) {
    //absorb  CRH(h(rho, t1), msg) into w1_state
    u8 mu[CRHBYTES];
    shake256_inc_init(state);
    shake256_inc_absorb(state, pk_hash, VERIF_HASH_LEN);
    shake256_inc_absorb(state, msg, msglen);
    shake256_inc_finalize(state);
    shake256_inc_squeeze(mu, CRHBYTES, state);
    shake256_inc_init(state);
    shake256_inc_absorb(state, mu, CRHBYTES);
}


int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos){
    size_t i;
    if(pk_pos == 0){
        for(i=0;i<SEEDBYTES;i++) {
            pk_rho[i] = chunk[i];
        }
        ctx->pk_chunk_size = CRYPTO_STREAM_MAX_CHUNK_SIZE;
        k_idx = 0;
        tmp_poly_pos = 0;
        //absorb  CRH(h(rho, t1), msg) into w1_state
        #ifndef USE_MINIMUM_MEMORY
        compute_w1_crh(&w1_state, sm + CRYPTO_BYTES  - 3*POLYZ_PACKEDBYTES, ctx->sm_len - CRYPTO_BYTES);
        #else
        compute_w1_crh(&w1_state, sm + CRYPTO_BYTES, ctx->sm_len - CRYPTO_BYTES);
        #endif
    } else {
        size_t bytesleft = ctx->pk_chunk_size;
        while(bytesleft){
            polyt1_unpack_inline(&tmp_poly.coeffs[tmp_poly_pos], chunk);
            tmp_poly_pos += 4;
            bytesleft -= 5;
            chunk += 5;
            if(tmp_poly_pos == N){
                // for k_idx in 0,..., K-1
                // absorbs packed w1 into w1_state
                result |= crypto_sign_compute_w1(&w1_state, k_idx, &tmp_poly, sm, pk_rho);
                k_idx++;
                tmp_poly_pos = 0;
                if(k_idx == K){
                    ctx->pk_chunk_size = 0;
                }
            }
        }
    }
    return result;
}

int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos){
    for (u32 i = 0; i < ctx->sm_chunk_size; ++i)
    {
        #ifndef USE_MINIMUM_MEMORY
        // cache NTT(z_0), NTT(z_1), NTT(z_2)
        sm[sm_pos - k_idx*POLYZ_PACKEDBYTES] = chunk[i];
        sm_pos++;

        if((sm_pos == (SEEDBYTES + (k_idx+1)*POLYZ_PACKEDBYTES)) && k_idx < 3){
            unpack_sig_z_idx(&z_poly[k_idx], sm, 0);
             if(poly_chknorm(&z_poly[k_idx], GAMMA1 - BETA))
                return -1;
            poly_ntt_leaktime(&z_poly[k_idx]);
            k_idx++;
        }

        #else
        sm[sm_pos++] = chunk[i];
        #endif
    }
    if(sm_pos == ctx->sm_len){
        ctx->sm_chunk_size = 0;

        #ifndef USE_MINIMUM_MEMORY
        // cache NTT(c)
        const uint8_t *c = getoffset_sig_c(sm);
        poly_challenge(&c_poly, c);
        poly_ntt_leaktime(&c_poly);
        #endif

    } else if (sm_pos + ctx->sm_chunk_size > ctx->sm_len) {
        ctx->sm_chunk_size = ctx->sm_len - sm_pos;
    }
    return 0;
}


int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen){

    result |= crypto_sign_verify_w1(&w1_state, sm);


    size_t i;
    if(result){
        *mlen = -1;
        for(i = 0; i < ctx->sm_len; ++i)
            m[i] = 0;
        return -1;
    } else {
        *mlen = ctx->sm_len - CRYPTO_BYTES;
        for(i = 0; i < *mlen; ++i) {
            #ifndef USE_MINIMUM_MEMORY
            m[i] = sm[CRYPTO_BYTES - 3*POLYZ_PACKEDBYTES + i];
            #else
            m[i] = sm[CRYPTO_BYTES + i];
            #endif
        }
        return 0;
    }
}

