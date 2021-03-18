#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>
#include "streaming.h"
#include "types.h"
#include "params.h"


#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_BYTES 17088
#define CRYPTO_SEEDBYTES 48


/*
 * Returns the length of a secret key, in bytes
 */
size_t crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
size_t crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
size_t crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

/* TREE_HEIGHT * N + WOTS_BYTES = 608 */
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
#define WOTS_CHUNK_SIZE (WOTS_BYTES + TREE_HEIGHT * N)
#define WOTS_TREES_PER_CHUNK 8
#define FORS_AND_R_SIZE (FORS_BYTES + N)
#define WOTS_MULT_CHUNK_SIZE (WOTS_TREES_PER_CHUNK * WOTS_CHUNK_SIZE) 
#define CRYPTO_STREAM_MAX_CHUNK_SIZE MAX(FORS_AND_R_SIZE,WOTS_MULT_CHUNK_SIZE)
#define CRYPTO_STREAM_MAX_MSG_LEN 33
#define CRYPTO_STREAM_ORDER_PK_SM
#define MAX_STACK_CANARY_SIZE 0x10000
/* Init streaming interface.
   mode - Tell streaming interface a specific mode affecting e.g. num and size
   num - How many chunks are expected
   size - Size of each individual chunk
*/
/* Initialize stream with given length of sm.
 * This function has to initialize the context ctx with chunk size etc.
 */
int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen, u8 *pk_hash_init);
/* Consume chunk of public key. id is the number of the chunk. */
int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
/* Consume chunk of sm. id is the number of the chunk. */
int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos);
/* Return result of verification process and the extracted message.
 * Signature was valid if this function returns 0.
 */
int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen);

typedef enum {
    STREAM_STATE_BEGIN = 0,
    STREAM_STATE_RECOVERD_FORS_ROOT,
} stream_state;

#endif
