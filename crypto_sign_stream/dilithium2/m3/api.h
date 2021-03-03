#ifndef API_H
#define API_H

#include <stddef.h>
#include "config.h"
#include "types.h"
#include "streaming.h"


#if DILITHIUM_MODE == 2
#define CRYPTO_PUBLICKEYBYTES 1312
#define CRYPTO_SECRETKEYBYTES 2528
#define CRYPTO_BYTES 2420

#elif DILITHIUM_MODE == 3
#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_SECRETKEYBYTES 4016
#define CRYPTO_BYTES 3293

#elif DILITHIUM_MODE == 5
#define CRYPTO_PUBLICKEYBYTES 2592
#define CRYPTO_SECRETKEYBYTES 4880
#define CRYPTO_BYTES 4595

#else
#error "invalid DILITHIUM_MODE"
#endif


#define CRYPTO_STREAM_MAX_MSG_LEN 33
#define CRYPTO_STREAM_MAX_CHUNK_SIZE (CRYPTO_STREAM_MAX_MSG_LEN + CRYPTO_BYTES)
#define CRYPTO_STREAM_ORDER_SM_PK
#define MAX_STACK_CANARY_SIZE 0x10000
// #define crypto_sign_keypair DILITHIUM_NAMESPACE(_keypair)
// int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

// #define crypto_sign DILITHIUM_NAMESPACE()
// int crypto_sign(unsigned char *sm, size_t *smlen,
//                 const unsigned char *msg, size_t len,
//                 const unsigned char *sk);

#define crypto_sign_open DILITHIUM_NAMESPACE(_open)
int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen,
                     const unsigned char *pk);

/* Init streaming interface.
   mode - Tell streaming interface a specific mode affecting e.g. num and size
   num - How many chunks are expected
   size - Size of each individual chunk
*/
/* Initialize stream with given length of sm. 
 * This function has to initialize the context ctx with chunk size etc.
 */
int crypto_sign_open_init_stream(crypto_stream_ctx *ctx, u32 smlen);
/* Consume chunk of public key. id is the number of the chunk. */
int crypto_sign_open_consume_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
/* Consume chunk of sm. id is the number of the chunk. */
int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos);
/* Return result of verification process and the extracted message.
 * Signature was valid if this function returns 0.
 */
int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen);

#endif
