#ifndef API_H
#define API_H

#include <stddef.h>
#include "config.h"
#include "types.h"
#include "params.h"
#include "streaming.h"

#define CRYPTO_STREAM_MAX_MSG_LEN 33
// if USE_MINIMUM_MEMORY is set, the implementation will use around 5656 bytes
// of memory, but will be slower (~2329k cycles)
// if it is not set, the implementation will use 8048 bytes, but only 1990k cycles
//#define USE_MINIMUM_MEMORY

#define CRYPTO_STREAM_MAX_CHUNK_SIZE 40

#define CRYPTO_STREAM_ORDER_SM_PK
#define MAX_STACK_CANARY_SIZE 0x10000

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

#endif
