#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "streaming.h"
#include "tools_gf2m.h"
#include "MQ_gf2.h"


#define CRYPTO_ALGNAME                      "gemss-128"

#define CRYPTO_SECRETKEYBYTES               16
#define CRYPTO_PUBLICKEYBYTES               352188
#define CRYPTO_BYTES                        33

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *msg, size_t len, const uint8_t *sk);
int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);
int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);


#define OFFSET_LAST_EQUATIONS (NB_MONOMIAL_PK*HFEmq8)
#define PK_CHUNK_SIZE (HFEmq8*500)
#define PK_LAST_CHUNK_SIZE (CRYPTO_PUBLICKEYBYTES-OFFSET_LAST_EQUATIONS)

#define CRYPTO_STREAM_MAX_MSG_LEN 33
#define CRYPTO_STREAM_MAX_CHUNK_SIZE (PK_LAST_CHUNK_SIZE > PK_CHUNK_SIZE ? PK_LAST_CHUNK_SIZE: PK_CHUNK_SIZE)
#define CRYPTO_STREAM_ORDER_SM_PK
#define MAX_STACK_CANARY_SIZE 0x10000
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


typedef enum {
    STREAM_IT_0,
    STREAM_LAST_0,
    STREAM_IT_1,
    STREAM_LAST_1,
    STREAM_IT_2,
    STREAM_LAST_2,
    STREAM_IT_3,
    STREAM_LAST_3,
    STREAM_DONE
} stream_state;

#endif
