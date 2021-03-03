#include <stddef.h>
#include "streaming.h"
#include "types.h"

#define CRYPTO_SECRETKEYBYTES   1281
#define CRYPTO_PUBLICKEYBYTES   897
#define CRYPTO_BYTES            690

#define CRYPTO_ALGNAME          "Falcon-512"



int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, size_t *smlen,
	const unsigned char *m, size_t mlen,
	const unsigned char *sk);

int crypto_sign_open(unsigned char *m, size_t *mlen,
	const unsigned char *sm, size_t smlen,
	const unsigned char *pk);


#define CRYPTO_STREAM_MAX_CHUNK_SIZE CRYPTO_PUBLICKEYBYTES
#define CRYPTO_STREAM_MAX_MSG_LEN 33
#define CRYPTO_STREAM_ORDER_SM_PK
#define MAX_STACK_CANARY_SIZE 0x400
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
/* Consume chunk of sm. id is the number of the chunk. */
int crypto_sign_open_consume_sm_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t sm_pos);
/* Add chunk to internal hash of pubkey */
int crypto_sign_open_hash_pk_chunk(crypto_stream_ctx *ctx, u8 *chunk, size_t pk_pos);
/* Return result of verification process and the extracted message.
 * Signature was valid if this function returns 0.
 */
int crypto_sign_open_get_result(crypto_stream_ctx *ctx, u8 *m, u32 *mlen);