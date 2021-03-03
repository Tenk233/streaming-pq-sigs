#include "api.h"
#include "randombytes.h"
#include "hal.h"
#include "sendfn.h"
#include "streaming.h"
#include "types.h"


#include <stdio.h>
#include <string.h>

#define printcycles(S, U) send_unsignedll((S), (U))

#define MLEN 33

/* sm + pk */
u8 m[MLEN];
u8 m_out[MLEN + CRYPTO_BYTES];


crypto_stream_ctx ctx;
u64 t0, t1;
int tmp_res;

int request_pk_chunk(u8 *dst, size_t pk_pos) {

  if ((pk_pos + ctx.pk_chunk_size) > CRYPTO_PUBLICKEYBYTES) {
    /* invalid position */
    return -1;
  }

  // Request new chunk
  stream_send_request(pk_pos, ctx.pk_chunk_size, STREAM_CHUNK_PK);

  for (u32 i = 0; i < ctx.pk_chunk_size; ++i)
  {
    *dst = hal_get_char();
    dst++;
  }
  return 0;
}

int request_sm_chunk(u8 *dst, size_t sm_pos) {
   if ((sm_pos + ctx.sm_chunk_size) > (MLEN + CRYPTO_BYTES)) {
    /* invalid position */
    return -1;
  }

  // Request new chunk
  stream_send_request(sm_pos, ctx.sm_chunk_size, STREAM_CHUNK_SM);

  for (u32 i = 0; i < ctx.sm_chunk_size; ++i)
  {
    *dst = hal_get_char();
    dst++;
  }

  return 0;
}

unsigned int canary_size = MAX_STACK_CANARY_SIZE;
volatile unsigned char *p;
unsigned int c;
uint8_t canary = 0x42;

#define FILL_STACK()                                                           \
  p = &a;                                                                      \
  while (p > &a - canary_size)                                                    \
    *(p--) = canary;
#define CHECK_STACK()                                                         \
  c = canary_size;                                                                \
  p = &a - canary_size + 1;                                                       \
  while (*p == canary && p <= &a) {                                             \
    p++;                                                                       \
    c--;                                                                       \
  }           

u32 max_stack_usage = 0;
size_t pk_pos = 0;
size_t chunk_size;

void stream_pk(u8 *chunk) {
  volatile unsigned char a;
  stream_send_str("[DEVICE]Streaming pubkey.");
  while(ctx.pk_chunk_size > 0){
    chunk_size = ctx.pk_chunk_size;
    if (request_pk_chunk(chunk, pk_pos) != 0) {
      stream_send_str("[DEVICE]Could not request pk chunk");
    }

    FILL_STACK();
    tmp_res = crypto_sign_open_hash_pk_chunk(&ctx, chunk, pk_pos);
    CHECK_STACK();

    if (c > max_stack_usage){
      max_stack_usage = c;
    }
    if (tmp_res != 0) {
      stream_send_str("[DEVICE]Authenticity of the public key could not be verified!");
    }

    FILL_STACK();
    tmp_res = crypto_sign_open_consume_pk_chunk(&ctx, chunk, pk_pos);
    CHECK_STACK();

    if (c > max_stack_usage){
      max_stack_usage = c;
    }

    if (tmp_res != 0) {
      stream_send_str("[DEVICE]Could not consume pk chunk");
    }

    pk_pos += chunk_size;
    // after the pk has ended, we just start from the start again
    // This functionality is currently only used by GeMSS as it needs the pk 4 tims
    if(pk_pos >= CRYPTO_PUBLICKEYBYTES) {
      pk_pos = 0;
    }
  }
}
  size_t sm_pos = 0;

void stream_sm(u8 *chunk){
  volatile unsigned char a;
  stream_send_str("[DEVICE]Streaming signature.");
  while(ctx.sm_chunk_size > 0) {
    chunk_size = ctx.sm_chunk_size;
    if (request_sm_chunk(chunk, sm_pos) != 0) {
      stream_send_str("[DEVICE]Could not request sm chunk");
    }


    FILL_STACK();
    tmp_res = crypto_sign_open_consume_sm_chunk(&ctx, chunk, sm_pos);
    CHECK_STACK();

    if (c > max_stack_usage){
      max_stack_usage = c;
    }
    if (tmp_res != 0) {
      stream_send_str("[DEVICE]Could not consume sm chunk");
    }


    sm_pos += chunk_size;
    // after the signature has ended, we just start from the start again
    // This functionality is currently not used, but just to be consistent with the pk streaming
    if(sm_pos >= ctx.sm_len){
      sm_pos = 0;
    }
  }
}

u8 chunk[CRYPTO_STREAM_MAX_CHUNK_SIZE];
u32 mlen;
u32 smlen;

int main(void) {
  volatile unsigned char a;
  hal_setup(CLOCK_BENCHMARK);
  
  stream_init();

  smlen = stream_recv_sm_length();
  stream_send_str("[DEVICE]Received length");
  
  FILL_STACK();
  tmp_res = crypto_sign_open_init_stream(&ctx, smlen);
  CHECK_STACK();
  stream_send_benchmark("crypto_sign_open_init_stream_stack", c);
  

  while (tmp_res != 0) {
    stream_send_str("[DEVICE]Could not initialize streaming interface");
  } 

  #ifdef CRYPTO_STREAM_ORDER_PK_SM
    stream_pk(chunk);
    stream_send_benchmark("crypto_sign_open_consume_pk_chunk_stack", max_stack_usage);
    max_stack_usage = 0;
    stream_sm(chunk);
    stream_send_benchmark("crypto_sign_open_consume_sm_chunk_stack", max_stack_usage);
  #elif defined(CRYPTO_STREAM_ORDER_SM_PK)
    stream_sm(chunk);
    stream_send_benchmark("crypto_sign_open_consume_sm_chunk_stack", max_stack_usage);
    max_stack_usage = 0;
    stream_pk(chunk);
    stream_send_benchmark("crypto_sign_open_consume_pk_chunk_stack", max_stack_usage);
  #else
    #error "No streaming order (SM,PK or PK,SM) has been specified for this scheme."
  #endif

  FILL_STACK();
  tmp_res = crypto_sign_open_get_result(&ctx, m, &mlen);
  CHECK_STACK();
  stream_send_benchmark("crypto_sign_open_get_result_stack", c);

  if (tmp_res == 0){
    stream_send_str("[RESULT]Signature valid!");
    stream_send_result(1);
  } else {
    stream_send_str("[RESULT]Signature invalid!");
    stream_send_result(0);
  }

  while(1);
 
  return 0;
}
