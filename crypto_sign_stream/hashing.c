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
u8 chunk[CRYPTO_STREAM_MAX_CHUNK_SIZE];


crypto_stream_ctx ctx;
u64 t0, t1;
int tmp_res;

unsigned long long aescycles;
unsigned long long sha2cycles;
unsigned long long sha3cycles;

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

void stream_pk() {
  stream_send_str("[DEVICE]Streaming pubkey.");
  aescycles = sha2cycles = sha3cycles = 0;
  u64 aes_hash, sha2_hash, sha3_hash;
  u64 aes_hash_accu = 0, sha2_hash_accu = 0, sha3_hash_accu = 0;

  t1 = 0;
  size_t pk_pos = 0;
  size_t chunk_size;
  while(ctx.pk_chunk_size > 0){
    chunk_size = ctx.pk_chunk_size;
    if (request_pk_chunk(chunk, pk_pos) != 0) {
      stream_send_str("[DEVICE]Could not request pk chunk");
    }

    aes_hash = aescycles;
    sha2_hash = sha2cycles;
    sha3_hash = sha3cycles;
    tmp_res = crypto_sign_open_hash_pk_chunk(&ctx, chunk, pk_pos);
    aes_hash_accu += aescycles - aes_hash;
    sha2_hash_accu += sha2cycles - sha2_hash;
    sha3_hash_accu += sha3cycles - sha3_hash;

    aescycles = aes_hash;
    sha2cycles = sha2_hash;
    sha3cycles = sha3_hash;

    if (tmp_res != 0) {
      stream_send_str("[DEVICE]Authenticity of the public key could not be verified!");
    }

    t0 = hal_get_time();
    tmp_res = crypto_sign_open_consume_pk_chunk(&ctx, chunk, pk_pos);
    t1 += hal_get_time() - t0;

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
  stream_send_benchmark("crypto_sign_open_consume_pk_chunk_aescycles", aescycles);
  stream_send_benchmark("crypto_sign_open_consume_pk_chunk_sha2cycles", sha2cycles);
  stream_send_benchmark("crypto_sign_open_consume_pk_chunk_sha3cycles", sha3cycles);

  stream_send_benchmark("crypto_sign_open_hash_pk_chunk_aescycles", aes_hash_accu);
  stream_send_benchmark("crypto_sign_open_hash_pk_chunk_sha2cycles", sha2_hash_accu);
  stream_send_benchmark("crypto_sign_open_hash_pk_chunk_sha3cycles", sha3_hash_accu);
}

void stream_sm(){
  stream_send_str("[DEVICE]Streaming signature.");
  aescycles = sha2cycles = sha3cycles = 0;
  t1 = 0;
  size_t sm_pos = 0;
  size_t chunk_size;
  while(ctx.sm_chunk_size > 0) {
    chunk_size = ctx.sm_chunk_size;
    if (request_sm_chunk(chunk, sm_pos) != 0) {
      stream_send_str("[DEVICE]Could not request sm chunk");
    }

    t0 = hal_get_time();
    tmp_res = crypto_sign_open_consume_sm_chunk(&ctx, chunk, sm_pos);
    t1 += hal_get_time() - t0;
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
  stream_send_benchmark("crypto_sign_open_consume_sm_chunk_cycles", t1);
  stream_send_benchmark("crypto_sign_open_consume_sm_chunk_aescycles", aescycles);
  stream_send_benchmark("crypto_sign_open_consume_sm_chunk_sha2cycles", sha2cycles);
  stream_send_benchmark("crypto_sign_open_consume_sm_chunk_sha3cycles", sha3cycles);
}


int main(void) {
  hal_setup(CLOCK_BENCHMARK);
  u32 mlen;
  u32 smlen;
  
  stream_init();

  smlen = stream_recv_sm_length();
  stream_send_str("[DEVICE]Received length");

  // Warning: In the real world the pk_hash would be embedded into the firmware.
  // As we don't want to do that in our experiments, we just copy it here
  u8 pk_hash[32];
  stream_recv_pk_hash(pk_hash);
  stream_send_str("[DEVICE]Received pk hash");

  
  aescycles = sha2cycles = sha3cycles = 0;
  t0 = hal_get_time();
  tmp_res = crypto_sign_open_init_stream(&ctx, smlen, pk_hash);
  t1 = hal_get_time() - t0;
  stream_send_benchmark("crypto_sign_open_init_stream_cycles", t1);
  stream_send_benchmark("crypto_sign_open_init_stream_aescycles", aescycles);
  stream_send_benchmark("crypto_sign_open_init_stream_sha2cycles", sha2cycles);
  stream_send_benchmark("crypto_sign_open_init_stream_sha3cycles", sha3cycles);

  while (tmp_res != 0) {
    stream_send_str("[DEVICE]Could not initialize streaming interface");
  } 

  #ifdef CRYPTO_STREAM_ORDER_PK_SM
    stream_pk(chunk);
    stream_sm(chunk);
  #elif defined(CRYPTO_STREAM_ORDER_SM_PK)
    stream_sm(chunk);
    stream_pk(chunk);
  #else
    #error "No streaming order (SM,PK or PK,SM) has been specified for this scheme."
  #endif

  aescycles = sha2cycles = sha3cycles = 0;
  t0 = hal_get_time();
  tmp_res = crypto_sign_open_get_result(&ctx, m, &mlen);
  t1 = hal_get_time() - t0;
  stream_send_benchmark("crypto_sign_open_get_result_cycles", t1);
  stream_send_benchmark("crypto_sign_open_get_result_aescycles", aescycles);
  stream_send_benchmark("crypto_sign_open_get_result_sha2cycles", sha2cycles);
  stream_send_benchmark("crypto_sign_open_get_result_sha3cycles", sha3cycles);

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
