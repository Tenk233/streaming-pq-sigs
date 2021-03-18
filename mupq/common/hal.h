#include <stdint.h>

#ifndef HAL_H
#define HAL_H

#include "types.h"

enum clock_mode {
    CLOCK_FAST,
    CLOCK_BENCHMARK
};

void hal_setup(const enum clock_mode clock);
void hal_send_str(const char* in);
uint64_t hal_get_time(void);

char hal_get_char();
void hal_recv_bytes_poll(u8 *dst, u32 n);
void hal_send_int_raw(const u32 n);
void hal_send_long_long_raw(const u64 n);
void hal_send_byte(const u8 c);

enum stream_msg_types {
    STREAM_INIT_MSG = 0,
    STREAM_DEBUG_STR,
    STREAM_CHUNK_REQUEST,
    STREAM_BENCHMARK,
    STREAM_RESULT,
    STREAM_DEBUG_BYTES
};

typedef enum {
    STREAM_CHUNK_PK = 0,
    STREAM_CHUNK_SM
} stream_chunk_type;

void stream_send_request(u32 offset, u32 size, stream_chunk_type type);
void stream_init();
unsigned int stream_recv_sm_length();
void stream_recv_pk_hash(u8 *pk_hash);
void stream_send_str(const char *pkg);
void stream_send_benchmark(const char *name, u64 result);
void stream_send_result(u32 result);
void stream_send_bytes(const char *name,const char *pkg, u32 len);

#endif
