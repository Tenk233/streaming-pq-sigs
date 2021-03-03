#ifndef _SIGN_OPENHFE_H
#define _SIGN_OPENHFE_H
#include "arch.h"
#include <stddef.h>
#include <stdint.h>

void uncompress_signHFE(UINT *sm, const unsigned char *sm8);
void sign_openHFE_eval_last(uint64_t *acc, const uint64_t *vars, const uint8_t *pk);



#endif
