#ifndef _EVALMQSNOCST8_QUO_GF2_H
#define _EVALMQSNOCST8_QUO_GF2_H
#include "arch.h"
#include "matrix_gf2.h"
#include "tools_gf2m.h"

#include <stddef.h>

void evalMQSnocst8_quo_gf2_column(uint64_t *c, cst_vecnv_gf2 m,
        const uint8_t *pk, int numChunks);

#endif
