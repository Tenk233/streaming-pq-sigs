#ifndef _MQ_GF2_H
#define _MQ_GF2_H
#include "arch.h"
#include "parameters_HFE.h"
#include "tools_gf2nv.h"


/* Number of monomial */
#define NB_MONOMIAL_PK (((HFEnv*(HFEnv+1))>>1)+1)

#define HFENr8 (NB_MONOMIAL_PK&7)
#define NB_BYTES_EQUATION ((NB_MONOMIAL_PK+7)>>3)
#define HFENr8c ((8-HFENr8)&7)


/* Size for an uncompressed equation */
#define NB_WORD_UNCOMP_EQ \
    ((((HFEnvq*(HFEnvq+1))>>1)*NB_BITS_UINT)+(HFEnvq+1)*HFEnvr)



#endif
