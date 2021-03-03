#ifndef _TOOLS_GF2NV_H
#define _TOOLS_GF2NV_H
#include "parameters_HFE.h"


/* n+v = NB_BITS_UINT*quo + rem */
#define HFEnvq (HFEnv/NB_BITS_UINT)
#define HFEnvr (HFEnv%NB_BITS_UINT)

#define HFEnvq8 (HFEnv>>3)
#define HFEnvr8 (HFEnv&7)
#define MASK8_GF2nv ((1U<<HFEnvr8)-1)
/* Number of bytes that an element of GF(2^(n+v)) needs */
#define NB_BYTES_GFqnv (HFEnvq8+1)

/* To choose macro for NB_WORD_GF2nv*64 bits */
#define NB_WORD_GF2nv 3
#define NB_WORD_GF2nvm (NB_WORD_GF2nv-NB_WORD_GF2m+1)
#endif
