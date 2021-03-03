#include "sign_openHFE.h"
#include "convMQ_gf2.h"
#include "tools_gf2nv.h"
#include "hash.h"
#include <stdlib.h>

#include "evalMQnocst_gf2.h"

//TODO: remove
#include <stdio.h>


#define SIZE_SIGN_UNCOMPRESSED (NB_WORD_GF2nv+(NB_ITE-1)*NB_WORD_GF2nvm)

/* Number of bits to complete the byte of sm64, in [0,7] */
#define VAL_BITS_M 6

/* Uncompress the signature */
void uncompress_signHFE(UINT *sm, const unsigned char *sm8) {
    unsigned char *sm64;
    unsigned int k2;

    sm64 = (unsigned char *)sm;
    /* Take the (n+v) first bits */
    for (k2 = 0; k2 < NB_BYTES_GFqnv; ++k2) {
        sm64[k2] = sm8[k2];
    }

    /* Clean the last byte */
    sm64[k2 - 1] &= MASK8_GF2nv;

    /* Take the (Delta+v)*(nb_ite-1) bits */
    unsigned int k1, nb_bits, nb_rem2, nb_rem_m, val_n;
    int nb_rem;

    /* HFEnv bits are already extracted from sm8 */
    nb_bits = HFEnv;
    sm64 += (NB_WORD_GF2nv << 3) + (HFEmq8 & 7U);

    for (k1 = 1; k1 < NB_ITE; ++k1) {
        /* Number of bits to complete the byte of sm8, in [0,7] */
        if ((24) < ((8 - (nb_bits & 7U)) & 7U)) {
            val_n = (24);
        } else {
            val_n = ((8 - (nb_bits & 7U)) & 7U);
        }

        /* First byte of sm8 */
        if (nb_bits & 7U) {
            *sm64 ^= (sm8[nb_bits >> 3] >> (nb_bits & 7U)) << HFEmr8;

            /* Number of bits to complete the first byte of sm8 */
            nb_rem = (int)((val_n - VAL_BITS_M));
            if (nb_rem >= 0) {
                /* We take the next byte since we used
                   VAL_BITS_M bits */
                ++sm64;
            }
            if (nb_rem > 0) {
                nb_bits += VAL_BITS_M;
                *sm64 ^= sm8[nb_bits >> 3] >> (nb_bits & 7U);
                nb_bits += nb_rem;
            } else {
                nb_bits += val_n;
            }
        }

        /* Other bytes of sm8 */
        nb_rem2 = (24) - val_n;
        /*nb_rem2 can be zero only in this case */
        /* Number of bits used of sm64, mod 8 */
        nb_rem_m = (HFEm + val_n) & 7U;

        /* Other bytes */
        if (nb_rem_m) {
            /* -1 to take the ceil of /8, -1 */
            for (k2 = 0; k2 < ((nb_rem2 - 1) >> 3); ++k2) {
                *sm64 ^= sm8[nb_bits >> 3] << nb_rem_m;
                ++sm64;
                *sm64 = sm8[nb_bits >> 3] >> (8 - nb_rem_m);

                nb_bits += 8;
            }
            /* The last byte of sm8, between 1 and 8 bits to put */
            *sm64 ^= sm8[nb_bits >> 3] << nb_rem_m;
            ++sm64;

            /* nb_rem2 between 1 and 8 bits */
            nb_rem2 = ((nb_rem2 + 7U) & 7U) + 1U;
            if (nb_rem2 > (8 - nb_rem_m)) {
                *sm64 = sm8[nb_bits >> 3] >> (8 - nb_rem_m);
                ++sm64;
            }

            nb_bits += nb_rem2;
        } else {
            /* We are at the beginning of the bytes of sm8 and sm64 */

            /* +7 to take the ceil of /8 */
            for (k2 = 0; k2 < ((nb_rem2 + 7) >> 3); ++k2) {
                *sm64 = sm8[nb_bits >> 3];
                nb_bits += 8;
                ++sm64;
            }
            /* The last byte has AT MOST 8 bits. */
            nb_bits -= (8 - (nb_rem2 & 7U)) & 7U;
        }

        /* Clean the last byte */
        sm64[-1] &= MASK8_GF2nv;

        /* We complete the word. Then we search the first byte. */
        sm64 += ((8 - (NB_BYTES_GFqnv & 7U)) & 7U) + (HFEmq8 & 7U);
    }
}


static void uncompress_last_equations(uint64_t *dest, const uint8_t *src){
    uint64_t cst = 0;
    size_t i;

    for (i = 0; i < (HFEmr8 - 1); i++) {
        cst ^= convMQ_uncompressL_gf2(dest + 1 + i * NB_WORD_UNCOMP_EQ,
                src + i * NB_BYTES_EQUATION) << i;
    }

    /* The last equation in input is smaller because compressed */
    cst ^= convMQ_last_uncompressL_gf2(dest + 1 + i * NB_WORD_UNCOMP_EQ,
            src + i * NB_BYTES_EQUATION) << i;

    cst <<= HFEmr - HFEmr8;
    *dest = cst;
}



void sign_openHFE_eval_last(uint64_t *acc, const uint64_t *vars,
                 const uint8_t *pk) {
    size_t i,j;
    uint64_t pk_last[1 + NB_WORD_UNCOMP_EQ * HFEmr8];
    uncompress_last_equations(pk_last, pk);
    uint64_t cst = pk_last[0];

    for (i = HFEmr - HFEmr8, j=0; i < HFEmr; ++i, ++j) {
        acc[HFEmq] ^= evalMQnocst_gf2(vars, pk_last + 1 + j*NB_WORD_UNCOMP_EQ) << i;
    }
    acc[HFEmq] ^= cst;
}



