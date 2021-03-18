#include "MQ_gf2.h"
#include "convMQ_gf2.h"
#include "parameters_HFE.h"



/* Number of lost bits by the zero padding of each equation
   (without the last) */
#define LOST_BITS ((HFEmr8-1)*HFENr8c)
/* Size of the last equation after to have removed the LOST_BITS last bits. */
#define SIZE_LAST_EQUATION ((NB_MONOMIAL_PK-((HFEmr8-1)*HFENr8c)+7)>>3)

#define HFEnvqm1 ((HFEnv-1)>>6)
#define HFEnvrm1 ((HFEnv-1)&63)

/**
 * @brief   Decompression of a compressed MQ equation in GF(2)[x1,...,x_(n+v)].
 * Both use a lower triangular matrix.
 * @details pk = (c,Q), with c the constant part in GF(2) and Q is a lower
 * triangular matrix of size (n+v)*(n+v) in GF(2). pk2 will have the same
 * format, but the equation will be decompressed. Here, the last byte of pk is
 * padded with null bits.
 * @param[in]   pk  A MQ equation in GF(2)[x1,...,x_(n+v)].
 * @param[out]  pk2 A MQ equation in GF(2)[x1,...,x_(n+v)].
 * @return  The constant c of pk2, in GF(2).
 * @remark  Requires to allocate NB_WORD_UNCOMP_EQ 64-bit words for pk2.
 * @remark  Requirement: at least NB_BYTES_EQUATION
 * + ((8-(NB_BYTES_EQUATION mod 8)) mod 8) bytes have to be allocated for pk
 * (because pk is casted in 64-bit, and the last memory access requires that
 * is allocated a multiple of 64 bits).
 * @remark  Constant-time implementation.
 */
UINT convMQ_uncompressL_gf2(uint64_t *pk2, const uint8_t *pk) {
    const uint8_t *pk64;
    unsigned int iq, ir, k, nb_bits;
    uint64_t t1, t2;

    pk64 = pk;

    nb_bits = 1;
    /* For each row */
    for (iq = 0; iq < HFEnvq; ++iq) {
        for (ir = 1; ir < 64; ++ir) {
            if (nb_bits & 63) {
                for (k = 0; k < iq; ++k) {
                    LOAD_UINT(t1, &pk64[8 * k])
                    LOAD_UINT(t2, &pk64[8 * (k + 1)])
                    pk2[k] = (t1 >> (nb_bits & 63))
                             ^ (t2 << (64 - (nb_bits & 63)));
                }

                LOAD_UINT(t1, &pk64[8 * k])
                pk2[k] = t1 >> (nb_bits & 63);
                if (((nb_bits & 63) + ir) > 64) {
                    LOAD_UINT(t1, &pk64[8 * (k + 1)])
                    pk2[k] ^= t1 << (64 - (nb_bits & 63));
                }

                if (((nb_bits & 63) + ir) >= 64) {
                    pk64 += 8;
                }
            } else {
                for (k = 0; k <= iq; ++k) {
                    LOAD_UINT(t1, &pk64[8 * k])
                    pk2[k] = t1;
                }
            }

            pk64 += 8 * iq;
            /* 0 padding on the last word */
            pk2[iq] &= (ONE64 << ir) - ONE64;
            pk2 += iq + 1;
            nb_bits += (iq << 6) + ir;
        }

        /* ir=64 */
        if (nb_bits & 63) {
            for (k = 0; k <= iq; ++k) {
                LOAD_UINT(t1, &pk64[8 * k])
                LOAD_UINT(t2, &pk64[8 * (k + 1)])
                pk2[k] = (t1 >> (nb_bits & 63)) ^ (t2 << (64 - (nb_bits & 63)));
            }
        } else {
            for (k = 0; k <= iq; ++k) {
                LOAD_UINT(t1, &pk64[8 * k])
                pk2[k] = t1;
            }
        }
        pk64 += 8 * (iq + 1);
        pk2 += iq + 1;
        nb_bits += (iq + 1) << 6;
    }

    for (ir = 1; ir <= HFEnvr; ++ir) {
        if (nb_bits & 63) {
            for (k = 0; k < iq; ++k) {
                LOAD_UINT(t1, &pk64[8 * k])
                LOAD_UINT(t2, &pk64[8 * (k + 1)])
                pk2[k] = (t1 >> (nb_bits & 63))
                         ^ (t2 << (64 - (nb_bits & 63)));
            }

            LOAD_UINT(t1, &pk64[8 * k])
            pk2[k] = t1 >> (nb_bits & 63);
            if (((nb_bits & 63) + ir) > 64) {
                LOAD_UINT(t1, &pk64[8 * (k + 1)])
                pk2[k] ^= t1 << (64 - (nb_bits & 63));
            }

            if (((nb_bits & 63) + ir) >= 64) {
                pk64 += 8;
            }
        } else {
            for (k = 0; k <= iq; ++k) {
                LOAD_UINT(t1, &pk64[8 * k])
                pk2[k] = t1;
            }
        }

        pk64 += 8 * iq;
        /* 0 padding on the last word */
        pk2[iq] &= (ONE64 << ir) - ONE64;
        pk2 += iq + 1;
        nb_bits += (iq << 6) + ir;
    }

    /* Constant */
    return (*pk) & 1;
}
