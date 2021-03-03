#include "evalMQSnocst8_quo_gf2.h"
#include "MQ_gf2.h"
#include <string.h>
#include <stdio.h>
#include "hal.h"

/* NB_VAR = NB_BITS_UINT*quo + rem */
#define NB_VAR (HFEnv)
#define NB_VARq (NB_VAR/NB_BITS_UINT)
#define NB_VARr (NB_VAR%NB_BITS_UINT)

/* NB_EQ = 8*quo + rem */
#define NB_EQ  (HFEm)
#define NB_EQq (NB_EQ>>3)
#define NB_EQr (NB_EQ&7)

extern int iq, ir, jq, jr;
static int skip = 0;

static inline void xor_column(uint8_t *acc, const uint8_t *column) {
    size_t j;
    for(j=0;j<NB_EQq;j++){
        acc[j] ^= column[j];
    }
}


static void inc_counters_nexti(void){
    ir++;

    if(ir >= NB_BITS_UINT) {
        iq++;
        ir = 0;
    }

    jq = iq;
    jr = ir;
}

static void inc_counters(int i){
    jr += i;
    if(jq < 2) { // 0 <= j < 128
        if(jr >= NB_BITS_UINT) {
            jr = 0;
            jq++;
        }
    } else { // 128 <= j < 186
        if(jr >= NB_VARr){
            inc_counters_nexti();
        }
    }
}

void evalMQSnocst8_quo_gf2_column(uint64_t *c, cst_vecnv_gf2 m,
        const uint8_t *pk, int numChunks) {
    uint64_t xi, xj;
    while(skip){
        skip--;
        numChunks--;
        pk += NB_EQq;
        if(numChunks == 0){
            return;
        }
    }
    // load first column of public key into c (only 32 bits of highest limb occupied)
    if(jr == -1){
        c[2] = 0;
        memcpy(c, pk, NB_EQq);
        inc_counters(1);
        pk += NB_EQq;
        numChunks--;
    }

    while(numChunks > 0) {
        xi = (m[iq] >> ir);
        if((xi & 1) == 0) {
            // skip i chunks
            numChunks -= NB_VAR - (iq*NB_BITS_UINT + ir);
            pk        += (NB_VAR - (iq*NB_BITS_UINT + ir))*NB_EQq;
            inc_counters_nexti();
            if(numChunks < 0){
               skip = -numChunks;
            }
        } else {
            xj = (m[jq] >> jr);
            if(jq < 2) {
                for (; jr< NB_BITS_UINT; jr++){
                    if(xj & 1)
                        xor_column((uint8_t *)c, pk);

                    pk += NB_EQq;
                    xj >>= 1;
                    if(--numChunks == 0){
                        inc_counters(1);
                        return;
                    }
                }
                inc_counters(0);
                if(jq == 1){
                    xj = m[jq];

                    for (jr = 0; jr < NB_BITS_UINT; jr++){
                        if(xj & 1)
                            xor_column((uint8_t *)c, pk);
                        pk += NB_EQq;
                        xj >>=1;
                        if(--numChunks == 0){
                            inc_counters(1);
                            return;
                        }
                    }
                }

                inc_counters(0);
                xj = m[jq];
                 for (; jr< NB_VARr; jr++){
                     if(xj & 1)
                         xor_column((uint8_t *)c, pk);
                     pk += NB_EQq;
                     xj >>= 1;
                     if(--numChunks == 0){
                         inc_counters(1);
                         return;
                     }
                 }
                 inc_counters(0);
            } else {
                for (; jr< NB_VARr; jr++){
                    if(xj & 1)
                        xor_column((uint8_t *)c, pk);

                    pk += NB_EQq;
                    xj >>= 1;
                    if(--numChunks == 0){
                        inc_counters(1);
                        return;
                    }
                }
                inc_counters(0);
            }
        }

    }
}
