#ifndef _EVALMQNOCST_GF2_H
#define _EVALMQNOCST_GF2_H
#include "arch.h"
#include "matrix_gf2.h"
#include "tools_gf2nv.h"



UINT evalMQnocst_unrolled_no_simd_gf2(const UINT *m,
        const UINT *mq);



#define evalMQnocst_gf2 evalMQnocst_unrolled_no_simd_gf2



#endif
