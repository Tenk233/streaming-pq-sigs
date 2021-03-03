#ifndef _TOOLS_GF2M_H
#define _TOOLS_GF2M_H
#include "parameters_HFE.h"


#define XOR1_2(c,a) \
    (c)[0]^=(a)[0];

#define XOR2_2(c,a) \
    XOR1_2(c,a);\
    (c)[1]^=(a)[1];

#define XOR3_2(c,a) \
    XOR2_2(c,a);\
    (c)[2]^=(a)[2];

#define ADD3_2_GF2X XOR3_2


/* Equality */
#define ISEQUAL1_NOCST(a,b) ((a)[0]==(b)[0])
#define ISEQUAL2_NOCST(a,b) (ISEQUAL1_NOCST(a,b)&&((a)[1]==(b)[1]))
#define ISEQUAL3_NOCST(a,b) (ISEQUAL2_NOCST(a,b)&&((a)[2]==(b)[2]))

/* m = NB_BITS_UINT*quo + rem */
#define HFEmq (HFEm/NB_BITS_UINT)
#define HFEmr (HFEm%NB_BITS_UINT)
/* Mask to truncate the last word */
#define MASK_GF2m ((UINT_1<<(HFEmr))-UINT_1)


#define HFEmq8 (HFEm>>3)
#define HFEmr8 (HFEm&7U)

/** Auxiliar macro. */
#define CONCAT2(a,b) a ## b
/** This macro permits to concat the names. */
#define CONCAT(a,b) CONCAT2(a,b)


/* To choose macro for NB_WORD_GF2m*64 bits */
#define NB_WORD_GF2m 3

#define CONCAT_NB_WORD_GF2m_SUP(name) CONCAT(name,NB_WORD_GF2m)


#define add2_gf2m CONCAT(CONCAT_NB_WORD_GF2m_SUP(ADD),_2_GF2X)
#define isEqual_nocst_gf2m CONCAT(CONCAT_NB_WORD_GF2m_SUP(ISEQUAL),_NOCST)

#endif
