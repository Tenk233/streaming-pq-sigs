#ifndef _ARCH_H
#define _ARCH_H
#include <inttypes.h>

#define ONE64  ((uint64_t)1)
#define NB_BITS_UINT 64

typedef uint64_t UINT;
#define UINT_1 ((UINT)1)

/** A reserved variable to do a for loop on a buffer of UINT. */
#define RESERVED_VARIABLE reserved_variable

#define FOR_LOOP(OP,SIZE) \
    {unsigned int RESERVED_VARIABLE; \
        for(RESERVED_VARIABLE=0U;RESERVED_VARIABLE<(SIZE);++RESERVED_VARIABLE) \
        { \
            OP;\
        } \
    }

/** Load a UINT from unsigned char * **/

#define LOAD_UINT(a, p) \
    (a) = (p)[7]; (a) <<= 8;\
    (a) |= (p)[6]; (a) <<= 8;\
    (a) |= (p)[5]; (a) <<= 8;\
    (a) |= (p)[4]; (a) <<= 8;\
    (a) |= (p)[3]; (a) <<= 8;\
    (a) |= (p)[2]; (a) <<= 8;\
    (a) |= (p)[1]; (a) <<= 8;\
    (a) |= (p)[0];

#define LOAD_UINT_ARRAY(a, p, N) \
    FOR_LOOP(LOAD_UINT((a)[RESERVED_VARIABLE], &(p)[8*RESERVED_VARIABLE]), (N))

#endif
