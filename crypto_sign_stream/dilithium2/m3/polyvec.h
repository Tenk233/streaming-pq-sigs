#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;

#define polyvecl_chknorm DILITHIUM_NAMESPACE(_polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, int32_t B);


#endif
