#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
  int32_t coeffs[N];
} poly __attribute__((aligned(32)));

#define poly_reduce DILITHIUM_NAMESPACE(_poly_reduce)
void poly_reduce(poly *a);
#define poly_caddq DILITHIUM_NAMESPACE(_poly_caddq)
void poly_caddq(poly *a);

#define poly_sub DILITHIUM_NAMESPACE(_poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
#define poly_shiftl DILITHIUM_NAMESPACE(_poly_shiftl)
void poly_shiftl(poly *a);

#define poly_ntt_leaktime DILITHIUM_NAMESPACE(_poly_ntt_leaktime)
void poly_ntt_leaktime(poly *a);
#define poly_invntt_tomont_leaktime DILITHIUM_NAMESPACE(_poly_invntt_tomont_leaktime)
void poly_invntt_tomont_leaktime(poly *a);

#define poly_pointwise_montgomery_leaktime DILITHIUM_NAMESPACE(_poly_pointwise_montgomery_leaktime)
void poly_pointwise_montgomery_leaktime(poly *c, const poly *a, const poly *b);
#define poly_pointwise_acc_montgomery_leaktime DILITHIUM_NAMESPACE(_poly_pointwise_acc_montgomery_leaktime)
void poly_pointwise_acc_montgomery_leaktime(poly *c, const poly *a, const poly *b);

#define poly_use_hint DILITHIUM_NAMESPACE(_poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h);

#define poly_chknorm DILITHIUM_NAMESPACE(_poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);
#define poly_uniform DILITHIUM_NAMESPACE(_poly_uniform)
void poly_uniform(poly *a,
                  const uint8_t seed[SEEDBYTES],
                  uint16_t nonce);

#define poly_challenge DILITHIUM_NAMESPACE(_poly_challenge)
void poly_challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define polyt1_unpack DILITHIUM_NAMESPACE(_polyt1_unpack)
void polyt1_unpack(poly *r, const uint8_t *a);

#define polyz_unpack DILITHIUM_NAMESPACE(_polyz_unpack)
void polyz_unpack(poly *r, const uint8_t *a);

#define polyw1_pack DILITHIUM_NAMESPACE(_polyw1_pack)
void polyw1_pack(uint8_t *r, const poly *a);

#endif
