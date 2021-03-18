#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

#define crypto_sign_verify DILITHIUM_NAMESPACE(_verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(_open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#define crypto_sign_compute_w1 DILITHIUM_NAMESPACE(_crypto_sign_compute_w1)
int crypto_sign_compute_w1(shake256incctx *w1_state,
                            size_t k_idx,
                            poly *t1,
                            uint8_t *sig,
                            uint8_t *rho);


#define crypto_sign_verify_w1 DILITHIUM_NAMESPACE(_crypto_sign_verify_w1)
int crypto_sign_verify_w1(shake256incctx *w1_state, uint8_t *sig);

#endif
