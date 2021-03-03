#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "polyvec.h"

const unsigned char *getoffset_pk_rho(const unsigned char pk[CRYPTO_PUBLICKEYBYTES]);
void unpack_pk_t1(poly *t1, size_t idx, const unsigned char pk[CRYPTO_PUBLICKEYBYTES]);

int unpack_sig_z(polyvecl *z, const unsigned char sig[CRYPTO_BYTES]);
int unpack_sig_h(poly *h, size_t idx, const unsigned char sig[CRYPTO_BYTES]);
const uint8_t *getoffset_sig_c(const uint8_t *sig);


#endif
