#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        getoffset_pk_rho
*
* Description: Unpack only rho from public key pk = (rho, t1).
*
* Arguments:   - const unsigned char *rho: pointer to rho inside of pk
*              - unsigned char pk[]: byte array containing bit-packed pk
*
* The lifetime of rho MUST NOT exceed the lifetime of pk!
**************************************************/
const unsigned char *getoffset_pk_rho(const unsigned char pk[CRYPTO_PUBLICKEYBYTES]) {
    return pk;
}

/*************************************************
* Name:        unpack_pk_t1
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const polyvec *t1: pointer to output vector t1
*              - const size_t idx: unpack n'th element from t1
*              - unsigned char pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk_t1(poly *t1, size_t idx, const unsigned char pk[CRYPTO_PUBLICKEYBYTES]) {
    pk += SEEDBYTES;
    polyt1_unpack(t1, pk + idx * POLYT1_PACKEDBYTES);
}


/*************************************************
* Name:        unpack_sig_z
*
* Description: Unpack only z from signature sig = (z, h, c).
*
* Arguments:   - polyvecl *z: pointer to output vector z
*              - const unsigned char sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig_z(polyvecl *z, const unsigned char sig[CRYPTO_BYTES]) {
    sig += SEEDBYTES;
    for (size_t i = 0; i < L; ++i) {
        polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
    }
    return 0;
}

int unpack_sig_z_idx(poly *z_elem, const unsigned char sig[CRYPTO_BYTES], size_t idx) {
    sig += SEEDBYTES;
    polyz_unpack(z_elem, sig + idx * POLYZ_PACKEDBYTES);
    return 0;
}

/*************************************************
* Name:        unpack_sig_h
*
* Description: Unpack only h from signature sig = (z, h, c).
*
* Arguments:   - polyveck *h: pointer to output hint vector h
*              - const unsigned char sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig_h(poly *h, size_t idx, const unsigned char sig[CRYPTO_BYTES]) {
    sig += SEEDBYTES;
    sig += L * POLYZ_PACKEDBYTES;

    /* Decode h */
    size_t k = 0;
    for (size_t i = 0; i < K; ++i) {
        for (size_t j = 0; j < N; ++j) {
            if (i == idx) {
                h->coeffs[j] = 0;
            }
        }

        if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA) {
            return 1;
        }

        for (size_t j = k; j < sig[OMEGA + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1]) {
                return 1;
            }
            if (i == idx) {
                h->coeffs[sig[j]] = 1;
            }
        }

        k = sig[OMEGA + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (size_t j = k; j < OMEGA; ++j) {
        if (sig[j]) {
            return 1;
        }
    }
    return 0;
}

const uint8_t * getoffset_sig_c(const uint8_t *sig) {
  return sig;
}