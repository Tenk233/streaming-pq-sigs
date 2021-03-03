#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

/*************************************************
* Name:        expand_mat_elem
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|i|j).
*
* Arguments:   - poly mat_elem: output matrix element
*              - const unsigned char rho[]: byte array containing seed rho
*              - k_idx: matrix row index
*              - l_idx: matrix col index
**************************************************/
static void expand_mat_elem(poly *mat_elem, const unsigned char rho[SEEDBYTES], size_t k_idx, size_t l_idx) {
    poly_uniform(mat_elem, rho, (uint16_t)((k_idx << 8) + l_idx));
}


/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  unsigned int i;
  shake256incctx state;
  uint8_t buf[POLYW1_PACKEDBYTES];
  const uint8_t *rho;
  uint8_t *mu = buf; // uint8_t mu[CRHBYTES];
  const uint8_t *c;
  polyvecl z;
  poly cp, w1_elem, tmp_elem;
  uint8_t *c2 = buf; //  uint8_t c2[SEEDBYTES];

  if(siglen != CRYPTO_BYTES)
    return -1;

  rho = getoffset_pk_rho(pk);
  c   = getoffset_sig_c(sig);

  if (unpack_sig_z(&z, sig) != 0) {
    return -1;
  };

  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(h(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

  // Hash [mu || w1'] to get c.
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, CRHBYTES);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  //polyvec_matrix_expand(mat, rho);

  for (i = 0; i < L; i++) {
    poly_ntt_leaktime(&z.vec[i]);
  }

  poly_ntt_leaktime(&cp);

  //polyvec_matrix_pointwise_montgomery_leaktime(&w1, mat, &z);
  for (size_t k_idx = 0; k_idx < K; k_idx++) {
    // Sample the current element from A.
    expand_mat_elem(&tmp_elem, rho, k_idx, 0);
    poly_pointwise_montgomery_leaktime(&w1_elem, &tmp_elem, &z.vec[0]);
    for (size_t l_idx = 1; l_idx < L; l_idx++) {
        // Sample the element from A.
        expand_mat_elem(&tmp_elem, rho, k_idx, l_idx);
        poly_pointwise_acc_montgomery_leaktime(&w1_elem, &tmp_elem, &z.vec[l_idx]);
    }

    unpack_pk_t1(&tmp_elem, k_idx, pk);
    poly_shiftl(&tmp_elem);
    poly_ntt_leaktime(&tmp_elem);
    poly_pointwise_montgomery_leaktime(&tmp_elem, &cp, &tmp_elem);
    poly_sub(&w1_elem, &w1_elem, &tmp_elem);
    poly_reduce(&w1_elem);
    poly_invntt_tomont_leaktime(&w1_elem);

    /* Reconstruct w1 */
    poly_caddq(&w1_elem);

    if (unpack_sig_h(&tmp_elem, k_idx, sig) != 0) {
      return -1;
    };
    poly_use_hint(&w1_elem, &w1_elem, &tmp_elem);
    polyw1_pack(buf, &w1_elem);
    shake256_inc_absorb(&state, buf, POLYW1_PACKEDBYTES);
  }

  /* Call random oracle and verify challenge */
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(c2, SEEDBYTES, &state);
  for(i = 0; i < SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
