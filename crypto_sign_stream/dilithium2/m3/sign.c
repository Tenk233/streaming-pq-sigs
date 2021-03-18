#include <stdint.h>
#include "api.h"
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

#define QINV 4236238847U
static void montgomery_multiplication(int32_t *acc, int32_t a, int32_t b){
  int32_t tmp0;
  asm("smull %[pa], %[res], %[pa], %[pb]\n"
      "mul   %[pb], %[pa], %[qinv]\n"
      "smlal %[pa], %[res], %[pb], %[q]\n"
      : [res] "=r" (tmp0),
        [pa]  "+r" (a),
        [pb]  "+r" (b)
      : [qinv]  "r" (QINV),
        [q] "r" (Q));
  *acc += tmp0;
}

static unsigned int rej_uniform_multiply(poly *acc, poly *b, uint8_t *buf, size_t buflen, 
                              size_t ctr)
{
    int32_t a;
    while(buflen >= 3){
      a  = buf[0];
      a  |= (uint32_t)buf[1] << 8;
      a  |= (uint32_t)buf[2] << 16;
      a  &= 0x7FFFFF;

      if(a < Q){
        montgomery_multiplication(acc->coeffs + ctr, a, b->coeffs[ctr]);
        ctr++;
        if(ctr >= N){
          break;
        }
      }

      buflen -= 3;
      buf += 3;
    }

    return ctr;
}

static void __attribute__ ((noinline)) expand_mat_elem_pointwise_acc_montgomery_leaktime(poly *acc, poly *b, const unsigned char rho[SEEDBYTES], size_t k_idx, size_t l_idx) {
  uint16_t nonce = (uint16_t)((k_idx << 8) + l_idx);

  unsigned int ctr=0;
  uint8_t buf[SHAKE128_RATE];
  stream128_state state;

  stream128_init(&state, rho, nonce);

  do {
    shake128_inc_squeeze(buf, sizeof(buf), &state);
    ctr = rej_uniform_multiply(acc, b, buf, sizeof(buf), ctr);
  } while(ctr < N);
 }


#ifndef USE_MINIMUM_MEMORY
extern poly c_poly;
extern poly z_poly[3];
#endif

int crypto_sign_compute_w1(shake256incctx *w1_state,
                            size_t k_idx,
                            poly *t1,
                            uint8_t *sig,
                            uint8_t *rho){
    poly z_elem;
    poly *w1_elem = t1;
    poly *tmp_elem = &z_elem;
    // if we have a KiB to spare, we can precompute NTT(c) and save about 125k cycles
    #ifdef USE_MINIMUM_MEMORY
    const uint8_t *c = getoffset_sig_c(sig);
    poly *cp = &z_elem;
    #else
    poly *cp = &c_poly;
    #endif

    // compute -c2^dt1 first, then add Az (to save one poly of stack space)
    poly_shiftl(w1_elem);
    poly_ntt_leaktime(w1_elem);

    #ifdef USE_MINIMUM_MEMORY
    poly_challenge(cp, c);
    poly_ntt_leaktime(cp);
    #endif
    poly_pointwise_montgomery_leaktime(w1_elem, cp, w1_elem);
    for(size_t i = 0; i<N; i++){
      w1_elem->coeffs[i] = -w1_elem->coeffs[i];
    }


    // We have another KiB to spare, so we cache NTT(z_0) -- saving around 80k cycles
    #ifdef USE_MINIMUM_MEMORY
    unpack_sig_z_idx(&z_elem, sig, 0);
    if(k_idx == 0){
        if(poly_chknorm(&z_elem, GAMMA1 - BETA))
          return -1;
    }

    poly_ntt_leaktime(&z_elem);
    expand_mat_elem_pointwise_acc_montgomery_leaktime(w1_elem, &z_elem, rho, k_idx, 0);
    for (size_t l_idx = 1; l_idx < L; l_idx++) {

        unpack_sig_z_idx(&z_elem, sig, l_idx);
        if(k_idx == 0){
          if(poly_chknorm(&z_elem, GAMMA1 - BETA))
            return -1;
        }
        poly_ntt_leaktime(&z_elem);
        expand_mat_elem_pointwise_acc_montgomery_leaktime(w1_elem, &z_elem, rho, k_idx, l_idx);
    }
    #else
    // NTT(z_0), NTT(z_1), NTT(z_2) is cached; NTT(z_3) is not
    expand_mat_elem_pointwise_acc_montgomery_leaktime(w1_elem, &z_poly[0], rho, k_idx, 0);
    expand_mat_elem_pointwise_acc_montgomery_leaktime(w1_elem, &z_poly[1], rho, k_idx, 1);
    expand_mat_elem_pointwise_acc_montgomery_leaktime(w1_elem, &z_poly[2], rho, k_idx, 2);
    unpack_sig_z_idx(&z_elem, sig, 0);
    if(k_idx == 0){
      if(poly_chknorm(&z_elem, GAMMA1 - BETA))
        return -1;
    }
    poly_ntt_leaktime(&z_elem);
    expand_mat_elem_pointwise_acc_montgomery_leaktime(w1_elem, &z_elem, rho, k_idx, 3);
    #endif

 

    poly_reduce(w1_elem);
    poly_invntt_tomont_leaktime(w1_elem);

    /* Reconstruct w1 */
    poly_caddq(w1_elem);

    #ifdef USE_MINIMUM_MEMORY
    if (unpack_sig_h(tmp_elem, k_idx, sig) != 0) {
      return -1;
    };
    #else
     if (unpack_sig_h(tmp_elem, k_idx, sig-3*POLYZ_PACKEDBYTES) != 0) {
      return -1;
    };
    #endif
    poly_use_hint(w1_elem, w1_elem, tmp_elem);

    polyw1_pack_absorb(w1_state, w1_elem);
    return 0;
}

int crypto_sign_verify_w1(shake256incctx *w1_state, uint8_t *sig){

  size_t i;
  uint8_t c2[SEEDBYTES];
  const uint8_t *c = getoffset_sig_c(sig);

  shake256_inc_finalize(w1_state);
  shake256_inc_squeeze(c2, SEEDBYTES, w1_state);
  for(i = 0; i < SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}