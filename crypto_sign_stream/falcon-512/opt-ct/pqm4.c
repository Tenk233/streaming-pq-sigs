#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

/* ==================================================================== */

/*
 * Falcon degree is N = 2^LOGN, where LOGN=9 (for Falcon-512) or 10
 * (for Falcon-1024). We use the advertised public key size to know
 * which degree is used.
 */
#if CRYPTO_PUBLICKEYBYTES == 897
#define LOGN   9
#elif CRYPTO_PUBLICKEYBYTES == 1793
#define LOGN   10
#else
#error Unknown Falcon degree (unexpected public key size)
#endif

#define N   ((size_t)1 << LOGN)
#define NONCELEN   40
#define SEEDLEN    48

/*
 * If the private key length is larger than 10000, then this is the
 * variant with precomputed expanded keys.
 */
#if CRYPTO_SECRETKEYBYTES > 10000
#define KG_EXPAND   1
#else
#define KG_EXPAND   0
#endif

/*
 * Common buffer, to avoid bulky stack allocation. The buffer sizes are
 * all expressed in bytes, but the buffer must be suitably aligned for
 * 64-bit integers and floating-point values.
 *
 * Required size (in bytes):
 *
 *   With expanded key:
 *      keygen:  48*N + 6*N = 54*N
 *      sign:    48*N + 2*N = 50*N
 *      vrfy:    8*N
 *
 *   Without expanded key:
 *      keygen:  28*N + 5*N = 33*N
 *      sign:    72*N + 6*N = 78*N
 *      vrfy:    8*N
 */
static union {
#if KG_EXPAND
	uint8_t b[8*N];
#else
	uint8_t b[8*N];
#endif
	uint64_t dummy_u64;
	fpr dummy_fp;
} tmp;

int randombytes(unsigned char *dst, size_t len);

int
crypto_sign_open(unsigned char *m, size_t *mlen,
	const unsigned char *sm, size_t smlen,
	const unsigned char *pk)
{
	uint16_t *h, *hm;
	int16_t *sig;
	const unsigned char *esig;
	inner_shake256_context sc;
	size_t sig_len, msg_len;

	h = (uint16_t *)&tmp.b[2 * N];
	hm = h + N;
	sig = (int16_t *)(hm + N);

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + LOGN) {
		return -1;
	}
	if (Zf(modq_decode)(h, LOGN, pk + 1, CRYPTO_PUBLICKEYBYTES - 1)
		!= CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}
	Zf(to_ntt_monty)(h, LOGN);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < 2 + NONCELEN) {
		return -1;
	}
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - NONCELEN)) {
		return -1;
	}
	msg_len = smlen - 2 - NONCELEN - sig_len;

	/*
	 * Decode signature.
	 */
	esig = sm + 2 + NONCELEN + msg_len;
	if (sig_len < 1 || esig[0] != 0x20 + LOGN) {
		return -1;
	}
	if (Zf(comp_decode)(sig, LOGN,
		esig + 1, sig_len - 1) != sig_len - 1)
	{
		return -1;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, NONCELEN + msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, LOGN);

	/*
	 * Verify signature.
	 */
	if (!Zf(verify_raw)(hm, sig, h, LOGN, tmp.b)) {
		return -1;
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sm + 2 + NONCELEN, msg_len);
	*mlen = msg_len;
	return 0;
}
