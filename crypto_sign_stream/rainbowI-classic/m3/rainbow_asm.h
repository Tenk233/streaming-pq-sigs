#ifndef RAINBOW_ASM_H
#define RAINBOW_ASM_H
#include <stdint.h>

void gf16mat_prod_512_32_normal_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
void gf16mat_prod_512_36_normal_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
void gf16mat_prod_16_32_normal_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
void gf16mat_prod_18_32_normal_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);

extern void batch_quad_trimat_eval_gf16_100_32_leaktime_asm(uint32_t *y, const unsigned char *trimat, const unsigned char *x, const unsigned char *lut);
extern void batch_quad_trimat_eval_gf16_96_32_leaktime_asm(uint32_t *y, const unsigned char *trimat, const unsigned char *x, const unsigned char *lut);
extern void batch_quad_trimat_eval_gf16_32_16_leaktime_asm(uint32_t *y, const unsigned char *trimat, const unsigned char *x, const unsigned char *lut);
extern void batch_quad_trimat_eval_gf16_36_16_leaktime_asm(uint32_t *y, const unsigned char *trimat, const unsigned char *x, const unsigned char *lut);


extern void batch_quad_trimat_eval_gf16_32_16_asm( unsigned char * y, const unsigned char * trimat, const unsigned char * x);
extern void batch_quad_trimat_eval_gf16_36_16_asm( unsigned char * y, const unsigned char * trimat, const unsigned char * x);

extern unsigned int gf16mat_inv_512_bitsliced_asm(unsigned char *mat);


//Input: bitsliced; Output: bitsliced
extern void gf16mat_prod_512_32_bitsliced_bitsliced_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
extern void gf16mat_prod_512_36_bitsliced_bitsliced_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);

// Input: bitsliced; Output: normal
extern void batch_quad_trimat_eval_gf16_32_16_bitsliced_normal_asm( unsigned char * y, const unsigned char * trimat, const unsigned char * x);
extern void batch_quad_trimat_eval_gf16_36_16_bitsliced_normal_asm( unsigned char * y, const unsigned char * trimat, const unsigned char * x);



// Input: bitsliced; Output: normal
extern void gf16mat_prod_16_32_bitsliced_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
extern void gf16mat_prod_18_32_bitsliced_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
extern void gf16mat_prod_512_32_bitsliced_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
extern void gf16mat_prod_512_36_bitsliced_normal_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);

// Input: normal; Output: bitsliced
extern void gf16mat_prod_512_32_normal_bitsliced_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);
extern void gf16mat_prod_512_36_normal_bitsliced_asm(uint8_t *c, const uint8_t *matA, const uint8_t *b);


extern void batch_quad_recmat_eval_gf16_32_32_16_leaktime_asm(uint32_t  *z, const unsigned char *recmat, const unsigned char *y, const unsigned char *x, const unsigned char *lut);
extern void batch_quad_recmat_eval_gf16_36_32_16_leaktime_asm(uint32_t *z, const unsigned char *recmat, const unsigned char *y, const unsigned char *x, const unsigned char *lut);


extern void gf16v_bitslice_asm(uint8_t *out, uint32_t len);

// lel, RG zone starting. There be dragons!
// Input: Normal; Output: bitsliced
extern void gf16v_madd_32B_asm(uint32_t *accu, uint32_t *aMat, u32 b);

#endif  