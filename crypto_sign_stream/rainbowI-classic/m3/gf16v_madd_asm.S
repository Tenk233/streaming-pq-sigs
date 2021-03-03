.syntax unified
.cpu cortex-m4
.thumb

#include "bitslice.inc"
#include "madd_bitsliced.inc"

//extern void gf16v_madd_32B_asm(uint32_t *accu, uint8_t *aMat, u32 b);
.global gf16v_madd_32B_asm
.type gf16v_madd_32B_asm, %function
.align 2
gf16v_madd_32B_asm:
    push.w {r4-r12, r14}
    
    .rept 2
    ldr.w r7, [r1, #4]
    ldr.w r8, [r1, #8]
    ldr.w r9, [r1, #12]
    ldr.w r6, [r1], #16
    push.w {r1}

    bitslice r1, r3, r4, r5, r6, r7, r8, r9

    ldr.w r6, [r0]
    ldr.w r7, [r0, #4]
    ldr.w r8, [r0, #8]
    ldr.w r9, [r0, #12]

    madd_bitsliced r6, r7, r8, r9, r1, r3, r4, r5, r2, r10, r11, r12, r14
    
    str.w r7, [r0, #4]
    str.w r8, [r0, #8]
    str.w r9, [r0, #12]
    str.w r6, [r0], #16
    pop.w {r1}
    .endr

    pop.w {r4-r12, pc}

