.syntax unified
.thumb
.macro redq a, tmp, q
    ubfx \tmp, \a, #0, #23
    asr.w \a, \a, #23
    sub.w \tmp, \tmp, \a
    add.w \a, \tmp, \a, lsl#13
    cmp.n \a, \q
    it ge
    subge.w \a, \a, \q
.endm

.global poly_reduce_asm
.type poly_reduce_asm, %function
.align 2
poly_reduce_asm:
    push {r4-r10}

    movw r12,#:lower16:8380417
    movt r12,#:upper16:8380417
    movw r10, #32
    1:
        ldr.w r1, [r0]
        ldr.w r2, [r0, #1*4]
        ldr.w r3, [r0, #2*4]
        ldr.w r4, [r0, #3*4]
        ldr.w r5, [r0, #4*4]
        ldr.w r6, [r0, #5*4]
        ldr.w r7, [r0, #6*4]
        ldr.w r8, [r0, #7*4]

        redq r1, r9, r12
        redq r2, r9, r12
        redq r3, r9, r12
        redq r4, r9, r12
        redq r5, r9, r12
        redq r6, r9, r12
        redq r7, r9, r12
        redq r8, r9, r12

        str.w r2, [r0, #1*4]
        str.w r3, [r0, #2*4]
        str.w r4, [r0, #3*4]
        str.w r5, [r0, #4*4]
        str.w r6, [r0, #5*4]
        str.w r7, [r0, #6*4]
        str.w r8, [r0, #7*4]
        str r1, [r0], #8*4
        subs r10, #1
        bne.w 1b

    pop {r4-r10}
    bx lr

