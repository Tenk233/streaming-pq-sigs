.syntax unified
.thumb

.macro montgomery_multiplication res, pa, pb, q, qinv
    smull \pa, \res, \pa, \pb
    mul \pb, \pa, \qinv
    smlal \pa, \res, \pb, \q
.endm


.global poly_pointwise_invmontgomery_asm_smull
.type poly_pointwise_invmontgomery_asm_smull,%function
.align 2
poly_pointwise_invmontgomery_asm_smull:
    push.w {r4-r11, r14}
    c_ptr .req r0
    a_ptr .req r1
    b_ptr .req r2
    qinv  .req r3
    q     .req r4
    pa0   .req r5
    pa1   .req r6
    pa2   .req r7
    pb0   .req r8
    pb1   .req r9
    pb2   .req r10
    tmp0  .req r11
    ctr   .req r12
    res   .req r14

    movw qinv, #:lower16:0xfc7fdfff
    movt qinv, #:upper16:0xfc7fdfff
    movw q, #0xE001
    movt q, #0x7F


    // 85x3 = 255 coefficients
    movw ctr, #85
    1:
        ldr.w pa1, [a_ptr, #4]
        ldr.w pa2, [a_ptr, #8]
        ldr pa0, [a_ptr], #12
        ldr.w pb1, [b_ptr, #4]
        ldr.w pb2, [b_ptr, #8]
        ldr pb0, [b_ptr], #12

        montgomery_multiplication res, pa0, pb0, q, qinv
        str res, [c_ptr], #4
        montgomery_multiplication res, pa1, pb1, q, qinv
        str res, [c_ptr], #4
        montgomery_multiplication res, pa2, pb2, q, qinv
        str res, [c_ptr], #4
    subs ctr, #1
    bne.w 1b

    // final coefficient
    ldr.w pa0, [a_ptr]
    ldr.w pb0, [b_ptr]
    montgomery_multiplication res, pa0, pb0, q, qinv
    str.w res, [c_ptr]

    pop.w {r4-r11, pc}




.global montgomery_multiplication_acc
.type montgomery_multiplication_acc, %function
.align 2
montgomery_multiplication_acc:
    push {r4-r10}

    // qinv
    movw r3, #:lower16:0xfc7fdfff
    movt r3, #:upper16:0xfc7fdfff
    // q
    movw r4, #0xE001
    movt r4, #0x7F


    montgomery_multiplication r5, r1, r2, r4, r3

    ldr r6, [r0]
    add r6, r5
    str r6, [r0]

    pop {r4-r10}
    bx lr
