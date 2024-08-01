
#if defined(__SUNPRO_C) && defined(__sparcv9)
# define ABI64  /* They've said -xarch=v9 at command line */
#elif defined(__GNUC__) && defined(__arch64__)
# define ABI64  /* They've said -m64 at command line */
#endif

#ifdef ABI64
  .register     %g2,#scratch
  .register     %g3,#scratch
# define        FRAME   -192
# define        BIAS    2047
#else
# define        FRAME   -96
# define        BIAS    0
#endif

.text

		
.global RdCTR_asm
.align  32
RdCTR_asm:
        subcc   %g0,1,%o0
        .word   0x91408000      !rd     %ccr,%o0
        cmp     %o0,0x99
        bne     .notick
        xor     %o0,%o0,%o0
        .word   0x91410000      !rd     %tick,%o0
        retl
        .word   0x93323020      !srlx   %o2,32,%o1
.notick:
        retl
        xor     %o1,%o1,%o1
.type   RdCTR_asm,#function
.size   RdCTR_asm,.-RdCTR_asm

