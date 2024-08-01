include platforms/${OPENSSL_LIBVER}/WIN_like.mk

asm/win_ia64/rng_ia64.obj: asm/win_ia64/rng_ia64.asm
	ias asm/win_ia64/rng_ia64.asm



BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS) opensslrc.RES

include platforms/WIN_like.mk



