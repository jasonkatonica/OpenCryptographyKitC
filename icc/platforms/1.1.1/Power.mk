
include platforms/${OPENSSL_LIBVER}/UNIX_like.mk

#
# Power64 assembler modules, common to AIX/Linux
#
ASM_OBJS =  ppccap.o  ppccpuid.o \
	sha1-ppc.o sha256-ppc.o sha512-ppc.o \
	aes-ppc.o aes_cbc.o aes_core.o \
	bn-ppc.o ppc-mont.o \
	camellia.o cmll_misc.o cmll_cbc.o \
	c_enc.o bf_enc.o des_enc.o \
	rc4_enc.o rc4_skey.o \
	vpaes-ppc.o aesp8-ppc.o \
	sha256p8-ppc.o sha512p8-ppc.o  \
	ghashp8-ppc.o \
	async.o async_posix.o threads_pthread.o \
	poly1305-ppc.o poly1305-ppcfp.o chacha-ppc.o
	

BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)

#
# Config file options for this platform
#
# Shouldn't be needed with the revised base TRNG
#
#TWEAKS="ICC_TRNG=TRNG_ALT2"
#

