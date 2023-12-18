include platforms/${OPENSSL_LIBVER}/UNIX_like.mk

ASM_OBJS= arm64cpuid.o armcap.o \
	sha1-armv8.o \
	sha256-armv8.o sha512-armv8.o \
	des_enc.o aes_core.o aes_cbc.o bf_enc.o bn_asm.o \
	c_enc.o rc4_enc.o rc4_skey.o \
	camellia.o cmll_misc.o cmll_cbc.o \
	ecp_nist.o bn_nist.o  \
	ghashv8-armx.o  \
	aesv8-armx.o vpaes-armv8.o \
	threads_pthread.o async_posix.o \
	armv8-mont.o chacha-armv8.o \
	ecp_nistz256.o poly1305-armv8.o ecp_nistz256-armv8.o \
	keccak1600-armv8.o

BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)

tmp/dummyfile:   $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  $(AR) x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@

