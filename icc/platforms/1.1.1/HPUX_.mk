include platforms/${OPENSSL_LIBVER}/UNIX_like.mk

ASM_OBJS = pariscid.o parisc-mont.o \
	rc4-parisc.o bn_asm.o \
	aes-parisc.o aes_core.o aes_cbc.o ghash-parisc.o \
	sha1-parisc.o sha256-parisc.o sha512-parisc.o \
	ecp_nist.o bn_nist.o \
	camellia.o cmll_misc.o cmll_cbc.o \
	c_enc.o bf_enc.o des_enc.o \
	chacha_enc.o \
	dso_dl.o \
	threads_pthread.o async_posix.o async_null.o lh_stats.o \
	keccak1600.o


BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)


tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@


