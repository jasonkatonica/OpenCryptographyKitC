include platforms/${OPENSSL_LIBVER}/UNIX_like.mk

ASM_OBJS = ia64cpuid.o bn-ia64.o ia64-mont.o \
	aes_core.o aes_cbc.o aes-ia64.o ghash-ia64.o \
	sha1-ia64.o sha256-ia64.o sha512-ia64.o \
	rc4_enc.o rc4_skey.o \
	c_enc.o bf_enc.o des_enc.o  \
	camellia.o cmll_misc.o cmll_cbc.o \
	chacha_enc.o \
	dso_dl.o \
	threads_pthread.o async_posix.o  async_null.o lh_stats.o \
	keccak1600.o 

BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)



tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd ..; \
	)
	touch $@




