include platforms/${OPENSSL_LIBVER}/UNIX_like.mk
ASM_OBJS = \
	threads_pthread.o \
	aesni-gcm-x86_64.o \
	aesni-sha1-x86_64.o \
	aesni-x86_64.o \
	bf_enc.o \
	des_enc.o \
	c_enc.o \
	cmll_misc.o \
	cmll-x86_64.o \
	ghash-x86_64.o \
	md5-x86_64.o \
	rc4-md5-x86_64.o \
	rc4-x86_64.o \
	sha1-x86_64.o \
	sha256-x86_64.o \
	sha512-x86_64.o  \
	vpaes-x86_64.o \
	x86_64cpuid.o \
	x86_64-gcc.o \
	x86_64-gf2m.o \
	x86_64-mont.o \
	x86_64-mont5.o \
	rsaz-avx2.o \
	sha1-mb-x86_64.o \
	sha256-mb-x86_64.o \
	aesni-mb-x86_64.o \
	aesni-sha256-x86_64.o \
	rsaz-x86_64.o \
	ecp_nistz256-x86_64.o \
	rsaz_exp.o \
	ecp_nistz256.o \
	chacha-x86_64.o \
	poly1305-x86_64.o \
	async_posix.o \
	keccak1600-x86_64.o \
	x25519-x86_64.o	



BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)




$(SLIBCRYPTO): Build_OSSL_Complete



tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@

