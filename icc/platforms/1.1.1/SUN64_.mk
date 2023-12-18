include platforms/${OPENSSL_LIBVER}/UNIX_like.mk



ASM_OBJS = \
	aes_core.o aes_cbc.o  \
	camellia.o cmll_misc.o cmll_cbc.o  \
	c_enc.o bf_enc.o  \
	rc4_enc.o rc4_skey.o \
	vis3-mont.o \
	md5-sparcv9.o \
	ghash-sparcv9.o \
	poly1305-sparcv9.o \
	sparcv8plus.o \
	sparcv9-gf2m.o \
	sparct4-mont.o \
	sparcv9a-mont.o \
	sparcv9-mont.o \
	des_enc-sparc.o \
	dest4-sparcv9.o \
	sha1-sparcv9.o \
	sha256-sparcv9.o \
	sha512-sparcv9.o \
	cmllt4-sparcv9.o \
	ecp_nistz256-sparcv9.o \
	sparcv9cap.o \
	sparccpuid.o \
	aest4-sparcv9.o \
	aesfx-sparcv9.o \
	aes-sparcv9.o \
	ecp_nistz256.o \
	chacha_enc.o \
	keccak1600.o \
	threads_pthread.o async_posix.o async_null.o  lh_stats.o


BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)



tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@


RdCTR_raw.o:
	cc $(CFLAGS) asm/sparc/RdCTR_raw.S -o RdCTR_raw.o
