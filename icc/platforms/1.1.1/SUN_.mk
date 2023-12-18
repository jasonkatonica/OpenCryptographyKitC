
include platforms/${OPENSSL_LIBVER}/UNIX_like.mk

ASM_OBJS = sha1-sparcv9.o sha512-sparcv9.o sha256-sparcv9.o \
	aes_core.o aes_cbc.o aes-sparcv9.o ghash-sparcv9.o \
	aest4-sparcv9.o aesfx-sparcv9.o \
	sparcv9cap.o \
	camellia.o cmll_misc.o cmll_cbc.o cmllt4-sparcv9.o \
	sparccpuid.o  \
	c_enc.o bf_enc.o \
	md5-sparcv9.o \
	dest4-sparcv9.o  des_enc-sparc.o \
	rc4_enc.o rc4_skey.o \
	ecp_nistz256-sparcv9.o \
	poly1305-sparcv9.o \
	threads_pthread.o async_posix.o lh_stats.o \
	sparcv8plus.o async_null.o ecp_nistz256.o \
	sparct4-mont.o vis3-mont.o sparcv9-mont.o \
	sparcv9a-mont.o \
	sparcv9-gf2m.o chacha_enc.o \
	e_chacha20_poly1305.o \
	keccak1600.o




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


# SUN_BUILD_OSSL	= cp platforms/SUN/libcrypto.num $(OSSL_DIR)/util/libcrypto.num ; cd $(OSSL_DIR); ./Configure threads shared $(OSSL_FLAGS) $(SUN_$(CONFIG)_CFLAGS) -R$(OSSLOBJ_DIR) solaris-sparcv9-cc; make depend;  make

