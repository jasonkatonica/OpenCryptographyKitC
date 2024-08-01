include platforms/${OPENSSL_LIBVER}/UNIX_like.mk


ASM_OBJS= armv4cpuid.o armcap.o \
	aes-armv4.o ghash-armv4.o \
	armv4-mont.o \
	armv4-gf2m.o \
	sha1-armv4-large.o \
	sha256-armv4.o sha512-armv4.o \
	des_enc.o aes_cbc.o bf_enc.o bn_asm.o \
   c_enc.o rc4_enc.o rc4_skey.o \
   camellia.o cmll_misc.o cmll_cbc.o \
   ecp_nist.o bn_nist.o aesv8-armx.o \
	ghashv8-armx.o bsaes-armv7.o \
	threads_pthread.o async_posix.o \
	chacha-armv4.o poly1305-armv4.o ecp_nistz256.o \
	ecp_nistz256-armv4.o \
	keccak1600-armv4.o

BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)

tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  $(AR) x ../$(SLIBCRYPTO); \
	  cd .. ;\
	)
	touch $@

