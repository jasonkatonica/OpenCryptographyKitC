
include platforms/${OPENSSL_LIBVER}/UNIX_like.mk


ASM_OBJS= cmll-x86.o vpaes-x86.o aesni-x86.o x86cpuid.o ghash-x86.o \
	x86-mont.o x86-gf2m.o sha1-586.o sha512-586.o sha256-586.o \
	md5-586.o rmd-586.o bf-586.o crypt586.o \
	des-586.o rc4-586.o co-586.o bn-586.o c_enc.o \
	ecp_nistz256.o ecp_nistz256-x86.o \
	threads_pthread.o async_posix.o \
	poly1305-x86.o \
	chacha-x86.o \
	keccak1600.o



BUILD_OBJS = $(BASE_OBJS) $(ASM_OBJS)



$(SLIBCRYPTO): Build_OSSL_Complete



tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@
