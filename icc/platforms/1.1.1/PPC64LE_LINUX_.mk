include platforms/${OPENSSL_LIBVER}/Power.mk

ASM_OBJS += keccak1600-ppc64.o x25519-ppc64.o \
				ecp_nistz256.o ecp_nistz256-ppc64.o

tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@
