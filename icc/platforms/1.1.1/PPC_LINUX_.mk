
include platforms/${OPENSSL_LIBVER}/Power.mk

#
# Not asm objs in this case. Objects that don't have asm boosts in 32 bit mode
#
ASM_OBJS += keccak1600.o curve25519.o \
						ecp_nistp256.o

tmp/dummyfile: $(SLIBCRYPTO)
	$(MKDIR) tmp
	( cd tmp; \
	  ar x ../$(SLIBCRYPTO); \
	  cd .. ; \
	)
	touch $@


