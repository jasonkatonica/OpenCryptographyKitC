# Makefile for building the KA test stubs as standalone executables
include ../platforms.mk

all: chacha$(EXESUFX)

chacha$(EXESUFX): chacha$(OBJSUFX)
	$(LD) $(LDFLAGS) -g  chacha$(OBJSUFX)  ../../openssl-1.1.1i/libcrypto.a -lpthread -ldl $(OUT) $@

chacha$(OBJSUFX): chacha.c
	$(CC) $(CFLAGS) -g3 -DSTANDALONE  -I../ chacha.c $(OUT) $@


clean:
	-$(RM) chacha$(EXESUFX) chacha$(OBJSUFX)
	