include platforms/${OPENSSL_LIBVER}/BASE_OSSL_FILES.mk

$(MYOPENSSL):  openssl$(EXESUFX)
	$(CP)  openssl$(EXESUFX) $@

openssl$(OBJSUFX): openssl.c
	$(CC) -DOPENSSL_NO_ENGINE $(CFLAGS) -I$(OSSLINC_DIR) -I$(OSSL_DIR)/apps/ -I$(OSSL_DIR) openssl.c

openssl$(EXESUFX): openssl$(OBJSUFX) $(E_OBJ) $(SLIBCRYPTO) $(SLIBSSL) platform$(OBJSUFX)
	$(LD) $(LDFLAGS) openssl$(OBJSUFX) platform$(OBJSUFX) $(E_OBJ) $(SLIBSSL) $(SLIBCRYPTO) $(LDLIBS)
	$(STRIP) $@

# Default to hardware RNG (if available)

#TWEAKS="ICC_TRNG=TRNG_ALT4"