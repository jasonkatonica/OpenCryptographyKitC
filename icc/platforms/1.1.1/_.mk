

#
# Moved to platform specific because at least on HP/UX 
# we need to unarchive libcrypto.a and relink it as a
# new shared library to get the internal library name correct
# This is the default (old) 
#
#- Copy OpenSSL crypto library to package directory
$(OSSLDLL): $(RTE_DIR)/osslib $(OSSLOBJ_DIR)/$(OSSLDLL_NAME)
	$(CP) $(OSSLOBJ_DIR)/$(OSSLDLL_NAME) $@
	$(STRIP) $@
