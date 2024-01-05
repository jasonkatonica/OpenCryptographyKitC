#
# Misc tools for R&D and PD
#

#
# FIPS_mem_collector was tested on x86/Z and didn't really help
# i.e. loop pver memory as a delay rather than a timing loop

# FIPS_lt_filter was an attempt to improve the histogram filter
# by making it effectively much wider. Also tested on x86/Z and
# didn't improve matters enough
#

TOOLS =	 \
   icclib_sa$(EXESUFX) \
	GenRndData$(EXESUFX) \
	smalltest$(EXESUFX) \
	smalltest4$(EXESUFX) \
	GenRndData2$(EXESUFX) \
	GenRndDataFIPS$(EXESUFX) \
	sha256x$(EXESUFX)

# Disabled. Tried, didn't work
#	FIPS_mem_collector$(EXESUFX) \
#	FIPS_filter_lt$(EXESUFX) \

#
# RNG data collection code.
#
GENRND_OBJS = GenRndData$(OBJSUFX) platform$(OBJSUFX) \
	timer_entropy$(OBJSUFX) nist_algs$(OBJSUFX) \
	noise_to_entropy$(OBJSUFX) \
	TRNG_ALT4$(OBJSUFX) looper$(OBJSUFX) \
	$(ASMOBJS)

GENRNDFIPS_OBJS =  GenRndDataFIPS$(OBJSUFX) platform$(OBJSUFX) \
	timer_entropy$(OBJSUFX) nist_algs$(OBJSUFX) \
	noise_to_entropy$(OBJSUFX) timer_fips$(OBJSUFX) \
	TRNG_FIPS$(OBJSUFX) looper$(OBJSUFX) \
	$(ASMOBJS)



#- Build RND data generator executable
# GENRND is either GenRdnData.exe (winxxx) or GenRndData
# So rather than use generic target keep separate so can do different processing on windows




#- Compile RNG data generator
GenRndData$(OBJSUFX): tools/GenRndData.c 
	-$(CC) $(CFLAGS) -I./  -I$(ZLIB_DIR) -I$(OSSLINC_DIR) -I$(OSSL_DIR) -I$(SDK_DIR) tools/GenRndData.c  $(ASM_TWEAKS)

GenRndData: $(GENRND_OBJS)
	-$(LD) $(LDFLAGS) $(GENRND_OBJS) tmp/tmp/*$(OBJSUFX) $(LDLIBS)
	-$(CP) GenRndData $(SDK_DIR)/

GenRndData.exe: $(GENRND_OBJS)
	-$(LD) $(LDFLAGS) $(GENRND_OBJS) $(ICCLIB) $(LDLIBS)
	-$(MT) -manifest $@.manifest  -outputresource:$@\;1

$(SDK_DIR)/GenRndData.exe: GenRndData.exe
	-$(CP) GenRndData.exe $@
	-$(CP) GenRndData.exe.manifest $(SDK_DIR)/


#- Compile hash check tool
sha256x$(OBJSUFX): tools/sha256x.c 
	-$(CC) $(CFLAGS) -I./ -I$(OSSLINC_DIR)  tools/sha256x.c 

sha256x: sha256x$(OBJSUFX) $(SLIBCRYPTO)
	-$(LD) $(LDFLAGS) sha256x$(OBJSUFX) $(SLIBCRYPTO) $(LDLIBS)
	-$(CP) sha256x $(SDK_DIR)/

sha256x.exe: sha256x$(OBJSUFX) $(SLIBCRYPTO)
	-$(LD) $(LDFLAGS) sha256x$(OBJSUFX) $(SLIBCRYPTO) $(SLIBSSL) $(LDLIBS)
	-$(MT) -manifest $@.manifest  -outputresource:$@\;1
	-$(CP) sha256x.exe $(SDK_DIR)/
#	-$(CP) sha256x.exe.manifest $(SDK_DIR)/

#- Build FIPS RND data generator executable
# GENRNDFIPS is either GenRdnDataFIPS.exe (winxxx) or GenRndDataFIPS
# So rather than use generic target keep separate so can do different processing on windows
#- Compile RNG data generator
#- Build RNG data generator executable


#- Compile newer RNG data generator
GenRndData2$(OBJSUFX): tools/GenRndData2.c  $(SDK_DIR)/icc.h $(SDK_DIR)/icc_a.h $(SDK_DIR)/iccglobals.h $(ICCPKG_DIR)/iccversion.h $(ICCPKG_DIR)/buildinfo.h
	-$(CC) $(CFLAGS) -I $(SDK_DIR) tools/GenRndData2.c

GenRndData2: GenRndData2$(OBJSUFX) $(ICCLIB)
	-$(LD) $(LDFLAGS) GenRndData2$(OBJSUFX) $(ICCLIB) $(LDLIBS) 
	-$(CP) GenRndData2 $(SDK_DIR)/


GenRndData2.exe: GenRndData2$(OBJSUFX) $(ICCLIB)
	-$(LD) $(LDFLAGS) GenRndData2$(OBJSUFX) $(ICCLIB) $(LDLIBS) 
	-$(MT) -manifest $@.manifest  -outputresource:$@\;1
	-$(CP) GenRndData2.exe $(SDK_DIR)/

#- FIPS specific RNG data generator	

GenRndDataFIPS$(OBJSUFX): tools/GenRndDataFIPS.c 
	-$(CC) $(CFLAGS) -I./  -I$(ZLIB_DIR) -I$(OSSLINC_DIR) -I$(OSSL_DIR) -I$(SDK_DIR) tools/GenRndDataFIPS.c  $(ASM_TWEAKS)

GenRndDataFIPS : $(GENRNDFIPS_OBJS)
	-$(LD) $(LDFLAGS) $(GENRNDFIPS_OBJS) $(LDLIBS)

GenRndDataFIPS.exe : $(GENRNDFIPS_OBJS)
	-$(LD) $(LDFLAGS) $(GENRNDFIPS_OBJS) $(LDLIBS)
	-$(MT) -manifest $@.manifest  -outputresource:$@\;1


#	
#- Build an exectuable version of libicclib.so so we can debug the POST code
#

#icclib_sa.c: icclib.c tracer.h
#	$(CP) icclib.c $@

icclib_sa$(OBJSUFX): icclib.c loaded.c loaded.h tracer.h extsig.h
	-$(CC) -DICCDLL_NAME="\"icclib_sa$(EXESUFX)\"" -DSTANDALONE_ICCLIB  -DOPSYS="\"$(OPSYS)\"" -DMYNAME=icclib_sa$(VTAG) $(CFLAGS) \
		 -I../$(ZLIB) -I./  -I$(SDK_DIR) -I$(OSSLINC_DIR) -I$(OSSL_DIR) -I$(API_DIR) icclib.c $(OUT)$@

icclib_sa$(EXESUFX): icclib_sa$(OBJSUFX) $(LIBOBJS) $(STLPRFX)zlib$(STLSUFX) tmp/tmp/dummyfile extsig$(OBJSUFX) signer$(EXESUFX)
	-$(LD) $(LDFLAGS)  icclib_sa$(OBJSUFX) $(LIBOBJS) $(STLPRFX)zlib$(STLSUFX)  tmp/tmp/*$(OBJSUFX) $(LDLIBS)
#	-./signer$(EXESUFX) ICCLIB_SA.txt  privkey.rsa -SELF -FILE icclib_sa$(EXESUFX) $(TWEAKS)


#- Build ICC test executables

smalltest$(OBJSUFX):  tools/smalltest.c $(SDK_DIR)/icc.h $(SDK_DIR)/icc_a.h $(SDK_DIR)/iccglobals.h
	-$(CC) $(CFLAGS)  -I./ -I $(SDK_DIR) tools/smalltest.c

smalltest$(EXESUFX): $(ICCDLL) $(ICCLIB) smalltest$(OBJSUFX) 
	-$(LD) $(LDFLAGS) smalltest$(OBJSUFX) $(ICCLIB) $(LDLIBS) 

smalltest4$(OBJSUFX):  tools/smalltest4.c $(SDK_DIR)/icc.h $(SDK_DIR)/icc_a.h $(SDK_DIR)/iccglobals.h
	-$(CC) $(CFLAGS)  -I./ -I $(SDK_DIR) tools/smalltest4.c

smalltest4$(EXESUFX): $(ICCDLL) $(ICCLIB) smalltest4$(OBJSUFX) 
	-$(LD) $(LDFLAGS) smalltest4$(OBJSUFX) $(ICCLIB) $(LDLIBS) 

# Integrity check API call test.

integ$(OBJSUFX):  integ.c $(SDK_DIR)/icc.h $(SDK_DIR)/icc_a.h $(SDK_DIR)/iccglobals.h
	-$(CC) $(CFLAGS)  -I./ -I $(SDK_DIR) tools/integ.c

integ$(EXESUFX): $(ICCDLL) $(ICCLIB) integ$(OBJSUFX) 
	-$(LD) $(LDFLAGS) integ$(OBJSUFX) $(ICCLIB) $(LDLIBS)