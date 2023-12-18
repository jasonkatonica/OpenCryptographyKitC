# 
# We have only one set of linker control files and some OS's fail when we try to export functions that are
# missing 
# GSkit8

$(AUXLIB_B).so: icc_aux$(OBJSUFX)
	$(SLD)  $(SLDFLAGS) icc_aux$(OBJSUFX) $(LDLIBS)
	-$(CP) $@ $(GSK_SDK)/$@.unstripped
	$(STRIP) $@
	-$(CP) $@ $(GSK_SDK)/$@

$(GSKLIB_B)_64.so: gsk_wrap2$(OBJSUFX) $(EX_OBJS) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(STKPK11) $(ZLIB_LIB) 
	$(SLD) $(SLDFLAGS) gsk_wrap2$(OBJSUFX) $(EX_OBJS) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET)   \
		$(STKPK11) $(ZLIB_LIB) $(EXPORT_FLAG)$(ICCPKG_EXPFILE) \
		$(LDLIBS)
	-$(CP) $@ $(GSK_DIR)/$@.unstripped
	$(STRIP) $@
	-$(CP) $@ $(GSK_DIR)/$@

# Java

$(JGSKLIB_B)_64.so: jgsk_wrap2$(OBJSUFX) $(JEX_OBJS) \
		$(JTIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(ZLIB_LIB)
	$(SLD) $(SLDFLAGS) jgsk_wrap2$(OBJSUFX) $(JEX_OBJS) \
		$(JTIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET)   \
		$(ZLIB_LIB) $(EXPORT_FLAG)$(JCCPKG_EXPFILE) \
		$(LDLIBS)
	-$(MKDIR) 	$(JGSK_SDK)/debug
	-$(CP) $@ $(JGSK_SDK)/debug/$@.unstripped
	$(STRIP) $@
	-$(CP) $@ $(JGSK_DIR)/$@

cache_test$(EXESUFX): cache_test$(OBJSUFX) exp$(OBJSUFX) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(STKPK11) $(ZLIB_LIB) 
	$(LD) cache_test$(OBJSUFX) exp$(OBJSUFX) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET)   \
		$(STKPK11) $(ZLIB_LIB) \
		$(LDLIBS) $(OUT) $@
