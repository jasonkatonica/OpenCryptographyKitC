# GSkit8

$(AUXLIB_B).sl: icc_aux$(OBJSUFX)
	$(SLD)  $(SLDFLAGS) icc_aux$(OBJSUFX) $(LDLIBS)
	-$(CP) $@ $(GSK_SDK)/$@.unstripped
	$(STRIP) $@
	-$(CP) $@ $(GSK_SDK)/$@

$(GSKLIB_B)_64.sl: gsk_wrap2$(OBJSUFX) $(EX_OBJS)  \
		$(TIMER_OBJS) \
		$(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(STKPK11) $(ZLIB_LIB)
	$(SLD) $(SLDFLAGS) gsk_wrap2$(OBJSUFX) $(EX_OBJS) \
		$(TIMER_OBJS)  $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(STKPK11) $(ZLIB_LIB) $(EXPORT_FLAG)$(ICCPKG_EXPFILE) \
		$(LDLIBS)
	-$(CP) $@ $(GSK_DIR)/$@.unstripped
	$(STRIP) $@

# GSkit7 compat

$(GSKLIB_B_OLD)_64.sl: gsk_wrap2_old$(OBJSUFX) exp$(OBJSUFX) \
		$(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(TIMER_OBJS) $(STKPK11) $(ZLIB_LIB)
	$(SLD) $(SLDFLAGS) gsk_wrap2_old$(OBJSUFX) exp$(OBJSUFX) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(STKPK11) $(ZLIB_LIB) $(EXPORT_FLAG)$(ICCPKG_OLD_EXPFILE) \
		$(LDLIBS)
	-$(CP) $@ $(GSK_DIR_OLD)/$@.unstripped
	$(STRIP) $@

#Java

$(JGSKLIB_B)_64.sl: jgsk_wrap2$(OBJSUFX) jexp$(OBJSUFX) \
		$(JTIMER_OBJS) \
		$(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(ZLIB_LIB)
	$(SLD)  $(SLDFLAGS) jgsk_wrap2$(OBJSUFX) jexp$(OBJSUFX) \
		$(JTIMER_OBJS)  $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(ZLIB_LIB) $(EXPORT_FLAG)$(JCCPKG_EXPFILE) \
		$(LDLIBS)
	-$(MKDIR) 	$(JGSK_SDK)/debug
	-$(CP) $@ $(JGSK_SDK)/debug/$@.unstripped
	$(STRIP) $@

cache_test$(EXESUFX): cache_test$(OBJSUFX) exp$(OBJSUFX) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET) \
		$(STKPK11) $(ZLIB_LIB) 
	$(LD) cache_test$(OBJSUFX) exp$(OBJSUFX) \
		$(TIMER_OBJS) $(NEW_ICC)/iccsdk/$(ICCLIB) $(MUPPET)   \
		$(STKPK11) $(ZLIB_LIB) \
		$(LDLIBS) $(OUT) $@