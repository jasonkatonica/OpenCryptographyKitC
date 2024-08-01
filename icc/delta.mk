#- Delta time code, used for checking vulnerability to timing attacks

DELTA = Delta_test$(EXESUFX) $(SHLPRFX)delta$(SHLSUFX)

#high_res_timer.c: TRNG/timer_entropy.c
#	$(CP) TRNG/timer_entropy.c $@

delta$(OBJSUFX): DELTA/delta.c TRNG/timer_entropy.h
	$(CC) $(CFLAGS) -I ./ DELTA/delta.c

iccstub$(OBJSUFX): DELTA/iccstub.c 
	$(CC) $(CFLAGS) -I ./ DELTA/iccstub.c

high_res_timer$(OBJSUFX): TRNG/timer_entropy.c
	$(CC) $(CFLAGS) $(ASM_TWEAKS) -D HIGH_RES_TIMER=1 -I . TRNG/timer_entropy.c $(OUT)$@	

Delta_test$(OBJSUFX): DELTA/Delta_test.c
	$(CC) $(CFLAGS) -I ./ DELTA/Delta_test.c

#- Build test code

Delta_test$(EXESUFX): delta$(OBJSUFX) Delta_test$(OBJSUFX) \
		high_res_timer$(OBJSUFX)  iccstub$(OBJSUFX) $(ASMOBJS)
	$(LD) $(LDFLAGS) delta$(OBJSUFX) Delta_test$(OBJSUFX) \
		high_res_timer$(OBJSUFX)  iccstub$(OBJSUFX) \
		 $(ASMOBJS) $(LDLIBS)

$(SHLPRFX)delta$(SHLSUFX):  delta$(OBJSUFX) \
		high_res_timer$(OBJSUFX) iccstub$(OBJSUFX) \
	 	$(ASMOBJS)
	$(SLD)  $(SLDFLAGS) delta$(OBJSUFX) \
		high_res_timer$(OBJSUFX) iccstub$(OBJSUFX) \
		$(ASMOBJS) \
	$(EXPORT_FLAG)DELTA/$(ICCLIB_EXPFILE)
	$(CP) $@ ../package/iccsdk/$@

