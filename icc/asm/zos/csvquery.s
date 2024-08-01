*
* int LOADPATH(void * codeAddr, char pathName[1026]);
*
LOADPATH EDCXPRLG ENTNAME=LOADPATH,DSASIZE=DYNLN,BASEREG=12,PARMWRDS=2
*
        USING  CEEDSAHP,R4
*
        L      R13,SAVEAREA         Point to save area for CSVQUERY
        ST     R1,CODEPTR           Store code addr to search for
*
        CSVQUERY INADDR=CODEPTR,OUTPATHNAME=(2),MF=(E,CSVQPL)
*
        LR     R3,R15              Move the return code into R3
        EDCXEPLG
*
* Dynamic data area
*
CEEDSAHP CEEDSA SECTYPE=XPLINK
CODEPTR  DS    F
SAVEAREA DS    18F
         CSVQUERY PLISTVER=6,MF=(L,CSVQPL)
DYNLN    EQU   *-CEEDSAHP_FIXED
*

*********************************************************************
* void s390x_km_native(char *in, char *out, long *len, char *parmBlock, 
*                      long *mode) 
s390_km_native EDCXPRLG ENTNAME=s390_km_native,BASEREG=12,PARMWRDS=5
S390_KM_NATIVE   ALIAS C's390_km_native'
* in is in r1 - out is in r2 - len is in r3 
* parmBlock and mode are in DSA
        LR     R6,R1               Move 'in' to source register
        LR     R10,R3              Get len address
        L      R7,0(R10)           Indirect length into source reg +1  
        L      R14,2048(R4)        Get DSA address
        L      R1,2112+4*3(R14)    Get param CB
        L      R10,2112+4*4(R14)   Get mode address
        L      R0,0(R10)           Indirect mode into R0
        KM     R2,R6               
        BRC    1,*-4               pay attention to partial completion
        EDCXEPLG

*********************************************************************
* void s390_kmc_native (signed char* in, signed char* out, void* len, 
*                       signed char* parm, long* mode); 
*
* This function invokes CPACF KMC instruction (CBC Cipher MODE)
*
s390_kmc_native EDCXPRLG ENTNAME=s390_kmc_native,BASEREG=12,           X
               PARMWRDS=5
S390_KMC_NATIVE   ALIAS C's390_kmc_native'
* in is in r1, out is in r2, len is in r3 
* parmBlock and mode are in DSA
        LR     R6,R1               Move in to source register
        L      R7,0(R3)        Indirect len ptr into source reg +1 reg  
        L      R14,2048(R4)        Get DSA address
        L      R1,2112+4*3(R14)    Get param CB
        L      R10,2112+4*4(R14)   Get function code address
        L      R0,0(R10)           Indirect function code address
        KMC    R2,R6
        BRC    1,*-4               pay attention to partial completion
        EDCXEPLG

*********************************************************************
* void s390_kimd_native(char *in, long *len, char *parmBlock,
*                       long *mode)
s390_kimd_native EDCXPRLG ENTNAME=s390_kimd_native,BASEREG=12,         X
               PARMWRDS=5
S390_KIMD_NATIVE   ALIAS C's390_kimd_native'
* inp is in r1 - len is in r2 - parmBlock is in r3 
* mode is in DSA
        LR     R6,R1               Move in to source register
        LR     R10,R2              Get len address
        L      R7,0(R10)           Indirect length into source reg +1
        LR     R1,R3               Move parmBlock into R1
        L      R14,2048(R4)        Get DSA address
        L      R10,2112+4*3(R14)   Get mode address
        L      R0,0(R10)           Indirect mode into R0
        KIMD   R0,R6
        BRC    1,*-4               pay attention to partial completion
        EDCXEPLG

*********************************************************************
* void s390_kmgcm_native(char* in, char* out, char* aad,
*                long *len, long *aadLen, char* parmBlock, long *mode)
s390_kmgcm_native EDCXPRLG ENTNAME=s390_kmgcm_native,BASEREG=12,       X
               PARMWRDS=7
S390_KMGCM_NATIVE   ALIAS C's390_kmgcm_native'
* in is in r1, out is in r2, aad is in r3 
* len, aadLen, parmBlock and mode are in DSA
        LR     R6,R1               Move in to source register
        LR     R8,R3               Move aad to third-Operand register
        L      R14,2048(R4)        Get DSA address
        L      R10,2112+4*3(R14)   Get len address
        L      R7,0(R10)        Indirect len and into source reg +1 reg 
        L      R10,2112+4*4(R14)   Get aadLen address
        L      R9,0(R10)    Indirect aadLen into 3rd-operand reg +1 reg
        L      R1,2112+4*5(R14)    Get param CB
        L      R10,2112+4*6(R14)   Get function code address
        L      R0,0(R10)           Indirect function code address
        KMA    R2,R8,R6
        BRC    1,*-4               pay attention to partial completion
        EDCXEPLG
*
        LTORG
*
R0       EQU   0
R1       EQU   1
R2       EQU   2
R3       EQU   3
R4       EQU   4
R5       EQU   5
R6       EQU   6
R7       EQU   7
R8       EQU   8
R9       EQU   9
R10      EQU   10
R11      EQU   11
R12      EQU   12
R13      EQU   13
R14      EQU   14
R15      EQU   15
         END
