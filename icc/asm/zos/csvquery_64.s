         SYSSTATE AMODE64=YES,ARCHLVL=2
*
* int LOADPATH(void * codeAddr, char pathName[1026]);
*
LOADPATH CELQPRLG ENTNAME=LOADPATH,BASEREG=R12,PARMWRDS=2
        LGR   R5,R1               Save codeAddr
*
* Get storage for plist
*
        STORAGE OBTAIN,LENGTH=LPDYNLT,ADDR=(1),LOC=31,COND=YES
        LR     R3,R15             Move the return code into R3
        LTR    R15,R15            Did we get the storage?
        BNZ    LPDONE             Nope, exit
*
        LGR    R13,R1
        USING  LPDYN,R13
*
        STG    R5,CODEPTR
        CSVQUERY INADDR64=CODEPTR,OUTPATHNAME=(2),MF=(E,CSVQPL)
*
        LR     R3,R15              Move the return code into R3
* Free the plist storage
        LGR    R1,R13
        STORAGE RELEASE,LENGTH=LPDYNLT,ADDR=(1)
        B      LPDONE
*
LPDONE  DS     0H
        CELQEPLG
*
* Use this area to figure out how big the 31 bit area should be
*
         LTORG
LPDYN    DSECT ,
CODEPTR  DS    FD
         CSVQUERY PLISTVER=6,MF=(L,CSVQPL)
LPDYNLT  EQU   *-LPDYN            Length of 31 bit dynamic area
*

*********************************************************************
* void s390x_km_native(char *in, char *out, long *len, char *parmBlock, 
*                      long *mode) 
s390_km_native CELQPRLG ENTNAME=s390_km_native,BASEREG=12,PARMWRDS=5
S390_KM_NATIVE   ALIAS C's390_km_native'
* in is in r1 - out is in r2 - len is in r3 
* parmBlock and mode are in DSA
        LGR    R6,R1               Move in to source register
        LGR    R10,R3              Get len address
        LG     R7,0(R10)           Indirect length into source reg +1  
        LG     R14,2048(R4)        Get DSA address
        LG     R1,2176+8*3(R14)    Get param CB
        LG     R10,2176+8*4(R14)   Get mode address
        LG     R0,0(R10)           Indirect mode into R0
        KM     R2,R6               
        BRC    1,*-4               pay attention to partial completion
        CELQEPLG

*********************************************************************
* void s390_kmc_native (signed char* in, signed char* out, void* len, 
*                       signed char* parm, long* mode); 
*
* This function invokes CPACF KMC instruction (CBC Cipher MODE)
*
s390_kmc_native CELQPRLG ENTNAME=s390_kmc_native,BASEREG=12,           X
               PARMWRDS=5
S390_KMC_NATIVE   ALIAS C's390_kmc_native'
* in is in r1, out is in r2, len is in r3 
* parmBlock and mode are in DSA
        LGR    R6,R1               Move in to source register
        LG     R7,0(R3)        Indirect len ptr into source reg +1 reg  
        LG     R14,2048(R4)        Get DSA address
        LG     R1,2176+8*3(R14)    Get param CB
        LG     R10,2176+8*4(R14)   Get function code address
        LG     R0,0(R10)           Indirect function code address
        KMC    R2,R6
        BRC    1,*-4               pay attention to partial completion
        CELQEPLG

*********************************************************************
* void s390_kimd_native(char *in, long *len, char *parmBlock,
*                       long *mode)
s390_kimd_native CELQPRLG ENTNAME=s390_kimd_native,BASEREG=12,         X
               PARMWRDS=5
S390_KIMD_NATIVE   ALIAS C's390_kimd_native'
* inp is in r1 - len is in r2 - parmBlock is in r3 
* mode is in DSA
        LGR    R6,R1               Move in to source register
        LGR    R10,R2              Get len address
        LG     R7,0(R10)           Indirect length into source reg +1
        LGR    R1,R3               Move parmBlock into R1
        LG     R14,2048(R4)        Get DSA address
        LG     R10,2176+8*3(R14)   Get mode address
        LG     R0,0(R10)           Indirect mode into R0
        KIMD   R0,R6
        BRC    1,*-4               pay attention to partial completion
        CELQEPLG

*********************************************************************
* void s390_kmgcm_native(char* in, char* out, char* aad,
*                long *len, long *aadLen, char* parmBlock, long *mode)
s390_kmgcm_native CELQPRLG ENTNAME=s390_kmgcm_native,BASEREG=12,       X
               PARMWRDS=7
S390_KMGCM_NATIVE   ALIAS C's390_kmgcm_native'
* in is in r1, out is in r2, aad is in r3 
* len, aadLen, parmBlock and mode are in DSA
        LGR    R6,R1               Move in to source register
        LGR    R8,R3               Move aad to third-Operand register
        LG     R14,2048(R4)        Get DSA address
        LG     R10,2176+8*3(R14)   Get len address
        LG     R7,0(R10)        Indirect len and into source reg +1 reg 
        LG     R10,2176+8*4(R14)   Get aadLen address
        LG     R9,0(R10)    Indirect aadLen into 3rd-operand reg +1 reg
        LG     R1,2176+8*5(R14)    Get param CB
        LG     R10,2176+8*6(R14)   Get function code address
        LG     R0,0(R10)           Indirect function code address
        KMA    R2,R8,R6
        BRC    1,*-4               pay attention to partial completion
        CELQEPLG
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
