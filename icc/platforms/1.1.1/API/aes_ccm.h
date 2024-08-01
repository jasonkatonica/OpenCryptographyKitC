/* crypto/aes/aes_ccm.h */
/*----------------------------------------------------------------------------
// Licensed materials - Property of IBM                                      
//
// (C) Copyright IBM Corp.  2007
// This code was donated to the OpenSSL project under the terms of the 
// OpenSSL license.
//
//---------------------------------------------------------------------------*/

#ifndef HEADER_AES_CCM_H
#define HEADER_AES_CCM_H


#ifdef __cplusplus
extern "C" {
#endif

int AES_CCM_Encrypt(ICClib *pcb,unsigned char *iv,unsigned int ivlen,
                    unsigned char *key,unsigned int keylen,
                    unsigned char *aad, unsigned long aadlen,
                    unsigned char *data,unsigned long datalen,
                    unsigned char *out, unsigned long *outlen,
                    unsigned int taglen
		      );


int AES_CCM_Decrypt(ICClib *pcb,unsigned char *iv,unsigned int ivlen,
                    unsigned char *key,unsigned int keylen,
                    unsigned char *aad, unsigned long aadlen,
                    unsigned char *data,unsigned long datalen,
                    unsigned char *out, unsigned long *outlen,
                    unsigned int taglen
                    );


#ifdef __cplusplus
}
#endif
                                                                           
#endif
