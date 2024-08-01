/*************************************************************************
// Copyright IBM Corp. 2023
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
*************************************************************************/

/*************************************************************************
// Description: Use hardware RNG's directly.
//
*************************************************************************/

/*!
  \FIPS TRNG_ALT4
   This entropy source relies entirely on an on-CPU hardware RBG to provide 
   entropy
*/

#include "platform.h"
#include "TRNG/nist_algs.h"
#include "TRNG/timer_entropy.h"
#include "TRNG/TRNG_ALT4.h"
#include "induced.h"

int OPENSSL_HW_rand(unsigned char *buf);


/*! Pre-init function for TRNG_ALT4
  
*/

void ALT4_preinit(int reinit)
{

}



/*! @brief
  Determine whether this noise source will is available
  @return 0 is not available , !0 if available
*/
int ALT4_Avail()
{  
  return (0 != OPENSSL_HW_rand(NULL));
}

static void alt4_read(unsigned char *buffer,int n)
{
  int i = 0;
  unsigned char x[sizeof(size_t)];
  memset(x,0,sizeof(x)); 
  while(n > 0 ) {
    i = OPENSSL_HW_rand(&x[0]);
    for( ; i > 0 && n > 0; ) {
      i--;
      n--;
      buffer[n] = x[i]; 
    }
  }
}

TRNG_ERRORS ALT4_Init(E_SOURCE *E, unsigned char *pers, int perl)
{
  TRNG_ERRORS rv = TRNG_OK;

  /* In all cases, if there's a hardware RNG use that */

  if(0 == OPENSSL_HW_rand(NULL)) {
    rv = TRNG_INIT;
  }
  return rv;
}

/*!
 @brief get a byte of "random" data.
 backup RNG for virtualized systems where the timer based source fails
 horribly.
 We get data from the OS RNG/HW RNG,
 @param ex_state extended state (unused)
 @return one byte of data
 @note
 - we do know reading one byte at a time is inefficient, but it gives 
 us more variation in the timebase counter we mix in for extra security.
 - if the external source is unavailable, we return 0's, this is detected
   at a higher level
*/
TRNG_ERRORS ALT4_getbytes(E_SOURCE *E,unsigned char *buffer,int len )
{

  alt4_read(buffer,len);
  /*! \induced 225. TRNG_ALT4. Fake failure of HW source
   */ 
  if(225 == icc_failure) {
    memset(buffer,0x73,len);
  }
  return TRNG_OK;
}

/*! @brief Cleanup any residual information in this entropy source 
  @param E The entropy source data structure
  @return TRNG_OK
 */
  
TRNG_ERRORS ALT4_Cleanup(E_SOURCE *E)
{
  TRNG_ERRORS rv = TRNG_OK;

  return rv;
}



