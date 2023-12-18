/*************************************************************************
// Copyright IBM Corp. 2023
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution.
*************************************************************************/

/*************************************************************************
// Description: ICC Version
//
*************************************************************************/

#ifndef INCLUDED_ICCVERSION
#define INCLUDED_ICCVERSION

/* NOTE: This must be changed every version (i.e. ICC v0.1, v1.1, v2.1, etc) */
#if !defined(ICC_VERSION_VER)
#  define ICC_VERSION_VER 8
#endif

/* NOTE: This must be changed every release (i.e. ICC v1.1, v1.2, v1.3, etc) */
#if !defined(ICC_VERSION_REL)
#  define ICC_VERSION_REL 9
#endif

#if defined(ICC_OFFICIAL_BUILD)

# include "buildinfo.h"

#else   /* !ICC_OFFICIAL_BUILD */

#  define ICC_PRODUCT_NAME       "Unknown"
#  define ICC_VERSION_MOD        0
#  define ICC_VERSION_FIX        0
#  define ICC_BUILD_DATE         0
#  define ICC_BUILD_TIME         0
#  define ICC_CMVC_INFO          "Unofficial build"
#  define ICC_EXTRACT_DATE       0
#  define ICC_EXTRACT_TIME       0

#endif   /* ICC_OFFICIAL_BUILD */

#if !defined(ICC_VERSION_MOD)
#   define ICC_VERSION_MOD 0
#endif

#if !defined(ICC_VERSION_FIX)
#define ICC_VERSION_FIX 0
#endif

/* Utility MACROs */
#define MAKESTRING_REALLY(x) #x
#define MAKESTRING(x) MAKESTRING_REALLY(x)


/* Win32 only ->                     v   default width of first visible field for rc v */
#define ICC_DESCRIPTION1            "Open Cryptography Kit for C"
#define ICC_DESCRIPTION2            ""
#define ICC_PRODUCT_VERSION         MAKESTRING(ICC_VERSION_VER) "." \
                                    MAKESTRING(ICC_VERSION_REL) "." \
                                    MAKESTRING(ICC_VERSION_MOD) "." \
                                    MAKESTRING(ICC_VERSION_FIX)
#define ICC_PRODUCT_VERSION_COMMAS  ICC_VERSION_VER,ICC_VERSION_REL,ICC_VERSION_MOD,ICC_VERSION_FIX
#define ICC_PRODUCT_INFO            __DATE__ " " \
                                    __TIME__


#endif   /* INCLUDED_ICCVERSION */
