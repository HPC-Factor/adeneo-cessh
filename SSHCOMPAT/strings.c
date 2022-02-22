//-------------------------------------------------------------------------
// <copyright file="strings.c" company="Adeneo">
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//    The use and distribution terms for this software are covered by the
//    Limited Permissive License (Ms-LPL) 
//    which can be found in the file LPL.txt at the root of this distribution.
//    By using this software in any fashion, you are agreeing to be bound by
//    the terms of this license.
//
//    The software is licensed "as-is."
//
//    You must not remove this notice, or any other, from this software.
// </copyright> 
//-------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//! \addtogroup	SSHCOmpat
//! @{
//!
//! All rights reserved ADENEO SAS 2005
//!
//! \file		strings.c
//!
//! \brief		
//!
//! 
//-----------------------------------------------------------------------------

// System include
#include <windows.h>




void asciiToUnicode(const char* src, WCHAR* dest)
{
	//We could use the fonction in Coredll but it's much simlplier this way.And we don't care about internationalization here
	register char c;
	
	do
	{
		c=*(src++);
		*(dest++) = c;
	}while(c);
}

void unicodeToAscii(const WCHAR* src, char* dest)
{
	register WCHAR wc;
	//We could use the fonction in Coredll but it's much simlplier this way. And we don't care about internationalization here
	do
	{
		wc=*(src++);
		*(dest++) = (char)wc;
	}
	while(wc);
}

char* strdupUnicodeToAscii(const WCHAR* wcstr)
{
	char* result = (char*)malloc(wcslen(wcstr)+1);
	if (result == NULL)
		return NULL;
	unicodeToAscii(wcstr, result);
	return result;
}

unsigned short* strdupAsciiToUnicode(const char* str)
{
	WCHAR* result = (unsigned short*)malloc((strlen(str)+1)*sizeof(WCHAR));
	if (result == NULL)
		return NULL;
	asciiToUnicode(str, result);
	return result;
}


// End of Doxygen group SSHCompat
//! @}