//-------------------------------------------------------------------------
// <copyright file="error.c" company="Adeneo">
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
//! \file		error.c
//!
//! \brief		
//!
//! 
//-----------------------------------------------------------------------------

// System include
#include <windows.h>
#include "abort.h"
#include "errno.h"

char* strerror(int errnum)
{
	return "Unknown error";
}

void perror(const char *prefix)
{
	if (prefix == NULL || *prefix == 0)
	{
		fprintf(stderr, "errno=%d\n", errno);
	}
	else
	{
		fprintf(stderr, "%s: errno=%d\n", prefix, errno);
	}
}

void __abort(char* file, int line)
{
	RETAILMSG(1,(TEXT("!!! ABORT !!! file %s line %d\r\n"),file,line));
	ASSERT(0);
	TerminateThread(GetCurrentThread(),errno);
}


// End of Doxygen group SSHCompat
//! @}