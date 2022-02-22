//-------------------------------------------------------------------------
// <copyright file="errno.h" company="Adeneo">
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
#ifndef __SSHCOMPAT__ERRNO_H__
#define __SSHCOMPAT__ERRNO_H__


#include <windows.h>
#include <winerror.h>

#define EINVAL 		ERROR_INVALID_PARAMETER 	/* Invalid argument */
#define ENOENT		ERROR_FILE_NOT_FOUND		/* not such file or directory*/
#define ENOSPC 		ERROR_NOT_ENOUGH_MEMORY
#define ENOMEM		ERROR_OUTOFMEMORY
#define ERANGE		EINVAL
	

#define EINTR WSAEINTR
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN WSATRY_AGAIN

#define errno (GetLastError())
#define SET_ERRNO(x) SetLastError((x))


#endif // __SSHCOMPAT__ERRNO_H__
