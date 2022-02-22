//-------------------------------------------------------------------------
// <copyright file="process.c" company="Adeneo">
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
//! \file		process.c
//!
//! \brief		
//!
//! 
//-----------------------------------------------------------------------------

// System include
#include <windows.h>


int getpid(void)
{
	return (int)GetCurrentProcessId();
}


// End of Doxygen group SSHCompat
//! @}