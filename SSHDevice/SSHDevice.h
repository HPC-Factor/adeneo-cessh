//-------------------------------------------------------------------------
// <copyright file="SSHDevice.h" company="Adeneo">
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
//! \addtogroup	SSHDevice
//! @{
//!  
//! \file		SSHDevice.h
//!
//! \if subversion
//!   $URL: $
//!   $Author: $
//!   $Revision: $
//!   $Date: $
//! \endif
//!
//-----------------------------------------------------------------------------

#ifndef __SSHDEVICE_H__
#define __SSHDEVICE_H__

typedef struct {	
	DWORD dwOpenCount;
	SOCKET s;
	BOOL bIsTTY;	
} T_SSHDEVICEINIT_STRUCTURE;

typedef struct {
	T_SSHDEVICEINIT_STRUCTURE *pDeviceContext;
	DWORD dwAccessCode;
	DWORD dwShareMode;

} T_SSHDEVICEOPEN_STRUCTURE;


#endif // __SSHDEVICE_H__

// End of Doxygen group SSHDevice
//! @}
//-----------------------------------------------------------------------------
// End of $URL: $
//-----------------------------------------------------------------------------
//
// Historique : $Log:  $
// Historique : 