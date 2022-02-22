//-------------------------------------------------------------------------
// <copyright file="dllmain.c" company="Adeneo">
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
//! \file		dllmain.c
//!
//! \brief		Entry point for the SSHCOMPAT dll.
//!
//! 
//-----------------------------------------------------------------------------

// System include
#include <windows.h>

#ifdef DEBUG

// The dpCurSettings structure for debug zones
DBGPARAM dpCurSettings =
{
    TEXT("ZonesApp"),
    {
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("Warning"),
        TEXT("Error")
    }
    , 0
};

#endif


BOOL WINAPI DllMain(HANDLE hInstDll, DWORD dwReason, LPVOID lpvReserved)
{
   switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DEBUGREGISTER((HMODULE)hInstDll);        
   	break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
#ifdef UNDER_CE
    case DLL_PROCESS_EXITING:        
        break;
    case DLL_SYSTEM_STARTED:
        break;
#endif
    }

    return TRUE;
}

// End of Doxygen group SSHCompat
//! @}