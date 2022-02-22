//-------------------------------------------------------------------------
// <copyright file="SSHDevice_DbgZones.h" company="Adeneo">
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
//! \addtogroup	MyDriver
//! @{
//!
//! \file
//!
//! \if cvs
//!   $RCSfile: $
//!   $Author: $
//!   $Revision: $
//!   $Date: $
//! \endif
//! 
//! Debug zones masks and declaration
//-----------------------------------------------------------------------------

#ifndef __DRIVER_DBGZONES_H__
#define __DRIVER_DBGZONES_H__

#include <DBGAPI.H>

#define DEBUGMASK(n) (0x00000001<<n)

#define MASK_INIT    DEBUGMASK(0)
#define MASK_DEINIT  DEBUGMASK(1)
#define MASK_OPEN    DEBUGMASK(2)
#define MASK_CLOSE   DEBUGMASK(3)
#define MASK_READ    DEBUGMASK(4)
#define MASK_WRITE   DEBUGMASK(5)
#define MASK_SEEK    DEBUGMASK(6)
#define MASK_IOCTL   DEBUGMASK(7)
#define MASK_ZONE8   DEBUGMASK(8)
#define MASK_ZONE9   DEBUGMASK(9)
#define MASK_ZONE10  DEBUGMASK(10)
#define MASK_ZONE11  DEBUGMASK(11)
#define MASK_ZONE12  DEBUGMASK(12)
#define MASK_INFO    DEBUGMASK(13)
#define MASK_WARN    DEBUGMASK(14)
#define MASK_ERROR   DEBUGMASK(15)


#define ZONE_INIT    DEBUGZONE(0)
#define ZONE_DEINIT  DEBUGZONE(1)
#define ZONE_OPEN    DEBUGZONE(2)
#define ZONE_CLOSE   DEBUGZONE(3)
#define ZONE_READ    DEBUGZONE(4)
#define ZONE_WRITE   DEBUGZONE(5)
#define ZONE_SEEK    DEBUGZONE(6)
#define ZONE_IOCTL   DEBUGZONE(7)
#define ZONE_ZONE8   DEBUGZONE(8)
#define ZONE_ZONE9   DEBUGZONE(9)
#define ZONE_ZONE10  DEBUGZONE(10)
#define ZONE_ZONE11  DEBUGZONE(11)
#define ZONE_ZONE12  DEBUGZONE(12)
#define ZONE_INFO    DEBUGZONE(13)
#define ZONE_WARN    DEBUGZONE(14)
#define ZONE_ERROR   DEBUGZONE(15)

#endif /*__DRIVER_DBGZONES_H__*/

// End of Doxygen group MyDriver
//! @}

//! @}
//-----------------------------------------------------------------------------
// End of $RCSfile: $
//-----------------------------------------------------------------------------
//
// Historique : $Log:  $
// Historique :