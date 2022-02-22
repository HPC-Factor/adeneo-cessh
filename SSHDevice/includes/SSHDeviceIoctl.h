//-----------------------------------------------------------------------------
//! \addtogroup	SSHDevice
//! @{
//!  
//! \file		SSHDeviceIoctl.h
//!
//! \if subversion
//!   $URL: $
//!   $Author: $
//!   $Revision: $
//!   $Date: $
//! \endif
//!
//! Header for Mydriver
//-----------------------------------------------------------------------------

#ifndef __SSHDEVICE_IOCTL_H__
#define __SSHDEVICE_IOCTL_H__

#define IOCTL_SELECT	CTL_CODE( FILE_DEVICE_UNKNOWN, 2048, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define INPUT_MASK	(1<<0)
#define OUTPUT_MASK	(1<<1)

#endif // __SSHDEVICE_IOCTL_H__

// End of Doxygen group SSHDevice
//! @}
//-----------------------------------------------------------------------------
// End of $URL: $
//-----------------------------------------------------------------------------
//
// Historique : $Log:  $
// Historique : 