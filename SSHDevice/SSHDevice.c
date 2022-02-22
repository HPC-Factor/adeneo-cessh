//-------------------------------------------------------------------------
// <copyright file="SSHDevice.c" company="Adeneo">
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
//! All rights reserved ADENEO SAS 2005
//!
//! \file		SSHDevice.c
//!
//! \brief		
//!
//! \if subversion
//!   $URL:  $
//!   $Author:  $
//!   $Revision:  $
//!   $Date:  $
//! \endif
//!
//! 
//-----------------------------------------------------------------------------

// System include
#include <windows.h>
#include <winsock2.h>
#include <devload.h>
#include "SSHDeviceIoctl.h"	


#include "SSHDevice_DbgZones.h"
#include "SSHDevice.h"


// The dpCurSettings structure for debug zones
DBGPARAM dpCurSettings =
{
    TEXT("ZonesApp"),
    {
        TEXT("Init"),
        TEXT("DeInit"),
        TEXT("Open"),
        TEXT("Close"),
        TEXT("Read"),
        TEXT("Write"),
        TEXT("Seek"),
        TEXT("IOCtl"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("na"),
        TEXT("Warning"),
        TEXT("Error")
    }
    , MASK_INIT | MASK_DEINIT | MASK_INFO | MASK_ERROR
};


BOOL Deinit(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext);

//-----------------------------------------------------------------------------
//! \fn			BOOL WINAPI DllEntry( HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
//!
//! \brief		This function is the entry point of the Dll driver
//!
//! \param		hinstDLL	DLL instance
//! \param		dwReason	Reason of the call
//! \param		lpvReserved	Not used
//!
//! \return		\e TRUE when all is good
//!	\return		\e FALSE when all is bad
//!
//! This function intialize debug zone when called with the DLL_PROCESS_ATTACH reason
//-----------------------------------------------------------------------------
BOOL WINAPI DllEntry(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DEBUGREGISTER((HMODULE)hinstDLL);
        DEBUGMSG(ZONE_INFO,(TEXT("SSHDRIVER: DLL_PROCESS_ATTACH\n")));
   	break;
    case DLL_THREAD_ATTACH:
        DEBUGMSG(ZONE_INFO,(TEXT("SSHDRIVER: DLL_THREAD_ATTACH\n")));
        break;
    case DLL_THREAD_DETACH:
        DEBUGMSG(ZONE_INFO,(TEXT("SSHDRIVER: DLL_THREAD_DETACH\n")));
        break;
    case DLL_PROCESS_DETACH:
        DEBUGMSG(ZONE_INFO,(TEXT("SSHDRIVER: DLL_PROCESS_DETACH\n")));
        break;
#ifdef UNDER_CE
    case DLL_PROCESS_EXITING:
        DEBUGMSG(ZONE_INFO,(TEXT("SSHDRIVER: DLL_PROCESS_EXITING\n")));
        break;
    case DLL_SYSTEM_STARTED:
        DEBUGMSG(ZONE_INFO,(TEXT("SSHDRIVER: DLL_SYSTEM_STARTED\n")));
        break;
#endif
    }

    return TRUE;
}


//-----------------------------------------------------------------------------
//! \fn			DWORD Init(LPCTSTR pContext, LPCVOID lpvBusContext)
//!
//! \brief		This function initializes the device.
//!
//! \param		pContext		Pointer to a string containing the registry path to the active key for the stream interface driver.
//! \param		lpvBusContext	Potentially process-mapped pointer passed as the 
//!								fourth parameter to ActivateDeviceEx. If this driver 
//!								was loaded through legacy mechanisms, then lpvBusContext 
//!								is zero. This pointer, if used, has only been mapped 
//!								again as it passes through the protected server library (PSL).
//!								The <b>Init<b> function is responsible for performing all protection 
//!								checking. In addition, any pointers referenced through lpvBusContext 
//!								must be remapped with the <b>MapCallerPtr</b> function before they 
//!								can be dereferenced.
//!
//! \return		Returns a handle to the device context created if successful. 
//!	\return		\e zero if not successful.
//!
//! Device Manager calls this function as a result of a call to the ActivateDeviceEx 
//! function. When the user starts using a device, such as inserting a PC Card, 
//! Device Manager calls this function to initialize the device. Applications do not call this function. 
//-----------------------------------------------------------------------------
DWORD Init(LPCTSTR pContext, LPCVOID lpvBusContext)
{
	T_SSHDEVICEINIT_STRUCTURE *pDeviceContext = (T_SSHDEVICEINIT_STRUCTURE *)LocalAlloc(LMEM_ZEROINIT|LMEM_FIXED, sizeof(T_SSHDEVICEINIT_STRUCTURE));
	WSADATA wsadata; //can be called multiple times. every successful call to WSAStartup should have WSACleanup
	SOCKET CommSock;
	DWORD dwPort,dwTTY,dwSize;
	HKEY hKey;
	u_long enabled = 1;	
	u_long disabled = 0;	
	struct sockaddr_in cli_addr;
	


	
	if (pDeviceContext == NULL)
	{
		return 0;
	}
	
	hKey = OpenDeviceKey(pContext);
	dwSize = sizeof(dwPort);
	if (RegQueryValueEx(hKey,L"LocalPort",NULL,NULL,(LPBYTE) &dwPort,&dwSize) != ERROR_SUCCESS)
	{
		Deinit(pDeviceContext);
		return (DWORD) NULL;
	}
	dwSize = sizeof(dwTTY);
	if (RegQueryValueEx(hKey,L"tty",NULL,NULL,(LPBYTE) &dwTTY,&dwSize) != ERROR_SUCCESS)
	{		
		dwTTY = 0;
	}
	RegCloseKey(hKey);	


	if (WSAStartup(MAKEWORD(2,2), &wsadata))
	{
		RETAILMSG(1,(TEXT("WSAStartup failed\r\n")));
		Deinit(pDeviceContext);
		return (DWORD) NULL;
	}

	memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cli_addr.sin_port = (u_short) dwPort;

    CommSock = socket(PF_INET, SOCK_STREAM, 0);
    if (CommSock == INVALID_SOCKET) 
	{	
		Deinit(pDeviceContext);
		return (DWORD) NULL;
    }

    if (connect(CommSock, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) != 0) 
	{
		Deinit(pDeviceContext);		
		return (DWORD) NULL;
    }


//	ioctlsocket(CommSock,FIONBIO,&enabled);
	ioctlsocket(CommSock,FIONBIO,&disabled);

	pDeviceContext->s = CommSock;
	pDeviceContext->dwOpenCount = 0;
	pDeviceContext->bIsTTY = dwTTY ? TRUE : FALSE;

	return (DWORD)pDeviceContext;
}


//-----------------------------------------------------------------------------
//! \fn			BOOL Deinit(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext)
//!
//! \brief		This function uninitializes the device.
//!
//! \param		pContextInit	Pointer to the the device init context. The Init (Device Manager)
//!								function creates and returns this pointer.
//!
//! \return		\e TRUE indicates success
//!	\return		\e FALSE indicates failure
//!
//! When the user stops using a device, such as when a PC Card is removed from its socket, 
//! Device Manager calls this function. Applications do not call this function. Device Manager 
//! calls the Deinit driver function as a result of a call to the DeactivateDevice function. 
//! Your stream interface driver should free any resources it has allocated, and then terminate.
//-----------------------------------------------------------------------------
BOOL Deinit(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext)
{
	BOOL bRet = TRUE;

	if (pDeviceContext != NULL)
	{
		// All devices have to be unloaded before deinitialising the driver
		if (pDeviceContext->dwOpenCount != 0)
		{
			bRet = FALSE;
		}
		else
		{
			// Free allocated memory
			if (LocalFree(pDeviceContext) != NULL)
			{
				bRet = FALSE;
			}
		}

	}

	if (bRet)
	{
		shutdown(pDeviceContext->s,SD_BOTH);
		closesocket(pDeviceContext->s);

		if (WSACleanup())
		{
			RETAILMSG(1,(TEXT("WSACleanup() failed.\r\n")));
		}
	}

	return bRet;
}


//-----------------------------------------------------------------------------
//! \fn			DWORD Open(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext, DWORD AccessCode, DWORD ShareMode)
//!
//! \brief		This function opens a device for reading, writing, or both.
//!
//! \param		pDeviceContext	Pointer to the the device open context. The <b>Init</b> (Device Manager)
//!								function creates and returns this identifier.
//! \param		AccessCode		Access code for the device. The access is a combination
//!								of read and write access from <b>CreateFile</b>. 
//! \param		ShareMode		File share mode of the device. The share mode is a combination 
//!								of read and write access sharing from <b>CreateFile</b>. 
//!
//! \return		This function returns a handle that identifies the open context of the device 
//!				to the calling application. If your device can be opened multiple times, use 
//!				this handle to identify each open context.
//!
//! When this function executes, your device should allocate the resources that it needs for 
//! each open context and prepare for operation. This might involve preparing the device for 
//! reading or writing and initializing data structures it uses for operation.
//-----------------------------------------------------------------------------
DWORD Open(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext, DWORD AccessCode, DWORD ShareMode)
{
	T_SSHDEVICEOPEN_STRUCTURE *pOpenContext = (T_SSHDEVICEOPEN_STRUCTURE*)LocalAlloc(LMEM_ZEROINIT|LMEM_FIXED, sizeof(T_SSHDEVICEOPEN_STRUCTURE));
	
	// Store device settings for futur use
	pOpenContext->pDeviceContext = pDeviceContext;
	pOpenContext->dwAccessCode = AccessCode;
	pOpenContext->dwShareMode = ShareMode;
	
	
	// Increase opened device counter
	pOpenContext->pDeviceContext->dwOpenCount++;	

	return (DWORD)pOpenContext;
}


//-----------------------------------------------------------------------------
//! \fn			BOOL Close(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext)
//!
//! \brief		This function closes a device context created by the pOpenContext parameter.
//!
//! \param		pOpenContext	Pointer returned by the <b>Open</b> (Device Manager) function, 
//!								which is used to identify the open context of the device. 
//!
//! \return		\e TRUE indicates success
//!	\return		\e FALSE indicates failure
//!
//! An application calls the CloseHandle function to stop using a stream interface driver. 
//! The hFile parameter specifies the handle associated with the device context. In response
//! to <b>CloseHandle</b>, the operating system invokes <b>Close</b>.
//-----------------------------------------------------------------------------
BOOL Close(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext)
{
	BOOL bRet = TRUE;
	
	if (pOpenContext != NULL)
	{
		T_SSHDEVICEINIT_STRUCTURE *pDeviceContext = pOpenContext->pDeviceContext;

		// Free memory
		if (LocalFree(pOpenContext) != NULL)
		{
			bRet = FALSE;
		}
		else
		{
			// Decrease opened device counter
			pDeviceContext->dwOpenCount--;

			if (pDeviceContext->dwOpenCount == 0)
			{
				closesocket(pDeviceContext->s);
			}
		}
		
	}

	return bRet;
}


//-----------------------------------------------------------------------------
//! \fn			DWORD Read(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, LPVOID pBuffer, DWORD Count)
//!
//! \brief		This function reads data from the device identified by the open context.
//!
//! \param		pOpenContext	Handle to the open context of the device. The <b>Open</b> 
//!								(Device Manager) function creates and returns this identifier.  
//! \param		pBuffer			Pointer to the buffer that stores the data read from 
//!								the device. This buffer should be at least <i>Count</i> bytes long. 
//! \param		dwCount			Number of bytes to read from the device into <i>pBuffer</i>.
//!
//! \return		\e zero to indicate <i>end-of-file</i>. 
//! \return		\e -1 to indicate an error. 
//! \return		The number of bytes read to indicate success.
//!
//! After an application calls the ReadFile function to read from the device, the operating system
//! invokes this function. The <i>hFile</i> parameter is a handle to the device. The <i>pBuffer</i> parameter 
//! points to the buffer that contains the data read from the device. The <i>dwCount</i> parameter indicates 
//! the number of bytes that the application requests to read from the device.
//-----------------------------------------------------------------------------
DWORD Read(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, LPVOID pBuffer, DWORD dwCount)
{
	DWORD dwDataSize = -1;
	T_SSHDEVICEINIT_STRUCTURE *pDeviceContext = pOpenContext->pDeviceContext;
	
	// At least a device have to be opened
	if (pOpenContext == NULL || !pOpenContext->pDeviceContext->dwOpenCount)
		return -1;

	// The device have to be readable
	if (! (pOpenContext->dwAccessCode & GENERIC_READ))
		return -1;


	if (!pDeviceContext->bIsTTY)
	{
		dwDataSize = recv(pDeviceContext->s,pBuffer,dwCount,0);
		

		//RETAILMSG(1,(TEXT("recv returned %d\r\n"),dwDataSize));

		return dwDataSize;
	}
	else
	{
		DWORD i;
		char* pTemp = pBuffer;
		dwDataSize = recv(pDeviceContext->s,pBuffer,dwCount,0);
		//Echo 
		send(pDeviceContext->s,pBuffer,dwDataSize,0);
		if (dwDataSize == 0xFFFFFFFF)
		{
			return 0xFFFFFFFF;
		}
		
		for (i=0;i<dwDataSize;i++)
		{
			if (pTemp[i] == '\r')
			{
				pTemp[i] = '\n';
			}
		}

		//RETAILMSG(1,(TEXT("recv TTY returned %d\r\n"),dwDataSize));

		return dwDataSize;
	}
}


//-----------------------------------------------------------------------------
//! \fn			DWORD Write(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, LPCVOID pBuffer, DWORD dwCount)
//!
//! \brief		This function writes data to the device.
//!
//! \param		pOpenContext	Handle to the open context of the device. The <b>Open</b> 
//!								(Device Manager) function creates and returns this identifier.  
//! \param		pBuffer			Pointer to the buffer that contains the data to write. 
//!								This buffer should be at least <i>Count</i> bytes long. 
//! \param		dwCount			Number of bytes to write from the <i>pBuffer</i> buffer into the device.
//!
//! \return		The number of bytes  written indicates success
//! \return		\e -1 to indicate an error. 
//!
//! After an application uses the WriteFile function to write to the device, the operating system, 
//! invokes this function. The <i>hFile</i> parameter is a handle to the device. The <i>pBuffer</i> parameter 
//! points to the buffer that contains the data read from the device. The <i>dwCount</i> parameter indicates 
//! the number of bytes that the application requests to write to the device.
//-----------------------------------------------------------------------------
DWORD Write(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, LPCVOID pBuffer, DWORD dwCount)
{
	DWORD dwDataSize = -1;
	T_SSHDEVICEINIT_STRUCTURE *pDeviceContext = pOpenContext->pDeviceContext;

	// At least a device have to be opened
	if (pOpenContext == NULL || !pOpenContext->pDeviceContext->dwOpenCount)
		return -1;

	// The device have to be readable
	if (! (pOpenContext->dwAccessCode & GENERIC_WRITE))
		return -1;

	
	dwDataSize = send(pDeviceContext->s,pBuffer,dwCount,0);
	//RETAILMSG(1,(TEXT("send returned %d\r\n"),dwDataSize));

	return dwDataSize;

}


//-----------------------------------------------------------------------------
//! \fn			DWORD Seek(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, long Amount, WORD wType)
//!
//! \brief		This function moves the data pointer in the device.
//!
//! \param		pOpenContext	Handle to the open context of the device. The <b>Open</b> 
//!								(Device Manager) function creates and returns this identifier.  
//! \param		Amount			Number of bytes to move the data pointer in the device. A positive value 
//!								moves the data pointer toward the end of the file and a negative value 
//!								moves it toward the beginning.
//! \param		wType			Starting point for the data pointer. The following table shows the available values for this parameter.
//!
//! \return		The new data pointer for the device indicates success.
//! \return		\e -1 to indicate an error. 
//!
//! After an application calls the SetFilePointer function to move the data pointer in the device, 
//! the operating system invokes this function. If your device is capable of opening more than once, 
//! this function modifies only the data pointer for the instance specified by <i>pOpenContext</i>.
//-----------------------------------------------------------------------------
DWORD Seek(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, long Amount, WORD wType)
{
	DWORD dwDataSeek = -1;

	// At least a device have to be opened
	if (pOpenContext == NULL || !pOpenContext->pDeviceContext->dwOpenCount)
		return -1;

	return dwDataSeek;
}


//-----------------------------------------------------------------------------
//! \fn			BOOL IOControl(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, DWORD dwCode, PBYTE pBufIn, DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut)
//!
//! \brief		This function sends a command to a device.
//!
//! \param		pOpenContext	Handle to the open context of the device. The <b>Open</b> 
//!								(Device Manager) function creates and returns this identifier.  
//! \param		dwCode			I/O control operation to perform. These codes are device-specific and 
//!								are usually exposed to developers through a header file. 
//!								Use <b>CTL_CODE</b> macro to generate a driver unique identifier for your iocontrol.
//! \param		pBufIn			Pointer to the buffer containing data to transfer to the device. 
//! \param		dwLenIn			Number of bytes of data in the buffer specified for <i>pBufIn</i>.
//! \param		pBufOut			Pointer to the buffer used to transfer the output data from the device.
//! \param		dwLenOut		Maximum number of bytes in the buffer specified by <i>pBufOut</i>.
//! \param		pdwActualOut	Pointer to the <b>DWORD</b> buffer that this function uses to 
//!								return the actual number of bytes received from the device. 
//!
//! \return		\e TRUE indicates success.
//! \return		\e FALSE indicates failure.
//!
//! An application uses the DeviceIoControl function to specify an operation to perform. The operating system,
//! in turn, invokes the <b>IOControl</b> function. The <i>dwCode</i> parameter contains the input or output 
//! operation to perform; these codes are usually specific to each device driver and are exposed to application 
//! programmers through a header file that the device driver developer makes available.
//-----------------------------------------------------------------------------
BOOL IOControl(T_SSHDEVICEOPEN_STRUCTURE *pOpenContext, DWORD dwCode, PBYTE pBufIn, DWORD dwLenIn, PBYTE pBufOut, DWORD dwLenOut, PDWORD pdwActualOut)
{
	BOOL bRet = TRUE;

	// At least a device have to be opened
	if (pOpenContext == NULL || !pOpenContext->pDeviceContext->dwOpenCount)
		return FALSE;

	switch (dwCode)
	{
		case IOCTL_SELECT:
			{
				int result;
				fd_set readset,writeset,errset;

				FD_ZERO(&readset);
				FD_ZERO(&writeset);
				FD_ZERO(&errset);
				
				if (pBufIn == NULL)
				{
					return FALSE;
				}
				if (*((DWORD*)pBufIn) & (1<<0))
				{
					FD_SET(pOpenContext->pDeviceContext->s, &readset);
				}
				if (*((DWORD*)pBufIn) & (1<<1))
				{
					FD_SET(pOpenContext->pDeviceContext->s, &writeset);
				}				
				
				if (select(0,&readset,&writeset,&errset,NULL) == SOCKET_ERROR)
				{
					bRet = FALSE;
					result = WSAGetLastError();
				}
				else
				{
					bRet = TRUE;
					result = (!FD_ISSET(pOpenContext->pDeviceContext->s, &readset) ? 0 : (1<<0) ) |
							 (!FD_ISSET(pOpenContext->pDeviceContext->s, &writeset) ? 0 : (1<<1) );
				}

				if (pBufOut && (dwLenOut >= sizeof(result)))
				{
					*((int*)pBufOut) = result;
					if (pdwActualOut)
					{
						*pdwActualOut = sizeof(result);
					}
				}
			}			
			break;

		default:
			bRet = FALSE;
	}

	return bRet;
}


//-----------------------------------------------------------------------------
//! \fn			void PowerDown(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext)
//!
//! \brief		This function suspends power to the device. It is useful only with devices that can 
//!				power down under software control. Such devices are typically, but not exclusively, PC Cards.
//!
//! \param		pDeviceContext	Pointer to the device context. The call to the <b>Init</b> 
//!								(Device Manager) function returns this identifier.  
//!
//! \return		none
//!
//! The OS invokes this function to suspend power to a device.
//-----------------------------------------------------------------------------
void PowerDown(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext)
{

}


//-----------------------------------------------------------------------------
//! \fn			void PowerUp(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext)
//!
//! \brief		This function restores power to a device.
//!
//! \param		pDeviceContext	Pointer to the device context. The call to the <b>Init</b> 
//!								(Device Manager) function returns this identifier.  
//!
//! \return		none
//!
//! The OS invokes this function to restore power to a device.
//-----------------------------------------------------------------------------
void PowerUp(T_SSHDEVICEINIT_STRUCTURE *pDeviceContext)
{

}


// End of Doxygen group SSHDevice
//! @}
//-----------------------------------------------------------------------------
// End of $URL: $
//-----------------------------------------------------------------------------
//
// Historique : $Log: $
// Historique : 
