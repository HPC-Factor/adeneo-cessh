/* This file is part of the open SSH port to Windows CE. It's not present in the original open SSH project.
*/


#include "stdafx.h"
#include "winsock2.h"
#include "version.h"


extern "C" void ServerMain(void);

#define ACKNOWLEDGEMENT L"This project makes use of OpenSSL and ZLIB projects"

int _tmain(int argc, TCHAR *argv[], TCHAR *envp[])
{
    _tprintf(_T("sshd!\r\n%s\r\n%s\r\n"),TEXT(SSH_VERSION),ACKNOWLEDGEMENT);
	
	WSADATA wsadata; //can be called multiple times. every successful call to WSAStartup should have WSACleanup
	
	if (WSAStartup(MAKEWORD(2,2), &wsadata))
	{
		RETAILMSG(1,(TEXT("WSAStartup failed\r\n")));
		return FALSE;	
	}
	

	ServerMain();


	if (WSACleanup())
	{
		RETAILMSG(1,(TEXT("WSACleanup() failed.\r\n")));
	}


    return 0;
}