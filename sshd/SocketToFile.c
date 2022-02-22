/* This file is part of the open SSH port to Windows CE. It's not present in the original open SSH project.
*/


#include "windows.h"
#include "devload.h"
#include "winsock2.h"


#define SERVICE_DLL_NAME	L"SocketToFile.dll"
#define KEY_NAME_BASE L"SocketToFile_"
#define NAME_BASE L"SF"	//SF stands for for Socket-to-File
#define MAX_NUMBER_OF_INSTANCE	30  // This can be defined up to 99
#define NAME_BASE_NB_CHARACTERS 2



int CreateListeningSocket(SOCKET *pListenningSock,struct sockaddr_in *pAddr)
{    
    int val;
    

    *pListenningSock = socket(PF_INET, SOCK_STREAM, 0);
    if (*pListenningSock == INVALID_SOCKET) {
	return WSAGetLastError();
    }

    memset(pAddr, 0, sizeof(*pAddr));
    pAddr->sin_family = AF_INET;
    pAddr->sin_addr.s_addr = htonl(INADDR_ANY);
    pAddr->sin_port = htons(0);
    
    val = sizeof(*pAddr);
    if (bind(*pListenningSock, (struct sockaddr *) pAddr, val) < 0) {
	closesocket(*pListenningSock);
	return WSAGetLastError();
    }

    listen(*pListenningSock, 1);

    if (getsockname (*pListenningSock, (struct sockaddr *) pAddr, &val) < 0) {
	closesocket(*pListenningSock);
	return WSAGetLastError();
    }

    

    return 0;
}



  

int FindFreeInstanceIndex()
{
	int i;
	HANDLE h;
	DEVMGR_DEVICE_INFORMATION di;
	WCHAR wzName[6];
	for (i=0;i<MAX_NUMBER_OF_INSTANCE;i++)
	{
		wsprintf(wzName,L"%s%02d:",NAME_BASE,i);
		di.dwSize = sizeof(di);
		h = FindFirstDevice(DeviceSearchByLegacyName,wzName,&di);
		if (h == INVALID_HANDLE_VALUE)
		{
			return i;
		}
		CloseHandle(h);
	}
	return -1;
}

void PrepareRegistryForInstance(DWORD dwIndex,DWORD dwLocalPort,WCHAR** wzKey, BOOL bUseTTY)
{
	DWORD dw;
	HKEY hk;
	WCHAR szKeyName[255];
	WCHAR wzPrefix[4]; //3 letter + zero character
	DWORD dwDisp;
	DWORD dwTTY;
	swprintf(wzPrefix,L"%s%d",NAME_BASE,dwIndex / 10);

	swprintf(szKeyName,L"Drivers\\%s%d",KEY_NAME_BASE,dwIndex);
	*wzKey = wcsdup(szKeyName);

	if (ERROR_SUCCESS != RegCreateKeyEx (HKEY_LOCAL_MACHINE, szKeyName, 0, NULL, 0, KEY_WRITE, NULL, &hk, &dwDisp)) {
		wprintf (L"Failed to create registry key %s, error = %d\n", szKeyName, GetLastError ());
		return;
	}

	RegSetValueEx (hk, L"dll", 0, REG_SZ, (BYTE *)SERVICE_DLL_NAME, sizeof(SERVICE_DLL_NAME));
	RegSetValueEx (hk, L"prefix", 0, REG_SZ, (BYTE *)wzPrefix, sizeof(wzPrefix));
	if (bUseTTY)
	{
		dwTTY = 1;
		RegSetValueEx (hk, L"tty", 0, REG_DWORD, (BYTE *)&dwTTY, sizeof(dwTTY));
	}
	
	dw = dwIndex % 10;
	RegSetValueEx (hk, L"index", 0, REG_DWORD, (BYTE *)&dw, sizeof(dw));

	dw = dwLocalPort ;
	RegSetValueEx (hk, L"LocalPort", 0, REG_DWORD, (BYTE *)&dw, sizeof(dw));

	dw = DEVFLAGS_LOADLIBRARY | DEVFLAGS_NAKEDENTRIES;
	RegSetValueEx (hk, L"Flags", 0, REG_DWORD, (BYTE *)&dw, sizeof(dw));

	RegCloseKey (hk);

	if (wzKey)
	{
		
	}

}

